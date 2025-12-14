"""
llm_client.py

Provider-agnostic client abstraction for τGuardian.

This module defines:
  - LLMConfig: normalized configuration for a model call.
  - LLMClient protocol: interface used by τGuardian.
  - Concrete provider clients: OpenAIClient, GeminiClient, FakeClient, LocalGemmaClient.
  - Factory helpers: get_client(), generate_code(), generate_code_from_env().
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any, Dict, Optional, Protocol, runtime_checkable, Literal, Tuple
import os

try:
    import torch  # type: ignore
    from transformers import AutoTokenizer, AutoModelForCausalLM  # type: ignore
except Exception:  # transformers is optional for non-local providers
    torch = None
    AutoTokenizer = None
    AutoModelForCausalLM = None

# -----------------------------------------------------------------------------
# Local Gemma 3n singleton (loaded once per process)
# -----------------------------------------------------------------------------
_LOCAL_GEMMA_MODEL = None
_LOCAL_GEMMA_TOKENIZER = None


def _load_local_gemma_model(model_path: str):
    """
    Lazily load Gemma 3n from a local HF directory.

    Expects `config`, `tokenizer_config`, and safetensors shards under model_path.
    """
    global _LOCAL_GEMMA_MODEL, _LOCAL_GEMMA_TOKENIZER

    if _LOCAL_GEMMA_MODEL is not None and _LOCAL_GEMMA_TOKENIZER is not None:
        return _LOCAL_GEMMA_MODEL, _LOCAL_GEMMA_TOKENIZER

    if torch is None or AutoTokenizer is None or AutoModelForCausalLM is None:
        raise RuntimeError(
            "Local Gemma requested but transformers/torch are not installed. "
            "Install with: pip install 'torch>=2.3.0' 'transformers>=4.53.0' accelerate safetensors"
        )

    # Prefer GPU if available; otherwise float16 on CPU to reduce RAM.
    if torch.cuda.is_available():
        dtype = torch.bfloat16
        device_map = "auto"
    else:
        dtype = torch.float16
        device_map = "cpu"

    tokenizer = AutoTokenizer.from_pretrained(
        model_path,
        trust_remote_code=True,
    )
    model = AutoModelForCausalLM.from_pretrained(
        model_path,
        dtype=dtype,
        device_map=device_map,
        low_cpu_mem_usage=True,
    )
    model.eval()

    _LOCAL_GEMMA_MODEL = model
    _LOCAL_GEMMA_TOKENIZER = tokenizer
    return model, tokenizer


ProviderName = Literal["openai", "gemini", "fake", "local_gemma"]


@dataclass(frozen=True)
class LLMConfig:
    """Normalized configuration for a single LLM call."""
    provider: ProviderName
    model: str
    temperature: float = 0.1
    max_tokens: int = 2048
    purpose: str = "code"  # reserved for future use


class LLMError(RuntimeError):
    """Unified error type for all provider failures."""


@runtime_checkable
class LLMClient(Protocol):
    config: LLMConfig

    def generate(self, prompt: str, **kwargs: Any) -> str:
        ...


# ---------------------------------------------------------------------------
# Provider implementations
# ---------------------------------------------------------------------------

class OpenAIClient:
    """OpenAI implementation using openai>=1.0.0."""

    def __init__(self, config: LLMConfig) -> None:
        self.config = config
        try:
            from openai import OpenAI  # type: ignore
        except ImportError as exc:
            raise LLMError(
                "openai package not installed. "
                "Run `pip install openai` in your virtualenv."
            ) from exc

        api_key = os.getenv("OPENAI_API_KEY")
        if not api_key:
            raise LLMError("OPENAI_API_KEY is not set in environment.")
        self._client = OpenAI(api_key=api_key)

    def generate(self, prompt: str, **_: Any) -> str:
        resp = self._client.chat.completions.create(
            model=self.config.model,
            messages=[
                {
                    "role": "system",
                    "content": (
                        "You are an expert software engineer. "
                        "Return ONLY the final code, inside a single fenced code block. "
                        "No explanations, no comments outside code."
                    ),
                },
                {"role": "user", "content": prompt},
            ],
            temperature=self.config.temperature,
            max_tokens=self.config.max_tokens,
        )
        text = resp.choices[0].message.content or ""
        return text


class GeminiClient:
    """Gemini implementation using google-generativeai."""

    def __init__(self, config: LLMConfig) -> None:
        self.config = config
        try:
            import google.generativeai as genai  # type: ignore
        except ImportError as exc:
            raise LLMError(
                "google-generativeai package not installed. "
                "Run `pip install google-generativeai` in your virtualenv."
            ) from exc

        api_key = os.getenv("GEMINI_API_KEY") or os.getenv("GOOGLE_API_KEY")
        if not api_key:
            raise LLMError(
                "GEMINI_API_KEY or GOOGLE_API_KEY must be set in environment "
                "for Gemini provider."
            )

        genai.configure(api_key=api_key)
        self._genai = genai

    def generate(self, prompt: str, **_: Any) -> str:
        """Generate text from Gemini.

        This version is defensive:
        - If the API raises, we return a debug string describing the error.
        - If the response has no text/parts, we also return a debug string
          instead of a silent empty string, so the harness logs are informative.
        """
        try:
            model = self._genai.GenerativeModel(self.config.model)
            response = model.generate_content(
                prompt,
                generation_config={
                    "temperature": self.config.temperature,
                    "max_output_tokens": self.config.max_tokens,
                },
            )
        except Exception as exc:  # pragma: no cover - network / quota issues
            # Surface the error as text so _tg_logs/*.txt captures it.
            return f"[TGEMINI_ERROR] {type(exc).__name__}: {exc!r}"

        # Try the standard quick accessor first.
        text: Optional[str] = None
        try:
            text = getattr(response, "text", None)  # type: ignore[attr-defined]
        except Exception:
            text = None

        if text and text.strip():
            return text

        # Fallback: aggregate any candidate.parts[].text
        parts: list[str] = []
        for cand in getattr(response, "candidates", []) or []:
            content = getattr(cand, "content", None)
            if not content:
                continue
            for part in getattr(content, "parts", []) or []:
                t = getattr(part, "text", None)
                if t:
                    parts.append(t)

        if parts:
            return "\n".join(parts)

        # Final fallback: emit a debug marker so we can see what happened.
        debug_fragments = ["[TGEMINI_EMPTY_RESPONSE]"]
        for attr in ("prompt_feedback", "finish_reason", "safety_ratings"):
            val = getattr(response, attr, None)
            if val is not None:
                debug_fragments.append(f"{attr}={val!r}")
        return "\n".join(debug_fragments)


class LocalGemmaClient:
    """
    Local Gemma 3n client using Hugging Face transformers.

    Activated with:
        LLM_PROVIDER=local_gemma
        GEMMA_MODEL_PATH=<local snapshot dir>

    Respects:
        LLM_MAX_TOKENS         -> max_new_tokens
        GEMMA_MAX_PROMPT_CHARS -> prompt truncation (chars; keep tail)
        LOCAL_GEMMA_FAST       -> if "1", return a stub response (no heavy compute)
    """

    def __init__(self, config: LLMConfig) -> None:
        self.config = config
        model_path = os.getenv("GEMMA_MODEL_PATH", "").strip()
        if not model_path:
            raise LLMError(
                "GEMMA_MODEL_PATH is not set. Please point it at your local Gemma 3n "
                "snapshot directory (the folder containing config + safetensors)."
            )
        self.model, self.tokenizer = _load_local_gemma_model(model_path)

    def generate(self, prompt: str, **_: Any) -> str:
        if torch is None:
            raise LLMError("torch is required for LocalGemmaClient but is not available.")

        # Optional ultra-fast stub to smoke-test τGuardian without heavy compute.
        if os.getenv("LOCAL_GEMMA_FAST", "0") == "1":
            print("[LocalGemma] LOCAL_GEMMA_FAST=1 -> returning stub response.")
            return "def handler(request):\n    return {'status': 200}\n"

        # 1) Truncate very long prompts for CPU safety.
        max_chars_env = os.getenv("GEMMA_MAX_PROMPT_CHARS", "4000")
        try:
            max_chars = int(max_chars_env)
        except ValueError:
            max_chars = 4000

        if len(prompt) > max_chars:
            # Keep the tail (usually contains failing tests + latest code).
            prompt = prompt[-max_chars:]

        # Small debug line so you can see effective prompt + generation settings.
        print(
            f"[LocalGemma] Prompt length: {len(prompt)} chars, "
            f"max_new_tokens={self.config.max_tokens}"
        )

        # 2) Tokenize & move to model device.
        inputs = self.tokenizer(prompt, return_tensors="pt")
        inputs = {k: v.to(self.model.device) for k, v in inputs.items()}

        # 3) Build generation kwargs.
        gen_kwargs: Dict[str, Any] = {
            "max_new_tokens": self.config.max_tokens,
            "pad_token_id": self.tokenizer.eos_token_id,
        }

        # Use deterministic decoding by default; sample only if temperature > 0.
        if self.config.temperature > 0.0:
            gen_kwargs["do_sample"] = True
            gen_kwargs["temperature"] = max(self.config.temperature, 0.1)
        else:
            gen_kwargs["do_sample"] = False

        # 4) Generate.
        with torch.no_grad():
            outputs = self.model.generate(**inputs, **gen_kwargs)

        # 5) Decode.
        return self.tokenizer.decode(outputs[0], skip_special_tokens=True)


class FakeClient:
    """Deterministic stub used for CI and offline testing."""

    def __init__(self, config: LLMConfig) -> None:
        self.config = config

    def generate(self, prompt: str, **_: Any) -> str:
        header = "# TG_FAKE_MODEL is enabled. No real LLM call was made.\n"
        return header + "# Prompt length: " + str(len(prompt)) + "\n"


# ---------------------------------------------------------------------------
# Factory & helpers
# ---------------------------------------------------------------------------

_CLIENT_CACHE: Dict[Tuple[ProviderName, str], LLMClient] = {}


def _make_client(config: LLMConfig) -> LLMClient:
    if os.getenv("TG_FAKE_MODEL", "0") == "1" or config.provider == "fake":
        return FakeClient(config)
    if config.provider == "openai":
        return OpenAIClient(config)
    if config.provider == "gemini":
        return GeminiClient(config)
    if config.provider == "local_gemma":
        return LocalGemmaClient(config)
    raise LLMError(f"Unsupported provider: {config.provider}")


def get_client(config: LLMConfig) -> LLMClient:
    key = (config.provider, config.model)
    if key not in _CLIENT_CACHE:
        _CLIENT_CACHE[key] = _make_client(config)
    return _CLIENT_CACHE[key]


def config_from_env(model_name: Optional[str] = None) -> LLMConfig:
    provider_str = os.getenv("LLM_PROVIDER", "openai").lower()
    if provider_str == "gemini":
        provider: ProviderName = "gemini"
    elif provider_str == "fake":
        provider = "fake"
    elif provider_str == "local_gemma":
        provider = "local_gemma"
    else:
        provider = "openai"

    model = model_name or os.getenv("LLM_MODEL_NAME", "")
    if not model:
        raise LLMError(
            "LLM_MODEL_NAME is not set and no model_name was passed to config_from_env()."
        )

    temp = float(os.getenv("LLM_TEMPERATURE", "0.1"))
    max_toks = int(os.getenv("LLM_MAX_TOKENS", "2048"))

    return LLMConfig(
        provider=provider,
        model=model,
        temperature=temp,
        max_tokens=max_toks,
    )


def generate_code(prompt: str, cfg: LLMConfig) -> str:
    client = get_client(cfg)
    return client.generate(prompt)


def generate_code_from_env(prompt: str, model_name: Optional[str] = None) -> str:
    cfg = config_from_env(model_name=model_name)
    return generate_code(prompt, cfg)
