"""
auto_runs.py

Automation wrapper for τGuardian local 10-task runs and mini-SWE Qwen runs.

Usage examples (from repo root, with venv activated):

  # 1) Run τGuardian-10 on GPT-5.1 (LLM_PROVIDER taken from env, e.g. openai)
  python auto_runs.py tau10 --model gpt-5.1 --tau-max 3

  # 2) Run τGuardian-10 on Gemini 2.5 Pro
  set LLM_PROVIDER=gemini
  python auto_runs.py tau10 --model gemini-2.5-pro

  # 3) Run mini-SWE with Qwen3-Coder via DashScope (numbered runs)
  python auto_runs.py swe-qwen --qwen-model dashscope/qwen3-coder-480b-a35b-instruct

This script will:
  - Choose the next available run number per model / experiment.
  - Call the right internal functions / CLIs.
  - Save results into numbered JSONL files and folders.
"""

from __future__ import annotations

import argparse
import glob
import os
import re
import subprocess
import sys
from typing import List, Tuple

# Local imports (assumes script is in the same directory as harness.py, analyze_mini_swe_results.py)
try:
    from harness import experiment as tau_experiment
except ImportError as exc:
    tau_experiment = None  # type: ignore[assignment]
    _HARNESS_IMPORT_ERROR = exc
else:
    _HARNESS_IMPORT_ERROR = None  # type: ignore[assignment]


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _safe_model_name(model: str) -> str:
    """
    Turn a model name into a filesystem-safe token.
    Example: "dashscope/qwen3-coder-480b-a35b-instruct" -> "dashscope_qwen3-coder-480b-a35b-instruct"
    """
    return re.sub(r"[^A-Za-z0-9_.-]+", "_", model.strip())


def _next_run_index(pattern: str) -> int:
    """
    Given a glob pattern like "results_gpt51_run*.jsonl" or "msa_qwen3_coder_run*",
    return the next free integer index (starting from 1).
    """
    existing = glob.glob(pattern)
    if not existing:
        return 1

    max_idx = 0
    for path in existing:
        m = re.search(r"_run(\d+)", os.path.basename(path))
        if m:
            try:
                idx = int(m.group(1))
            except ValueError:
                continue
            if idx > max_idx:
                max_idx = idx
    return max_idx + 1 if max_idx > 0 else 1


def _run_subprocess(cmd: List[str], cwd: str | None = None) -> Tuple[int, str]:
    """Run a subprocess and return (exit_code, combined_output), forcing UTF-8 so Rich/emoji don't crash on Windows."""
    env = os.environ.copy()
    # Force Python in the child process to use UTF-8 for stdout/stderr
    env.setdefault("PYTHONIOENCODING", "utf-8")
    env.setdefault("PYTHONUTF8", "1")
    # Tell Rich / terminal to avoid fancy Windows console paths
    env.setdefault("TERM", "xterm")
    env.setdefault("NO_COLOR", "1")  # many tools, including rich, respect this

    proc = subprocess.run(
        cmd,
        cwd=cwd,
        stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT,
        text=True,
        env=env,
    )
    return proc.returncode, proc.stdout



# ---------------------------------------------------------------------------
# τGuardian-10 automation
# ---------------------------------------------------------------------------


def cmd_tau10(args: argparse.Namespace) -> None:
    if tau_experiment is None:
        raise RuntimeError(
            f"Could not import harness.experiment: {_HARNESS_IMPORT_ERROR}. "
            "Make sure auto_runs.py is in the same directory as harness.py and you run it from the repo root."
        )

    model = args.model
    tau_max = args.tau_max
    results_dir = args.results_dir

    # Optional provider override
    if args.provider:
        os.environ["LLM_PROVIDER"] = args.provider

    os.makedirs(results_dir, exist_ok=True)

    model_safe = _safe_model_name(model)
    base = os.path.join(results_dir, f"results_{model_safe}")
    next_idx = _next_run_index(base + "_run*.jsonl")
    out_path = f"{base}_run{next_idx:02d}.jsonl"

    print("=" * 80)
    print(f"[τGuardian-10] Running model '{model}' (provider={os.getenv('LLM_PROVIDER', 'openai')})")
    print(f"[τGuardian-10] τ_max          : {tau_max}")
    print(f"[τGuardian-10] Output JSONL   : {out_path}")
    print("=" * 80)

    tau_experiment(model_name=model, tau_max=tau_max, results_path=out_path)

    print(f"[τGuardian-10] Done. Results saved to: {out_path}")


# ---------------------------------------------------------------------------
# mini-SWE Qwen automation
# ---------------------------------------------------------------------------


def cmd_swe_qwen(args: argparse.Namespace) -> None:
    """
    Automate a single mini-SWE run for Qwen3-Coder and convert to τGuardian JSONL.
    """
    qwen_model = args.qwen_model
    subset = args.subset
    split = args.split
    task_filter = args.filter
    msa_prefix = args.msa_prefix
    swe_prefix = args.swe_prefix
    run_eval = args.run_eval

    # mini-SWE output directory (numbered)
    next_idx = _next_run_index(msa_prefix + "_run*")
    msa_dir = f"{msa_prefix}_run{next_idx:02d}"

    print("=" * 80)
    print(f"[mini-SWE/Qwen] Running SWE-bench via mini-extra")
    print(f"[mini-SWE/Qwen] Model        : {qwen_model}")
    print(f"[mini-SWE/Qwen] Subset       : {subset}")
    print(f"[mini-SWE/Qwen] Split        : {split}")
    print(f"[mini-SWE/Qwen] Filter       : {task_filter}")
    print(f"[mini-SWE/Qwen] Output dir   : {msa_dir}")
    print("=" * 80)

    # Build mini-extra command
    cmd = [
        "mini-extra",
        "swebench",
        "--subset",
        subset,
        "--split",
        split,
        "--filter",
        task_filter,
        "--output",
        msa_dir,
        "--model",
        qwen_model,
    ]

    code, out = _run_subprocess(cmd, cwd=os.getcwd())
    print("[mini-SWE/Qwen] mini-extra output:")
    print(out)
    if code != 0:
        print(f"[mini-SWE/Qwen] mini-extra exited with code {code}; aborting before JSONL conversion.")
        return

    # Now convert mini-SWE artifacts to τGuardian JSONL using analyze_mini_swe_results.py
    next_swe_idx = _next_run_index(swe_prefix + "_run*.jsonl")
    swe_out = f"{swe_prefix}_run{next_swe_idx:02d}.jsonl"

    analyze_cmd = [
        sys.executable,
        "analyze_mini_swe_results.py",
        "--msa-dir",
        msa_dir,
        "--model-id",
        qwen_model,
        "--output",
        swe_out,
    ]
    if run_eval:
        analyze_cmd.extend(
            [
                "--run-eval",
                "--dataset-name",
                args.dataset_name,
                "--split",
                split,
            ]
        )

    print("=" * 80)
    print(f"[mini-SWE/Qwen] Converting mini-SWE outputs to τGuardian JSONL")
    print(f"[mini-SWE/Qwen] MSA dir      : {msa_dir}")
    print(f"[mini-SWE/Qwen] Output JSONL : {swe_out}")
    print("=" * 80)

    code2, out2 = _run_subprocess(analyze_cmd, cwd=os.getcwd())
    print("[mini-SWE/Qwen] analyze_mini_swe_results.py output:")
    print(out2)
    if code2 != 0:
        print(f"[mini-SWE/Qwen] analyze_mini_swe_results.py exited with code {code2}")
    else:
        print(f"[mini-SWE/Qwen] Done. Results saved to: {swe_out}")


# ---------------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------------


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description="Automation wrapper for τGuardian experiments.")
    subparsers = parser.add_subparsers(dest="command", required=True)

    # τGuardian-10 local tasks
    p_tau10 = subparsers.add_parser("tau10", help="Run τGuardian-10 local tasks for a given model.")
    p_tau10.add_argument(
        "--model",
        required=True,
        help="Model name to evaluate (e.g. gpt-5.1, gpt-4.1, gemini-2.5-pro).",
    )
    p_tau10.add_argument(
        "--provider",
        default=None,
        help="LLM_PROVIDER value (openai, gemini, fake, local_gemma). If omitted, current env is used.",
    )
    p_tau10.add_argument(
        "--tau-max",
        type=int,
        default=int(os.getenv("TAU_MAX", "3")),
        help="Maximum τ iterations for wrapped runs (default: env TAU_MAX or 3).",
    )
    p_tau10.add_argument(
        "--results-dir",
        default=".",
        help="Directory to store results_*.jsonl files (default: current directory).",
    )
    p_tau10.set_defaults(func=cmd_tau10)

    # mini-SWE Qwen
    p_swe = subparsers.add_parser("swe-qwen", help="Run mini-SWE agent with Qwen and convert to τGuardian JSONL.")
    p_swe.add_argument(
        "--qwen-model",
        default="dashscope/qwen3-coder-480b-a35b-instruct",
        help="Full LiteLLM Qwen model id (e.g. dashscope/qwen3-coder-480b-a35b-instruct).",
    )
    p_swe.add_argument(
        "--subset",
        default="lite",
        help="SWE-bench subset (default: lite).",
    )
    p_swe.add_argument(
        "--split",
        default="test",
        help="SWE-bench split (default: test).",
    )
    p_swe.add_argument(
        "--filter",
        default="astropy__astropy-12907",
        help="Instance filter, e.g. astropy__astropy-12907.",
    )
    p_swe.add_argument(
        "--msa-prefix",
        default="msa_qwen3_coder",
        help="Prefix for mini-SWE output directories (default: msa_qwen3_coder).",
    )
    p_swe.add_argument(
        "--swe-prefix",
        default="swe_qwen3_coder",
        help="Prefix for τGuardian JSONL SWE results (default: swe_qwen3_coder).",
    )
    p_swe.add_argument(
        "--run-eval",
        action="store_true",
        help="If set, run SWE-bench ground-truth evaluation (requires eval tools and dataset).",
    )
    p_swe.add_argument(
        "--dataset-name",
        default="princeton-nlp/SWE-bench_Lite",
        help="Dataset name to use when --run-eval is set.",
    )
    p_swe.set_defaults(func=cmd_swe_qwen)

    return parser


def main() -> None:
    parser = build_parser()
    args = parser.parse_args()
    args.func(args)


if __name__ == "__main__":
    main()
