import os

import pytest

pytest.importorskip("openai")
from openai import OpenAI


@pytest.mark.skipif(
    not os.environ.get("DEEPSEEK_API_KEY"),
    reason="DEEPSEEK_API_KEY not configured",
)
def test_deepseek_reasoner_smoke() -> None:
    api_key = os.environ["DEEPSEEK_API_KEY"]

    # DeepSeek uses an OpenAI-compatible endpoint
    client = OpenAI(
        api_key=api_key,
        base_url="https://api.deepseek.com",
    )

    response = client.chat.completions.create(
        model="deepseek-reasoner",
        messages=[
            {"role": "system", "content": "You are a careful coding assistant."},
            {
                "role": "user",
                "content": (
                    "In 2–3 sentences, explain what a SWE-bench style harness like "
                    "τGuardian does, and why abstaining on bad patches is important."
                ),
            },
        ],
        max_tokens=256,
        stream=False,
    )

    choice = response.choices[0]

    # DeepSeek Reasoner may include 'reasoning_content' in the message
    reasoning = getattr(choice.message, "reasoning_content", None)

    # Ensure the response looks well-formed
    assert choice.message.content
    if reasoning is not None:
        assert isinstance(reasoning, str)
