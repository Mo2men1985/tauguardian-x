import os
from openai import OpenAI

# Make sure the env var is set: set DEEPSEEK_API_KEY=...
api_key = os.environ.get("DEEPSEEK_API_KEY")
if not api_key:
    raise RuntimeError("Please set DEEPSEEK_API_KEY before running this script.")

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

print("=== REASONING (if present) ===")
print(reasoning or "<no reasoning_content field>")

print("\n=== FINAL ANSWER ===")
print(choice.message.content)
