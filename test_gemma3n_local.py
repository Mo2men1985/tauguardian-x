import torch
from transformers import AutoTokenizer, AutoModelForCausalLM

# Exact folder from your screenshot:
MODEL_PATH = r"E:\hf_cache\hub\models--google--gemma-3n-E4B-it\snapshots\e4c12697f6160380846ed13294cc7984c8c2ba9f"


def main() -> None:
    print("Loading tokenizer and model from:", MODEL_PATH)

    tokenizer = AutoTokenizer.from_pretrained(
        MODEL_PATH,
        trust_remote_code=True,
    )

    if torch.cuda.is_available():
        dtype = torch.bfloat16
        device_map = "auto"
        print("Using CUDA with bfloat16.")
    else:
        dtype = torch.float32
        device_map = None
        print("Using CPU with float32 (may be slower).")

    model = AutoModelForCausalLM.from_pretrained(
        MODEL_PATH,
        torch_dtype=dtype,
        device_map=device_map,
    )

    messages = [
        {
            "role": "user",
            "content": (
                "You are a senior Python engineer. "
                "Write a Python function add(a: int, b: int) -> int with a short "
                "docstring and one example in a comment."
            ),
        }
    ]

    if hasattr(tokenizer, "apply_chat_template"):
        prompt = tokenizer.apply_chat_template(
            messages,
            tokenize=False,
            add_generation_prompt=True,
        )
    else:
        prompt = messages[0]["content"]

    inputs = tokenizer(prompt, return_tensors="pt")
    inputs = {k: v.to(model.device) for k, v in inputs.items()}

    with torch.no_grad():
        outputs = model.generate(
            **inputs,
            max_new_tokens=256,
            do_sample=False,
            pad_token_id=tokenizer.eos_token_id,
        )

    text = tokenizer.decode(outputs[0], skip_special_tokens=True)
    print("\n=== MODEL OUTPUT ===")
    print(text)


if __name__ == "__main__":
    main()
