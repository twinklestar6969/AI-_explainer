from transformers import AutoTokenizer, AutoModelForCausalLM

MODEL_NAME = "Qwen/Qwen2.5-3B-Instruct"

print("Loading model...")

tokenizer = AutoTokenizer.from_pretrained(MODEL_NAME)
model = AutoModelForCausalLM.from_pretrained(
    MODEL_NAME,
    device_map="auto",
    torch_dtype="auto"
)

messages = [
    {
        "role": "system",
        "content": "You are an AWS security expert. Explain security findings clearly and simply."
    },
    {
        "role": "user",
        "content": """
Explain this AWS security finding:

Rule: IAM_MFA
Severity: HIGH
Status: FAIL
Message: IAM user does not have MFA enabled.

Give:
1. What is wrong
2. Why it is dangerous
3. How to fix it
"""
    }
]

inputs = tokenizer.apply_chat_template(
    messages,
    add_generation_prompt=True,
    tokenize=True,
    return_tensors="pt"
).to(model.device)

outputs = model.generate(
    inputs,
    max_new_tokens=400
)

response = tokenizer.decode(
    outputs[0][inputs.shape[-1]:],
    skip_special_tokens=True
)

print("\n===== AI EXPLANATION =====\n")
print(response)
