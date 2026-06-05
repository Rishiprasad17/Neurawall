"""
finetune_cpu.py — Fine-tune Phi-3 on CPU using standard transformers
Works on Intel UHD / CPU-only machines. No CUDA required.

Usage:
    pip install transformers datasets peft accelerate
    python finetune_cpu.py

Runtime: 4-8 hours on CPU
Output:  neurawall_phi3/ — your custom security model
"""

import json
import os
import sys
import subprocess
from pathlib import Path


def install_requirements():
    packages = [
        "transformers>=4.40.0",
        "datasets",
        "peft",
        "accelerate",
        "torch",
        "trl",
    ]
    print("  Installing requirements...")
    for pkg in packages:
        print(f"    pip install {pkg}...")
        subprocess.check_call([sys.executable, "-m", "pip", "install", pkg, "-q"])
    print("  Done.\n")


def run_finetuning():
    print("\n" + "="*60)
    print("  NEURAWALL PHI-3 FINE-TUNING (CPU MODE)")
    print("  LoRA fine-tune on HTTP security data")
    print("="*60)

    import torch
    from transformers import (
        AutoModelForCausalLM,
        AutoTokenizer,
        TrainingArguments,
        Trainer,
        DataCollatorForLanguageModeling,
    )
    from peft import LoraConfig, get_peft_model, TaskType
    from datasets import load_dataset

    MODEL_NAME  = "microsoft/Phi-3.5-mini-instruct"
    OUTPUT_DIR  = "neurawall_phi3"
    TRAIN_FILE  = "training_data/neurawall_train.jsonl"
    VAL_FILE    = "training_data/neurawall_val.jsonl"
    MAX_LENGTH  = 512
    EPOCHS      = 2        # reduce for CPU speed
    BATCH_SIZE  = 1        # CPU needs small batch
    GRAD_ACCUM  = 8        # accumulate to effective batch=8

    if not Path(TRAIN_FILE).exists():
        print("  ERROR: Run prepare_training_data.py first")
        return

    # Load tokenizer
    print(f"\n  Loading tokenizer: {MODEL_NAME}")
    tokenizer = AutoTokenizer.from_pretrained(
        MODEL_NAME, trust_remote_code=True
    )
    tokenizer.pad_token = tokenizer.eos_token

    # Load model — use float32 for CPU
    print(f"  Loading model (this takes 2-3 minutes on first run)...")
    model = AutoModelForCausalLM.from_pretrained(
        MODEL_NAME,
        torch_dtype=torch.float32,
        trust_remote_code=True,
        low_cpu_mem_usage=True,
    )

    # Add LoRA — fine-tune only small adapter layers
    print("  Adding LoRA adapters (r=8 for CPU efficiency)...")
    lora_config = LoraConfig(
        task_type=TaskType.CAUSAL_LM,
        r=8,                    # smaller rank for CPU
        lora_alpha=16,
        target_modules=["qkv_proj", "o_proj"],  # fewer modules for speed
        lora_dropout=0.05,
        bias="none",
    )
    model = get_peft_model(model, lora_config)
    model.print_trainable_parameters()

    # Load and tokenize dataset
    print("\n  Loading training data...")
    raw = load_dataset("json", data_files={
        "train":      TRAIN_FILE,
        "validation": VAL_FILE,
    })

    def tokenize(example):
        msgs = example["messages"]
        # Format as simple text
        text = ""
        for m in msgs:
            role = m["role"]
            content = m["content"]
            if role == "system":
                text += f"<|system|>\n{content}<|end|>\n"
            elif role == "user":
                text += f"<|user|>\n{content}<|end|>\n"
            elif role == "assistant":
                text += f"<|assistant|>\n{content}<|end|>\n"

        tokens = tokenizer(
            text,
            truncation=True,
            max_length=MAX_LENGTH,
            padding="max_length",
        )
        tokens["labels"] = tokens["input_ids"].copy()
        return tokens

    print("  Tokenizing...")
    tokenized = raw.map(tokenize, remove_columns=["messages"])

    data_collator = DataCollatorForLanguageModeling(
        tokenizer=tokenizer, mlm=False
    )

    # Training args — optimised for CPU
    training_args = TrainingArguments(
        output_dir=OUTPUT_DIR,
        num_train_epochs=EPOCHS,
        per_device_train_batch_size=BATCH_SIZE,
        per_device_eval_batch_size=BATCH_SIZE,
        gradient_accumulation_steps=GRAD_ACCUM,
        evaluation_strategy="epoch",
        save_strategy="epoch",
        logging_steps=5,
        learning_rate=2e-4,
        weight_decay=0.01,
        warmup_steps=10,
        load_best_model_at_end=True,
        no_cuda=True,           # force CPU
        dataloader_num_workers=0,
        report_to="none",       # no wandb
        fp16=False,             # no mixed precision on CPU
        bf16=False,
    )

    trainer = Trainer(
        model=model,
        args=training_args,
        train_dataset=tokenized["train"],
        eval_dataset=tokenized["validation"],
        data_collator=data_collator,
    )

    print(f"\n  Starting training ({EPOCHS} epochs, {len(tokenized['train'])} samples)")
    print(f"  Estimated time: 4-8 hours on CPU")
    print(f"  Leave this running overnight...\n")

    trainer.train()

    print("\n  Saving model...")
    model.save_pretrained(OUTPUT_DIR)
    tokenizer.save_pretrained(OUTPUT_DIR)
    print(f"  Saved to: {OUTPUT_DIR}/")

    print("\n" + "="*60)
    print("  FINE-TUNING COMPLETE")
    print("  Next steps:")
    print("  1. Convert to GGUF:")
    print("     pip install llama-cpp-python")
    print("     python convert_to_gguf.py")
    print("  2. Register with Ollama:")
    print("     ollama create neurawall-phi3 -f Modelfile")
    print("  3. Test:")
    print("     python model_comparison.py")
    print("="*60 + "\n")


def main():
    print("\n  Checking requirements...")
    missing = []
    for pkg in ["transformers", "datasets", "peft", "trl"]:
        try:
            __import__(pkg)
        except ImportError:
            missing.append(pkg)

    if missing:
        print(f"  Installing: {missing}")
        install_requirements()

    if not Path("training_data/neurawall_train.jsonl").exists():
        print("  Running prepare_training_data.py first...")
        subprocess.check_call([sys.executable, "prepare_training_data.py"])

    run_finetuning()


if __name__ == "__main__":
    main()
