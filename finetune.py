"""
finetune.py — Phase 2: Fine-tune Phi-3 on Neurawall security data
Uses Unsloth for fast LoRA fine-tuning on CPU/GPU.

Run AFTER prepare_training_data.py

Usage:
    pip install unsloth
    python finetune.py

Output: neurawall_phi3/ — your custom security model
        neurawall_phi3.gguf — Ollama-compatible model file
"""

import json
import os
from pathlib import Path


def check_requirements():
    missing = []
    try:
        import torch
    except ImportError:
        missing.append("torch")
    try:
        import unsloth
    except ImportError:
        missing.append("unsloth")
    try:
        import datasets
    except ImportError:
        missing.append("datasets")
    try:
        import trl
    except ImportError:
        missing.append("trl")
    return missing


def install_requirements():
    import subprocess, sys
    print("  Installing fine-tuning requirements...")
    packages = [
        "unsloth",
        "datasets",
        "trl",
        "transformers",
        "peft",
        "accelerate",
        "bitsandbytes",
    ]
    for pkg in packages:
        print(f"    pip install {pkg}...")
        subprocess.check_call([sys.executable, "-m", "pip", "install", pkg, "-q"])
    print("  Done installing.\n")


def run_finetuning():
    from unsloth import FastLanguageModel
    from datasets import load_dataset
    from trl import SFTTrainer
    from transformers import TrainingArguments
    import torch

    print("\n" + "="*60)
    print("  NEURAWALL PHI-3 FINE-TUNING")
    print("  LoRA fine-tune on HTTP security classification")
    print("="*60)

    # Load base model — 4-bit quantized for CPU efficiency
    print("\n  Loading Phi-3 mini (4-bit quantized)...")
    model, tokenizer = FastLanguageModel.from_pretrained(
        model_name="unsloth/Phi-3-mini-4k-instruct",
        max_seq_length=2048,
        dtype=None,
        load_in_4bit=True,
    )

    # Add LoRA adapters
    print("  Adding LoRA adapters...")
    model = FastLanguageModel.get_peft_model(
        model,
        r=16,                           # LoRA rank
        target_modules=["q_proj", "k_proj", "v_proj", "o_proj",
                        "gate_proj", "up_proj", "down_proj"],
        lora_alpha=16,
        lora_dropout=0,
        bias="none",
        use_gradient_checkpointing="unsloth",
        random_state=42,
    )

    # Load dataset
    print("  Loading training data...")
    train_file = "training_data/neurawall_train.jsonl"
    val_file   = "training_data/neurawall_val.jsonl"

    if not Path(train_file).exists():
        print("  ERROR: Run prepare_training_data.py first")
        return

    dataset = load_dataset("json", data_files={
        "train": train_file,
        "validation": val_file,
    })

    print(f"  Train: {len(dataset['train'])} samples")
    print(f"  Val:   {len(dataset['validation'])} samples")

    def format_chat(example):
        """Format messages into Phi-3 chat template."""
        messages = example["messages"]
        text = tokenizer.apply_chat_template(
            messages, tokenize=False, add_generation_prompt=False
        )
        return {"text": text}

    dataset = dataset.map(format_chat)

    # Training config
    print("\n  Starting training...")
    trainer = SFTTrainer(
        model=model,
        tokenizer=tokenizer,
        train_dataset=dataset["train"],
        eval_dataset=dataset["validation"],
        dataset_text_field="text",
        max_seq_length=2048,
        dataset_num_proc=2,
        args=TrainingArguments(
            per_device_train_batch_size=2,
            gradient_accumulation_steps=4,
            warmup_steps=5,
            num_train_epochs=3,
            learning_rate=2e-4,
            fp16=not torch.cuda.is_available(),
            bf16=torch.cuda.is_available(),
            logging_steps=10,
            optim="adamw_8bit",
            weight_decay=0.01,
            lr_scheduler_type="linear",
            seed=42,
            output_dir="neurawall_phi3_checkpoints",
            evaluation_strategy="epoch",
            save_strategy="epoch",
            load_best_model_at_end=True,
        ),
    )

    trainer_stats = trainer.train()

    print(f"\n  Training complete!")
    print(f"  Loss: {trainer_stats.training_loss:.4f}")

    # Save model
    print("\n  Saving model...")
    model.save_pretrained("neurawall_phi3")
    tokenizer.save_pretrained("neurawall_phi3")
    print("  Saved: neurawall_phi3/")

    # Export to GGUF for Ollama
    print("\n  Exporting to GGUF for Ollama...")
    try:
        model.save_pretrained_gguf(
            "neurawall_phi3_gguf",
            tokenizer,
            quantization_method="q4_k_m",
        )
        print("  Saved: neurawall_phi3_gguf/")
        print("\n  To use with Ollama:")
        print("    ollama create neurawall-phi3 -f neurawall_phi3_gguf/Modelfile")
        print("    ollama run neurawall-phi3")
    except Exception as e:
        print(f"  GGUF export failed: {e}")
        print("  Model saved in HuggingFace format at neurawall_phi3/")

    print("\n" + "="*60)
    print("  FINE-TUNING COMPLETE")
    print("  Update example_app.py to use: ollama_model='neurawall-phi3'")
    print("="*60 + "\n")


def main():
    print("\n  Checking requirements...")
    missing = check_requirements()

    if missing:
        print(f"  Missing: {missing}")
        print("  Installing now (this takes 5-10 minutes first time)...")
        install_requirements()

    # Check training data exists
    if not Path("training_data/neurawall_train.jsonl").exists():
        print("\n  Training data not found. Running prepare_training_data.py first...")
        import subprocess, sys
        subprocess.check_call([sys.executable, "prepare_training_data.py"])

    run_finetuning()


if __name__ == "__main__":
    main()
