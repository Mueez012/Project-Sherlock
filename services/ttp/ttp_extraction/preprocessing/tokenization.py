"""SecureBERT tokenisation with a padding mask.

Sequences keep <s> and </s>, are padded to the longest sentence in the batch,
and are capped at MAX_LENGTH. The longest sentence in CTI2TTPs.csv is 138
tokens (Module 0 audit), so the cap truncates nothing in the dataset.
"""
from __future__ import annotations

import argparse
from pathlib import Path

import numpy as np
from transformers import AutoTokenizer

MODEL_NAME = "ehsanaghaei/SecureBERT"
MAX_LENGTH = 160


def load_tokenizer(name: str = MODEL_NAME):
    """By hub name (downloaded once to the Hugging Face cache) or from a local folder (no network)."""
    return AutoTokenizer.from_pretrained(name, local_files_only=Path(name).is_dir())


def encode(tokenizer, texts, max_length: int = MAX_LENGTH) -> dict[str, np.ndarray]:
    """Return input_ids and attention_mask, both of shape (B, T), dtype int64."""
    batch = tokenizer(
        list(texts),
        add_special_tokens=True,
        padding="longest",
        truncation=True,
        max_length=max_length,
        return_tensors="np",
    )
    return {
        "input_ids": batch["input_ids"].astype(np.int64),
        "attention_mask": batch["attention_mask"].astype(np.int64),
    }


def main() -> None:
    from ttp_extraction.data.labels import load_dataset

    p = argparse.ArgumentParser(description="Check that MAX_LENGTH truncates nothing.")
    p.add_argument("--csv", type=Path, required=True)
    args = p.parse_args()

    texts, _, _ = load_dataset(args.csv)
    tokenizer = load_tokenizer()
    lengths = np.array([
        len(ids)
        for i in range(0, len(texts), 512)
        for ids in tokenizer(texts[i : i + 512], add_special_tokens=True, truncation=False)["input_ids"]
    ])
    print({
        "sentences": len(lengths),
        "max_tokens": int(lengths.max()),
        "max_length": MAX_LENGTH,
        "truncated": int((lengths > MAX_LENGTH).sum()),
    })


if __name__ == "__main__":
    main()