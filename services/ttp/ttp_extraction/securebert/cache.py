"""One-time cache of SecureBERT token embeddings.

Layout in the cache folder:
  embeddings.npy  float32, (total_tokens, 768), real tokens only, in dataset order
  offsets.npy     int64, (N + 1,); sentence i is embeddings[offsets[i]:offsets[i+1]]
  meta.json       model name, max length, counts, which layers

The default cache holds the last hidden layer (the paper). Other layer choices
go in their own folder, securebert_<layers>, so caches are never mixed up.
"""
from __future__ import annotations

import argparse
import json
from pathlib import Path

import numpy as np

from ttp_extraction.preprocessing.tokenization import MAX_LENGTH, MODEL_NAME, encode, load_tokenizer
from ttp_extraction.securebert.encoder import LAYER_CHOICES, embed, load_encoder

DEFAULT_ROOT = Path.home() / "ttp_cache" / "securebert"


def cache_root(layers: str = "last") -> Path:
    return DEFAULT_ROOT if layers == "last" else DEFAULT_ROOT.with_name(f"securebert_{layers}")


class EmbeddingCache:
    def __init__(self, root: Path):
        self.embeddings = np.load(root / "embeddings.npy", mmap_mode="r")
        self.offsets = np.load(root / "offsets.npy")
        self.meta = json.loads((root / "meta.json").read_text(encoding="utf-8"))

    def __len__(self) -> int:
        return len(self.offsets) - 1

    def __getitem__(self, i: int) -> np.ndarray:
        """Token embeddings of sentence i, shape (T_i, 768)."""
        return self.embeddings[self.offsets[i] : self.offsets[i + 1]]


def build_cache(texts, tokenizer, encoder, root: Path, batch_size: int = 64,
                max_length: int = MAX_LENGTH, layers: str = "last") -> EmbeddingCache:
    root.mkdir(parents=True, exist_ok=True)
    lengths = np.array([
        len(ids)
        for i in range(0, len(texts), 512)
        for ids in tokenizer(texts[i : i + 512], add_special_tokens=True,
                             truncation=True, max_length=max_length)["input_ids"]
    ], dtype=np.int64)
    offsets = np.concatenate([[0], np.cumsum(lengths)]).astype(np.int64)

    store = np.lib.format.open_memmap(
        root / "embeddings.npy", mode="w+", dtype=np.float32,
        shape=(int(offsets[-1]), LAYER_CHOICES[layers]),
    )
    order = np.argsort(lengths, kind="stable")  # similar lengths together: less padding
    for start in range(0, len(order), batch_size):
        idx = order[start : start + batch_size]
        batch = encode(tokenizer, [texts[i] for i in idx], max_length)
        hidden = embed(encoder, batch, layers).float().cpu().numpy()
        for row, i in enumerate(idx):
            n = int(batch["attention_mask"][row].sum())
            assert n == lengths[i], f"token count mismatch for sentence {i}"
            store[offsets[i] : offsets[i + 1]] = hidden[row, :n]
        if (start // batch_size) % 20 == 0:
            print(f"  encoded {min(start + batch_size, len(order))}/{len(order)}")
    store.flush()
    del store

    np.save(root / "offsets.npy", offsets)
    meta = {"model": MODEL_NAME, "max_length": max_length, "sentences": len(texts),
            "total_tokens": int(offsets[-1]), "hidden_size": LAYER_CHOICES[layers],
            "layers": layers}
    (root / "meta.json").write_text(json.dumps(meta, indent=2), encoding="utf-8")
    return EmbeddingCache(root)


def main() -> None:
    from ttp_extraction.data.labels import load_dataset

    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument("--csv", type=Path, required=True)
    p.add_argument("--layers", choices=tuple(LAYER_CHOICES), default="last")
    p.add_argument("--out", type=Path, default=None, help="default: cache_root(layers)")
    p.add_argument("--batch-size", type=int, default=64)
    args = p.parse_args()
    args.out = args.out or cache_root(args.layers)

    texts, _, _ = load_dataset(args.csv)
    encoder = load_encoder()
    print(f"device: {next(encoder.parameters()).device}")
    cache = build_cache(texts, load_tokenizer(), encoder, args.out, args.batch_size,
                        layers=args.layers)
    print({**cache.meta, "embeddings_shape": list(cache.embeddings.shape), "cache": str(args.out)})


if __name__ == "__main__":
    main()