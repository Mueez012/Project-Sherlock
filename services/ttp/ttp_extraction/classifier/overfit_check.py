"""Sanity check: can the assembled model memorise a handful of real sentences?

Not the paper's training run. It uses a higher learning rate and no dropout so
that a working model fits 32 sentences within a few hundred steps.
"""
from __future__ import annotations

import argparse
from pathlib import Path

import numpy as np
import torch
import torch.nn.functional as F

from ttp_extraction.classifier.model import CLASSIFIERS, TTPExtractor
from ttp_extraction.data.batching import pad_batch
from ttp_extraction.data.labels import load_dataset
from ttp_extraction.securebert.cache import DEFAULT_ROOT, EmbeddingCache


def main() -> None:
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument("--csv", type=Path, required=True)
    p.add_argument("--cache", type=Path, default=DEFAULT_ROOT)
    p.add_argument("--n", type=int, default=32)
    p.add_argument("--steps", type=int, default=300)
    p.add_argument("--lr", type=float, default=1e-3)
    p.add_argument("--classifier", choices=CLASSIFIERS, default="concat")
    args = p.parse_args()

    torch.manual_seed(0)
    _, y, vocab = load_dataset(args.csv)
    cache = EmbeddingCache(args.cache)
    idx = np.random.default_rng(0).choice(len(cache), size=args.n, replace=False)
    embeddings, mask = pad_batch([cache[int(i)] for i in idx])
    targets = torch.from_numpy(y[idx]).float()

    model = TTPExtractor(n_labels=len(vocab), dropout=0.0, classifier=args.classifier)
    optimizer = torch.optim.Adam(model.parameters(), lr=args.lr)

    rate = targets.mean()
    baseline = F.binary_cross_entropy(torch.full_like(targets, rate.item()), targets).item()
    print(f"parameters: {sum(p.numel() for p in model.parameters()):,}")
    print(f"batch: {tuple(embeddings.shape)}, positives per sentence: {targets.sum(1).mean():.2f}")
    print(f"loss of a constant prediction (no learning): {baseline:.4f}")

    for step in range(args.steps + 1):
        out = model(embeddings, mask)
        loss = F.binary_cross_entropy_with_logits(out["logits"], targets)
        if step % 50 == 0:
            real = mask.unsqueeze(1).expand_as(out["similarity"])
            scores = out["similarity"][real]
            predicted = out["probabilities"] > 0.5
            true_positive = (predicted & targets.bool()).sum().item()
            f1 = 2 * true_positive / max(predicted.sum().item() + targets.sum().item(), 1)
            print(f"step {step:4d}  loss {loss.item():.4f}  micro-F1 {f1:.3f}  "
                  f"S mean {scores.mean().item():.3f}  S min {scores.min().item():.2e}  "
                  f"H std {out['hidden'][mask].std().item():.3f}")
        if step < args.steps:
            optimizer.zero_grad()
            loss.backward()
            optimizer.step()


if __name__ == "__main__":
    main()