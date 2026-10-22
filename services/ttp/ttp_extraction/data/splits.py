"""Seeded train/validation/test split matching Table II of the paper.

Test = 1,241 rows (Table II). Validation = last 10% of the shuffled
training rows (Table V, "Valid-split 0.1").
"""
from __future__ import annotations

import json
from pathlib import Path

import numpy as np

from ttp_extraction.data.labels import LabelVocab

TEST_SIZE = 1241
VAL_FRACTION = 0.1


def make_split(n: int, seed: int, test_size: int = TEST_SIZE,
               val_fraction: float = VAL_FRACTION) -> dict[str, np.ndarray]:
    perm = np.random.default_rng(seed).permutation(n)
    test, rest = perm[:test_size], perm[test_size:]
    n_train = int(len(rest) * (1 - val_fraction))
    return {
        "train": np.sort(rest[:n_train]),
        "val": np.sort(rest[n_train:]),
        "test": np.sort(test),
    }


def coverage(y: np.ndarray, split: dict[str, np.ndarray], vocab: LabelVocab) -> dict:
    """How the rare techniques fall across the split."""
    tech = vocab.technique_slice
    support = {name: y[idx][:, tech].sum(axis=0) for name, idx in split.items()}
    unseen = (support["test"] > 0) & (support["train"] == 0)
    test_tech = y[split["test"]][:, tech]
    return {
        "sizes": {name: int(len(idx)) for name, idx in split.items()},
        "techniques_absent_from_train": int((support["train"] == 0).sum()),
        "techniques_absent_from_val": int((support["val"] == 0).sum()),
        "techniques_absent_from_test": int((support["test"] == 0).sum()),
        "test_techniques_unseen_in_train": int(unseen.sum()),
        "test_rows_with_unseen_technique": int((test_tech[:, unseen].sum(axis=1) > 0).sum()),
    }


def save_split(split: dict[str, np.ndarray], seed: int, path: Path) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    payload = {"seed": seed, **{name: idx.tolist() for name, idx in split.items()}}
    path.write_text(json.dumps(payload), encoding="utf-8")


def load_split(path: Path) -> dict[str, np.ndarray]:
    payload = json.loads(path.read_text(encoding="utf-8"))
    return {name: np.asarray(payload[name], dtype=np.int64) for name in ("train", "val", "test")}