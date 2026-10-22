"""Label vocabulary and dataset loading for CTI2TTPs.csv.

Target space: 14 tactics + 189 parent techniques = 203 labels.
Sub-technique columns are dropped; the Module 0 audit showed every flagged
sub-technique already has its parent flagged (rows_changed_by_roll_up = 0).
"""
from __future__ import annotations

import json
from dataclasses import dataclass
from pathlib import Path

import numpy as np
import pandas as pd

from ttp_extraction.data.audit import classify_columns, pick_text_column


@dataclass(frozen=True)
class LabelVocab:
    tactics: tuple[str, ...]
    techniques: tuple[str, ...]

    @property
    def labels(self) -> tuple[str, ...]:
        return self.tactics + self.techniques

    @property
    def tactic_slice(self) -> slice:
        return slice(0, len(self.tactics))

    @property
    def technique_slice(self) -> slice:
        return slice(len(self.tactics), len(self.labels))

    def __len__(self) -> int:
        return len(self.labels)

    @classmethod
    def from_columns(cls, columns) -> "LabelVocab":
        groups = classify_columns(columns)
        return cls(tuple(sorted(groups["tactics"])), tuple(sorted(groups["techniques"])))

    def save(self, path: Path) -> None:
        path.parent.mkdir(parents=True, exist_ok=True)
        payload = {"tactics": list(self.tactics), "techniques": list(self.techniques)}
        path.write_text(json.dumps(payload, indent=2), encoding="utf-8")

    @classmethod
    def load(cls, path: Path) -> "LabelVocab":
        payload = json.loads(path.read_text(encoding="utf-8"))
        return cls(tuple(payload["tactics"]), tuple(payload["techniques"]))


def load_d1(d1_dir: Path) -> tuple[list[str], np.ndarray, LabelVocab, dict[str, np.ndarray]]:
    """The team's cleaned D1 (datasets/d1_model_ready): train.csv, valid.csv, test.csv, labels.json.

    Returns (texts, labels (N, 203), vocabulary, split). The three files are
    concatenated in that order and the split holds their row ranges, so the
    team's split is used exactly as given. Label columns are mapped by id
    through labels.json, never by position; the vocabulary keeps this
    package's order (sorted tactics, sorted techniques). Every row is kept
    (duplicates are part of the dataset).
    """
    d1_dir = Path(d1_dir)
    meta = json.loads((d1_dir / "labels.json").read_text(encoding="utf-8"))
    tactics = [x["id"] for x in meta["tactics"]]
    techniques = [x["id"] for x in meta["techniques"]]
    vocab = LabelVocab(tuple(sorted(tactics)), tuple(sorted(techniques)))
    texts, rows, split, start = [], [], {}, 0
    for name, file in (("train", "train.csv"), ("val", "valid.csv"), ("test", "test.csv")):
        df = pd.read_csv(d1_dir / file, encoding="utf-8", keep_default_na=False, dtype={"Text": str})
        if list(df.columns) != ["Text", *tactics, *techniques]:
            raise ValueError(f"{file}: columns do not match labels.json")
        texts.extend(df["Text"].tolist())
        rows.append(df[list(vocab.labels)].to_numpy(dtype=np.int8))
        split[name] = np.arange(start, start + len(df))
        start += len(df)
    y = np.concatenate(rows)
    if not set(np.unique(y).tolist()) <= {0, 1}:
        raise ValueError("D1 labels must be 0 or 1")
    return texts, y, vocab, split


def load_dataset(csv: Path, encoding: str = "gb18030") -> tuple[list[str], np.ndarray, LabelVocab]:
    """Return (texts, multi-hot labels of shape (N, 203), vocabulary)."""
    df = pd.read_csv(csv, encoding=encoding, low_memory=False)
    df.columns = [str(c).strip() for c in df.columns]
    vocab = LabelVocab.from_columns(df.columns)
    text_col = pick_text_column(classify_columns(df.columns)["other"])
    texts = df[text_col].astype(str).tolist()
    y = df[list(vocab.labels)].to_numpy(dtype=np.int8)
    return texts, y, vocab