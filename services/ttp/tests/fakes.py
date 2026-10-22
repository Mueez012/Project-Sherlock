"""A fake TTPPredictor for fast tests: keyword rules instead of the neural model.

It has the same interface as ttp_extraction.inference.predictor.TTPPredictor
(labels, n_tactics, thresholds, manifest, technique_to_tactics, max_length,
token_lengths, predict), uses the real 203-label vocabulary and returns
probabilities chosen by keywords, so results are predictable.
"""
from __future__ import annotations

import json
import time
from pathlib import Path

import numpy as np

from ttp_extraction.inference.predictor import Thresholds

ROOT = Path(__file__).resolve().parents[1]
VOCAB = json.loads((ROOT / "artifacts" / "label_vocab.json").read_text(encoding="utf-8"))
LABELS = VOCAB["tactics"] + VOCAB["techniques"]
N_TACTICS = len(VOCAB["tactics"])

# keyword -> {label: probability}
RULES = {
    "powershell": {"T1059": 0.91, "TA0002": 0.88},
    "spearphishing": {"T1566": 0.85, "TA0001": 0.93},
    "scheduled task": {"T1053": 0.62, "TA0003": 0.40},
    "compressed": {"T1560": 0.42, "TA0009": 0.30},
    "credentials": {"T1003": 0.55},
}


class FakePredictor:
    def __init__(self, delay_per_batch: float = 0.0, fail: bool = False):
        self.labels = list(LABELS)
        self.n_tactics = N_TACTICS
        self.max_length = 160
        per_label = np.full(len(LABELS), 0.5)
        per_label[LABELS.index("T1560")] = 0.35             # lets a "low" band technique through
        self.thresholds = Thresholds("fixed", {"fixed": np.full(len(LABELS), 0.5), "per_label": per_label})
        catalog = json.loads((ROOT / "data" / "attack" / "catalog-v14.json").read_text(encoding="utf-8"))
        self.technique_to_tactics = {t: catalog["techniques"][t]["tactics"] for t in VOCAB["techniques"]}
        self.manifest = {"name": "ThreatMAMBA-TTP", "version": "fake", "run_id": "fake_run",
                         "model_type": "frozen_head", "encoder": "fake"}
        self.delay_per_batch = delay_per_batch
        self.fail = fail
        self.calls: list[list[str]] = []

    def token_lengths(self, sentences):
        return [len(s.split()) + 2 for s in sentences]

    def predict(self, sentences, batch_size=32, progress_cb=None):
        if self.fail:
            raise RuntimeError("boom")
        self.calls.append(list(sentences))
        probs = np.full((len(sentences), len(LABELS)), 0.01, dtype=np.float32)
        for i, s in enumerate(sentences):
            for keyword, rule in RULES.items():
                if keyword in s.lower():
                    for label, p in rule.items():
                        probs[i, LABELS.index(label)] = max(probs[i, LABELS.index(label)], p)
        for start in range(0, len(sentences), batch_size):
            time.sleep(self.delay_per_batch)
            if progress_cb:
                progress_cb(min(start + batch_size, len(sentences)), len(sentences))
        return probs
