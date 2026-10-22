"""TTPPredictor: load a model bundle once, turn sentences into label probabilities.

A bundle is a folder (models/ttp-v1/) with
  manifest.json            what is served: run id, model type, metrics, sha256s
  config.json              the run's training config
  label_vocab.json         the 203 labels (14 tactics + 189 techniques), in model order
  thresholds.json          decision thresholds (fixed / per_slice / per_label / report_tuned)
  technique_to_tactics.json  ATT&CK v14 technique -> tactic ids
and a checkpoint, either `best.pt` in the folder or the path given in
manifest["checkpoint"] (relative to the bundle). Pointing at the run's own
best.pt avoids copying a 500 MB file; swapping models = editing the manifest.

model_type
  frozen_head    frozen SecureBERT + trained head (train.py runs). The head was
                 trained on float16-cached embeddings, so they are rounded the same way.
  finetuned_e2e  fine-tuned SecureBERT + head (train_finetune.py runs).

Probabilities are computed in float32 (no autocast), so they equal the
reference forward pass of evaluation/evaluate*.py run in float32.

Ensembles: manifest["members"] = [{"run_id", "checkpoint", "config"}, ...] loads several
fine-tuned models (each with its own SecureBERT) and AVERAGES their probabilities, exactly
like `evaluate.py --ensemble`. Without "members" the bundle has one model (config.json +
manifest["checkpoint"]).
"""
from __future__ import annotations

import hashlib
import json
import logging
import os
import time
from dataclasses import dataclass
from pathlib import Path
from typing import Callable

import numpy as np
import torch

log = logging.getLogger(__name__)
MODEL_TYPES = ("frozen_head", "finetuned_e2e")


class BundleError(Exception):
    pass


def vocab_hash(labels) -> str:
    """sha256 of the label list in model order (order matters: it is the output layout)."""
    return hashlib.sha256(json.dumps(list(labels)).encode("utf-8")).hexdigest()


def file_sha256(path: Path, chunk: int = 1 << 20) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        while block := handle.read(chunk):
            digest.update(block)
    return digest.hexdigest()


@dataclass
class Thresholds:
    """Per-label thresholds for each mode stored in thresholds.json."""
    default_mode: str
    modes: dict[str, np.ndarray]

    def get(self, mode: str | None = None, fixed: float | None = None, n_labels: int = 0) -> np.ndarray:
        if mode == "fixed" or (mode is None and fixed is not None):
            return np.full(n_labels, 0.5 if fixed is None else fixed)
        mode = mode or self.default_mode
        if mode not in self.modes:
            raise KeyError(f"threshold mode {mode!r} is not in this bundle ({sorted(self.modes)})")
        return self.modes[mode]

    @classmethod
    def load(cls, path: Path, n_labels: int) -> "Thresholds":
        payload = json.loads(path.read_text(encoding="utf-8"))
        modes = {"fixed": np.full(n_labels, float(payload.get("fixed", 0.5)))}
        for name in ("per_slice", "per_label", "report_tuned"):
            if name in payload:
                values = np.asarray(payload[name], dtype=float)
                if values.shape != (n_labels,):
                    raise BundleError(f"thresholds.json[{name}] has {values.shape}, expected ({n_labels},)")
                modes[name] = values
        return cls(payload.get("default_mode", "fixed"), modes)


class TTPPredictor:
    def __init__(self, model, tokenizer, encoder, labels, n_tactics: int, thresholds: Thresholds,
                 manifest: dict, technique_to_tactics: dict[str, list[str]], device=None,
                 max_length: int = 160, members: list | None = None):
        self.model = model.eval()
        self.encoder = encoder.eval() if encoder is not None else None
        # (head, encoder) pairs whose probabilities are averaged; one pair for a single model
        self.members = [(m.eval(), e.eval()) for m, e in members] if members else [(self.model, self.encoder)]
        self.tokenizer = tokenizer
        self.labels = list(labels)
        self.n_tactics = n_tactics
        self.thresholds = thresholds
        self.manifest = manifest
        self.technique_to_tactics = technique_to_tactics
        self.device = device or torch.device("cpu")
        self.max_length = max_length
        self.model_type = manifest.get("model_type", "frozen_head")

    # -------------------------------------------------------------- loading
    @classmethod
    def load(cls, bundle_dir: Path, device: str | torch.device = "cpu",
             num_threads: int | None = None, warmup: bool = True) -> "TTPPredictor":
        from ttp_extraction.preprocessing.tokenization import MODEL_NAME, load_tokenizer

        bundle_dir = Path(bundle_dir)
        device = torch.device(device)
        if device.type == "cpu":
            torch.set_num_threads(num_threads or os.cpu_count() or 1)
        manifest = json.loads((bundle_dir / "manifest.json").read_text(encoding="utf-8"))
        model_type = manifest.get("model_type", "frozen_head")
        if model_type not in MODEL_TYPES:
            raise BundleError(f"manifest model_type must be one of {MODEL_TYPES}, got {model_type!r}")
        vocab = json.loads((bundle_dir / "label_vocab.json").read_text(encoding="utf-8"))
        labels = vocab["tactics"] + vocab["techniques"]
        expected = manifest.get("label_vocab_sha256")
        if expected and expected != vocab_hash(labels):
            raise BundleError("label_vocab.json does not match the manifest's label_vocab_sha256")
        if manifest.get("members"):
            if model_type != "finetuned_e2e":
                raise BundleError("ensembles are supported for finetuned_e2e bundles only")
            specs = [(bundle_dir / m["checkpoint"], m["config"]) for m in manifest["members"]]
        else:
            specs = [(bundle_dir / manifest.get("checkpoint", "best.pt"),
                      json.loads((bundle_dir / "config.json").read_text(encoding="utf-8")))]
        encoder_name = manifest.get("encoder", MODEL_NAME)
        t0 = time.perf_counter()
        members = [cls._load_member(model_type, checkpoint, config, labels, encoder_name, device)
                   for checkpoint, config in specs]
        model, encoder = members[0]
        tt_path = bundle_dir / "technique_to_tactics.json"
        tt = json.loads(tt_path.read_text(encoding="utf-8")) if tt_path.exists() else {}
        predictor = cls(model, load_tokenizer(encoder_name), encoder, labels, len(vocab["tactics"]),
                        Thresholds.load(bundle_dir / "thresholds.json", len(labels)), manifest, tt,
                        device=device, max_length=int(manifest.get("max_length", 160)), members=members)
        log.info("model %s (%s, %d member(s)) loaded in %.1f s on %s", manifest.get("version"), model_type,
                 len(members), time.perf_counter() - t0, device)
        if warmup:
            t0 = time.perf_counter()
            predictor.predict(["The actor used PowerShell to download a second-stage payload."] * 4)
            log.info("warm-up batch took %.0f ms", 1000 * (time.perf_counter() - t0))
        return predictor

    @staticmethod
    def _load_member(model_type: str, checkpoint: Path, config: dict, labels, encoder_name: str, device):
        """One (head, encoder) pair from a checkpoint and its training config."""
        if not checkpoint.exists():
            raise BundleError(f"checkpoint not found: {checkpoint}")
        state = torch.load(checkpoint, map_location="cpu", weights_only=True)
        out_key = "head.classifier.linear.bias" if model_type == "finetuned_e2e" else "classifier.linear.bias"
        if out_key in state and state[out_key].shape[0] != len(labels):
            raise BundleError(f"checkpoint predicts {state[out_key].shape[0]} labels, "
                              f"label_vocab.json has {len(labels)}")
        if model_type == "finetuned_e2e":
            from transformers import AutoConfig, AutoModel

            from ttp_extraction.classifier.model import TTPExtractorE2E

            e2e = TTPExtractorE2E(AutoModel.from_config(AutoConfig.from_pretrained(encoder_name)),
                                  n_labels=len(labels), d_model=config["d_model"],
                                  d_state=config["d_state"], n_layers=config["n_layers"],
                                  kernel_size=config["kernel_size"], dropout=config["dropout"],
                                  classifier=config["classifier"])
            e2e.load_state_dict(state)
            return e2e.head.to(device), e2e.encoder.to(device)
        from ttp_extraction.securebert.encoder import load_encoder
        from ttp_extraction.training.train import TrainConfig, build_model

        train_config = TrainConfig.from_dict(config)
        if getattr(train_config, "features", "last") != "last":
            raise BundleError("only runs trained on last-layer SecureBERT features can be served")
        model = build_model(train_config, len(labels))
        model.load_state_dict(state)
        return model.to(device), load_encoder(device=device)

    # -------------------------------------------------------------- inference
    def token_lengths(self, sentences: list[str]) -> list[int]:
        """Token count of each sentence before truncation (incl. <s> and </s>)."""
        ids = self.tokenizer(list(sentences), add_special_tokens=True, truncation=False)["input_ids"]
        return [len(x) for x in ids]

    @torch.inference_mode()
    def predict(self, sentences: list[str], batch_size: int = 32,
                progress_cb: Callable[[int, int], None] | None = None) -> np.ndarray:
        """(N, n_labels) float32 probabilities, rows in the order of `sentences`.

        Sentences are processed shortest-first (less padding, faster); the
        output order is restored. progress_cb(done, total) runs after each batch.
        """
        from ttp_extraction.data.batching import pad_batch
        from ttp_extraction.preprocessing.tokenization import encode

        n = len(sentences)
        probs = np.zeros((n, len(self.labels)), dtype=np.float32)
        if n == 0:
            return probs
        order = np.argsort(self.token_lengths(sentences), kind="stable")
        done = 0
        for start in range(0, n, batch_size):
            idx = order[start : start + batch_size]
            batch = encode(self.tokenizer, [sentences[i] for i in idx], self.max_length)
            ids = torch.from_numpy(batch["input_ids"]).to(self.device)
            mask = torch.from_numpy(batch["attention_mask"]).to(self.device)
            batch_probs = np.zeros((len(idx), len(self.labels)), dtype=np.float32)
            for head, encoder in self.members:
                hidden = encoder(input_ids=ids, attention_mask=mask).last_hidden_state
                if self.model_type == "finetuned_e2e":
                    # Same as TTPExtractorE2E.forward: encoder output and mask straight into the head.
                    out = head(hidden, mask.bool())
                else:
                    # Same as the training cache: real tokens only, stored as float16, zero padding.
                    lengths = mask.sum(1).tolist()
                    x, m = pad_batch([hidden[r, :k].half().float().cpu().numpy() for r, k in enumerate(lengths)])
                    out = head(x.to(self.device), m.to(self.device))
                batch_probs += out["probabilities"].float().cpu().numpy()
            probs[idx] = batch_probs / len(self.members)   # ensemble = mean probability
            done += len(idx)
            if progress_cb:
                progress_cb(done, n)
        return probs
