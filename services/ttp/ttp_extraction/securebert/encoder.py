"""Frozen SecureBERT encoder: token-level outputs, no pooling.

Paper, Section III-A-2: E_i = SecureBERT(X_i) in R^{|E| x V_E}. We return the
last hidden state for every token, shape (B, T, 768).

Beyond the paper (Phase 4): `layers` can also average the last four hidden
layers (last4_mean, 768 dims) or concatenate them (last4_concat, 3072 dims).
"""
from __future__ import annotations

import numpy as np
import torch
from transformers import AutoModel

from ttp_extraction.preprocessing.tokenization import MODEL_NAME

HIDDEN_SIZE = 768
LAYER_CHOICES = {"last": HIDDEN_SIZE, "last4_mean": HIDDEN_SIZE, "last4_concat": 4 * HIDDEN_SIZE}


def pick_device() -> torch.device:
    return torch.device("cuda" if torch.cuda.is_available() else "cpu")


def load_encoder(name: str = MODEL_NAME, device: torch.device | None = None):
    encoder = AutoModel.from_pretrained(name)
    encoder.requires_grad_(False)
    return encoder.eval().to(device or pick_device())


@torch.no_grad()
def embed(encoder, batch: dict[str, np.ndarray], layers: str = "last") -> torch.Tensor:
    """batch: output of tokenization.encode. Returns (B, T, 768) on the encoder's device
    (3072 for last4_concat)."""
    if layers not in LAYER_CHOICES:
        raise ValueError(f"layers must be one of {tuple(LAYER_CHOICES)}, got {layers!r}")
    device = next(encoder.parameters()).device
    input_ids = torch.from_numpy(batch["input_ids"]).to(device)
    attention_mask = torch.from_numpy(batch["attention_mask"]).to(device)
    if layers == "last":
        return encoder(input_ids=input_ids, attention_mask=attention_mask).last_hidden_state
    hidden = encoder(input_ids=input_ids, attention_mask=attention_mask,
                     output_hidden_states=True).hidden_states[-4:]
    if layers == "last4_mean":
        return torch.stack(hidden).mean(dim=0)
    return torch.cat(hidden, dim=-1)