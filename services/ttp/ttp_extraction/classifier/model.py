"""Eq. 5 classifier and the assembled TTP extraction model.

    SecureBERT embeddings (B, T, 768)
      -> TTPStateSpace          H (B, T, 48)           Eq. 2
      -> GaussianPrototypes     S (B, L, T), T (B, L, 48)   Eq. 3-4
      -> LabelClassifier        Y (B, L)               Eq. 5

Eq. 5 is Y = sigmoid(Linear(T)). The paper does not say how the linear layer is
applied to the L label vectors, so three readings are implemented:
  shared     one D -> 1 layer applied to every label vector
  per_label  a separate D -> 1 weight vector and bias for each label
  concat     one (L * D) -> L layer on the concatenated label vectors
"""
from __future__ import annotations

import math

import torch
from torch import nn

from ttp_extraction.gaussian.prototypes import GaussianPrototypes
from ttp_extraction.mamba.s6 import TTPStateSpace

CLASSIFIERS = ("shared", "per_label", "concat")


class LabelClassifier(nn.Module):
    """Returns logits; apply sigmoid for probabilities."""

    def __init__(self, n_labels: int, d_model: int, mode: str = "concat"):
        super().__init__()
        if mode not in CLASSIFIERS:
            raise ValueError(f"classifier must be one of {CLASSIFIERS}, got {mode!r}")
        self.mode = mode
        if mode == "shared":
            self.linear = nn.Linear(d_model, 1)
        elif mode == "per_label":
            bound = 1.0 / math.sqrt(d_model)
            self.weight = nn.Parameter(torch.empty(n_labels, d_model).uniform_(-bound, bound))
            self.bias = nn.Parameter(torch.zeros(n_labels))
        else:  # concat
            self.linear = nn.Linear(n_labels * d_model, n_labels)

    def forward(self, label_repr: torch.Tensor) -> torch.Tensor:
        """label_repr: (B, L, D) -> logits (B, L)."""
        if self.mode == "shared":
            return self.linear(label_repr).squeeze(-1)
        if self.mode == "per_label":
            return (label_repr * self.weight).sum(dim=-1) + self.bias
        return self.linear(label_repr.flatten(1))


class TTPExtractor(nn.Module):
    """Head model: S6 state-space + Gaussian prototypes + classifier.

    Backward-compatible: accepts both the old `per_label_classifier` bool and
    the new `classifier` string.
    """

    def __init__(self, n_labels: int = 203, d_input: int = 768, d_model: int = 48,
                 d_state: int = 4, n_layers: int = 3, kernel_size: int = 4,
                 dropout: float = 0.1, classifier: str = "concat",
                 per_label_classifier: bool | None = None, *,
                 activation: str = "sigmoid", block: str = "paper",
                 bidirectional: bool = False, input_dropout: float = 0.0,
                 covariance: str = "full", similarity_temperature: bool = False,
                 repr_norm: str = "none"):
        super().__init__()
        # Backward compat: old boolean flag overrides if explicitly passed.
        if per_label_classifier is not None:
            classifier = "per_label" if per_label_classifier else "shared"
        self.state_space = TTPStateSpace(d_input, d_model, d_state, n_layers, kernel_size, dropout,
                                         activation=activation, block=block,
                                         bidirectional=bidirectional, input_dropout=input_dropout)
        self.prototypes = GaussianPrototypes(n_labels, d_model, covariance=covariance,
                                             temperature=similarity_temperature,
                                             repr_norm=repr_norm)
        self.classifier = LabelClassifier(n_labels, d_model, classifier)

    @torch.no_grad()
    def init_prior_bias(self, label_rate: torch.Tensor) -> None:
        """Set each label's bias to log(p / (1 - p)), p = its training frequency.

        At the start the model then predicts each label's base rate instead of
        0.5, which keeps the first epochs from being spent on pushing all 203
        outputs down. Needs a per-label bias (per_label or concat classifier).
        """
        if self.classifier.mode == "shared":
            raise ValueError("prior bias init needs a per-label bias (per_label or concat)")
        p = label_rate.clamp(1e-4, 1 - 1e-4)
        bias = self.classifier.bias if self.classifier.mode == "per_label" else self.classifier.linear.bias
        bias.copy_(torch.log(p / (1 - p)).to(bias))

    def forward(self, embeddings: torch.Tensor, mask: torch.Tensor) -> dict[str, torch.Tensor]:
        """embeddings: (B, T, d_input), mask: (B, T) with True at real tokens."""
        hidden = self.state_space(embeddings, mask)
        label_repr, similarity = self.prototypes(hidden, mask)
        logits = self.classifier(label_repr)
        return {
            "logits": logits,                        # (B, L)
            "probabilities": torch.sigmoid(logits),  # (B, L)   Eq. 5
            "label_repr": label_repr,                # (B, L, D) Eq. 4
            "similarity": similarity,                # (B, L, T) Eq. 3
            "hidden": hidden,                        # (B, T, D) Eq. 2
        }


class TTPExtractorE2E(nn.Module):
    """End-to-end model: SecureBERT encoder + TTP extraction head.

    Unlike TTPExtractor which takes pre-computed embeddings, this model takes
    raw token IDs and runs them through the (trainable) encoder first.
    """

    def __init__(self, encoder, n_labels: int = 203, d_model: int = 48,
                 d_state: int = 4, n_layers: int = 3, kernel_size: int = 4,
                 dropout: float = 0.1, classifier: str = "concat"):
        super().__init__()
        self.encoder = encoder
        d_input = encoder.config.hidden_size  # 768 for SecureBERT
        self.head = TTPExtractor(n_labels, d_input, d_model, d_state,
                                 n_layers, kernel_size, dropout, classifier)

    def forward(self, input_ids: torch.Tensor, attention_mask: torch.Tensor
                ) -> dict[str, torch.Tensor]:
        """input_ids, attention_mask: (B, T) from the tokenizer."""
        embeddings = self.encoder(
            input_ids=input_ids, attention_mask=attention_mask
        ).last_hidden_state
        return self.head(embeddings, attention_mask.bool())