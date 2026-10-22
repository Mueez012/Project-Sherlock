"""Gaussian TTP prototypes: Eq. 3 (similarity) and Eq. 4 (label representations).

    S(H_t, P_l) = exp( -1/2 (H_t - mu_l)^T Sigma_l^{-1} (H_t - mu_l) )     in (0, 1]
    T_l         = sum_t S(H_t, P_l) H_t

Each label l has a learned mean mu_l and a learned full covariance, stored as a
precision factor: Sigma_l^{-1} = L_l L_l^T with L_l lower-triangular and a
positive diagonal. The quadratic form is then ||L_l^T (H_t - mu_l)||^2.

Options beyond the paper (defaults reproduce Eq. 3-4 exactly):
  covariance="diagonal"   Sigma_l^{-1} diagonal: D numbers per label instead of
                          D*D, which may overfit rare labels less
  temperature=True        learnable per-label scale tau_l > 0 in the exponent,
                          S = exp(-tau_l / 2 * distance), initialised to 1
  repr_norm="sum_s"       T_l = sum_t S H_t / (sum_t S + eps): a weighted
                          average, independent of sentence length
"""
from __future__ import annotations

import math

import torch
import torch.nn.functional as F
from torch import nn

COVARIANCES = ("full", "diagonal")
REPR_NORMS = ("none", "sum_s")


class GaussianPrototypes(nn.Module):
    def __init__(self, n_labels: int = 203, d_model: int = 48,
                 mu_std: float = 0.1, eps: float = 1e-4, covariance: str = "full",
                 temperature: bool = False, repr_norm: str = "none"):
        super().__init__()
        if covariance not in COVARIANCES:
            raise ValueError(f"covariance must be one of {COVARIANCES}, got {covariance!r}")
        if repr_norm not in REPR_NORMS:
            raise ValueError(f"repr_norm must be one of {REPR_NORMS}, got {repr_norm!r}")
        self.eps, self.covariance, self.repr_norm = eps, covariance, repr_norm
        self.mu = nn.Parameter(mu_std * torch.randn(n_labels, d_model))
        # Initial precision = identity: zero off-diagonal, softplus(raw_diag) + eps = 1.
        if covariance == "full":
            self.raw_tril = nn.Parameter(torch.zeros(n_labels, d_model, d_model))
        self.raw_diag = nn.Parameter(
            torch.full((n_labels, d_model), math.log(math.expm1(1.0 - eps)))
        )
        if temperature:   # softplus(raw) = 1 at init
            self.raw_temperature = nn.Parameter(torch.full((n_labels,), math.log(math.expm1(1.0))))
        else:
            self.raw_temperature = None

    def diagonal(self) -> torch.Tensor:
        return F.softplus(self.raw_diag) + self.eps

    def scale_tril(self) -> torch.Tensor:
        """L_l, shape (L, D, D): lower-triangular with a positive diagonal."""
        if self.covariance == "diagonal":
            return torch.diag_embed(self.diagonal())
        return torch.tril(self.raw_tril, diagonal=-1) + torch.diag_embed(self.diagonal())

    def precision(self) -> torch.Tensor:
        """Sigma_l^{-1}, shape (L, D, D)."""
        tril = self.scale_tril()
        return tril @ tril.transpose(-1, -2)

    def distance(self, H: torch.Tensor) -> torch.Tensor:
        """Squared Mahalanobis distance, (B, T, D) -> (B, T, L)."""
        mu = self.mu.to(H.dtype)
        if self.covariance == "diagonal":
            precision = self.diagonal().to(H.dtype).pow(2)            # (L, D)
            # sum_d p_ld (h_d - mu_ld)^2, expanded to avoid a (B, T, L, D) tensor.
            return (H.pow(2) @ precision.T - 2 * H @ (precision * mu).T
                    + (precision * mu.pow(2)).sum(-1))
        tril = self.scale_tril().to(H.dtype)
        # z = L_l^T (H_t - mu_l), computed without building the (B, T, L, D) difference.
        z = torch.einsum("btj,ljk->btlk", H, tril) - torch.einsum("lj,ljk->lk", mu, tril)
        return z.pow(2).sum(dim=-1)

    def similarity(self, H: torch.Tensor, mask: torch.Tensor) -> torch.Tensor:
        """Eq. 3. H: (B, T, D), mask: (B, T) -> S: (B, L, T), zero at padding."""
        distance = self.distance(H).clamp_min(0)                     # (B, T, L)
        if self.raw_temperature is not None:
            distance = distance * F.softplus(self.raw_temperature).to(H.dtype)
        S = torch.exp(-0.5 * distance).transpose(1, 2)               # (B, L, T)
        return S * mask.unsqueeze(1).to(S.dtype)

    def forward(self, H: torch.Tensor, mask: torch.Tensor):
        """Returns (T, S): label representations (B, L, D) and similarities (B, L, T)."""
        S = self.similarity(H, mask)
        T = torch.einsum("blt,btd->bld", S, H)
        if self.repr_norm == "sum_s":
            T = T / (S.sum(dim=-1, keepdim=True) + 1e-6)
        return T, S
