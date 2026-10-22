"""Selective state-space model (S6) following Eq. 2 of the ThreatMAMBA paper.

    h_t = A_bar_t h_{t-1} + B_bar_t E_t          h_t in R^{N x D}
    H_t = C_t h_t                                 H_t in R^{D}
    A_bar_t = exp(Delta_t A)
    B_bar_t = (Delta_t A)^{-1} (exp(Delta_t A) - I) Delta_t B_t

Delta_t is a scalar per token, A is a full N x N matrix shared by all channels,
B_t and C_t are linear functions of the input token. Unidirectional, h_0 = 0.
"""
from __future__ import annotations

import math

import torch
import torch.nn.functional as F
from torch import nn


class S6(nn.Module):
    def __init__(self, d_model: int = 48, d_state: int = 4,
                 delta_init: float = 0.01, eps: float = 1e-4):
        super().__init__()
        self.d_model, self.d_state, self.eps = d_model, d_state, eps
        self.to_delta = nn.Linear(d_model, 1)
        self.to_B = nn.Linear(d_model, d_state)
        self.to_C = nn.Linear(d_model, d_state)

        # A = (K - K^T) - (M M^T + eps I); initialised to -diag(1..N).
        diagonal = torch.arange(1, d_state + 1, dtype=torch.float32)
        self.A_sym = nn.Parameter(torch.diag((diagonal - eps).sqrt()))
        self.A_skew = nn.Parameter(torch.zeros(d_state, d_state))

        with torch.no_grad():  # softplus(bias) = delta_init
            self.to_delta.bias.fill_(math.log(math.expm1(delta_init)))

    def A(self) -> torch.Tensor:
        eye = torch.eye(self.d_state, dtype=self.A_sym.dtype, device=self.A_sym.device)
        return (self.A_skew - self.A_skew.T) - (self.A_sym @ self.A_sym.T + self.eps * eye)

    def discretize(self, delta: torch.Tensor, B: torch.Tensor):
        """delta (..., 1), B (..., N) -> A_bar (..., N, N), B_bar (..., N).

        Computed in at least float32 (never in fp16 under autocast), and in
        float64 when the inputs are float64.

        Both come from ONE matrix exponential of an (N+1) x (N+1) block matrix:
            exp([[dA, dB], [0, 0]]) = [[exp(dA), (dA)^-1 (exp(dA) - I) dB], [0, 1]]
        This is the same formula as Eq. 2 but never inverts dA, so it cannot
        fail when dA is (numerically) singular. The earlier
        torch.linalg.solve version crashed for some hyperparameter settings.
        """
        dtype = torch.promote_types(B.dtype, torch.float32)
        n = self.d_state
        with torch.autocast(device_type="cuda" if delta.is_cuda else "cpu", enabled=False):
            delta_f, B_f = delta.to(dtype), B.to(dtype)
            A_f = self.A().to(dtype)
            block = delta_f.new_zeros(*B_f.shape[:-1], n + 1, n + 1)
            block[..., :n, :n] = delta_f.unsqueeze(-1) * A_f
            block[..., :n, n] = delta_f * B_f
            out = torch.linalg.matrix_exp(block)
            A_bar, B_bar = out[..., :n, :n], out[..., :n, n]
        return A_bar.to(B.dtype), B_bar.to(B.dtype)

    def forward(self, x: torch.Tensor) -> torch.Tensor:
        """x: (B, T, D) -> (B, T, D)."""
        delta = F.softplus(self.to_delta(x))                   # (B, T, 1)
        A_bar, B_bar = self.discretize(delta, self.to_B(x))    # (B, T, N, N), (B, T, N)
        C = self.to_C(x)                                       # (B, T, N)
        inputs = B_bar.unsqueeze(-1) * x.unsqueeze(-2)         # (B, T, N, D)
        h = parallel_scan(A_bar, inputs)                       # (B, T, N, D)
        return torch.einsum("btn,btnd->btd", C, h)


def parallel_scan(A: torch.Tensor, b: torch.Tensor) -> torch.Tensor:
    """All states of h_t = A_t h_{t-1} + b_t with h_0 = 0, in log2(T) steps.

    A: (B, T, N, N), b: (B, T, N, D) -> h: (B, T, N, D). Same result as the
    sequential loop (up to float rounding). Step k combines every position t
    with position t - k: (A, b)_t <- (A_t A_{t-k}, A_t b_{t-k} + b_t).
    Position t never reads positions after t, so the scan stays causal.
    """
    steps, shift = A.shape[1], 1
    while shift < steps:
        A_now, b_now = A[:, shift:], b[:, shift:]
        b = torch.cat([b[:, :shift], A_now @ b[:, :-shift] + b_now], dim=1)
        if shift * 2 < steps:  # the last step does not need the A products
            A = torch.cat([A[:, :shift], A_now @ A[:, :-shift]], dim=1)
        shift *= 2
    return b


ACTIVATIONS = {"sigmoid": torch.sigmoid, "silu": F.silu}
BLOCKS = ("paper", "mamba")


def causal_conv(conv: nn.Conv1d, x: torch.Tensor) -> torch.Tensor:
    """Depthwise conv padded on both sides; keep the first T outputs (position t sees <= t)."""
    return conv(x.transpose(1, 2))[..., : x.shape[1]].transpose(1, 2)


class S6Layer(nn.Module):
    """Eq. 13-14 without the GAT input: SSM(act(Conv1D(Linear(x)))) + Linear_res(x).

    act is sigmoid in the paper; SiLU (used by Mamba) is an option.
    """

    def __init__(self, d_model: int = 48, d_state: int = 4,
                 kernel_size: int = 4, dropout: float = 0.1, activation: str = "sigmoid"):
        super().__init__()
        self.linear = nn.Linear(d_model, d_model)
        self.conv = nn.Conv1d(d_model, d_model, kernel_size,
                              groups=d_model, padding=kernel_size - 1)
        self.ssm = S6(d_model, d_state)
        self.residual = nn.Linear(d_model, d_model)
        self.dropout = nn.Dropout(dropout)
        self.activation = ACTIVATIONS[activation]

    def forward(self, x: torch.Tensor) -> torch.Tensor:
        z = causal_conv(self.conv, self.linear(x))
        z = self.ssm(self.activation(z))
        return self.dropout(z) + self.residual(x)


class MambaBlock(nn.Module):
    """Standard Mamba block (Gu & Dao, 2023) around the same S6 core. Beyond the paper.

    x -> LayerNorm -> Linear to (u, gate) -> conv -> SiLU -> S6 -> * SiLU(gate)
      -> Linear -> dropout -> + x
    """

    def __init__(self, d_model: int = 48, d_state: int = 4, kernel_size: int = 4,
                 dropout: float = 0.1, expand: int = 2):
        super().__init__()
        d_inner = expand * d_model
        self.norm = nn.LayerNorm(d_model)
        self.in_proj = nn.Linear(d_model, 2 * d_inner)
        self.conv = nn.Conv1d(d_inner, d_inner, kernel_size, groups=d_inner,
                              padding=kernel_size - 1)
        self.ssm = S6(d_inner, d_state)
        self.out_proj = nn.Linear(d_inner, d_model)
        self.dropout = nn.Dropout(dropout)

    def forward(self, x: torch.Tensor) -> torch.Tensor:
        u, gate = self.in_proj(self.norm(x)).chunk(2, dim=-1)
        u = self.ssm(F.silu(causal_conv(self.conv, u)))
        return x + self.dropout(self.out_proj(u * F.silu(gate)))


def reverse_padded(x: torch.Tensor, mask: torch.Tensor) -> torch.Tensor:
    """Reverse each sequence's real tokens; right padding stays on the right.

    Applying it twice gives back the input (on real tokens).
    """
    lengths = mask.sum(dim=1, keepdim=True)                       # (B, 1)
    steps = torch.arange(x.shape[1], device=x.device).unsqueeze(0)
    index = torch.where(steps < lengths, lengths - 1 - steps, steps)
    return x.gather(1, index.unsqueeze(-1).expand_as(x))


class TTPStateSpace(nn.Module):
    """SecureBERT token embeddings (B, T, 768) -> hidden states H (B, T, 48).

    Options beyond the paper (all off by default): SiLU activation, standard
    Mamba blocks, dropout on the 768-dim input features, and a second stack
    reading each sentence backwards (outputs summed). Sentences are classified
    whole, so reading backwards does not leak anything.
    """

    def __init__(self, d_input: int = 768, d_model: int = 48, d_state: int = 4,
                 n_layers: int = 3, kernel_size: int = 4, dropout: float = 0.1,
                 activation: str = "sigmoid", block: str = "paper",
                 bidirectional: bool = False, input_dropout: float = 0.0):
        super().__init__()
        if block not in BLOCKS:
            raise ValueError(f"block must be one of {BLOCKS}, got {block!r}")
        # Identity when off, so the paper preset draws exactly the same random numbers.
        self.input_dropout = nn.Dropout(input_dropout) if input_dropout > 0 else nn.Identity()
        self.project = nn.Linear(d_input, d_model)

        def stack():
            if block == "mamba":
                return nn.ModuleList(MambaBlock(d_model, d_state, kernel_size, dropout)
                                     for _ in range(n_layers))
            return nn.ModuleList(S6Layer(d_model, d_state, kernel_size, dropout, activation)
                                 for _ in range(n_layers))

        self.layers = stack()
        self.backward_layers = stack() if bidirectional else None

    def forward(self, embeddings: torch.Tensor, mask: torch.Tensor | None = None) -> torch.Tensor:
        h = self.project(self.input_dropout(embeddings))
        out = h
        for layer in self.layers:
            out = layer(out)
        if self.backward_layers is not None:
            if mask is None:
                mask = torch.ones(h.shape[:2], dtype=torch.bool, device=h.device)
            back = reverse_padded(h, mask)
            for layer in self.backward_layers:
                back = layer(back)
            out = out + reverse_padded(back, mask)
        return out