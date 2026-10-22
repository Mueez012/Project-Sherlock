"""Pad variable-length cached embeddings into one batch."""
from __future__ import annotations

import numpy as np
import torch


def pad_batch(sequences: list[np.ndarray]) -> tuple[torch.Tensor, torch.Tensor]:
    """List of (T_i, D) arrays -> embeddings (B, T_max, D) float32, mask (B, T_max) bool."""
    longest = max(len(s) for s in sequences)
    embeddings = np.zeros((len(sequences), longest, sequences[0].shape[1]), dtype=np.float32)
    mask = np.zeros((len(sequences), longest), dtype=bool)
    for row, sequence in enumerate(sequences):
        embeddings[row, : len(sequence)] = sequence
        mask[row, : len(sequence)] = True
    return torch.from_numpy(embeddings), torch.from_numpy(mask)


class DeviceSequences:
    """All sentences stored as one flat (total_tokens, D) tensor on a device.

    Builds the same padded batches as pad_batch, without reading from disk or
    copying to the GPU every step. Accepts an EmbeddingCache (uses its flat
    array and offsets) or any list of (T_i, D) arrays.
    """

    def __init__(self, sequences, device: torch.device):
        if hasattr(sequences, "offsets") and hasattr(sequences, "embeddings"):
            flat, offsets = np.asarray(sequences.embeddings), np.asarray(sequences.offsets)
        else:
            lengths = [len(s) for s in sequences]
            flat = np.concatenate([np.asarray(s, dtype=np.float32) for s in sequences])
            offsets = np.concatenate([[0], np.cumsum(lengths)])
        self.flat = torch.as_tensor(flat, dtype=torch.float32, device=device)
        self.offsets = torch.as_tensor(offsets, dtype=torch.int64, device=device)
        self.device = device

    def __len__(self) -> int:
        return len(self.offsets) - 1

    def __getitem__(self, i: int) -> np.ndarray:
        return self.flat[self.offsets[i] : self.offsets[i + 1]].cpu().numpy()

    def batch(self, idx) -> tuple[torch.Tensor, torch.Tensor]:
        """Row indices -> embeddings (B, T_max, D) with zero padding, mask (B, T_max)."""
        idx = torch.as_tensor(np.asarray(idx), dtype=torch.int64, device=self.device)
        starts = self.offsets[idx]
        lengths = self.offsets[idx + 1] - starts
        steps = torch.arange(int(lengths.max()), device=self.device)
        mask = steps.unsqueeze(0) < lengths.unsqueeze(1)
        positions = torch.where(mask, starts.unsqueeze(1) + steps, 0)
        return self.flat[positions] * mask.unsqueeze(-1), mask
