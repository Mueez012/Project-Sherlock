"""Every model option: shapes, finite gradients, padding invariance, batch-mate independence."""
from dataclasses import replace

import numpy as np
import pytest
import torch
import torch.nn.functional as F

from ttp_extraction.classifier.model import TTPExtractor
from ttp_extraction.gaussian.prototypes import GaussianPrototypes
from ttp_extraction.mamba.s6 import reverse_padded
from ttp_extraction.training.train import TrainConfig, build_model, fit, row_repeats

N_LABELS, D_INPUT, D_MODEL = 6, 16, 8
VARIANTS = {
    "paper": {},
    "silu": {"activation": "silu"},
    "diagonal": {"covariance": "diagonal"},
    "mamba": {"block": "mamba"},
    "bidirectional": {"bidirectional": True},
    "repr_norm": {"repr_norm": "sum_s"},
    "temperature": {"similarity_temperature": True},
    "input_dropout": {"input_dropout": 0.2},
}


def small(**options) -> TTPExtractor:
    torch.manual_seed(0)
    return TTPExtractor(n_labels=N_LABELS, d_input=D_INPUT, d_model=D_MODEL, d_state=4,
                        n_layers=2, **options).double().eval()


def batch(steps=6):
    torch.manual_seed(1)
    return (torch.randn(2, steps, D_INPUT, dtype=torch.float64),
            torch.ones(2, steps, dtype=torch.bool))


@pytest.mark.parametrize("name", VARIANTS)
def test_shapes_and_finite_gradients(name):
    model = small(**VARIANTS[name]).train()
    out = model(*batch())
    assert out["logits"].shape == (2, N_LABELS)
    assert out["label_repr"].shape == (2, N_LABELS, D_MODEL)
    targets = torch.zeros(2, N_LABELS, dtype=torch.float64)
    targets[0, 1] = 1.0
    F.binary_cross_entropy_with_logits(out["logits"], targets).backward()
    for pname, parameter in model.named_parameters():
        assert parameter.grad is not None, pname
        assert torch.isfinite(parameter.grad).all(), pname


@pytest.mark.parametrize("name", VARIANTS)
def test_padding_content_does_not_change_predictions(name):
    model = small(**VARIANTS[name])
    embeddings, mask = batch()
    mask[0, 4:] = False
    garbage = embeddings.clone()
    garbage[0, 4:] = torch.randn(2, D_INPUT, dtype=torch.float64)
    alone = model(embeddings[:1, :4], torch.ones(1, 4, dtype=torch.bool))["logits"][0]
    assert torch.allclose(model(embeddings, mask)["logits"][0], alone, atol=1e-9)
    assert torch.allclose(model(garbage, mask)["logits"][0], alone, atol=1e-9)


@pytest.mark.parametrize("name", VARIANTS)
def test_predictions_do_not_depend_on_batch_mates(name):
    model = small(**VARIANTS[name])
    embeddings, mask = batch()
    together = model(embeddings, mask)["logits"][0]
    alone = model(embeddings[:1], mask[:1])["logits"][0]
    assert torch.allclose(together, alone, atol=1e-9)


def test_diagonal_equals_full_with_diagonal_precision():
    torch.manual_seed(0)
    full = GaussianPrototypes(4, 5).double()
    diag = GaussianPrototypes(4, 5, covariance="diagonal").double()
    with torch.no_grad():
        diag.mu.copy_(full.mu)
        full.raw_diag.add_(0.3 * torch.randn_like(full.raw_diag))
        diag.raw_diag.copy_(full.raw_diag)
    H = torch.randn(2, 7, 5, dtype=torch.float64)
    mask = torch.ones(2, 7, dtype=torch.bool)
    assert torch.allclose(full(H, mask)[1], diag(H, mask)[1], atol=1e-10)
    assert sum(p.numel() for p in diag.parameters()) == 4 * 5 * 2


def test_reverse_padded_keeps_padding_on_the_right():
    x = torch.arange(10.0).reshape(2, 5, 1)
    mask = torch.tensor([[1, 1, 1, 0, 0], [1, 1, 1, 1, 1]], dtype=torch.bool)
    out = reverse_padded(x, mask)
    assert out[0, :3, 0].tolist() == [2.0, 1.0, 0.0]
    assert out[1, :, 0].tolist() == [9.0, 8.0, 7.0, 6.0, 5.0]
    assert torch.equal(reverse_padded(out, mask)[mask], x[mask])


def test_repr_norm_is_a_weighted_average():
    model = small(repr_norm="sum_s")
    out = model(*batch())
    S, T = out["similarity"], out["label_repr"]
    expected = torch.einsum("blt,btd->bld", S, out["hidden"]) / (S.sum(-1, keepdim=True) + 1e-6)
    assert torch.allclose(T, expected)


def test_prior_bias_init_sets_base_rate():
    model = small()
    rate = torch.tensor([0.5, 0.1, 0.01, 0.2, 0.3, 0.05])
    model.init_prior_bias(rate)
    assert torch.allclose(torch.sigmoid(model.classifier.linear.bias.float()), rate, atol=1e-6)


def test_rare_oversample_repeats_only_rare_rows():
    y = np.zeros((30, 4), dtype=np.int8)   # 1 tactic + 3 techniques
    y[:, 1] = 1                             # common technique in every row
    y[:2, 2] = 1                            # rare: 2 rows
    config = TrainConfig(sampler="rare_oversample", rare_threshold=20, oversample_max=3)
    repeats = row_repeats(y, 1, config)
    assert repeats[:2].tolist() == [3, 3] and (repeats[2:] == 1).all()
    assert (row_repeats(y, 1, TrainConfig()) == 1).all()


TOY_CONFIG = TrainConfig(d_input=16, d_model=8, n_layers=2, batch_size=8, max_epochs=2, lr=1e-3)


def toy():
    rng = np.random.default_rng(0)
    sequences = [rng.standard_normal((int(rng.integers(3, 9)), 16)).astype(np.float32)
                 for _ in range(40)]
    y = (rng.random((40, 6)) < 0.3).astype(np.int8)
    return sequences, y, {"train": np.arange(28), "val": np.arange(28, 34), "test": np.arange(34, 40)}


@pytest.mark.parametrize("options", [
    {"loss": "asl", "pos_weight": "sqrt", "prior_bias_init": True},
    {"loss": "focal", "optimizer": "adamw", "weight_decay": 1e-2, "grad_clip": 1.0},
    {"lr_schedule": "cosine", "warmup_epochs": 1, "early_stop_metric": "val_macro_f1"},
    {"lr_schedule": "plateau", "ema": 0.9, "token_dropout": 0.1, "sampler": "rare_oversample"},
    {"block": "mamba", "bidirectional": True, "covariance": "diagonal"},
])
def test_fit_runs_with_options(tmp_path, options):
    config = replace(TOY_CONFIG, **options)
    model, history = fit(*toy(), config, tmp_path, n_tactics=2, device=torch.device("cpu"),
                         log=lambda _: None)
    assert len(history) == 2 and all(np.isfinite(r["val_loss"]) for r in history)


def test_resume_with_ema_and_schedule_matches_straight_run(tmp_path):
    config = replace(TOY_CONFIG, ema=0.9, lr_schedule="plateau", token_dropout=0.1, max_epochs=4)
    cpu = torch.device("cpu")
    _, straight = fit(*toy(), config, tmp_path / "s", n_tactics=2, device=cpu, log=lambda _: None)
    fit(*toy(), replace(config, max_epochs=2), tmp_path / "r", n_tactics=2, device=cpu, log=lambda _: None)
    _, resumed = fit(*toy(), config, tmp_path / "r", n_tactics=2, resume=True, device=cpu,
                     log=lambda _: None)
    assert [r["val_loss"] for r in resumed] == pytest.approx([r["val_loss"] for r in straight], rel=1e-6)


def test_build_model_paper_config_has_paper_parameter_count():
    model = build_model(TrainConfig(), 203)
    # Full covariance: 203 * 48 * 48 lower-triangular factors dominate the head.
    assert model.prototypes.raw_tril.shape == (203, 48, 48)
