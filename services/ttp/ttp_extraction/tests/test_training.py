from dataclasses import replace

import numpy as np
import pytest
import torch

from ttp_extraction.training.train import EarlyStopping, TrainConfig, fit

CONFIG = TrainConfig(d_input=16, d_model=8, n_layers=2, batch_size=8, max_epochs=2, lr=1e-3)


def toy():
    rng = np.random.default_rng(0)
    sequences = [rng.standard_normal((int(rng.integers(3, 9)), 16)).astype(np.float32)
                 for _ in range(40)]
    y = (rng.random((40, 6)) < 0.3).astype(np.int8)
    split = {"train": np.arange(0, 28), "val": np.arange(28, 34), "test": np.arange(34, 40)}
    return sequences, y, split


def run(tmp_path, config=CONFIG, resume=False):
    return fit(*toy(), config, tmp_path, n_tactics=2, resume=resume, log=lambda _: None)


def test_early_stopping_waits_for_patience():
    stopper = EarlyStopping(patience=5)
    for epoch, loss in enumerate([1.0, 0.9, 0.95, 0.96, 0.97, 0.98], start=1):
        stopper.update(loss, epoch)
        assert not stopper.should_stop
    stopper.update(0.99, 7)
    assert stopper.should_stop
    assert (stopper.best, stopper.best_epoch) == (0.9, 2)


def test_fit_writes_run_files_and_history(tmp_path):
    _, history = run(tmp_path)
    assert len(history) == 2
    assert all(np.isfinite(r["train_loss"]) and np.isfinite(r["val_loss"]) for r in history)
    for name in ("best.pt", "last.pt", "config.json", "history.json", "summary.json"):
        assert (tmp_path / name).exists()


def test_fit_restores_best_weights(tmp_path):
    model, _ = run(tmp_path)
    best = torch.load(tmp_path / "best.pt")
    for name, value in model.state_dict().items():
        assert torch.equal(value, best[name]), name


def test_same_seed_gives_same_history(tmp_path):
    _, first = run(tmp_path / "a")
    _, second = run(tmp_path / "b")
    assert [r["train_loss"] for r in first] == pytest.approx([r["train_loss"] for r in second], rel=1e-5)


def test_resume_continues_the_same_run(tmp_path):
    four = replace(CONFIG, max_epochs=4)
    _, straight = run(tmp_path / "straight", four)
    run(tmp_path / "resumed")
    _, resumed = run(tmp_path / "resumed", four, resume=True)
    assert len(resumed) == 4
    assert [r["val_loss"] for r in resumed] == pytest.approx([r["val_loss"] for r in straight], rel=1e-5)