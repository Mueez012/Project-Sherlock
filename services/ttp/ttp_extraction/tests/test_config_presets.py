import argparse
import json
from dataclasses import asdict

import numpy as np
import pytest
import torch

from ttp_extraction.data.batching import DeviceSequences, pad_batch
from ttp_extraction.mamba.s6 import parallel_scan
from ttp_extraction.training.train import (
    TrainConfig, add_config_arguments, config_from_args, preset_config,
)

TABLE_V = {"d_model": 48, "d_state": 4, "n_layers": 3, "dropout": 0.1, "lr": 1e-4,
           "max_epochs": 100, "classifier": "concat"}


def test_paper_preset_is_table_v():
    config = asdict(preset_config("paper"))
    for key, value in TABLE_V.items():
        assert config[key] == value, key


def parse(argv):
    p = argparse.ArgumentParser()
    p.add_argument("--seed", type=int, default=0)
    add_config_arguments(p)
    return config_from_args(p.parse_args(argv))


def test_cli_defaults_equal_paper_preset():
    assert parse([]) == TrainConfig()


def test_cli_flags_override_one_field_only():
    config = parse(["--seed", "2", "--dropout", "0.3", "--classifier", "shared"])
    assert config == TrainConfig(seed=2, dropout=0.3, classifier="shared")


def test_tuned_preset_loads_from_json(tmp_path):
    path = tmp_path / "tuned.json"
    path.write_text(json.dumps({**asdict(TrainConfig()), "dropout": 0.25}))
    assert preset_config("tuned", path).dropout == 0.25


def test_old_config_with_per_label_bool_still_loads():
    old = {k: v for k, v in asdict(TrainConfig()).items() if k != "classifier"}
    assert TrainConfig.from_dict({**old, "per_label_classifier": False}).classifier == "shared"
    assert TrainConfig.from_dict({**old, "per_label_classifier": True}).classifier == "per_label"
    with pytest.raises(ValueError):
        TrainConfig.from_dict({**old, "made_up_field": 1})


def test_device_sequences_match_pad_batch():
    rng = np.random.default_rng(0)
    sequences = [rng.standard_normal((int(rng.integers(1, 9)), 5)).astype(np.float32)
                 for _ in range(12)]
    store = DeviceSequences(sequences, torch.device("cpu"))
    idx = np.array([3, 0, 11, 7])
    expected = pad_batch([sequences[i] for i in idx])
    got = store.batch(idx)
    assert torch.equal(got[0], expected[0]) and torch.equal(got[1], expected[1])


def test_parallel_scan_equals_sequential_loop():
    torch.manual_seed(0)
    A = 0.5 * torch.randn(3, 11, 4, 4, dtype=torch.float64)
    b = torch.randn(3, 11, 4, 6, dtype=torch.float64)
    h, expected = torch.zeros(3, 4, 6, dtype=torch.float64), []
    for t in range(11):
        h = A[:, t] @ h + b[:, t]
        expected.append(h)
    assert torch.allclose(parallel_scan(A, b), torch.stack(expected, 1), atol=1e-10)
