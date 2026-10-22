import json
import os
from pathlib import Path

import numpy as np
import pytest
import torch

from ttp_extraction.classifier.model import TTPExtractor
from ttp_extraction.inference.predictor import BundleError, Thresholds, TTPPredictor, vocab_hash
from ttp_extraction.tests.test_extract_report import FakeEncoder, FakeTokenizer

BUNDLE = Path("models/ttp-v1")
LABELS = ["TA0001", "TA0002", "T1001", "T1002", "T1003"]


def tiny_predictor():
    torch.manual_seed(0)
    model = TTPExtractor(n_labels=len(LABELS), d_input=8, d_model=4, d_state=2, n_layers=1)
    th = Thresholds("fixed", {"fixed": np.full(len(LABELS), 0.5)})
    return TTPPredictor(model, FakeTokenizer(), FakeEncoder(), LABELS, 2, th, {"model_type": "frozen_head"}, {})


def test_batch_order_is_restored_and_progress_reported():
    predictor = tiny_predictor()
    sentences = ["a b c d e f g h i", "a", "a b c", "a b c d e f", "a b"]
    seen = []
    batched = predictor.predict(sentences, batch_size=2, progress_cb=lambda d, n: seen.append((d, n)))
    one_by_one = np.vstack([predictor.predict([s], batch_size=1) for s in sentences])
    np.testing.assert_allclose(batched, one_by_one, atol=1e-5)
    assert seen == [(2, 5), (4, 5), (5, 5)]
    assert predictor.predict([]).shape == (0, len(LABELS))


def write_bundle(tmp_path: Path, labels, manifest_extra=None, bias_size=None):
    (tmp_path / "label_vocab.json").write_text(json.dumps({"tactics": labels[:2], "techniques": labels[2:]}))
    (tmp_path / "config.json").write_text("{}")
    (tmp_path / "thresholds.json").write_text(json.dumps({"fixed": 0.5}))
    manifest = {"model_type": "frozen_head", "label_vocab_sha256": vocab_hash(labels), **(manifest_extra or {})}
    (tmp_path / "manifest.json").write_text(json.dumps(manifest))
    torch.save({"classifier.linear.bias": torch.zeros(bias_size or len(labels))}, tmp_path / "best.pt")


def test_vocab_hash_mismatch_raises(tmp_path):
    write_bundle(tmp_path, LABELS, {"label_vocab_sha256": vocab_hash(LABELS[::-1])})
    with pytest.raises(BundleError, match="label_vocab"):
        TTPPredictor.load(tmp_path, warmup=False)


def test_label_count_mismatch_raises(tmp_path):
    write_bundle(tmp_path, LABELS, bias_size=203)
    with pytest.raises(BundleError, match="203 labels"):
        TTPPredictor.load(tmp_path, warmup=False)


def test_unknown_threshold_mode_raises():
    th = Thresholds("fixed", {"fixed": np.full(3, 0.5)})
    assert th.get("fixed", 0.3, 3).tolist() == [0.3, 0.3, 0.3]
    with pytest.raises(KeyError):
        th.get("per_label", None, 3)


@pytest.mark.slow
@pytest.mark.skipif(not (BUNDLE / "manifest.json").exists(), reason="no model bundle")
def test_golden_probabilities_match_reference_forward():
    """TTPPredictor == the evaluation forward pass (TTPExtractorE2E / evaluate_e2e batches,
    float32) for 50 test-split sentences, to 1e-5."""
    from ttp_extraction.data.labels import load_dataset
    from ttp_extraction.data.splits import load_split
    from ttp_extraction.preprocessing.tokenization import encode
    from ttp_extraction.training.train_finetune import trim

    predictor = TTPPredictor.load(BUNDLE, num_threads=min(8, os.cpu_count() or 1), warmup=False)
    texts, _, _ = load_dataset(Path("ThreatMAMBA-main/CTI2TTPs.csv"))
    idx = load_split(Path("artifacts/splits/seed_0.json"))["test"][:50]
    sentences = [texts[i] for i in idx]
    ours = predictor.predict(sentences, batch_size=7)       # odd batch size: order restoration matters

    enc = encode(predictor.tokenizer, sentences)
    ids, mask = torch.from_numpy(enc["input_ids"]), torch.from_numpy(enc["attention_mask"])
    reference = []
    with torch.inference_mode():
        for s in range(0, len(sentences), 16):          # evaluate_e2e: fixed order, trimmed padding
            b_ids, b_mask = trim(ids[s : s + 16], mask[s : s + 16])
            hidden = predictor.encoder(input_ids=b_ids, attention_mask=b_mask).last_hidden_state
            reference.append(predictor.model(hidden, b_mask.bool())["probabilities"].numpy())
    np.testing.assert_allclose(ours, np.concatenate(reference), atol=1e-5)

    # The stored validation/test probabilities were computed on the GPU in float16 autocast,
    # so they agree only to about 1e-2 (reported, not an exact check).
    stored = np.load(Path("runs") / predictor.manifest["run_id"] / "probabilities.npz")["test"][:50]
    assert np.abs(ours - stored).max() < 2e-2


def test_ensemble_averages_member_probabilities():
    torch.manual_seed(0)
    heads = [TTPExtractor(n_labels=len(LABELS), d_input=8, d_model=4, d_state=2, n_layers=1) for _ in range(2)]
    encoder = FakeEncoder()
    th = Thresholds("fixed", {"fixed": np.full(len(LABELS), 0.5)})
    manifest = {"model_type": "frozen_head"}
    singles = [TTPPredictor(h, FakeTokenizer(), encoder, LABELS, 2, th, manifest, {}) for h in heads]
    ensemble = TTPPredictor(heads[0], FakeTokenizer(), encoder, LABELS, 2, th, manifest, {},
                            members=[(h, encoder) for h in heads])
    sentences = ["a b c", "a b c d e f g", "a"]
    expected = (singles[0].predict(sentences) + singles[1].predict(sentences)) / 2
    np.testing.assert_allclose(ensemble.predict(sentences, batch_size=2), expected, atol=1e-6)


@pytest.mark.slow
@pytest.mark.skipif(not Path("models/ttp-v2/manifest.json").exists(), reason="no ensemble bundle")
def test_served_ensemble_bundle_loads_both_members():
    predictor = TTPPredictor.load(Path("models/ttp-v2"), num_threads=min(8, os.cpu_count() or 1), warmup=False)
    assert len(predictor.members) == 2
    assert predictor.thresholds.default_mode == "report_tuned"
    probs = predictor.predict(["The actor used PowerShell to download a second-stage payload."])
    assert probs.shape == (1, 203) and probs[0, predictor.labels.index("T1059")] > 0.5
