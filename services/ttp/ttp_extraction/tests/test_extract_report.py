import json
from types import SimpleNamespace

import numpy as np
import pytest
import torch
from torch import nn

from ttp_extraction.classifier.model import TTPExtractor
from ttp_extraction.inference.extract_report import ReportExtractor, compare_with_authors

LABELS = ["TA0001", "TA0002", "T1001", "T1002", "T1003"]
D = 8


class FakeTokenizer:
    """Word-level stand-in for the SecureBERT tokenizer (ids 0 = <s>, 1 = pad, 2 = </s>)."""

    def __call__(self, texts, add_special_tokens=True, padding="longest", truncation=True,
                 max_length=160, return_tensors="np"):
        rows = [[0] + [3 + hash(w) % 50 for w in t.split()][: max_length - 2] + [2] for t in texts]
        width = max(map(len, rows))
        ids = np.ones((len(rows), width), dtype=np.int64)
        mask = np.zeros((len(rows), width), dtype=np.int64)
        for i, r in enumerate(rows):
            ids[i, : len(r)], mask[i, : len(r)] = r, 1
        return {"input_ids": ids, "attention_mask": mask}


class FakeEncoder(nn.Module):
    def __init__(self):
        super().__init__()
        torch.manual_seed(0)
        self.table = nn.Embedding(60, D)

    def forward(self, input_ids, attention_mask):
        return SimpleNamespace(last_hidden_state=self.table(input_ids))


@pytest.fixture
def extractor():
    torch.manual_seed(0)
    model = TTPExtractor(n_labels=len(LABELS), d_input=D, d_model=4, d_state=2, n_layers=1)
    with torch.no_grad():
        model.classifier.linear.bias.copy_(torch.tensor([3.0, -3.0, 0.0, 3.0, -3.0]))
    thresholds = np.array([0.5, 0.5, 0.5, 0.5, 0.5])
    return ReportExtractor(model, FakeTokenizer(), FakeEncoder(), LABELS, thresholds, n_tactics=2,
                           device=torch.device("cpu"))


REPORT = ("The actor sent spearphishing emails with malicious attachments. "
          "Then a dropper installed a backdoor.\n\nThe backdoor used HTTP for command and control. "
          "Data was compressed before exfiltration.")


def test_tiny_report_returns_a_ttp_set_with_evidence(extractor):
    result = extractor.extract(REPORT)
    assert result["n_sentences"] == 4
    ids = {t["id"] for t in result["ttps"]}
    assert "TA0001" in ids and "T1002" in ids
    for ttp in result["ttps"]:
        j = LABELS.index(ttp["id"])
        assert ttp["evidence"]
        for ev in ttp["evidence"]:
            # every evidence sentence really passes that label's threshold
            assert ev["probability"] > extractor.thresholds[j]


def test_sentence_order_and_batching_do_not_change_results(extractor):
    from ttp_extraction.preprocessing.sentences import split_sentences

    sentences = split_sentences(REPORT)
    embeddings = extractor.embed(sentences)
    probs = extractor.probabilities(embeddings)
    alone = np.vstack([extractor.probabilities([e]) for e in embeddings])
    assert np.allclose(probs, alone, atol=1e-5)          # padding / batch-mates do not matter
    order = [3, 1, 0, 2]
    shuffled = extractor.aggregate([sentences[i] for i in order], probs[order])
    straight = extractor.aggregate(sentences, probs)
    assert {t["id"] for t in shuffled["ttps"]} == {t["id"] for t in straight["ttps"]}


def test_min_sentences_and_max_prob_rules(extractor):
    sentences = ["a", "b", "c"]
    probs = np.array([[0.9, 0.1, 0.6, 0.1, 0.1],
                      [0.9, 0.1, 0.1, 0.1, 0.1],
                      [0.1, 0.1, 0.1, 0.1, 0.45]])
    ids = lambda r: {t["id"] for t in r["ttps"]}
    assert ids(extractor.aggregate(sentences, probs)) == {"TA0001", "T1001"}
    assert ids(extractor.aggregate(sentences, probs, min_sentences=2)) == {"TA0001"}
    assert ids(extractor.aggregate(sentences, probs, min_sentences=2, max_prob=0.6)) == {"TA0001", "T1001"}


def test_empty_report(extractor):
    assert extractor.extract("   ")["ttps"] == []


def test_agreement_scores(tmp_path, monkeypatch):
    import pandas as pd
    import ttp_extraction.inference.extract_report as er

    authors = tmp_path / "authors.csv"
    pd.DataFrame({"TTPs": [json.dumps(["T1001", "T1002.001", "T9999"])] * 2,
                  "Context": ["x", "x"], "Group": ["g", "g"], "original_index": [7, 7]}).to_csv(authors)
    monkeypatch.setattr(er, "AUTHORS_TTP", authors)
    ours = tmp_path / "ours.jsonl"
    ours.write_text(json.dumps({"id": 7, "ttps": [{"id": "T1001", "kind": "technique"},
                                                  {"id": "T1003", "kind": "technique"}]}) + "\n")
    scores = compare_with_authors(ours, ["T1001", "T1002", "T1003"])
    assert scores["reports_compared"] == 1
    assert scores["micro"]["precision"] == pytest.approx(50.0)   # T1001 right, T1003 extra
    assert scores["micro"]["recall"] == pytest.approx(50.0)      # T1002 (from T1002.001) missed
    assert scores["their_labels_outside_our_189"] == 1           # T9999
    assert scores["mean_jaccard"] == pytest.approx(1 / 3)
