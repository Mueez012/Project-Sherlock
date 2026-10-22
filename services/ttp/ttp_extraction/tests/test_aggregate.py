import numpy as np

from ttp_extraction.inference.aggregate import AggregateOptions, aggregate, band
from ttp_extraction.inference.segment import Sentence

LABELS = ["TA0001", "TA0002", "TA0043", "T1059", "T1566", "T1595"]
N_TACTICS = 3
TT = {"T1059": ["TA0002"], "T1566": ["TA0001"], "T1595": ["TA0043"]}
CATALOG = {"tactics": {"TA0043": {"name": "Reconnaissance", "order": 1},
                       "TA0001": {"name": "Initial Access", "order": 3},
                       "TA0002": {"name": "Execution", "order": 4}},
           "techniques": {"T1059": {"name": "Command and Scripting Interpreter"},
                          "T1566": {"name": "Phishing"}, "T1595": {"name": "Active Scanning"}}}


def sentences(n, skipped=()):
    return [Sentence(i, f"sentence {i} text here", 10 * i, 10 * i + 8, None,
                     "short" if i in skipped else None) for i in range(n)]


def run(probs, n=None, skipped=(), thresholds=0.5, **opts):
    probs = np.asarray(probs, dtype=float)
    sents = sentences(n or len(probs) + len(skipped), skipped)
    return aggregate(sents, probs, LABELS, N_TACTICS, np.full(len(LABELS), thresholds), TT, CATALOG,
                     AggregateOptions(**opts))


def test_threshold_and_evidence_sorted():
    #        TA1  TA2  TA43 T1059 T1566 T1595
    probs = [[0.1, 0.9, 0.0, 0.60, 0.1, 0.0],
             [0.1, 0.2, 0.0, 0.95, 0.1, 0.0],
             [0.1, 0.1, 0.0, 0.49, 0.1, 0.0]]
    out = run(probs)
    t = out["techniques"][0]
    assert [x["id"] for x in out["techniques"]] == ["T1059"]
    assert t["confidence"] == 0.95 and t["sentence_count"] == 2 and t["band"] == "high"
    assert [e["probability"] for e in t["evidence"]] == [0.95, 0.6]
    assert t["mean_confidence"] == round((0.95 + 0.6) / 2, 4)
    assert t["name"] == "Command and Scripting Interpreter" and t["tactic_ids"] == ["TA0002"]


def test_min_evidence_and_strong_threshold_rules():
    probs = [[0, 0, 0, 0.60, 0.85, 0],
             [0, 0, 0, 0.10, 0.10, 0]]
    out = run(probs, min_evidence_sentences=2, strong_threshold=0.8)
    # T1059 has one sentence at 0.60 (< strong) -> dropped; T1566 has one at 0.85 (>= strong) -> kept
    assert [t["id"] for t in out["techniques"]] == ["T1566"]


def test_hierarchy_implied_tactics_are_marked_and_kill_chain_ordered():
    probs = [[0, 0.9, 0, 0.9, 0.0, 0.7]]
    out = run(probs)
    tactics = {t["id"]: t for t in out["tactics"]}
    assert tactics["TA0002"]["source"] == "model"
    assert tactics["TA0043"]["source"] == "implied_by_technique"
    assert tactics["TA0043"]["technique_ids"] == ["T1595"]
    assert [t["id"] for t in out["tactics"]] == ["TA0043", "TA0002"]     # Recon before Execution
    no_hier = run(probs, apply_hierarchy=False)
    assert [t["id"] for t in no_hier["tactics"]] == ["TA0002"]


def test_skipped_sentences_keep_their_index():
    probs = [[0, 0, 0, 0.9, 0, 0]]
    out = run(probs, n=3, skipped=(0, 1))
    assert out["techniques"][0]["evidence"][0]["sentence_index"] == 2
    assert [s["skipped"] for s in out["sentences"]] == ["short", "short", None]
    assert out["sentences"][2]["labels"][0] == {"id": "T1059", "p": 0.9, "passed": True}


def test_bands_and_summary():
    assert (band(0.8), band(0.79), band(0.5), band(0.3)) == ("high", "medium", "medium", "low")
    probs = [[0, 0, 0, 0.9, 0.6, 0.35]]
    out = run(probs, thresholds=0.3)
    assert out["summary"]["confidence_bands"] == {"high": 1, "medium": 1, "low": 1}
    assert out["summary"]["n_techniques"] == 3


def test_empty_report():
    out = run(np.zeros((0, len(LABELS))), n=2, skipped=(0, 1))
    assert out["techniques"] == [] and out["tactics"] == [] and out["summary"]["top_tactic"] is None
