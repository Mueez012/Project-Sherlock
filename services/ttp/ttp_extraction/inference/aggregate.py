"""Sentence probabilities -> report-level ATT&CK tactics and techniques with evidence.

Rules (one implementation for the API and the command line):
  * a sentence predicts label l when p >= threshold_l;
  * a label is reported when at least `min_evidence_sentences` sentences predict it,
    OR one sentence reaches `strong_threshold`;
  * report confidence = highest sentence probability (the mean over its positive
    sentences is returned too); evidence = top `max_evidence` sentences by probability;
  * with `apply_hierarchy`, every reported technique also reports its ATT&CK
    tactic(s); a tactic found ONLY this way is marked source="implied_by_technique";
  * tactics are ordered by the ATT&CK kill chain (Reconnaissance -> Impact),
    techniques by confidence, then number of sentences.

The top-1 rule of the decision layer is not used: most sentences of a real
report describe no technique, so forcing a label onto every sentence would
flood the result with false positives.
"""
from __future__ import annotations

from dataclasses import dataclass

import numpy as np

HIGH, MEDIUM = 0.80, 0.50
ATTACK_URL = "https://attack.mitre.org"


@dataclass
class AggregateOptions:
    min_evidence_sentences: int = 1
    strong_threshold: float = 0.8
    include_sentences: bool = True
    apply_hierarchy: bool = True
    max_evidence: int = 5
    max_sentence_labels: int = 5


def band(confidence: float) -> str:
    """high >= 0.80, medium 0.50-0.79, low = passed its threshold but < 0.50."""
    if confidence >= HIGH:
        return "high"
    return "medium" if confidence >= MEDIUM else "low"


def _r(x: float) -> float:
    return round(float(x), 4)


def technique_url(tid: str) -> str:
    return f"{ATTACK_URL}/techniques/{tid.replace('.', '/')}/"


def aggregate(sentences, probs: np.ndarray, labels, n_tactics: int, thresholds: np.ndarray,
              technique_to_tactics: dict[str, list[str]], catalog: dict | None = None,
              options: AggregateOptions | None = None) -> dict:
    """sentences: segment.Sentence list (all of them, skipped ones included).
    probs: (n_analysed, L) for the sentences with skip_reason None, in order.
    catalog: {"tactics": {id: {name, order}}, "techniques": {id: {name, url}}} (names optional).
    """
    options = options or AggregateOptions()
    catalog = catalog or {"tactics": {}, "techniques": {}}
    analysed = [s for s in sentences if s.skip_reason is None]
    if len(analysed) != len(probs):
        raise ValueError(f"{len(analysed)} analysed sentences but {len(probs)} probability rows")
    thresholds = np.asarray(thresholds, dtype=float)
    labels = list(labels)
    passed = probs >= thresholds[None, :] if len(probs) else np.zeros((0, len(labels)), bool)

    def evidence(j: int, rows: np.ndarray) -> list[dict]:
        ranked = rows[np.argsort(-probs[rows, j], kind="stable")][: options.max_evidence]
        return [{"sentence_index": analysed[i].index, "text": analysed[i].text,
                 "probability": _r(probs[i, j]), "char_start": analysed[i].char_start,
                 "char_end": analysed[i].char_end, "page": analysed[i].page} for i in ranked]

    def reported(j: int) -> np.ndarray | None:
        rows = np.flatnonzero(passed[:, j])
        best = probs[:, j].max() if len(probs) else 0.0
        if len(rows) >= options.min_evidence_sentences or (len(rows) and best >= options.strong_threshold):
            return rows
        return None

    techniques = []
    for j in range(n_tactics, len(labels)):
        rows = reported(j)
        if rows is None or not len(rows):
            continue
        tid = labels[j]
        info = catalog["techniques"].get(tid, {})
        conf = float(probs[rows, j].max())
        techniques.append({
            "id": tid, "name": info.get("name", tid),
            "tactic_ids": list(technique_to_tactics.get(tid, info.get("tactics", []))),
            "url": info.get("url", technique_url(tid)),
            "confidence": _r(conf), "band": band(conf),
            "mean_confidence": _r(probs[rows, j].mean()), "sentence_count": int(len(rows)),
            "threshold": _r(thresholds[j]), "evidence": evidence(j, rows),
        })
    techniques.sort(key=lambda t: (-t["confidence"], -t["sentence_count"], t["id"]))

    tactic_info = catalog["tactics"]
    order = {tid: tactic_info.get(tid, {}).get("order", 100 + k) for k, tid in enumerate(labels[:n_tactics])}
    tactics = {}
    for j in range(n_tactics):
        rows = reported(j)
        if rows is None or not len(rows):
            continue
        tid = labels[j]
        tactics[tid] = {"id": tid, "confidence": _r(probs[rows, j].max()), "source": "model",
                        "sentence_count": int(len(rows)), "evidence": evidence(j, rows)}
    for technique in techniques:
        for tid in technique["tactic_ids"]:
            if tid in tactics or not options.apply_hierarchy or tid not in order:
                continue
            tactics[tid] = {"id": tid, "confidence": 0.0, "source": "implied_by_technique",
                            "sentence_count": 0, "evidence": []}
    for tid, tactic in tactics.items():
        linked = [t for t in techniques if tid in t["tactic_ids"]]
        tactic["technique_ids"] = [t["id"] for t in linked]
        if tactic["source"] == "implied_by_technique":
            tactic["confidence"] = max(t["confidence"] for t in linked)
            tactic["sentence_count"] = len({e["sentence_index"] for t in linked for e in t["evidence"]})
        info = tactic_info.get(tid, {})
        tactic.update(name=info.get("name", tid), order=order[tid],
                      url=info.get("url", f"{ATTACK_URL}/tactics/{tid}/"))
    tactic_list = sorted(tactics.values(), key=lambda t: t["order"])

    sentence_rows = []
    if options.include_sentences:
        row_of = {s.index: k for k, s in enumerate(analysed)}
        for s in sentences:
            entry = {"index": s.index, "text": s.text, "char_start": s.char_start,
                     "char_end": s.char_end, "page": s.page, "skipped": s.skip_reason, "labels": []}
            k = row_of.get(s.index)
            if k is not None:
                top = np.argsort(-probs[k], kind="stable")[: options.max_sentence_labels]
                entry["labels"] = [{"id": labels[j], "p": _r(probs[k, j]), "passed": bool(passed[k, j])}
                                   for j in top if passed[k, j] or probs[k, j] >= 0.1]
            sentence_rows.append(entry)

    bands = {"high": 0, "medium": 0, "low": 0}
    for t in techniques:
        bands[t["band"]] += 1
    top_tactic = max(tactic_list, key=lambda t: (t["confidence"], t["sentence_count"]))["id"] if tactic_list else None
    return {
        "summary": {"n_tactics": len(tactic_list), "n_techniques": len(techniques),
                    "top_tactic": top_tactic, "confidence_bands": bands},
        "tactics": tactic_list,
        "techniques": techniques,
        "sentences": sentence_rows,
    }
