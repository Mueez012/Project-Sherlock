"""The datasets gate on a tiny synthetic copy of the real layout (the real files are checked by the datasets CI job)."""

import csv
import hashlib
import json

from threatmamba.data.verify_datasets import main
from threatmamba.text import split_sentences

TACTICS = [f"TA{i:04d}" for i in range(1, 15)]
TECHNIQUES = [f"T{1000 + i}" for i in range(1, 190)]


def _write_d1(d1, uncovered=None):
    d1.mkdir(parents=True)
    (d1 / "labels.json").write_text(
        json.dumps({"tactics": [{"id": t} for t in TACTICS], "techniques": [{"id": t} for t in TECHNIQUES]})
    )
    rows = {"train": [], "valid": [], "test": []}
    for j, tech in enumerate(TECHNIQUES):
        for split in ("train", "test"):
            target = "train" if tech == uncovered else split  # `uncovered` never reaches test
            rows[target].append(
                [f"Sentence about {tech} in {split}.", *([1] + [0] * 13), *[int(k == j) for k in range(189)]]
            )
    rows["valid"].append(["A validation sentence.", *([1] + [0] * 13), *([1] + [0] * 188)])
    for split, body in rows.items():
        with open(d1 / f"{split}.csv", "w", encoding="utf-8", newline="") as fh:  # csv default: Windows line endings
            w = csv.writer(fh)
            w.writerow(["Text", *TACTICS, *TECHNIQUES])
            w.writerows(body)
    return sum(len(b) for b in rows.values())


def _write_d2(d2, bad_sentences=False):
    d2.mkdir(parents=True)
    groups = [{"label": i, "group": f"Group{i}", "reports": 3} for i in range(25)]
    (d2 / "groups.json").write_text(json.dumps(groups))
    rid = 2
    for split in ("train", "valid", "test"):
        with open(d2 / f"{split}.jsonl", "w", encoding="utf-8") as fh:
            for g in groups:
                text = f"{g['group']} sent a lure. J\nThen it ran PowerShell."
                sentences = split_sentences(text)
                if bad_sentences and rid == 2:
                    sentences = [text]
                rec = {"report_id": rid, "group": g["group"], "label": g["label"], "cut_by_excel": False}
                fh.write(json.dumps({**rec, "text": text, "sentences": sentences}) + "\n")
                rid += 1


def _write_sums(root):
    lines = []
    for folder in ("d1_model_ready", "d2_model_ready"):
        for p in sorted((root / folder).glob("*")):
            lines.append(f"{hashlib.sha256(p.read_bytes()).hexdigest()}  {folder}/{p.name}")
    (root / "SHA256SUMS").write_text("\n".join(lines) + "\n")


def _datasets(tmp_path, **kw):
    root = tmp_path / "datasets"
    n = _write_d1(root / "d1_model_ready", kw.get("uncovered"))
    _write_d2(root / "d2_model_ready", kw.get("bad_sentences", False))
    _write_sums(root)
    return root, n


def test_intact_datasets_pass(tmp_path, capsys):
    root, n = _datasets(tmp_path)
    assert main([str(root), "--d1-rows", str(n)]) == 0
    assert "FAIL" not in capsys.readouterr().out


def test_a_changed_file_fails_the_checksum(tmp_path, capsys):
    root, n = _datasets(tmp_path)
    with open(root / "d1_model_ready" / "train.csv", "a", encoding="utf-8") as fh:
        fh.write("\n")
    assert main([str(root), "--d1-rows", str(n)]) == 1
    assert "FAIL every dataset file matches SHA256SUMS" in capsys.readouterr().out


def test_sentences_that_disagree_with_the_hub_splitter_fail(tmp_path, capsys):
    root, n = _datasets(tmp_path, bad_sentences=True)
    assert main([str(root), "--d1-rows", str(n)]) == 1
    assert "FAIL D2 sentences == threatmamba.text.split_sentences(text) (1 differ: [2])" in capsys.readouterr().out


def test_a_technique_missing_from_test_fails(tmp_path, capsys):
    root, n = _datasets(tmp_path, uncovered="T1005")
    assert main([str(root), "--d1-rows", str(n)]) == 1
    assert "missing: ['T1005']" in capsys.readouterr().out
