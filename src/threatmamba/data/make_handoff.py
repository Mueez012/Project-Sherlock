#!/usr/bin/env python3
"""Package verified Base Truth Matrices for the Phase 2 modules (TTP Extractor, IOCHunter).

Output layout (handoff/):
  manifest.json              counts, per-class sizes, label map, TTP vocab order, sha256 of every file
  d1_ttp_base.csv            training matrix for the TTP Extractor (copied as-is)
  d2/shard_XXX.jsonl         one CTI report per line, streamed in fixed-size shards
Each D2 line: {"doc_id","split","label","group_name","group_alias","text","meta":{...}}
doc_id is the join key Phase 2 must carry onto every graph it returns.
"""

import argparse
import csv
import hashlib
import json
import re
import shutil
import sys
from collections import Counter
from pathlib import Path


def sha256(p: Path) -> str:
    h = hashlib.sha256()
    with open(p, "rb") as f:
        for b in iter(lambda: f.read(1 << 20), b""):
            h.update(b)
    return h.hexdigest()


ap = argparse.ArgumentParser()
ap.add_argument("--base", type=Path, required=True)
ap.add_argument("--out", type=Path, required=True)
ap.add_argument("--shard-size", type=int, default=500)
a = ap.parse_args()
(a.out / "d2").mkdir(parents=True, exist_ok=True)

shutil.copyfile(a.base / "d1_ttp_base.csv", a.out / "d1_ttp_base.csv")
with open(a.base / "d1_ttp_base.csv", encoding="utf-8") as f:
    header = next(csv.reader(f))
vocab = {
    "tactics": [c for c in header if re.fullmatch(r"TA\d{4}", c)],
    "techniques": [c for c in header if re.fullmatch(r"T\d{4}", c)],
}

csv.field_size_limit(sys.maxsize)
shards, per, splits, k, fh = [], Counter(), Counter(), 0, None
with open(a.base / "d2_cti_base.csv", encoding="utf-8", newline="") as src:
    for i, r in enumerate(csv.DictReader(src)):
        if i % a.shard_size == 0:
            if fh:
                fh.close()
            p = a.out / "d2" / f"shard_{len(shards):03d}.jsonl"
            shards.append(p)
            fh = open(p, "w", encoding="utf-8")
        rec = {
            "doc_id": r["doc_id"],
            "split": r["split"],
            "label": int(r["label"]),
            "group_name": r["group_name"],
            "group_alias": r["group_alias"],
            "text": r["text"],
            "meta": {
                "group_id": r["group_id"],
                "n_chars": int(r["n_chars"]),
                "truncated_at_excel_limit": r["truncated"] == "1",
                "source": "CTI2Attacker.csv",
            },
        }
        fh.write(json.dumps(rec, ensure_ascii=False) + "\n")
        per[r["group_name"]] += 1
        splits[r["split"]] += 1
        k += 1
if fh:
    fh.close()

files = [a.out / "d1_ttp_base.csv", *shards]
manifest = {
    "schema_version": "phase1-v2",
    "d1": {"rows": 12406, "tactics": 14, "techniques": 189, "file": "d1_ttp_base.csv"},
    "d2": {
        "rows": k,
        "classes": len(per),
        "splits": dict(splits),
        "per_class": dict(per.most_common()),
        "shards": [p.name for p in shards],
    },
    "label_map": json.loads((a.base / "d2_label_map.json").read_text(encoding="utf-8")),
    "ttp_vocab": vocab,
    "build_report": json.loads((a.base / "build_report.json").read_text(encoding="utf-8")),
    "expected_return_from_phase2": {
        "per_doc": "graphs/<doc_id>.json with nodes[{id,type in IOC|TTP|SEQ,...}], edges[{src,dst,rel}]",
        "paper_totals_to_compare": {"graphs": 3338, "nodes": 177918, "edges": 492262},
        "rule": "every returned doc_id must exist in d2 shards; label is joined back by doc_id, never by text",
    },
    "sha256": {str(p.relative_to(a.out)): sha256(p) for p in files},
}
(a.out / "manifest.json").write_text(json.dumps(manifest, ensure_ascii=False, indent=2), encoding="utf-8")
print(f"handoff ready: {k} reports in {len(shards)} shards, {len(per)} classes -> {a.out}")
