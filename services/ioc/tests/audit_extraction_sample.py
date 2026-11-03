"""Reproducible extraction audit: 12 random reports plus targeted reference cases.

Run from ioc-hunter: .venv/Scripts/python tests/audit_extraction_sample.py --label after
The JSON artifact retains every extracted IOC and its original context for review.
"""
import argparse
from dataclasses import asdict
import json
from pathlib import Path
import random
import sys
import time

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
from ioc_hunter import interactive_extraction as extraction


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--label", choices=["before", "after"], required=True)
    parser.add_argument("--extra-rows", nargs="*", type=int, default=[])
    args = parser.parse_args()
    path = ROOT.parent / "ThreatMamba-Datasets/ThreatMAMBA-main/cleaned_CTI2Attacker(main).csv"
    rows = extraction.load_reports(path)
    chosen = sorted(random.Random(20261010).sample(range(len(rows)), 12))
    random_rows = [i + 1 for i in chosen]
    chosen = sorted(set(chosen) | {row - 1 for row in args.extra_rows})
    nlp = extraction.create_sentencizer()
    audit = {"seed": 20261010, "random_rows": random_rows, "reports": []}
    for index in chosen:
        started = time.monotonic()
        row = rows[index]
        original = row["cti_content"]
        text = original
        excluded = []
        if hasattr(extraction, "filter_report_sections"):
            text, excluded = extraction.filter_report_sections(original)
        sentences = extraction.split_sentences(text, nlp)
        matches = extraction.find_sentence_iocs(sentences)
        objects = extraction.build_iocs(sentences, matches, "cti report")
        result = {"row": index + 1, "index": row["index"], "sentences": len(sentences),
                  "excluded": excluded, "iocs": [asdict(item) for item in objects],
                  "seconds": round(time.monotonic() - started, 2)}
        assert len({(item.type, item.value) for item in objects}) == len(objects)
        assert all(item.source == "cti report" and item.context for item in objects)
        assert all(context in original for item in objects for context in item.context)
        audit["reports"].append(result)
        print(f"Row {index + 1}, index {row['index']}: {len(sentences)} sentences, "
              f"{len(objects)} IOCs, {len(excluded)} excluded sections ({result['seconds']}s)", flush=True)
    output = ROOT / "output" / f"extraction-audit-{args.label}.json"
    output.parent.mkdir(exist_ok=True)
    output.write_text(json.dumps(audit, indent=2, ensure_ascii=False), encoding="utf-8")
    print(f"Saved {output}")


if __name__ == "__main__":
    main()
