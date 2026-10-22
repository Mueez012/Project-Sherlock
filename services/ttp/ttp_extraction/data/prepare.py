"""Module 1 entry point: write the label vocabulary and seeded splits."""
from __future__ import annotations

import argparse
import json
from pathlib import Path

from ttp_extraction.data.labels import load_dataset
from ttp_extraction.data.splits import coverage, make_split, save_split


def main() -> None:
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument("--csv", type=Path, required=True)
    p.add_argument("--encoding", default="gb18030")
    p.add_argument("--seeds", type=int, nargs="+", default=[0, 1, 2])
    p.add_argument("--artifacts", type=Path, default=Path("artifacts"))
    p.add_argument("--reports", type=Path, default=Path("reports"))
    args = p.parse_args()

    texts, y, vocab = load_dataset(args.csv, args.encoding)
    vocab.save(args.artifacts / "label_vocab.json")

    summary = {"rows": len(texts), "label_matrix_shape": list(y.shape),
               "n_tactics": len(vocab.tactics), "n_techniques": len(vocab.techniques),
               "splits": {}}
    for seed in args.seeds:
        split = make_split(len(texts), seed)
        save_split(split, seed, args.artifacts / "splits" / f"seed_{seed}.json")
        summary["splits"][f"seed_{seed}"] = coverage(y, split, vocab)

    args.reports.mkdir(parents=True, exist_ok=True)
    text = json.dumps(summary, indent=2)
    (args.reports / "splits.json").write_text(text, encoding="utf-8")
    print(text)


if __name__ == "__main__":
    main()