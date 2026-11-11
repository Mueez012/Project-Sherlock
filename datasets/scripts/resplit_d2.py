"""Rewrite the `sentences` and `spans` fields of every D2 report with the hub's splitter (threatmamba.text).

The splitter decides the timeline (real sentences only, see src/threatmamba/text.py); D2 must hold exactly what it
produces, and the datasets CI job checks that. Every other field and byte stays as it is. Run from the repo root:

    uv run python datasets/scripts/resplit_d2.py
    cd datasets && sha256sum d1_model_ready/* d2_model_ready/* > SHA256SUMS
"""

import json
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / "src"))
from threatmamba.text import segment  # noqa: E402

D2 = ROOT / "datasets" / "d2_model_ready"


def main(out_dir: Path = D2) -> None:
    for part in ("train", "valid", "test"):
        lines = (D2 / f"{part}.jsonl").read_text(encoding="utf-8").splitlines()
        records = [json.loads(line) for line in lines]
        for record in records:
            timeline = [u for u in segment(record["text"]) if u.kind == "sentence"]
            record["sentences"] = [u.text for u in timeline]
            record["spans"] = [[u.start, u.end] for u in timeline]  # exact positions, so nobody has to search for them
        text = "".join(json.dumps(record, ensure_ascii=False) + "\n" for record in records)
        (out_dir / f"{part}.jsonl").write_text(text, encoding="utf-8", newline="\n")
        print(f"{part}: {len(records)} reports, {sum(len(r['sentences']) for r in records)} sentences")


if __name__ == "__main__":
    main(Path(sys.argv[1]) if len(sys.argv) > 1 else D2)
