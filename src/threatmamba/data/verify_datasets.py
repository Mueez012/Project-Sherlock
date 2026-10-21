"""Hard gate on the committed datasets. Exits non-zero if any check fails.

    uv run python -m threatmamba.data.verify_datasets datasets

The cleaned datasets are the source of truth and are never rebuilt; this only proves they are intact (checksums)
and internally consistent (shapes, labels, splits, and the hub's sentence splitter).
"""

import argparse
import csv
import hashlib
import json
import re
import sys
from collections import Counter
from pathlib import Path

from pydantic import ValidationError

from threatmamba.contracts import D2Report
from threatmamba.text import split_sentences

SPLITS = ("train", "valid", "test")
D1_ROWS = 12406  # paper Table II
N_TACTICS, N_TECHNIQUES, N_GROUPS = 14, 189, 25


class Checks:
    def __init__(self) -> None:
        self.failed = 0

    def __call__(self, ok: bool, msg: str) -> None:
        print(("PASS " if ok else "FAIL ") + msg)
        self.failed += not ok


def _sha256(path: Path) -> str:
    h = hashlib.sha256()
    with open(path, "rb") as fh:
        for block in iter(lambda: fh.read(1 << 20), b""):
            h.update(block)
    return h.hexdigest()


def check_checksums(root: Path, check: Checks) -> None:
    sums = root / "SHA256SUMS"
    if not sums.is_file():
        check(False, "SHA256SUMS exists")
        return
    listed: dict[str, str] = {}
    for line in sums.read_text(encoding="utf-8").splitlines():
        if line.strip():
            digest, name = line.split(maxsplit=1)
            listed[name.lstrip("*")] = digest
    on_disk = sorted(
        p.relative_to(root).as_posix()
        for folder in ("d1_model_ready", "d2_model_ready")
        for p in (root / folder).glob("*")
        if p.is_file()
    )
    check(sorted(listed) == on_disk, f"SHA256SUMS lists exactly the {len(on_disk)} dataset files")
    differ = [n for n, h in listed.items() if not (root / n).is_file() or _sha256(root / n) != h]
    check(not differ, f"every dataset file matches SHA256SUMS ({len(differ)} differ: {differ[:5]})")


def check_d1(d1: Path, expected_rows: int, check: Checks) -> None:
    labels = json.loads((d1 / "labels.json").read_text(encoding="utf-8"))
    tactics = [x["id"] for x in labels["tactics"]]
    techniques = [x["id"] for x in labels["techniques"]]
    check(
        len(tactics) == len(set(tactics)) == N_TACTICS and all(re.fullmatch(r"TA\d{4}", t) for t in tactics),
        f"D1 labels.json has {N_TACTICS} distinct tactics (got {len(tactics)})",
    )
    check(
        len(techniques) == len(set(techniques)) == N_TECHNIQUES and all(re.fullmatch(r"T\d{4}", t) for t in techniques),
        f"D1 labels.json has {N_TECHNIQUES} distinct parent techniques (got {len(techniques)})",
    )
    header = ["Text", *tactics, *techniques]
    csv.field_size_limit(sys.maxsize)
    rows: dict[str, int] = {}
    positives = {s: [0] * len(techniques) for s in SPLITS}
    bad_header, bad_rows, empty, undecodable, unlabelled = [], 0, 0, 0, 0
    for split in SPLITS:
        with open(d1 / f"{split}.csv", encoding="utf-8", newline="") as fh:
            reader = csv.reader(fh)
            if next(reader, None) != header:
                bad_header.append(split)
                continue
            rows[split] = 0
            for row in reader:
                rows[split] += 1
                if len(row) != len(header) or any(c not in ("0", "1") for c in row[1:]):
                    bad_rows += 1
                    continue
                text, tac, tech = row[0], row[1 : 1 + N_TACTICS], row[1 + N_TACTICS :]
                empty += not text.strip()
                undecodable += "\ufffd" in text
                unlabelled += "1" not in tac or "1" not in tech
                for j, cell in enumerate(tech):
                    positives[split][j] += cell == "1"
    check(not bad_header, f"D1 headers are Text + the labels.json order in every split (wrong: {bad_header})")
    total = sum(rows.values())
    check(total == expected_rows, f"D1 rows = {total} (want {expected_rows})  split: {rows}")
    check(bad_rows == 0, f"D1 every row has {len(header)} columns and only 0/1 labels ({bad_rows} bad)")
    check(empty == 0, f"D1 no empty sentence ({empty})")
    check(undecodable == 0, f"D1 no undecodable character U+FFFD in any sentence ({undecodable})")
    check(unlabelled == 0, f"D1 every row has at least one tactic and one technique ({unlabelled} without)")
    uncovered = [
        t
        for j, t in enumerate(techniques)
        if sum(positives[s][j] for s in SPLITS) >= 2 and (positives["train"][j] == 0 or positives["test"][j] == 0)
    ]
    check(not uncovered, f"D1 every technique with >= 2 rows is in train and in test (missing: {uncovered[:10]})")


def check_d2(d2: Path, check: Checks) -> None:
    groups = json.loads((d2 / "groups.json").read_text(encoding="utf-8"))
    label_of = {g["group"]: g["label"] for g in groups}
    check(
        len(groups) == len(label_of) == N_GROUPS and sorted(label_of.values()) == list(range(N_GROUPS)),
        f"D2 groups.json has {N_GROUPS} distinct groups labelled 0-{N_GROUPS - 1}",
    )
    ids: Counter[int] = Counter()
    per_split = {s: Counter() for s in SPLITS}
    invalid, wrong_label, split_differs = 0, 0, []
    for split in SPLITS:
        with open(d2 / f"{split}.jsonl", encoding="utf-8") as fh:
            for line in fh:
                if not line.strip():
                    continue
                try:
                    r = D2Report.model_validate_json(line)
                except ValidationError:
                    invalid += 1
                    continue
                ids[r.report_id] += 1
                per_split[split][r.group] += 1
                wrong_label += label_of.get(r.group) != r.label
                if r.sentences != split_sentences(r.text):
                    split_differs.append(r.report_id)
    per_group = sum(per_split.values(), Counter())
    check(invalid == 0, f"D2 every line is a valid D2Report ({invalid} invalid)")
    check(all(n == 1 for n in ids.values()), "D2 report_id is unique across train, valid and test")
    check(wrong_label == 0, f"D2 every label matches groups.json ({wrong_label} wrong)")
    check(
        all(per_group[g["group"]] == g["reports"] for g in groups),
        "D2 reports per group match the counts in groups.json",
    )
    check(
        all(per_split[s][g] > 0 for s in SPLITS for g in label_of),
        "D2 every group has reports in train, valid and test",
    )
    check(
        not split_differs,
        f"D2 sentences == threatmamba.text.split_sentences(text) ({len(split_differs)} differ: {split_differs[:5]})",
    )
    print(f"     D2 reports: {sum(per_group.values())}  split: { {s: sum(per_split[s].values()) for s in SPLITS} }")


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    ap.add_argument("root", type=Path, help="the datasets/ folder")
    ap.add_argument("--d1-rows", type=int, default=D1_ROWS, help="expected D1 rows over all splits")
    a = ap.parse_args(argv)
    check = Checks()
    check_checksums(a.root, check)
    check_d1(a.root / "d1_model_ready", a.d1_rows, check)
    check_d2(a.root / "d2_model_ready", check)
    print("ALL CHECKS PASSED" if not check.failed else f"VERIFICATION FAILED ({check.failed} checks)")
    return 1 if check.failed else 0


if __name__ == "__main__":
    sys.exit(main())
