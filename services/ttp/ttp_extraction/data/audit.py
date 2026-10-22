"""Module 0: read-only audit of CTI2TTPs.csv.

Checks the file against Table II of the paper (12,406 samples, 14 tactics,
189 techniques) and answers the open questions Module 1 depends on.
Writes reports/data_audit.json and prints the same JSON.
"""
from __future__ import annotations

import argparse
import json
import re
from pathlib import Path

import numpy as np
import pandas as pd

TACTIC = re.compile(r"^TA\d{4}$")
TECH = re.compile(r"^T\d{4}$")
SUB = re.compile(r"^T\d{4}\.\d{3}$")

EXPECTED = {"rows": 12406, "tactics": 14, "techniques": 189}


def classify_columns(columns) -> dict[str, list[str]]:
    groups = {"tactics": [], "techniques": [], "subtechniques": [], "other": []}
    for c in columns:
        if TACTIC.match(c):
            groups["tactics"].append(c)
        elif SUB.match(c):
            groups["subtechniques"].append(c)
        elif TECH.match(c):
            groups["techniques"].append(c)
        else:
            groups["other"].append(c)
    return groups


def pick_text_column(other: list[str]) -> str:
    if len(other) == 1:
        return other[0]
    named = [c for c in other if c.lower() in {"text", "sentence", "content"}]
    if len(named) == 1:
        return named[0]
    raise SystemExit(f"Cannot identify the text column among: {other}")


def roll_up(labels: pd.DataFrame, techniques, subtechniques) -> pd.DataFrame:
    """A parent technique is positive if it or any of its sub-techniques is flagged."""
    rolled = labels[techniques].copy()
    for s in subtechniques:
        parent = s.split(".")[0]
        if parent in rolled.columns:
            rolled[parent] = np.maximum(rolled[parent].to_numpy(), labels[s].to_numpy())
    return rolled


def stats(values) -> dict:
    v = np.asarray(values)
    return {
        "mean": float(v.mean()),
        "p50": float(np.percentile(v, 50)),
        "p90": float(np.percentile(v, 90)),
        "p95": float(np.percentile(v, 95)),
        "p99": float(np.percentile(v, 99)),
        "max": int(v.max()),
    }


def token_lengths(texts: list[str], tokenizer_name: str) -> dict:
    from transformers import AutoTokenizer

    tok = AutoTokenizer.from_pretrained(tokenizer_name)
    lengths = []
    for i in range(0, len(texts), 512):
        batch = tok(texts[i : i + 512], add_special_tokens=True, truncation=False)
        lengths.extend(len(ids) for ids in batch["input_ids"])
    v = np.asarray(lengths)
    out = stats(v)
    out.update({f"share_over_{n}": float((v > n).mean()) for n in (64, 128, 256, 512)})
    return out


def audit(csv: Path, encoding: str, contribution: Path | None, tokenizer: str | None) -> dict:
    df = pd.read_csv(csv, encoding=encoding, low_memory=False)
    df.columns = [str(c).strip() for c in df.columns]

    groups = classify_columns(df.columns)
    tactics, techs, subs = groups["tactics"], groups["techniques"], groups["subtechniques"]
    text_col = pick_text_column(groups["other"])
    label_cols = tactics + techs + subs

    raw = df[label_cols].apply(pd.to_numeric, errors="coerce")
    n_missing = int(raw.isna().sum().sum())
    n_non_binary = int((~raw.isin([0, 1]) & raw.notna()).sum().sum())
    labels = raw.fillna(0).astype(np.int8)

    # Parent / sub-technique consistency.
    parents_without_column = sorted({s.split(".")[0] for s in subs} - set(techs))
    violations = {}
    for s in subs:
        parent = s.split(".")[0]
        if parent in techs:
            n = int(((labels[s] == 1) & (labels[parent] == 0)).sum())
            if n:
                violations[s] = n
    rolled = roll_up(labels, techs, subs)
    rows_changed = int((rolled.to_numpy() != labels[techs].to_numpy()).any(axis=1).sum())

    # The 203-label target space: tactics + rolled-up parent techniques.
    target = pd.concat([labels[tactics], rolled], axis=1)
    tactic_support = labels[tactics].sum().sort_values(ascending=False)
    tech_support = rolled.sum().sort_values(ascending=False)

    text = df[text_col].astype("string")
    empty_text = int((text.isna() | (text.str.strip() == "")).sum())
    signature = pd.Series([row.tobytes() for row in target.to_numpy()], index=df.index)
    per_text = pd.DataFrame({"text": text, "sig": signature}).groupby("text")["sig"].nunique()

    report = {
        "file": str(csv),
        "encoding": encoding,
        "rows": len(df),
        "columns": df.shape[1],
        "text_column": text_col,
        "other_columns": groups["other"],
        "n_tactics": len(tactics),
        "n_parent_techniques": len(techs),
        "n_subtechniques": len(subs),
        "tactic_ids": tactics,
        "label_cells_missing": n_missing,
        "label_cells_non_binary": n_non_binary,
        "parents_without_column": parents_without_column,
        "subtechniques_flagged_without_parent": len(violations),
        "rows_flagged_without_parent_top20": dict(
            sorted(violations.items(), key=lambda kv: -kv[1])[:20]
        ),
        "rows_changed_by_roll_up": rows_changed,
        "labels_per_row_all_554": stats(labels.sum(axis=1)),
        "labels_per_row_target_203": stats(target.sum(axis=1)),
        "rows_without_tactic": int((labels[tactics].sum(axis=1) == 0).sum()),
        "rows_without_technique": int((rolled.sum(axis=1) == 0).sum()),
        "tactic_support": {k: int(v) for k, v in tactic_support.items()},
        "technique_support_top10": {k: int(v) for k, v in tech_support.head(10).items()},
        "technique_support_bottom10": {k: int(v) for k, v in tech_support.tail(10).items()},
        "techniques_with_zero_support": [k for k, v in tech_support.items() if v == 0],
        "techniques_with_under_10_rows": int((tech_support < 10).sum()),
        "empty_text_rows": empty_text,
        "duplicate_text_rows": int(text.duplicated().sum()),
        "duplicate_texts_with_conflicting_labels": int((per_text > 1).sum()),
        "text_chars": stats(text.fillna("").str.len()),
    }

    if contribution is not None:
        contrib = pd.read_csv(contribution, encoding="utf-8")
        col = "ttp" if "ttp" in contrib.columns else contrib.columns[0]
        theirs = set(contrib[col].astype(str).str.strip())
        ours = set(techs)
        report["contribution_file"] = {
            "n_ttps": len(theirs),
            "matches_parent_columns": theirs == ours,
            "only_in_csv": sorted(ours - theirs),
            "only_in_contribution": sorted(theirs - ours),
        }

    if tokenizer is not None:
        report["token_lengths"] = token_lengths(text.fillna("").tolist(), tokenizer)

    report["checks"] = {
        "rows_match_table_II": report["rows"] == EXPECTED["rows"],
        "tactics_match_table_II": report["n_tactics"] == EXPECTED["tactics"],
        "techniques_match_table_II": report["n_parent_techniques"] == EXPECTED["techniques"],
        "labels_are_binary": n_missing == 0 and n_non_binary == 0,
        "no_empty_text": empty_text == 0,
    }
    return report


def main() -> None:
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument("--csv", type=Path, required=True)
    p.add_argument("--encoding", default="gb18030")
    p.add_argument("--contribution", type=Path, default=None,
                   help="Path to TTP_Group_Contribution.csv")
    p.add_argument("--tokenizer", default=None,
                   help="e.g. ehsanaghaei/SecureBERT; omit to skip token lengths")
    p.add_argument("--out", type=Path, default=Path("reports/data_audit.json"))
    args = p.parse_args()

    report = audit(args.csv, args.encoding, args.contribution, args.tokenizer)
    args.out.parent.mkdir(parents=True, exist_ok=True)
    text = json.dumps(report, indent=2, ensure_ascii=False)
    args.out.write_text(text, encoding="utf-8")
    print(text)


if __name__ == "__main__":
    main()