#!/usr/bin/env python3
"""Gate between Phase 1 and Phase 2. Streams the outputs; exits non-zero on any failed invariant."""

import argparse
import csv
import json
import re
import resource
import sys
from collections import Counter
from pathlib import Path

import pandas as pd

ok = True


def check(cond, msg):
    global ok
    print(("PASS " if cond else "FAIL ") + msg)
    ok &= bool(cond)


ap = argparse.ArgumentParser()
ap.add_argument("--base", type=Path, required=True)
ap.add_argument("--contrib", type=Path, help="TTP_Group_Contribution.csv for a vocabulary cross-check")
ap.add_argument("--d2-min", type=int, default=3200)
ap.add_argument("--d2-max", type=int, default=3338)  # paper's Table II count is the ceiling
a = ap.parse_args()

# ---------------- D1
d1 = a.base / "d1_ttp_base.csv"
cols = list(pd.read_csv(d1, nrows=0).columns)
ta = [c for c in cols if re.fullmatch(r"TA\d{4}", c)]
t = [c for c in cols if re.fullmatch(r"T\d{4}", c)]
check(cols[:3] == ["doc_id", "split", "text"], "D1 leading columns are doc_id, split, text")
check(len(ta) == 14, f"D1 tactic columns = {len(ta)} (want 14)")
check(len(t) == 189, f"D1 technique columns = {len(t)} (want 189)")
check(len(cols) == 3 + 14 + 189, f"D1 total columns = {len(cols)} (want 206, no sub-techniques)")
n = bad_val = no_ta = no_t = empty = cjk = repl = 0
ids = set()
splits = Counter()
pos_tr = pd.Series(0, index=t)
pos_te = pd.Series(0, index=t)
for ch in pd.read_csv(d1, chunksize=2000):
    n += len(ch)
    L = ch[ta + t]
    bad_val += int((~L.isin([0, 1])).sum().sum())
    no_ta += int((L[ta].sum(axis=1) == 0).sum())
    no_t += int((L[t].sum(axis=1) == 0).sum())
    empty += int(ch.text.fillna("").str.strip().eq("").sum())
    cjk += int(ch.text.fillna("").str.contains(r"[\u4e00-\u9fff]").sum())  # D1 is English ATT&CK text
    repl += int(ch.text.fillna("").str.contains("\ufffd").sum())
    ids.update(ch.doc_id)
    splits.update(ch.split)
    pos_tr += ch.loc[ch.split == "train", t].sum()
    pos_te += ch.loc[ch.split == "test", t].sum()
check(n == 12406, f"D1 rows = {n} (want 12406)")
check(len(ids) == n, "D1 doc_id unique")
check(
    bad_val == 0 and no_ta == 0 and no_t == 0 and empty == 0,
    f"D1 labels binary / every row has >=1 tactic and >=1 technique / no empty text ({bad_val},{no_ta},{no_t},{empty})",
)
check(cjk == 0 and repl == 0, f"D1 text has no CJK mojibake and no U+FFFD ({cjk},{repl})")
tot = pos_tr + pos_te
gap = int(((tot >= 2) & ((pos_tr == 0) | (pos_te == 0))).sum())
check(gap == 0, f"D1 every technique with >=2 positives appears in both train and test ({gap} missing)")
print(f"     D1 split: {dict(splits)}  (paper Table II: 11165/1241)")
if a.contrib:
    vocab = set(pd.read_csv(a.contrib, usecols=["ttp"]).ttp.str.strip())
    check(vocab == set(t), f"D1 technique vocab == TTP_Group_Contribution vocab (|diff|={len(vocab ^ set(t))})")

# ---------------- D2
d2 = a.base / "d2_cti_base.csv"
lm = json.loads((a.base / "d2_label_map.json").read_text(encoding="utf-8"))
name_of = {e["label"]: e["group_name"] for e in lm}
check(len(name_of) == 25 and sorted(name_of) == list(range(25)), "D2 label map has labels 0..24")
csv.field_size_limit(sys.maxsize)
n = 0
per = Counter()
ids = set()
mism = empty = 0
splits = Counter()
trunc = 0
test_per = Counter()
with open(d2, encoding="utf-8", newline="") as fh:
    for r in csv.DictReader(fh):
        n += 1
        per[r["group_name"]] += 1
        ids.add(r["doc_id"])
        splits[r["split"]] += 1
        mism += name_of.get(int(r["label"])) != r["group_name"]
        empty += not r["text"].strip()
        trunc += r["truncated"] == "1"
        test_per[r["group_name"]] += r["split"] == "test"
check(a.d2_min <= n <= a.d2_max, f"D2 rows = {n} (window {a.d2_min}-{a.d2_max}; paper says 3338)")
check(len(per) == 25, f"D2 distinct classes = {len(per)} (want 25)")
check(min(per.values()) >= 10, f"D2 smallest class = {min(per.values())}")
check(
    len(ids) == n and mism == 0 and empty == 0,
    f"D2 unique ids / label-name consistent / no empty text ({n - len(ids)},{mism},{empty})",
)
check(all(per[name_of[l]] for l in name_of), "D2 every label in map has rows")
check(min(test_per[c] for c in per) >= 2, f"D2 every class has >=2 test reports (min {min(test_per[c] for c in per)})")
test_share = splits["test"] / n
check(0.07 <= test_share <= 0.13, f"D2 test share = {test_share:.3f}")
print(f"     D2 split: {dict(splits)}  (paper Table II: 3015/336)  truncated-at-32767: {trunc}")
print(f"     peak RSS of this check: {resource.getrusage(resource.RUSAGE_SELF).ru_maxrss / 1024:.0f} MB")
print("ALL CHECKS PASSED" if ok else "VERIFICATION FAILED")
sys.exit(0 if ok else 1)
