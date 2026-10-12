#!/usr/bin/env python3
"""Recompute every number Claude reported for ThreatMAMBA Phase 1, from the raw repo files and the handoff.

Self-contained on purpose: it does NOT import build_threatmamba_base.py, so it is a second implementation.
Each number has an ID (N01...). Output: one line per ID with the recomputed value, the value Claude
claimed, and OK/MISMATCH. Exit code 1 if anything mismatches.

usage: python3 audit_numbers.py --raw DIR --handoff DIR
  --raw      contains CTI2TTPs.csv, CTI2Attacker.csv, TTP_Group_Contribution.csv
  --handoff  contains d1_ttp_base.csv, shard_000..006.jsonl (or d2/shard_*.jsonl), manifest.json
"""

import argparse
import csv
import glob
import hashlib
import io
import json
import os
import re
import statistics
import sys
from collections import Counter

import pandas as pd

ap = argparse.ArgumentParser()
ap.add_argument("--raw", required=True)
ap.add_argument("--handoff", required=True)
a = ap.parse_args()
R = lambda f: os.path.join(a.raw, f)
H = lambda f: os.path.join(a.handoff, f)
csv.field_size_limit(sys.maxsize)
results = []


def rec(nid, what, value, claimed, tol=0.0):
    ok = (
        (abs(value - claimed) <= tol)
        if isinstance(claimed, (int, float)) and isinstance(value, (int, float))
        else value == claimed
    )
    results.append((nid, what, value, claimed, ok))


CJK = re.compile(r"[\u4e00-\u9fff]")
sha = lambda s: hashlib.sha1(s.encode("utf-8")).hexdigest()

# ---------------------------------------------------------------- D1 raw (CTI2TTPs.csv)
raw1 = open(R("CTI2TTPs.csv"), "rb").read()
lines = raw1.split(b"\n")
bad_lines = 0
for l in lines:
    try:
        l.decode("utf-8")
    except UnicodeDecodeError:
        bad_lines += 1
rec("N01", "D1 raw lines that are not valid UTF-8", bad_lines, 22)
rec("N02", "D1 raw occurrences of bytes E2 80 3F (apostrophe missing last byte)", raw1.count(b"\xe2\x80?"), 28)
gb = pd.read_csv(R("CTI2TTPs.csv"), encoding="gb18030")
rec("N03", "D1 rows with CJK characters if wrongly decoded as GB18030", int(gb.Text.str.contains(CJK).sum()), 320)
utf = pd.read_csv(R("CTI2TTPs.csv"), encoding="utf-8", encoding_errors="replace")
cols = list(utf.columns[1:])
rec("N04", "D1 rows", len(utf), 12406)
rec("N05", "D1 tactic columns  ^TA\\d{4}$", sum(bool(re.fullmatch(r"TA\d{4}", c)) for c in cols), 14)
rec("N06", "D1 technique columns  ^T\\d{4}$", sum(bool(re.fullmatch(r"T\d{4}", c)) for c in cols), 189)
rec(
    "N07",
    "D1 sub-technique columns  ^T\\d{4}\\.\\d{3}$",
    sum(bool(re.fullmatch(r"T\d{4}\.\d{3}", c)) for c in cols),
    351,
)
contrib = set(pd.read_csv(R("TTP_Group_Contribution.csv")).ttp.str.strip())
tech = [c for c in cols if re.fullmatch(r"T\d{4}", c)]
rec(
    "N08",
    "D1 technique set == TTP_Group_Contribution.csv ttp set (symmetric difference size)",
    len(contrib ^ set(tech)),
    0,
)

# ---------------------------------------------------------------- D2 raw (CTI2Attacker.csv)
raw2 = open(R("CTI2Attacker.csv"), "rb").read()
txt2 = raw2.decode("gb18030", errors="replace")
rec("N09", "D2 raw bytes undecodable as GB18030 (U+FFFD after decode)", txt2.count("\ufffd"), 38)
rows = list(csv.reader(io.StringIO(txt2, newline="")))[1:]
rec("N10", "D2 physical CSV rows (excluding header)", len(rows), 10510)
is_rec = lambda r: len(r) > 2 and r[0].strip().isdigit() and r[1].strip() != ""
blank = sum(1 for r in rows if not any(c.strip() for c in r))
nrec = sum(1 for r in rows if is_rec(r))
rec("N11", "D2 blank rows (every cell empty/whitespace)", blank, 3919)
rec("N12", "D2 record rows (col0 all digits AND col1 non-empty)", nrec, 3568)
rec("N13", "D2 fragment rows = physical - blank - record", len(rows) - blank - nrec, 3023)
recs, cur, frag_owner = [], None, set()
for r in rows:
    cells = [c for c in r if c.strip()]
    if not cells:
        continue
    if is_rec(r):
        cur = {
            "gid": r[0].strip(),
            "name": r[1].strip(),
            "text": ",".join(c for c in r[2:] if c != ""),
            "cell_len": len(r[2]),
            "frag": False,
            "overflow": any(c.strip() for c in r[3:]),
        }
        recs.append(cur)
    else:
        cur["text"] += "\n" + ",".join(cells)
        cur["frag"] = True
rec("N14", "D2 records that received fragments", sum(x["frag"] for x in recs), 39)
rec("N15", "D2 records with non-empty cells beyond column 3 (stray commas)", sum(x["overflow"] for x in recs), 3)
al = lambda s: re.sub(r"[^A-Za-z0-9]", "", s)
rec(
    "N16",
    "Reassembly preserves every alphanumeric char of the raw file in order (1=yes)",
    int(al("groupgroup_namecti_content" + "".join(x["gid"] + x["name"] + x["text"] for x in recs)) == al(txt2)),
    1,
)
freq = Counter(x["name"] for x in recs)
top = freq.most_common()
top25 = [n for n, _ in top[:25]]
rec("N17", "Count of 25th most frequent actor (Lamberts)", top[24][1], 21)
rec("N18", "Count of 26th most frequent actor (APT41)", top[25][1], 19)
f5 = set(pd.read_csv(R("TTP_Group_Contribution.csv"), nrows=0).columns[1:])
rec("N19", "Fig.5 / contribution-file actors that are inside our top 25", len(f5 & set(top25)), 21)
rec("N20", "Our top-25 actors NOT in the contribution file", len(set(top25) - f5), 4)
rec(
    "N21",
    "Actors outside the paper's 21 that outnumber Molerats",
    sum(1 for n, c in top if n not in f5 and c > freq["Molerats"]),
    2,
)
out_scope = [x for x in recs if x["name"] not in top25]
rec("N22", "Records from actors outside the top 25", len(out_scope), 302)
norm = lambda s: re.sub(
    r"[ \t]+",
    " ",
    __import__("unicodedata").normalize("NFC", s).replace("\r\n", "\n").replace("\r", "\n").replace("\x00", ""),
).strip()
inscope = [dict(x, t=norm(x["text"])) for x in recs if x["name"] in top25]
empty = [x for x in inscope if not x["t"]]
rec("N23", "In-scope records with empty text after normalisation", len(empty), 3)
seen, dups, kept = set(), 0, []
for x in inscope:
    if not x["t"]:
        continue
    h = sha(x["t"])
    if h in seen:
        dups += 1
        continue
    seen.add(h)
    kept.append(x)
rec("N24", "Exact duplicate texts dropped (first occurrence kept)", dups, 4)
rec("N25", "D2 reports kept = 3568 - 302 - 3 - 4", len(kept), 3259)
rec("N26", "Kept reports whose raw text cell is exactly 32,767 chars", sum(x["cell_len"] >= 32767 for x in kept), 24)
rec("N27", "All records whose raw text cell is exactly 32,767 chars", sum(x["cell_len"] >= 32767 for x in recs), 32)
rec("N28", "Kept reports containing U+FFFD", sum("\ufffd" in x["t"] for x in kept), 20)

# ---------------------------------------------------------------- handoff files
man = json.load(open(H("manifest.json"), encoding="utf-8"))
shard_paths = sorted(glob.glob(H("shard_*.jsonl")) or glob.glob(H("d2/shard_*.jsonl")))
mism = 0
for p in [H("d1_ttp_base.csv")] + shard_paths:
    key = "d1_ttp_base.csv" if p.endswith("d1_ttp_base.csv") else "d2/" + os.path.basename(p)
    mism += hashlib.sha256(open(p, "rb").read()).hexdigest() != man["sha256"][key]
rec("N29", "Handoff files whose SHA-256 differs from manifest.json", mism, 0)
d2 = [json.loads(l) for p in shard_paths for l in open(p, encoding="utf-8")]
rec("N30", "D2 handoff reports", len(d2), 3259)
rec(
    "N31",
    "D2 doc_ids in handoff == sha1(text)[:12] of independently rebuilt reports (1=yes)",
    int({r["doc_id"] for r in d2} == {"d2_" + sha(x["t"])[:12] for x in kept}),
    1,
)
spl = Counter(r["split"] for r in d2)
rec("N32", "D2 train", spl["train"], 2933)
rec("N33", "D2 test", spl["test"], 326)
tpc = Counter(r["group_name"] for r in d2 if r["split"] == "test")
rec("N34", "D2 minimum test reports in any actor", min(tpc.values()), 2)
pc = Counter(r["group_name"] for r in d2)
top3 = sum(c for _, c in pc.most_common(3))
rec("N35", "Top-3 actors' share of D2, % = (576+490+350)/3259*100", round(top3 / len(d2) * 100, 1), 43.4)
rec("N36", "Smallest actor size", min(pc.values()), 21)
rec("N37", "5th smallest actor size", sorted(pc.values())[4], 28)
rec(
    "N38",
    "Majority baseline top-1 on our test set, % = FIN7 test / all test",
    round(tpc["FIN7"] / spl["test"] * 100, 1),
    17.8,
)
nch = [r["meta"]["n_chars"] for r in d2]
rec("N39", "Mean report length, chars (int)", int(statistics.mean(nch)), 5781)
rec("N40", "Median report length, chars (int)", int(statistics.median(nch)), 4420)
sent = [len([s for s in re.split(r"(?<=[.!?])\s+|\n+", r["text"]) if len(s.strip()) > 20]) for r in d2]
rec("N41", "Mean sentences per report (heuristic splitter, see doc)", round(statistics.mean(sent), 1), 46.1)
rec("N42", "Median sentences per report (heuristic splitter)", statistics.median(sent), 33)

d1 = pd.read_csv(H("d1_ttp_base.csv"))
s1 = d1.split.value_counts()
rec("N43", "D1 train", int(s1["train"]), 11147)
rec("N44", "D1 test", int(s1["test"]), 1259)
te, tr = d1[d1.split == "test"][tech].sum(), d1[d1.split == "train"][tech].sum()
tot = te + tr
rec(
    "N45",
    "Techniques with >=2 positives missing from train or test",
    int(((tot >= 2) & ((te == 0) | (tr == 0))).sum()),
    0,
)
rec("N46", "Techniques with exactly 1 positive in D1", int((tot == 1).sum()), 10)
rec("N47", "D1 handoff rows containing CJK or U+FFFD", int(d1.text.str.contains(r"[\u4e00-\u9fff\ufffd]").sum()), 0)

# ---------------------------------------------------------------- counterfactual: the old plain-hash split
old = lambda doc_id: int(sha(doc_id)[:8], 16) % 100 < 10
old_te_d2 = Counter(r["group_name"] for r in d2 if old(r["doc_id"]))
rec("N48", "OLD hash split: Lamberts test reports", old_te_d2["Lamberts"], 0)
rec("N49", "OLD hash split: Winnti Group test reports", old_te_d2["Winnti Group"], 1)
rec("N50", "OLD hash split: 蔓灵花 (BITTER) test reports", old_te_d2["蔓灵花"], 1)
m = d1.doc_id.map(old)
rec("N51", "OLD hash split: techniques with zero test positives", int((d1[m][tech].sum() == 0).sum()), 56)

# ---------------------------------------------------------------- arithmetic on paper numbers (inputs typed from the PDF)
P = dict(d1=12406, d1_tr=11165, d1_te=1241, d2=3338, d2_tr=3015, d2_te=336, nodes=177918, edges=492262, classes=25)
rec("N52", "Paper D2 train+test", P["d2_tr"] + P["d2_te"], 3351)
rec("N53", "Paper D1 train share", round(P["d1_tr"] / P["d1"], 4), 0.9000)
rec("N54", "Paper D2 train share of 3,351", round(P["d2_tr"] / (P["d2_tr"] + P["d2_te"]), 4), 0.8997)
rec("N55", "Reports short of paper", P["d2"] - len(d2), 79)
rec("N56", "Shortfall, % of paper", round((P["d2"] - len(d2)) / P["d2"] * 100, 1), 2.4)
rec("N57", "D1 train difference, paper - ours", P["d1_tr"] - int(s1["train"]), 18)
rec("N58", "Paper avg nodes per graph", round(P["nodes"] / P["d2"], 1), 53.3)
rec("N59", "Paper avg edges per graph", round(P["edges"] / P["d2"], 1), 147.5)
rec("N60", "Paper edges per node", round(P["edges"] / P["nodes"], 2), 2.77)
rec("N61", "Uniform random top-1 accuracy, % = 100/25", 100 / P["classes"], 4.0)
rec(
    "N62",
    "Macro-accuracy points moved by 1 report in a 2-report test class = (1/2)/25*100",
    (1 / 2) / P["classes"] * 100,
    2.0,
)

w = max(len(x[1]) for x in results)
bad = 0
for nid, what, v, c, ok in results:
    bad += not ok
    print(f"{nid}  {'OK      ' if ok else 'MISMATCH'}  {what:<{w}}  got={v}  claimed={c}")
print(f"\n{len(results)} numbers, {bad} mismatches")
sys.exit(1 if bad else 0)
