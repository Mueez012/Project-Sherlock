"""
fix_d1.py  -  clean CTI2TTPs.csv (the paper's dataset D1)

    python fix_d1.py ThreatMAMBA/CTI2TTPs.csv | tee d1_proof.txt

Writes d1_model_ready/ (train.csv, valid.csv, test.csv, labels.json). Everything printed is computed from the file (and from MITRE's official
ATT&CK v14.0 data, downloaded once to enterprise-attack-14.0.json).
"""

import csv, collections, difflib, io, json, os, re, sys, urllib.request

SRC = sys.argv[1] if len(sys.argv) > 1 else "ThreatMAMBA/CTI2TTPs.csv"
MITRE_FILE = "enterprise-attack-14.0.json"
MITRE_URL = (
    "https://raw.githubusercontent.com/mitre-attack/attack-stix-data/master/"
    "enterprise-attack/enterprise-attack-14.0.json"
)


def clean(s):  # strip MITRE's citation markers and markup
    s = re.sub(r"\(Citation:[^)]*\)", "", s)
    s = re.sub(r"\[([^\]]+)\]\([^)]*\)", r"\1", s)
    return re.sub(r"\s+", " ", re.sub(r"<[^>]+>", "", s)).strip()


def key(s):  # letters and digits only (ignores broken punctuation)
    return re.sub(r"[\W_]+", "", s.casefold())


# 1. Broken characters ---------------------------------------------------------------
text = open(SRC, "rb").read().decode("utf-8", errors="replace")
broken = [n for n, line in enumerate(text.split("\n"), 1) if "\ufffd" in line]
print(f"[1] Lines with characters that are not valid UTF-8: {len(broken)}")
print(f"    line numbers: {broken}")

# 2. Columns -------------------------------------------------------------------------
rows = list(csv.reader(io.StringIO(text, newline="")))
header, body = rows[0], rows[1:]
tactics = [i for i, h in enumerate(header) if re.fullmatch(r"TA\d{4}", h)]
techs = [i for i, h in enumerate(header) if re.fullmatch(r"T\d{4}(\.\d{3})?", h)]
parents = sorted({header[i][:5] for i in techs})
print(
    f"\n[2] Rows: {len(body)}   tactic columns: {len(tactics)}   technique columns: {len(techs)} "
    f"(includes sub-techniques like T1059.001)   parent techniques: {len(parents)}"
)

# 3. Repair the broken characters from MITRE's original text ------------------------
if not os.path.exists(MITRE_FILE):
    print(
        "    downloading MITRE ATT&CK v14.0 (~40 MB, only the first time)...",
        flush=True,
    )
    urllib.request.urlretrieve(MITRE_URL, MITRE_FILE)
mitre = {}
for o in json.load(open(MITRE_FILE, encoding="utf-8"))["objects"]:
    if (
        o.get("type") == "relationship"
        and o.get("relationship_type") == "uses"
        and o.get("description")
    ):
        d = clean(o["description"])
        mitre.setdefault(key(d), d)
found = sum(1 for r in body if key(r[0]) in mitre)
print(
    f"\n[3] Rows found word-for-word in MITRE ATT&CK v14.0 procedure examples: {found} of {len(body)}"
)
for n, r in enumerate(body):
    t = r[0]
    if "\ufffd" not in t:
        continue
    src = mitre.get(key(t))
    if src is None:
        print(f"    line {n + 2}: no MITRE source found, left as is")
        continue
    ops = difflib.SequenceMatcher(None, t, src, autojunk=False).get_opcodes()
    r[0] = "".join(
        src[b1:b2] if (op != "equal" and "\ufffd" in t[a1:a2]) else t[a1:a2]
        for op, a1, a2, b1, b2 in ops
    )
    i = t.index("\ufffd")
    print(
        f"    line {n + 2}: ...{t[max(0, i - 20) : i + 10]}...  ->  ...{r[0][max(0, i - 20) : i + 10]}..."
    )

# 4. Sentences that appear twice -----------------------------------------------------
seen = collections.defaultdict(list)
for n, r in enumerate(body):
    seen[r[0].strip()].append(n + 2)
dups = {t: v for t, v in seen.items() if len(v) > 1}
print(
    f"\n[4] Sentences that appear more than once: {len(dups)} (kept, as the paper counts 12,406 rows)"
)
for t, v in dups.items():
    print(f"    lines {v}: {t[:70]}...")

# 5. Collapse sub-techniques into their parent (T1059.001 -> T1059) -----------------
members = [
    [i for i in techs if header[i][:5] == p] for p in parents
]  # columns belonging to each parent
Y = [[1 if any(r[i] == "1" for i in cols) else 0 for cols in members] for r in body]

# 6. 90/10 split, stratified over the 189 techniques ---------------------------------
import numpy as np
from iterstrat.ml_stratifiers import MultilabelStratifiedShuffleSplit

Y = np.array(Y, dtype=np.int8)
tr, te = next(
    MultilabelStratifiedShuffleSplit(
        n_splits=1, test_size=0.1, random_state=1337
    ).split(np.zeros(len(Y)), Y)
)
split = ["train"] * len(body)
for i in te:
    split[i] = "test"
moved = 0
for j in range(len(parents)):  # make sure every technique with >=2 rows is in test too
    rows_j = np.flatnonzero(Y[:, j])
    if len(rows_j) >= 2 and all(split[i] == "train" for i in rows_j):
        split[min(rows_j, key=lambda i: Y[i].sum())] = "test"
        moved += 1
print(
    f"\n[6] Split: train {split.count('train')} / test {split.count('test')} "
    f"({moved} rows moved to test so every technique appears in both)"
)

# 7. Model-ready output: train / valid / test ------------------------------------------
#    Paper Table II: 90/10 train/test. Paper Table V: 10% of train is held out for validation.
train_idx = [i for i in range(len(body)) if split[i] == "train"]
tr2, va = next(
    MultilabelStratifiedShuffleSplit(
        n_splits=1, test_size=0.1, random_state=1337
    ).split(np.zeros(len(train_idx)), Y[train_idx])
)
for k in va:
    split[train_idx[k]] = "valid"
names = {}
for o in json.load(open(MITRE_FILE, encoding="utf-8"))["objects"]:
    ref = next(
        (
            x["external_id"]
            for x in o.get("external_references", [])
            if x.get("source_name") == "mitre-attack"
        ),
        None,
    )
    if ref and o.get("type") in ("x-mitre-tactic", "attack-pattern"):
        names[ref] = o["name"]
OUT = "d1_model_ready"
os.makedirs(OUT, exist_ok=True)
cols = ["Text"] + [header[i] for i in tactics] + parents
for part in ("train", "valid", "test"):
    with open(f"{OUT}/{part}.csv", "w", encoding="utf-8", newline="") as f:
        w = csv.writer(f)
        w.writerow(cols)
        for n, r in enumerate(body):
            if split[n] == part:
                w.writerow([r[0]] + [r[i] for i in tactics] + [int(v) for v in Y[n]])
json.dump(
    {
        "tactics": [
            {"id": header[i], "name": names.get(header[i], "")} for i in tactics
        ],
        "techniques": [{"id": p, "name": names.get(p, "")} for p in parents],
    },
    open(f"{OUT}/labels.json", "w", encoding="utf-8"),
    indent=1,
    ensure_ascii=False,
)
print(
    f"\n[7] Wrote {OUT}/: train.csv {split.count('train')}, valid.csv {split.count('valid')}, "
    f"test.csv {split.count('test')} rows; labels.json (14 tactics, {len(parents)} techniques)"
)
print(
    "    Columns: Text, then 14 tactic columns, then 189 technique columns (0/1, multi-label)."
)
print(
    f"    Paper Table II: 12,406 rows, 14 tactics, 189 techniques.  "
    f"This file: {len(body)} rows, {len(tactics)} tactics, {len(parents)} techniques."
)
