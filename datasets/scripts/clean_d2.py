"""
fix_d2.py  -  clean CTI2Attacker.csv (the paper's dataset D2)

    python fix_d2.py ThreatMAMBA/CTI2Attacker.csv | tee d2_proof.txt

Writes d2_model_ready/ (train.jsonl, valid.jsonl, test.jsonl, groups.json). Everything printed is computed from the file. "line" always means the line
number in CTI2Attacker.csv as a text editor shows it.
"""

import collections, csv, re, sys

SRC = sys.argv[1] if len(sys.argv) > 1 else "ThreatMAMBA/CTI2Attacker.csv"
csv.field_size_limit(2**31 - 1)


def split_fields(row):  # split one CSV row on commas, respecting "quoted, fields"
    out, cur, q, i = [], [], False, 0
    while i < len(row):
        c = row[i]
        if q and c == '"' and row[i + 1 : i + 2] == '"':
            cur.append('"')
            i += 2
            continue
        if c == '"' and (q or not cur):
            q = not q
        elif c == "," and not q:
            out.append("".join(cur))
            cur = []
        else:
            cur.append(c)
        i += 1
    return out + ["".join(cur)]


def unquote(s):
    if len(s) >= 2 and s[0] == s[-1] == '"' and '"' not in s[1:-1].replace('""', ""):
        return s[1:-1].replace('""', '"')
    return s


def is_group_name(
    s,
):  # rejects numbers split at a comma ("2,035 domains" -> "035 domains")
    return (
        bool(s)
        and not s[0].isdigit()
        and len(s) <= 40
        and len(s.split()) <= 4
        and s[-1] not in ".,;:!?"
    )


# 1. Encoding: Chinese GB18030; byte 0x80 is the euro sign --------------------------------
raw = open(SRC, "rb").read()
euro_lines = [
    raw.count(b"\n", 0, m.start()) + 1
    for m in re.finditer(rb"(?<![\x81-\xfe])\x80", raw)
]
text = raw.replace(b"\x80", b"\xa2\xe3").decode(
    "gb18030"
)  # A2 E3 = euro sign in GB18030
print(
    f"[1] File is GB18030 (Chinese). Undecodable byte 0x80 = euro sign, found {len(euro_lines)} times."
)
for ln in sorted(set(euro_lines))[:5]:
    i = text.split("\n")[ln - 1].find("€")
    print(
        f"    line {ln}: ...{text.split(chr(10))[ln - 1][max(0, i - 30) : i + 15]}..."
    )
print(f"    all lines: {euro_lines}")

# 2. Rows end with Windows line endings (\r\n); a plain \n is a line break inside a report -----
rows, line = [], 1
for chunk in text.split("\r\n"):
    rows.append((line, chunk))
    line += chunk.count("\n") + 1
rows = [r for r in rows[1:] if r[1] != "" or r is not rows[-1]]  # drop header
print(
    f"\n[2] Header (line 1): {text.split(chr(13))[0][:60]}...  (3 real columns + ~58 empty ones)"
)

# 3. Rebuild reports ---------------------------------------------------------------------
#    START   : "<number>,<group name>,<text>"        -> new report
#    ID-LIST : "... '9']\",<group name>,<text>"       -> new report (the id field is a broken list)
#    EMPTY   : only commas                            -> skipped
#    else    : continuation of the report above
reports, idlist_lines, empty, cur = [], [], 0, None
for ln, row in rows:
    r = row.rstrip(",")
    if not r.strip():
        empty += 1
        continue
    f = split_fields(r)
    m = re.match(r"""^\s*[\s"\[\]',\d]*\]\s*"?,""", r)
    if len(f) >= 3 and f[0].strip().isdigit() and is_group_name(f[1].strip()):
        cur = dict(
            line=ln,
            gid=f[0].strip(),
            group=f[1].strip(),
            parts=[r[len(f[0]) + len(f[1]) + 2 :]]
            if '"' not in f[0] + f[1]
            else [",".join(f[2:])],
        )
        reports.append(cur)
    elif m and is_group_name(split_fields(r[m.end() :])[0].strip()):
        g = split_fields(r[m.end() :])
        cur = dict(
            line=ln, gid="", group=g[0].strip(), parts=[r[m.end() + len(g[0]) + 1 :]]
        )
        reports.append(cur)
        idlist_lines.append(ln)
    elif cur is not None:
        cur["parts"].append(r)
for rep in reports:
    rep["text"] = unquote("\n".join(rep["parts"]).strip())
print(f"\n[3] Reports rebuilt: {len(reports)}   empty rows skipped: {empty}")
print(
    f"    Reports whose id field is a broken list (Ctrl+F  ']\",  ) : {len(idlist_lines)}"
)
print(f"    their lines: {idlist_lines}")

# 4. Cells cut at Excel's limit (32,767 characters per cell) ------------------------------
print(
    "\n[4] Cells exactly 32,767 characters long (cut by Excel; text after it is lost):"
)
cut = []
for ln, row in rows:
    for fld in split_fields(row.rstrip(",")):
        if len(unquote(fld)) == 32767:
            rep = next(x for x in reversed(reports) if x["line"] <= ln)
            cut.append(rep["line"])
            end = ln + row.count("\n")
            print(
                f"    {rep['group']:<15} lines {ln}-{end}   ends with: ...{unquote(fld)[-40:]!r}"
            )

# 5. Pick the 25 biggest groups -------------------------------------------------------------
counts = collections.Counter(x["group"] for x in reports if x["text"].strip())
ranked = counts.most_common()
print(f"\n[5] Groups: {len(counts)}. Reports per group (the 25 biggest are kept):")
for k, (g, n) in enumerate(ranked[:27], 1):
    print(
        f"    {k:>2}. {g:<16} {n}"
        + ("   <- 25th" if k == 25 else "   <- not kept" if k > 25 else "")
    )
top25 = {g for g, _ in ranked[:25]}

# 6. Drop exact duplicates ----------------------------------------------------------------
final, seen = [], {}
for x in reports:
    if x["group"] in top25 and x["text"].strip():
        k = " ".join(x["text"].split())
        if k in seen:
            print(
                f"    duplicate dropped: line {x['line']} ({x['group']}) = line {seen[k]} "
            )
        else:
            seen[k] = x["line"]
            final.append(x)
kept_all = sum(n for _, n in ranked[:25])
print(
    f"\n[6] Reports in the 25 groups: {kept_all}   after dropping duplicates: {len(final)}"
)
print(
    f"    Paper Table II says 3,338 (and its own train 3,015 + test 336 = {3015 + 336})."
)
print(
    f"    Even keeping duplicates, the 25 biggest groups only hold {kept_all}: no choice of 25 groups reaches 3,338."
)

# 7. Model-ready output: train / valid / test, each report split into ordered sentences ----
#    Paper Table II: 90/10 train/test. Paper Table V: 10% of train held out for validation.
#    Paper Sec. III-A-3: the order of sentences is the attack's timeline, so sentence order is kept.
import json, os
from sklearn.model_selection import train_test_split

y = [x["group"] for x in final]
tr, te = train_test_split(
    range(len(final)), test_size=0.1, random_state=1337, stratify=y
)
tr, va = train_test_split(
    list(tr), test_size=0.1, random_state=1337, stratify=[y[i] for i in tr]
)
split = {i: "train" for i in tr} | {i: "valid" for i in va} | {i: "test" for i in te}
groups = sorted(top25, key=lambda g: -counts[g])
label = {g: k for k, g in enumerate(groups)}


def sentences(
    t,
):  # split at line breaks, then after . ! ? followed by a space and a capital/digit/quote
    out = []
    for line in t.split("\n"):
        out += [
            s.strip()
            for s in re.split(r"(?<=[.!?])\s+(?=[A-Z0-9\"“(])", line)
            if s.strip()
        ]
    return out


OUT = "d2_model_ready"
os.makedirs(OUT, exist_ok=True)
files = {
    p: open(f"{OUT}/{p}.jsonl", "w", encoding="utf-8")
    for p in ("train", "valid", "test")
}
for i, x in enumerate(final):
    files[split[i]].write(
        json.dumps(
            {
                "report_id": x["line"],
                "group": x["group"],
                "label": label[x["group"]],
                "cut_by_excel": x["line"] in cut,
                "text": x["text"],
                "sentences": sentences(x["text"]),
            },
            ensure_ascii=False,
        )
        + "\n"
    )
for f in files.values():
    f.close()
json.dump(
    [
        {"label": label[g], "group": g, "reports": sum(1 for v in y if v == g)}
        for g in groups
    ],
    open(f"{OUT}/groups.json", "w", encoding="utf-8"),
    indent=1,
    ensure_ascii=False,
)
print(
    f"\n[7] Wrote {OUT}/: train.jsonl {len(tr)}, valid.jsonl {len(va)}, test.jsonl {len(te)} reports; "
    f"groups.json (25 groups, label 0-24)"
)
print(
    "    One report per line: report_id (line in CTI2Attacker.csv), group, label, cut_by_excel, text, sentences."
)
print(
    f"    {sum(1 for x in final if x['line'] in cut)} reports contain a cell cut by Excel (cut_by_excel = true)."
)
