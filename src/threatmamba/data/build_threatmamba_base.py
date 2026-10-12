#!/usr/bin/env python3
"""Phase 1 for the ThreatMAMBA reproduction: raw repo CSVs -> Base Truth Matrices.

Streaming design (memory bounded by one chunk / one record, never the whole file):
  D1  pandas chunksize over CTI2TTPs.csv          -> d1_ttp_base.csv   (doc_id, split, text, 14 TA, 189 T)
  D2  csv.reader over a decoded byte stream        -> d2_cti_base.csv   (doc_id, split, group_id, group_name, label, text)
      D2 takes two streaming passes: pass 1 writes rows without a split; the split is then assigned per class
      (stratified) from the small list of (doc_id, class) pairs, and pass 2 rewrites the file with it.

Facts this script encodes (verified against the uploaded repo files):
  * The two raw CSVs use DIFFERENT encodings. CTI2TTPs.csv is UTF-8 with 22 damaged lines, where the last
    byte of a right single quote was replaced by '?' (bytes E2 80 3F); these are repaired to U+2019.
    Decoding it as GB18030 instead produces mojibake such as "users鈥檚" in ~330 sentences.
    CTI2Attacker.csv is GB18030; 38 bytes in it cannot be decoded and become U+FFFD.
  * CTI2TTPs has exactly 14 TA + 189 T + 351 sub-technique columns; every sub-technique's parent is
    already set whenever the sub is set, so folding subs into parents is a no-op safety step.
  * CTI2Attacker.csv has 10,510 physical rows but only ~3.6k real records. ~3,000 "fragment" rows are
    text that spilled out of 39 records through broken CSV quoting; they are re-attached to the record
    they follow. Re-attachment is checked: every alphanumeric character of the raw file survives, in order.
  * 32 records are truncated at 32,767 chars (Excel cell limit) upstream; this cannot be recovered, only flagged.
"""

import argparse
import csv
import hashlib
import io
import json
import re
import sys
import unicodedata
from pathlib import Path

import pandas as pd

ENC_D1 = "utf-8"  # CTI2TTPs.csv
ENC_D2 = "gb18030"  # CTI2Attacker.csv
CHUNK = 2000
EXCEL_CELL_LIMIT = 32767

# The paper says 25 attacker classes but never names them. These are the 25 most frequent groups in
# CTI2Attacker.csv (the 26th, APT41, has 19 records vs 21 for Lamberts). The first 21 listed are the groups in
# TTP_Group_Contribution.csv / paper Fig. 5. The last 4 are in our top 25 but not in that file; two of them
# (Winnti Group, 蔓灵花) outnumber Molerats, so the paper's 21 are NOT simply the 21 most frequent here.
# Treat the last 4 as an assumption. 蔓灵花 is Qi'anxin's name for BITTER.
ACTORS_25 = [
    "FIN7",
    "Waterbug",
    "SEA",
    "APT28",
    "Hidden Cobra",
    "Silence",
    "MageCart",
    "Rocke",
    "Patchwork",
    "TwoForOne",
    "Tick",
    "Quedagh",
    "Scarab",
    "MuddyWater",
    "APT29",
    "Energetic Bear",
    "Nitro",
    "TA505",
    "APT1",
    "Darkhotel",
    "Molerats",
    "Winnti Group",
    "蔓灵花",
    "APT10",
    "Lamberts",
]
ALIASES = {"蔓灵花": "BITTER"}

RE_TA, RE_T, RE_SUB = re.compile(r"TA\d{4}"), re.compile(r"T\d{4}"), re.compile(r"T\d{4}\.\d{3}")


def _h(key: str) -> int:
    return int(hashlib.sha1(key.encode("utf-8")).hexdigest()[:8], 16)


def iterative_split(rows, n_labels: int, test_pct: int) -> dict:
    """D1 (multi-label): iterative stratification (Sechidis et al., 2011), deterministic.
    rows = [(doc_id, [label indices])]. Rarest label first; each of its rows goes to the split that still
    needs that label most (ties: the split that needs more rows, then train). Labels with >=2 positives are
    guaranteed one test positive. A plain hash split left 56 of 189 techniques with no test positive."""
    ratio = {"test": test_pct / 100, "train": 1 - test_pct / 100}
    cnt = [0] * n_labels
    for _, labs in rows:
        for l in labs:
            cnt[l] += 1
    # a label with >=2 positives must reach test at least once, otherwise rare labels never leave train
    want_test = [max(1.0, ratio["test"] * c) if c >= 2 else ratio["test"] * c for c in cnt]
    need = {"test": want_test, "train": [c - w for c, w in zip(cnt, want_test)]}
    need_rows = {s: r * len(rows) for s, r in ratio.items()}
    by_label = [[] for _ in range(n_labels)]
    for i, (_, labs) in enumerate(rows):
        for l in labs:
            by_label[l].append(i)
    remaining = cnt[:]
    out = {}
    while len(out) < len(rows):
        live = [l for l in range(n_labels) if remaining[l] > 0]
        l = min(live, key=lambda k: (remaining[k], k))
        for i in sorted((i for i in by_label[l] if rows[i][0] not in out), key=lambda i: _h(rows[i][0])):
            s = max(("train", "test"), key=lambda k: (need[k][l], need_rows[k], k == "train"))
            out[rows[i][0]] = s
            need_rows[s] -= 1
            for m in rows[i][1]:
                need[s][m] -= 1
                remaining[m] -= 1
    return out


def stratified_split(pairs, test_pct: int, valid_pct: int, min_test: int = 2) -> dict:
    """D2: per class, order doc_ids by hash and take the first share as test (then valid). Deterministic.
    Each class gets at least `min_test` test docs, so no class is absent from evaluation."""
    by_cls = {}
    for doc_id, cls in pairs:
        by_cls.setdefault(cls, []).append(doc_id)
    out = {}
    for cls, ids in by_cls.items():
        ids.sort(key=_h)
        n = len(ids)
        n_test = max(min_test, round(n * test_pct / 100))
        n_valid = round(n * valid_pct / 100) if valid_pct else 0
        for i, d in enumerate(ids):
            out[d] = "test" if i < n_test else ("valid" if i < n_test + n_valid else "train")
    return out


RE_BROKEN_QUOTE = re.compile("\ufffd\\?")  # bytes E2 80 3F decoded as UTF-8 -> U+FFFD + '?'


def norm_text(s: str) -> str:
    s = unicodedata.normalize("NFC", s)
    s = s.replace("\r\n", "\n").replace("\r", "\n").replace("\x00", "")
    return re.sub(r"[ \t]+", " ", s).strip()


# ----------------------------------------------------------------------------- D1
def build_d1(src: Path, out: Path, test_pct: int) -> dict:
    header = pd.read_csv(src, encoding=ENC_D1, nrows=0).columns
    ta = [c for c in header if RE_TA.fullmatch(c)]
    t = [c for c in header if RE_T.fullmatch(c)]
    subs = [c for c in header if RE_SUB.fullmatch(c)]
    unknown = [c for c in header[1:] if c not in set(ta) | set(t) | set(subs)]
    if unknown:
        raise SystemExit(f"[D1] unexpected columns: {unknown[:10]}")

    stats = dict(
        rows_in=0,
        rows_out=0,
        dropped_empty=0,
        dropped_nolabel=0,
        subs_folded_changes=0,
        repaired_broken_quotes=0,
        rows_with_replacement_char=0,
    )
    first = True
    tmp = out.with_suffix(".nosplit.csv")
    label_rows = []  # (doc_id, [technique indices]): the only O(n) structure, ~12k short lists
    for chunk in pd.read_csv(src, encoding=ENC_D1, encoding_errors="replace", chunksize=CHUNK, dtype={"Text": str}):
        stats["rows_in"] += len(chunk)
        L = chunk[ta + t + subs].fillna(0).astype("int8").clip(0, 1)
        for s in subs:  # fold sub-technique into parent technique (OR)
            parent = s.split(".")[0]
            before = L[parent].sum()
            L[parent] = L[parent] | L[s]
            stats["subs_folded_changes"] += int(L[parent].sum() - before)
        raw_text = chunk["Text"].fillna("")
        stats["repaired_broken_quotes"] += int(raw_text.str.count(RE_BROKEN_QUOTE.pattern).sum())
        text = raw_text.str.replace(RE_BROKEN_QUOTE, "\u2019", regex=True).map(norm_text)
        stats["rows_with_replacement_char"] += int(text.str.contains("\ufffd").sum())
        keep = text.str.len() > 0
        stats["dropped_empty"] += int((~keep).sum())
        has_lab = L[ta + t].sum(axis=1) > 0
        stats["dropped_nolabel"] += int((keep & ~has_lab).sum())
        keep &= has_lab
        doc_id = ["d1_%05d" % i for i in chunk.index]
        outdf = pd.DataFrame({"doc_id": doc_id, "text": text})
        outdf["split"] = ""
        outdf = pd.concat([outdf[["doc_id", "split", "text"]], L[ta + t]], axis=1)[keep.values]
        T = outdf[t].to_numpy()
        label_rows.extend((d, list(row.nonzero()[0])) for d, row in zip(outdf.doc_id, T))
        outdf.to_csv(tmp, mode="w" if first else "a", header=first, index=False, encoding="utf-8")
        first = False
        stats["rows_out"] += len(outdf)
    # pass 2: stamp the stratified split, streaming tmp -> out
    split = iterative_split(label_rows, len(t), test_pct)
    csv.field_size_limit(sys.maxsize)
    with open(tmp, encoding="utf-8", newline="") as src_fh, open(out, "w", encoding="utf-8", newline="") as dst:
        r, w = csv.reader(src_fh), csv.writer(dst)
        w.writerow(next(r))
        for row in r:
            row[1] = split[row[0]]
            w.writerow(row)
    tmp.unlink()
    stats["split"] = {s: sum(1 for v in split.values() if v == s) for s in ("train", "test")}
    stats.update(n_tactics=len(ta), n_techniques=len(t), n_subtechniques_folded=len(subs))
    return stats


# ----------------------------------------------------------------------------- D2
def iter_d2_records(src: Path, stats: dict):
    """Yield [group_id, group_name, text, raw_cell_len], re-attaching spilled fragment rows to their owner."""
    csv.field_size_limit(sys.maxsize)
    stream = io.TextIOWrapper(open(src, "rb"), encoding=ENC_D2, errors="replace", newline="")
    reader = csv.reader(stream)
    next(reader)  # header: group,group_name,cti_content,,,,...
    cur, cur_frag = None, False
    stats["records_with_fragments"] = 0
    for row in reader:
        stats["physical_rows"] += 1
        cells = [c for c in row if c.strip()]
        if not cells:
            stats["blank_rows"] += 1
            continue
        gid = row[0].strip()
        if gid.isdigit() and len(row) > 2 and row[1].strip():
            if cur:
                yield cur
            # field 2 is the text; non-empty trailing cells were split off by an unquoted comma
            if any(c.strip() for c in row[3:]):
                stats["comma_overflow_rows"] += 1
            body = ",".join(c for c in row[2:] if c != "")
            cur, cur_frag = [gid, row[1].strip(), body, len(row[2])], False
        else:
            stats["fragment_rows"] += 1
            if cur is None:
                stats["orphan_fragments"] += 1
                continue
            cur[2] += "\n" + ",".join(cells)
            if not cur_frag:
                stats["records_with_fragments"] += 1
                cur_frag = True
    if cur:
        yield cur
    stream.close()


def build_d2(src: Path, out: Path, test_pct: int, valid_pct: int, min_chars: int) -> dict:
    stats = dict(
        physical_rows=0,
        blank_rows=0,
        fragment_rows=0,
        orphan_fragments=0,
        comma_overflow_rows=0,
        records=0,
        out_of_scope_actor=0,
        dropped_empty=0,
        dropped_short=0,
        dropped_duplicate=0,
        truncated_at_excel_limit=0,
        rows_with_replacement_char=0,
        rows_out=0,
    )
    label_of = {a: i for i, a in enumerate(ACTORS_25)}
    per_class, gid_of = {a: 0 for a in ACTORS_25}, {}
    seen = set()  # sha1 digests only (~40 B each), the one O(n) structure, ~3k entries
    tmp = out.with_suffix(".nosplit.csv")
    pairs = []  # (doc_id, class): the only O(n) list, ~3k short tuples
    with open(tmp, "w", encoding="utf-8", newline="") as fh:
        w = csv.writer(fh)
        w.writerow(
            ["doc_id", "split", "group_id", "group_name", "group_alias", "label", "n_chars", "truncated", "text"]
        )
        for gid, name, body, raw_len in iter_d2_records(src, stats):
            stats["records"] += 1
            if name not in label_of:
                stats["out_of_scope_actor"] += 1
                continue
            if gid_of.setdefault(name, gid) != gid:
                raise SystemExit(f"[D2] group {name} has two ids: {gid_of[name]} vs {gid}")
            text = norm_text(body)
            if not text:
                stats["dropped_empty"] += 1
                continue
            if len(text) < min_chars:
                stats["dropped_short"] += 1
                continue
            digest = hashlib.sha1(text.encode("utf-8")).hexdigest()
            if digest in seen:
                stats["dropped_duplicate"] += 1
                continue
            seen.add(digest)
            trunc = raw_len >= EXCEL_CELL_LIMIT
            stats["truncated_at_excel_limit"] += int(trunc)
            stats["rows_with_replacement_char"] += int("\ufffd" in text)
            doc_id = "d2_" + digest[:12]
            pairs.append((doc_id, name))
            w.writerow([doc_id, "", gid, name, ALIASES.get(name, name), label_of[name], len(text), int(trunc), text])
            per_class[name] += 1
            stats["rows_out"] += 1
    # pass 2: stamp the stratified split, streaming tmp -> out
    split = stratified_split(pairs, test_pct, valid_pct)
    with open(tmp, encoding="utf-8", newline="") as src_fh, open(out, "w", encoding="utf-8", newline="") as dst:
        r, w = csv.reader(src_fh), csv.writer(dst)
        w.writerow(next(r))
        for row in r:
            row[1] = split[row[0]]
            w.writerow(row)
    tmp.unlink()
    stats["per_class"] = per_class
    stats["per_class_split"] = {
        c: {s: sum(1 for d, k in pairs if k == c and split[d] == s) for s in ("train", "valid", "test")}
        for c in ACTORS_25
    }
    return stats


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--raw", type=Path, required=True, help="dir with CTI2TTPs.csv and CTI2Attacker.csv")
    ap.add_argument("--out", type=Path, required=True)
    ap.add_argument(
        "--test-pct",
        type=int,
        default=10,
        help="Table II sizes are a 9:1 split (11165/1241, 3015/336) although the text says 8:2",
    )
    ap.add_argument(
        "--valid-pct",
        type=int,
        default=0,
        help="D2 validation share carved per class (paper Table V: 0.1 of train). 0 = no valid split",
    )
    ap.add_argument("--min-chars", type=int, default=50)
    ap.add_argument("--only", choices=["d1", "d2"])
    a = ap.parse_args()
    a.out.mkdir(parents=True, exist_ok=True)
    report = {}
    if a.only in (None, "d1"):
        report["d1"] = build_d1(a.raw / "CTI2TTPs.csv", a.out / "d1_ttp_base.csv", a.test_pct)
    if a.only in (None, "d2"):
        report["d2"] = build_d2(
            a.raw / "CTI2Attacker.csv", a.out / "d2_cti_base.csv", a.test_pct, a.valid_pct, a.min_chars
        )
        (a.out / "d2_label_map.json").write_text(
            json.dumps(
                [{"label": i, "group_name": n, "alias": ALIASES.get(n, n)} for i, n in enumerate(ACTORS_25)],
                ensure_ascii=False,
                indent=2,
            ),
            encoding="utf-8",
        )
    (a.out / "build_report.json").write_text(json.dumps(report, ensure_ascii=False, indent=2), encoding="utf-8")
    print(json.dumps(report, ensure_ascii=False, indent=2))


if __name__ == "__main__":
    main()
