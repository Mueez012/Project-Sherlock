"""Phase 1 parsing rules on a tiny synthetic copy of the raw files (the real files run in the phase1 CI job)."""

import json

from threatmamba.data import build_threatmamba_base as b

D1_HEADER = "Text,TA0001,TA0002,T1566,T1059,T1059.001\n"


def _write_d1(path):
    rows = [
        "Spear phishing email,1,0,1,0,0",
        "PowerShell one-liner,0,1,0,1,1",
        # UTF-8 apostrophe whose last byte became '?': bytes E2 80 3F
        "users\u2019 creds,1,0,1,0,0",
        "Second phishing lure,1,0,1,0,0",
        "Second PowerShell use,0,1,0,1,0",
    ]
    data = (D1_HEADER + "\n".join(rows) + "\n").encode("utf-8").replace(b"\xe2\x80\x99", b"\xe2\x80?")
    path.write_bytes(data)


def _write_d2(path):
    lines = [
        "group,group_name,cti_content,,",
        '1,FIN7,"FIN7 report one about phishing",,',
        "1,FIN7,FIN7 report two first half",  # text broken by an unquoted newline...
        "second half after the break,,",  # ...so this is a fragment row: re-attached to report two
        ",,,,",  # blank row
        '1,FIN7,"FIN7 report three",,',
        '1,FIN7,"FIN7 report one about phishing",,',  # exact duplicate
        '2,Waterbug,"Waterbug report one",,',
        '2,Waterbug,"Waterbug report two",,',
        '2,Waterbug,"Waterbug report three",,',
        '3,NotATop25Actor,"out of scope",,',
        '2,Waterbug,"",,',  # empty text
    ]
    path.write_bytes(("\r\n".join(lines) + "\r\n").encode("gb18030"))


def test_build_d1_repairs_apostrophes_and_folds_subtechniques(tmp_path):
    _write_d1(tmp_path / "d1.csv")
    stats = b.build_d1(tmp_path / "d1.csv", tmp_path / "out.csv", test_pct=10)
    assert stats["rows_out"] == 5
    assert stats["repaired_broken_quotes"] == 1
    assert stats["rows_with_replacement_char"] == 0
    text = (tmp_path / "out.csv").read_text(encoding="utf-8")
    assert "users\u2019 creds" in text
    assert "T1059.001" not in text.splitlines()[0]


def test_build_d1_puts_every_technique_with_two_examples_in_both_splits(tmp_path):
    _write_d1(tmp_path / "d1.csv")
    b.build_d1(tmp_path / "d1.csv", tmp_path / "out.csv", test_pct=10)
    import pandas as pd

    df = pd.read_csv(tmp_path / "out.csv")
    for tech in ("T1566", "T1059"):
        assert set(df.loc[df[tech] == 1, "split"]) == {"train", "test"}


def test_build_d2_record_rules(tmp_path):
    _write_d2(tmp_path / "d2.csv")
    stats = b.build_d2(tmp_path / "d2.csv", tmp_path / "out.csv", test_pct=10, valid_pct=0, min_chars=5)
    assert stats["records"] == 9
    assert stats["fragment_rows"] == 1 and stats["records_with_fragments"] == 1
    assert stats["blank_rows"] == 1
    assert stats["out_of_scope_actor"] == 1
    assert stats["dropped_duplicate"] == 1
    assert stats["dropped_empty"] == 1
    assert stats["rows_out"] == 6
    out = (tmp_path / "out.csv").read_text(encoding="utf-8")
    assert "first half\nsecond half after the break" in out


def test_stratified_split_is_deterministic_and_gives_each_class_two_tests():
    pairs = [(f"d2_{i:012x}", "A" if i < 20 else "B") for i in range(23)]
    s1, s2 = b.stratified_split(pairs, 10, 0), b.stratified_split(list(reversed(pairs)), 10, 0)
    assert s1 == s2
    for cls in ("A", "B"):
        assert sum(1 for d, c in pairs if c == cls and s1[d] == "test") >= 2


def test_label_map_has_25_unique_actors():
    assert len(b.ACTORS_25) == len(set(b.ACTORS_25)) == 25
    json.dumps(b.ACTORS_25, ensure_ascii=False)
