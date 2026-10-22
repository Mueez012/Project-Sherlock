from ttp_extraction.evaluation.real_reports import TECH_ID, frequency_baseline, prepare_one, prf

HTML = """<html><head><title>Test Advisory | CISA</title></head><body><main>
<h1>Test Advisory</h1>
<p>The actors sent spearphishing emails with malicious links [<a href="#">T1566.002</a>].</p>
<p>They then ran PowerShell scripts (T1059.001) to download tools [T1105].</p>
<table><tr><th>Technique Title</th><th>ID</th><th>Use</th></tr>
<tr><td>Valid Accounts</td><td>T1078</td><td>The actors logged in with stolen administrator credentials.</td></tr></table>
<table><tr><th>IP address</th><th>First seen</th></tr><tr><td>10.1.2.3</td><td>T1999 noise</td></tr></table>
<footer>Related: AA00-000A</footer>
</main></body></html>"""


def test_answer_key_and_clean_text(tmp_path):
    path = tmp_path / "aa99-001a.html"
    path.write_text(HTML, encoding="utf-8")
    rec = prepare_one(path)
    assert rec["title"] == "Test Advisory"
    assert set(rec["truth"]) >= {"T1566", "T1059", "T1105", "T1078"}          # sub-techniques rolled up
    assert not TECH_ID.search(rec["text"])                                    # no id left for the model
    assert "spearphishing emails" in rec["text"] and "PowerShell scripts" in rec["text"]
    assert "stolen administrator credentials" in rec["text"]                  # ATT&CK table "Use" column kept
    assert "Valid Accounts" not in rec["text"]                                # technique-name column dropped
    assert "10.1.2.3" not in rec["text"]                                      # IOC table dropped
    assert rec["table_descriptions_kept"] == 1


def test_prose_only_drops_all_tables(tmp_path):
    path = tmp_path / "aa99-001a.html"
    path.write_text(HTML, encoding="utf-8")
    rec = prepare_one(path, keep_table_text=False)
    assert "stolen administrator credentials" not in rec["text"]
    assert rec["table_descriptions_kept"] == 0


def test_scoring_helpers():
    s = prf({"T1", "T2", "T3"}, {"T2", "T3", "T4", "T5"})
    assert (s["tp"], s["fp"], s["fn"]) == (2, 1, 2)
    assert round(s["f1"], 3) == round(2 * (2 / 3) * 0.5 / (2 / 3 + 0.5), 3)
    truth = [{"id": "a", "truth": ["T1", "T2"]}, {"id": "b", "truth": ["T1", "T3"]}, {"id": "c", "truth": ["T1"]}]
    assert frequency_baseline("c", truth, {"T1", "T2", "T3"}, 1) == {"T1"}     # leave-one-out counts
