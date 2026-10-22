"""API tests with a fake predictor injected via dependency override (run in seconds)."""
import csv
import io
import json
import time
from pathlib import Path

import pytest
from fastapi.testclient import TestClient

from tests.fakes import FakePredictor
from ttp_api.config import Settings
from ttp_api.deps import get_predictor
from ttp_api.main import create_app
from ttp_api.schemas import AnalysisResult

REPORT = ("Operation Test began with spearphishing emails that carried a malicious document.\n\n"
          "A macro launched PowerShell to fetch a loader from the attacker's server. "
          "The loader created a scheduled task to keep running after reboot. "
          "Stolen files were compressed into an archive before they were sent out.\n\n"
          "44d88612fea8a8f36de82e1278abb02f 10.1.2.3 hxxp://evil[.]com/a.exe\n\n"
          "Done.")


def make_client(tmp_path, predictor=None, **settings):
    s = Settings(**{"load_model": False, "tmp_dir": tmp_path / "uploads", "job_store": "memory", **settings})
    app = create_app(s)
    fake = predictor or FakePredictor()
    app.dependency_overrides[get_predictor] = lambda: fake
    return TestClient(app), fake, s


@pytest.fixture
def client(tmp_path):
    c, fake, _ = make_client(tmp_path)
    with c:
        yield c


def wait(client, job_id, timeout=10.0):
    end = time.time() + timeout
    while time.time() < end:
        status = client.get(f"/api/v1/analyses/{job_id}").json()
        if status["status"] in ("completed", "failed"):
            return status
        time.sleep(0.05)
    raise AssertionError("job did not finish")


def upload(client, name="report.txt", data=REPORT.encode(), options=None, incident="Op Test"):
    form = {"incident_name": incident}
    if options is not None:
        form["options"] = json.dumps(options) if not isinstance(options, str) else options
    return client.post("/api/v1/analyses", files={"file": (name, data)}, data=form)


def assert_problem(response, status, code):
    assert response.status_code == status, response.text
    assert response.headers["content-type"].startswith("application/problem+json")
    body = response.json()
    assert {"type", "title", "status", "detail", "code"} <= body.keys()
    assert body["status"] == status and body["code"] == code


def test_upload_poll_and_result(client):
    r = upload(client)
    assert r.status_code == 202
    created = r.json()
    assert created["status"] == "queued" and created["links"]["result"].endswith("/result")
    status = wait(client, created["id"])
    assert status["status"] == "completed" and status["progress"] == 1.0
    result = client.get(f"/api/v1/analyses/{created['id']}/result").json()
    AnalysisResult.model_validate(result)                       # matches the published schema
    ids = [t["id"] for t in result["techniques"]]
    assert ids[:2] == ["T1059", "T1566"]                                    # sorted by confidence
    assert {"T1059", "T1566", "T1053"} <= set(ids) and "T1560" not in ids     # 0.42 < 0.5
    assert result["summary"]["n_techniques"] == len(ids)
    tactics = {t["id"]: t for t in result["tactics"]}
    assert tactics["TA0003"]["source"] == "implied_by_technique"           # from T1053 only
    assert result["document"]["n_sentences_analyzed"] < result["document"]["n_sentences"]
    assert any("hashes" in w for w in result["warnings"])
    assert list(result["timings_ms"]) == ["extracting_text", "splitting", "encoding", "classifying", "aggregating"]
    assert all(v >= 0 for v in result["timings_ms"].values())
    ev = result["techniques"][0]["evidence"][0]
    assert result["document"]["text"][ev["char_start"]:ev["char_end"]] == ev["text"]


def test_options_change_thresholds(client):
    job = upload(client, options={"threshold_mode": "per_label"}).json()
    wait(client, job["id"])
    result = client.get(f"/api/v1/analyses/{job['id']}/result").json()
    low = next(t for t in result["techniques"] if t["id"] == "T1560")
    assert low["band"] == "low" and low["threshold"] == 0.35
    job = upload(client, options={"threshold_mode": "fixed", "fixed_threshold": 0.9}).json()
    wait(client, job["id"])
    assert client.get(f"/api/v1/analyses/{job['id']}/result").json()["techniques"][0]["id"] == "T1059"


def test_pasted_text(client):
    r = client.post("/api/v1/analyses/text", json={"text": REPORT, "incident_name": "Pasted"})
    assert r.status_code == 202
    assert wait(client, r.json()["id"])["status"] == "completed"
    assert_problem(client.post("/api/v1/analyses/text", json={"text": "   "}), 422, "empty_text")


def test_upload_errors(tmp_path):
    c, _, _ = make_client(tmp_path, max_upload_mb=0.001)
    with c:
        assert_problem(upload(c, data=b"x" * 2000), 413, "file_too_large")
        assert_problem(upload(c, name="evil.exe", data=b"MZ..."), 415, "unsupported_file")
        assert_problem(upload(c, name="fake.pdf", data=b"not a pdf"), 415, "unsupported_file")
        assert_problem(upload(c, name="x.json", data=b'{"a": 1}'), 415, "unsupported_file")
        assert_problem(upload(c, data=b""), 422, "empty_file")
        assert_problem(upload(c, data=b"hello world", options="{bad json"), 400, "bad_options")
        assert_problem(upload(c, data=b"hello world", options={"fixed_threshold": 5}), 400, "bad_options")
        assert not list((tmp_path / "uploads").glob("*")), "rejected uploads must not stay on disk"


def test_not_found_and_not_finished(tmp_path):
    c, _, _ = make_client(tmp_path, predictor=FakePredictor(delay_per_batch=0.5))
    with c:
        assert_problem(c.get("/api/v1/analyses/an_missing"), 404, "not_found")
        assert_problem(c.get("/api/v1/analyses/an_missing/result"), 404, "not_found")
        job = upload(c).json()
        assert_problem(c.get(f"/api/v1/analyses/{job['id']}/result"), 409, "not_finished")
        assert_problem(c.get(f"/api/v1/analyses/{job['id']}/export?format=csv"), 409, "not_finished")
        wait(c, job["id"])


def test_queue_full_returns_429(tmp_path):
    c, _, _ = make_client(tmp_path, predictor=FakePredictor(delay_per_batch=0.3), queue_limit=2)
    with c:
        a, b = upload(c).json(), upload(c).json()
        assert_problem(upload(c), 429, "queue_full")
        wait(c, a["id"]), wait(c, b["id"])
        assert upload(c).status_code == 202


def test_failed_job_and_temp_file_deleted(tmp_path):
    c, _, _ = make_client(tmp_path, predictor=FakePredictor(fail=True))
    with c:
        job = upload(c).json()
        status = wait(c, job["id"])
        assert status["status"] == "failed" and status["error"]["code"] == "model_error"
        assert_problem(c.get(f"/api/v1/analyses/{job['id']}/result"), 409, "job_failed")
        assert not list((tmp_path / "uploads").glob("*"))


def test_temp_file_deleted_after_success(client, tmp_path):
    wait(client, upload(client).json()["id"])
    assert not list((tmp_path / "uploads").glob("*"))


def test_too_many_sentences(tmp_path):
    c, _, _ = make_client(tmp_path, max_sentences=2)
    with c:
        status = wait(c, upload(c).json()["id"])
        assert status["status"] == "failed" and status["error"]["code"] == "too_many_sentences"


def test_scanned_pdf_fails_with_no_text_layer(client):
    import pymupdf

    pdf = pymupdf.open()
    pdf.new_page()
    status = wait(client, upload(client, name="scan.pdf", data=pdf.tobytes()).json()["id"])
    assert status["error"]["code"] == "no_text_layer"


def test_exports_parse(client):
    job = upload(client).json()
    wait(client, job["id"])
    base = f"/api/v1/analyses/{job['id']}/export?format="
    result = client.get(base + "json").json()
    assert result["id"] == job["id"]
    r = client.get(base + "csv")
    assert "attachment" in r.headers["content-disposition"]
    rows = list(csv.DictReader(io.StringIO(r.text)))
    assert {row["technique_id"] for row in rows} == {t["id"] for t in result["techniques"]}
    layer = client.get(base + "navigator").json()
    # Required fields of the Navigator layer format 4.5
    assert layer["versions"]["layer"] == "4.5" and layer["domain"] == "enterprise-attack"
    for t in layer["techniques"]:
        assert t["techniqueID"].startswith("T") and 0 <= t["score"] <= 100 and isinstance(t["tactic"], str)
    stix = client.get(base + "stix").json()
    assert stix["type"] == "bundle"
    report = next(o for o in stix["objects"] if o["type"] == "report")
    patterns = {o["id"]: o for o in stix["objects"] if o["type"] == "attack-pattern"}
    assert set(report["object_refs"]) == set(patterns)
    assert {p["external_references"][0]["external_id"] for p in patterns.values()} == {
        t["id"] for t in result["techniques"]}
    for o in stix["objects"]:
        assert o["spec_version"] == "2.1" and o["id"].startswith(o["type"] + "--")
    assert_problem(client.get(base + "pdf"), 400, "bad_request")


def test_list_and_delete(client):
    job = upload(client).json()
    wait(client, job["id"])
    assert job["id"] in [j["id"] for j in client.get("/api/v1/analyses").json()["items"]]
    assert client.delete(f"/api/v1/analyses/{job['id']}").status_code == 204
    assert_problem(client.delete(f"/api/v1/analyses/{job['id']}"), 404, "not_found")


def test_events_stream_ends_with_completed(client):
    job = upload(client).json()
    with client.stream("GET", f"/api/v1/analyses/{job['id']}/events") as r:
        events = [json.loads(line[6:]) for line in r.iter_lines() if line.startswith("data: ")]
    assert events[-1]["status"] == "completed"


def test_health_model_and_catalog(tmp_path):
    c, _, _ = make_client(tmp_path)
    with c:
        assert c.get("/api/v1/health").status_code == 503          # no real model in this app
        catalog = c.get("/api/v1/attack/techniques").json()
        assert [t["id"] for t in catalog["tactics"]][:2] == ["TA0043", "TA0042"]
        c.app.state.predictor = FakePredictor()
        assert c.get("/api/v1/health").json() == {"status": "ok", "model_loaded": True, "detail": None}
        assert c.get("/api/v1/model").json()["version"] == "fake"
        assert len(c.get("/api/v1/attack/techniques").json()["techniques"]) == 189


def test_sqlite_store_survives_restart(tmp_path):
    db = tmp_path / "jobs.sqlite3"
    c, _, _ = make_client(tmp_path, job_store="sqlite", sqlite_path=db)
    with c:
        job = upload(c).json()
        wait(c, job["id"])
    c2, _, _ = make_client(tmp_path, job_store="sqlite", sqlite_path=db)
    with c2:
        assert c2.get(f"/api/v1/analyses/{job['id']}/result").status_code == 200
