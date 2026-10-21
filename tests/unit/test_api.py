import json
from pathlib import Path

import httpx
import pytest
from fastapi.testclient import TestClient

from threatmamba.api import main
from threatmamba.api.main import app
from threatmamba.clients import TTPServiceExtractor

client = TestClient(app)
NOBODY = "http://127.0.0.1:9"  # nothing listens here: connection refused at once, no network needed
FIXTURE = json.loads((Path(__file__).parent.parent / "fixtures" / "ttp_predict_response.json").read_text())


def test_health_stub_mode(monkeypatch):
    monkeypatch.setenv("TM_MODEL_MODE", "stub")
    r = client.get("/health")
    assert r.status_code == 200
    assert r.json()["mode"] == "stub"


def test_health_real_mode_reports_each_service(monkeypatch):
    monkeypatch.setenv("TM_MODEL_MODE", "real")
    monkeypatch.setenv("TM_TTP_URL", NOBODY)
    r = client.get("/health")
    assert r.status_code == 200
    assert r.json()["status"] == "degraded"
    assert r.json()["services"] == {"ttp": "down", "ioc": "not integrated"}


def test_real_ttp_that_is_down_is_a_503_naming_it(monkeypatch):
    monkeypatch.setenv("TM_TTP_MODE", "real")
    monkeypatch.setenv("TM_TTP_URL", NOBODY)
    r = client.post("/api/analyze", json={"text": "Spear-phishing email."})
    assert r.status_code == 503
    assert r.json()["detail"].startswith("ttp service unavailable")


def test_real_ioc_is_a_503_until_integrated(monkeypatch):
    monkeypatch.setenv("TM_IOC_MODE", "real")
    r = client.post("/api/analyze", json={"text": "Spear-phishing email."})
    assert r.status_code == 503
    assert r.json()["detail"].startswith("ioc service unavailable")


def test_real_ttp_with_stub_ioc_is_mixed_mode(monkeypatch):
    monkeypatch.setenv("TM_TTP_MODE", "real")
    transport = httpx.MockTransport(lambda request: httpx.Response(200, json=FIXTURE))
    monkeypatch.setattr(main, "TTPServiceExtractor", lambda url, timeout: TTPServiceExtractor(url, timeout, transport))
    r = client.post("/api/analyze", json={"sentences": ["Spear-phishing email arrived.", "C2 was 10.0.0[.]1."]})
    assert r.status_code == 200
    body = r.json()
    assert body["mode"] == "mixed"
    assert {(t["technique_id"], t["sentence_index"]) for t in body["ttps"]} == {("T1566", 0), ("TA0001", 0)}
    assert body["iocs"][0]["value"] == "10.0.0.1"


def test_analyze_returns_contract_shape():
    r = client.post("/api/analyze", json={"text": "Spear-phishing led to PowerShell. C2 was 10.0.0[.]1."})
    assert r.status_code == 200
    body = r.json()
    assert body["sentences"] == ["Spear-phishing led to PowerShell.", "C2 was 10.0.0[.]1."]
    assert {t["technique_id"] for t in body["ttps"]} == {"T1566", "T1059", "T1071"}
    assert body["iocs"][0]["value"] == "10.0.0.1"
    assert body["attribution"] is None


def test_analyze_uses_given_sentences_unchanged():
    sents = ["J", "Spear-phishing email arrived"]
    r = client.post("/api/analyze", json={"sentences": sents})
    assert r.status_code == 200
    body = r.json()
    assert body["sentences"] == sents
    assert {(t["technique_id"], t["sentence_index"]) for t in body["ttps"]} == {("T1566", 1)}


@pytest.mark.parametrize("payload", [{"text": ""}, {"sentences": []}, {}])
def test_analyze_rejects_empty_input(payload):
    assert client.post("/api/analyze", json=payload).status_code == 422


def test_interface_is_served():
    r = client.get("/")
    assert r.status_code == 200
    assert "Analyze report" in r.text


def test_openapi_lists_endpoints():
    paths = client.get("/openapi.json").json()["paths"]
    assert "/api/analyze" in paths and "/health" in paths
