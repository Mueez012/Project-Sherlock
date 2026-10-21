import pytest
from fastapi.testclient import TestClient

from threatmamba.api.main import app

client = TestClient(app)


def test_health_stub_mode(monkeypatch):
    monkeypatch.setenv("TM_MODEL_MODE", "stub")
    r = client.get("/health")
    assert r.status_code == 200
    assert r.json()["mode"] == "stub"


def test_health_real_mode_is_unavailable_until_checkpoints_exist(monkeypatch):
    monkeypatch.setenv("TM_MODEL_MODE", "real")
    assert client.get("/health").status_code == 503


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
