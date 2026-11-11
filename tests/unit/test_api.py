import json
from pathlib import Path

import httpx
import pytest
from fastapi.testclient import TestClient

from threatmamba.api import main
from threatmamba.api.main import app
from threatmamba.clients import IOCServiceExtractor, TTPServiceExtractor

client = TestClient(app)
NOBODY = "http://127.0.0.1:9"  # nothing listens here: connection refused at once, no network needed
FIXTURES = Path(__file__).parent.parent / "fixtures"
FIXTURE = json.loads((FIXTURES / "ttp_predict_response.json").read_text())
IOC_FIXTURE = json.loads((FIXTURES / "ioc_extract_response.json").read_text(encoding="utf-8"))


def test_health_stub_mode(monkeypatch):
    monkeypatch.setenv("TM_MODEL_MODE", "stub")
    r = client.get("/health")
    assert r.status_code == 200
    assert r.json()["mode"] == "stub"


def test_health_real_mode_reports_each_service(monkeypatch):
    monkeypatch.setenv("TM_MODEL_MODE", "real")
    monkeypatch.setenv("TM_TTP_URL", NOBODY)
    monkeypatch.setenv("TM_IOC_URL", NOBODY)
    r = client.get("/health")
    assert r.status_code == 200
    assert r.json()["status"] == "degraded"
    assert r.json()["services"] == {"ttp": "down", "ioc": "down"}


def test_real_ttp_that_is_down_is_a_503_naming_it(monkeypatch):
    monkeypatch.setenv("TM_TTP_MODE", "real")
    monkeypatch.setenv("TM_TTP_URL", NOBODY)
    r = client.post("/api/analyze", json={"text": "A spear-phishing email reached the finance team."})
    assert r.status_code == 503
    assert r.json()["detail"].startswith("ttp service unavailable")


def test_real_ioc_that_is_down_is_a_503_naming_it(monkeypatch):
    monkeypatch.setenv("TM_IOC_MODE", "real")
    monkeypatch.setenv("TM_IOC_URL", NOBODY)
    r = client.post("/api/analyze", json={"text": "A spear-phishing email reached the finance team."})
    assert r.status_code == 503
    assert r.json()["detail"].startswith("ioc service unavailable")


def test_real_ioc_with_stub_ttp_sends_the_original_text(monkeypatch):
    monkeypatch.setenv("TM_IOC_MODE", "real")
    seen = {}

    def handler(request):
        seen["body"] = json.loads(request.content)
        return httpx.Response(200, json=IOC_FIXTURE["response"])

    transport = httpx.MockTransport(handler)
    monkeypatch.setattr(
        main, "IOCServiceExtractor", lambda url, timeout, **kw: IOCServiceExtractor(url, timeout, transport, **kw)
    )
    text = IOC_FIXTURE["request"]["text"]
    r = client.post("/api/analyze", json={"text": text})
    assert r.status_code == 200
    body = r.json()
    assert body["mode"] == "mixed"
    # IOC-hunter reads the whole report and is asked about every unit, kept or not
    assert seen["body"] == {"text": text, "sentences": IOC_FIXTURE["request"]["sentences"], "extended_types": False}
    assert len(body["sentences"]) == 4  # the timeline: real sentences only
    indices = {i["value"]: i["sentence_indices"] for i in body["iocs"]}
    contexts = {i["value"]: i["context"] for i in body["iocs"]}
    assert indices["185.220.101.4"] == [1, 3]
    # only in the indicator list: no timeline sentence, and its context is that list line, not a nearby sentence
    assert indices["d41d8cd98f00b204e9800998ecf8427e"] == []
    assert contexts["d41d8cd98f00b204e9800998ecf8427e"] == ["d41d8cd98f00b204e9800998ecf8427e"]


def test_real_ttp_with_stub_ioc_is_mixed_mode(monkeypatch):
    monkeypatch.setenv("TM_TTP_MODE", "real")
    transport = httpx.MockTransport(lambda request: httpx.Response(200, json=FIXTURE))
    monkeypatch.setattr(main, "TTPServiceExtractor", lambda url, timeout: TTPServiceExtractor(url, timeout, transport))
    r = client.post("/api/analyze", json={"sentences": ["Spear-phishing email arrived.", "C2 was 10.0.0[.]1."]})
    assert r.status_code == 200
    body = r.json()
    assert body["mode"] == "mixed"
    assert {(t["technique_id"], t["sentence_index"]) for t in body["ttps"]} == {
        ("T1566", 0),
        ("TA0001", 0),
        ("TA0002", 0),
    }
    assert body["iocs"][0]["value"] == "10.0.0.1"
    assert body["iocs"][0]["sentence_indices"] == [1]


def test_analyze_returns_contract_shape():
    text = "Spear-phishing led to PowerShell. The C2 server was 10.0.0[.]1."
    r = client.post("/api/analyze", json={"text": text})
    assert r.status_code == 200
    body = r.json()
    assert body["sentences"] == ["Spear-phishing led to PowerShell.", "The C2 server was 10.0.0[.]1."]
    assert body["text"] == text
    assert [text[s["start"] : s["end"]] for s in body["spans"]] == body["sentences"]
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
