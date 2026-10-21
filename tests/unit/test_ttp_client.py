"""The TTP client against a recorded /api/v1/predict answer: no network, no container."""

import json
from pathlib import Path

import httpx
import pytest

from threatmamba.clients import ServiceError, TTPServiceExtractor

FIXTURE = json.loads((Path(__file__).parent.parent / "fixtures" / "ttp_predict_response.json").read_text())


def _client(handler):
    return TTPServiceExtractor("http://ttp:8001", transport=httpx.MockTransport(handler))


def test_passed_labels_become_hits_and_tactics_are_kept():
    seen = {}

    def handler(request):
        seen["path"], seen["body"] = request.url.path, json.loads(request.content)
        return httpx.Response(200, json=FIXTURE)

    hits = _client(handler).predict(["Spear-phishing email arrived.", "Nothing here."])
    assert seen["path"] == "/api/v1/predict"
    assert seen["body"] == {
        "sentences": [{"index": 0, "text": "Spear-phishing email arrived."}, {"index": 1, "text": "Nothing here."}]
    }
    assert [(h.technique_id, h.score, h.sentence_index) for h in hits] == [("T1566", 0.93, 0), ("TA0001", 0.88, 0)]


@pytest.mark.parametrize(
    "response",
    [
        httpx.Response(500, json={"detail": "boom"}),
        httpx.Response(200, content=b"not json"),
        httpx.Response(200, json={"wrong": "shape"}),
        httpx.Response(200, json={"sentences": [{"index": 5, "labels": []}]}),
        httpx.Response(
            200, json={"sentences": [{"index": 0, "labels": [{"id": "T1566.001", "p": 0.9, "passed": True}]}]}
        ),
    ],
    ids=["http-500", "not-json", "wrong-shape", "unknown-sentence", "sub-technique"],
)
def test_any_bad_answer_is_a_service_error(response):
    with pytest.raises(ServiceError) as e:
        _client(lambda request: response).predict(["one sentence"])
    assert e.value.service == "ttp"


def test_unreachable_service_is_a_service_error():
    def handler(request):
        raise httpx.ConnectError("refused", request=request)

    with pytest.raises(ServiceError):
        _client(handler).predict(["one sentence"])


def test_health_reports_ok_or_down():
    assert _client(lambda r: httpx.Response(200, json={"status": "ok"})).health() == "ok"
    assert _client(lambda r: httpx.Response(503)).health() == "down"
