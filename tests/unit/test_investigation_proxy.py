"""The hub's /api/investigations routes forward to the IOC service unchanged and return its answers unchanged."""

import json
from uuid import uuid4

import httpx
import pytest
from fastapi.testclient import TestClient

from threatmamba.api import investigations
from threatmamba.api.main import app
from threatmamba.clients.investigations import IOCInvestigationClient

client = TestClient(app)


def configure(monkeypatch, handler):
    remote = IOCInvestigationClient("http://ioc:8002", transport=httpx.MockTransport(handler))
    monkeypatch.setattr(investigations, "_client", lambda: remote)


@pytest.mark.parametrize("status", [200, 201, 404, 409, 422, 503])
def test_create_forwards_the_request_unchanged_and_returns_the_answer_unchanged(monkeypatch, status):
    seen = {}
    run_id, key = uuid4().hex, uuid4().hex
    payload = {"run": {"id": run_id}} if status < 400 else {"error": {"code": "upstream_outcome", "message": "m"}}

    def handler(request):
        seen["request"] = request
        return httpx.Response(status, json=payload, headers={"Location": f"/v1/investigations/{run_id}"})

    configure(monkeypatch, handler)
    body = {"text": "Report names example.com.", "anything": "the IOC service decides"}
    response = client.post(
        "/api/investigations", json=body, headers={"Idempotency-Key": key, "Authorization": "Bearer ignored"}
    )
    assert response.status_code == status
    assert response.json() == payload  # the IOC service's own error format passes through untouched
    assert response.headers["location"] == f"/api/investigations/{run_id}"
    sent = seen["request"]
    assert sent.method == "POST" and sent.url.path == "/v1/investigations"
    assert sent.headers["idempotency-key"] == key
    assert "authorization" not in sent.headers  # there are no users
    assert json.loads(sent.content) == body  # the hub does not validate or rewrite the body


def test_queries_step_selection_and_export_are_transported(monkeypatch):
    seen = []
    run_id, node_id, step_id = uuid4().hex, uuid4().hex, uuid4().hex

    def handler(request):
        seen.append(request)
        if request.url.path.endswith("/export"):
            return httpx.Response(
                200,
                content=b'{"version":1}',
                headers={
                    "Content-Type": "application/json",
                    "Content-Disposition": 'attachment; filename="saved.json"',
                },
            )
        return httpx.Response(200, json={"forwarded": True})

    configure(monkeypatch, handler)
    base = f"/api/investigations/{run_id}"
    assert client.get("/api/investigations?limit=2&offset=3&status=ready").status_code == 200
    assert dict(seen[-1].url.params) == {"limit": "2", "offset": "3", "status": "ready"}
    expected = {
        base: f"/v1/investigations/{run_id}",
        f"{base}/nodes/{node_id}/methods": f"/v1/investigations/{run_id}/nodes/{node_id}/methods",
        f"{base}/steps/{step_id}?include_snapshots=true": f"/v1/investigations/{run_id}/steps/{step_id}",
    }
    for path, upstream in expected.items():
        assert client.get(path).status_code == 200
        assert seen[-1].url.path == upstream
    assert seen[-1].url.params["include_snapshots"] == "true"
    body = {
        "step_id": step_id,
        "input_node_id": node_id,
        "method_id": "rapiddns.domain_to_ipv4",
        "expected_graph_revision": 1,
    }
    assert client.post(f"{base}/steps", json=body).status_code == 200
    assert json.loads(seen[-1].content) == body
    assert client.post(f"{base}/resume", json={}).status_code == 200
    assert seen[-1].url.path.endswith("/resume")
    assert client.post(f"{base}/close", json={"action": "finish"}).status_code == 200
    assert json.loads(seen[-1].content) == {"action": "finish"}
    downloaded = client.get(f"{base}/export?include_evidence=false")
    assert downloaded.content == b'{"version":1}'
    assert downloaded.headers["content-disposition"] == 'attachment; filename="saved.json"'
    assert seen[-1].url.params["include_evidence"] == "false"


def test_path_parts_are_encoded(monkeypatch):
    seen = []
    configure(monkeypatch, lambda request: seen.append(request) or httpx.Response(404, json={"error": {}}))
    client.get("/api/investigations/a%20b/nodes/c%3Fd/methods")
    assert seen[-1].url.raw_path == b"/v1/investigations/a%20b/nodes/c%3Fd/methods"


def test_an_unreachable_ioc_service_is_a_503(monkeypatch):
    def offline(request):
        raise httpx.ConnectError("offline", request=request)

    configure(monkeypatch, offline)
    response = client.get(f"/api/investigations/{uuid4().hex}")
    assert response.status_code == 503
    assert response.json()["detail"].startswith("ioc service unavailable")


def test_the_hub_lists_every_investigation_route():
    paths = client.get("/openapi.json").json()["paths"]
    assert {p for p in paths if p.startswith("/api/investigations")} == {
        "/api/investigations",
        "/api/investigations/{run_id}",
        "/api/investigations/{run_id}/nodes/{node_id}/methods",
        "/api/investigations/{run_id}/steps",
        "/api/investigations/{run_id}/steps/{step_id}",
        "/api/investigations/{run_id}/resume",
        "/api/investigations/{run_id}/close",
        "/api/investigations/{run_id}/export",
    }


def test_investigations_wait_for_a_whole_lookup(monkeypatch):
    """A lookup can take minutes; analyses keep their own, shorter IOC timeout."""
    monkeypatch.delenv("TM_IOC_INVESTIGATION_TIMEOUT_S", raising=False)
    assert investigations._client().timeout_s == 600.0
    monkeypatch.setenv("TM_IOC_INVESTIGATION_TIMEOUT_S", "900")
    assert investigations._client().timeout_s == 900.0
