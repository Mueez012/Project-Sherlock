"""The Hub transports saved operations; state/authorization remain in IOC Hunter."""

import importlib.util
import json
from pathlib import Path
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


@pytest.mark.parametrize("status", [200, 201, 404, 409, 503])
def test_create_forwards_identity_key_body_and_exact_domain_response(monkeypatch, status):
    seen = {}
    run_id, key = uuid4().hex, uuid4().hex
    payload = {"run": {"id": run_id}} if status < 400 else {"error": {"code": "upstream_outcome"}}

    def handler(request):
        seen["request"] = request
        return httpx.Response(status, json=payload, headers={"Location": f"/v1/investigations/{run_id}"})

    configure(monkeypatch, handler)
    response = client.post(
        "/api/investigations",
        json={"text": "Report names example.com."},
        headers={
            "Authorization": "Bearer externally-verified",
            "Idempotency-Key": key,
        },
    )
    assert response.status_code == status
    assert response.json() == payload
    assert response.headers["location"] == f"/api/investigations/{run_id}"
    sent = seen["request"]
    assert sent.method == "POST" and sent.url.path == "/v1/investigations"
    assert sent.headers["authorization"] == "Bearer externally-verified"
    assert sent.headers["idempotency-key"] == key
    assert json.loads(sent.content)["text"] == "Report names example.com."
    assert "sentences" not in json.loads(sent.content)


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
    for path in (base, f"{base}/nodes/{node_id}/methods", f"{base}/steps/{step_id}?include_snapshots=true"):
        assert client.get(path).status_code == 200
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
    assert client.post(f"{base}/close", json={"action": "finish"}).status_code == 200
    downloaded = client.get(f"{base}/export?include_evidence=false")
    assert downloaded.content == b'{"version":1}'
    assert downloaded.headers["content-disposition"] == 'attachment; filename="saved.json"'
    assert seen[-1].url.params["include_evidence"] == "false"


def test_unreachable_ioc_service_and_wire_validation(monkeypatch):
    def offline(request):
        raise httpx.ConnectError("offline", request=request)

    configure(monkeypatch, offline)
    response = client.get(f"/api/investigations/{uuid4().hex}")
    assert response.status_code == 503
    assert response.json()["error"]["code"] == "ioc_service_unavailable"
    invalid = client.post("/api/investigations", json={"text": "Report", "owner_id": "forged"})
    assert invalid.status_code == 422
    assert invalid.json()["error"]["code"] == "invalid_request"
    assert client.post("/api/investigations", json={"text": "Report"}).status_code == 422


def test_hub_and_ioc_wire_schemas_stay_equivalent():
    from threatmamba.api import investigation_models as hub

    source = Path(__file__).resolve().parents[2] / "services/ioc/ioc_hunter/api/schemas.py"
    spec = importlib.util.spec_from_file_location("ioc_wire_contract", source)
    ioc = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(ioc)

    def expanded(model):
        schema = model.model_json_schema()
        definitions = schema.get("$defs", {})

        def visit(value):
            if isinstance(value, list):
                return [visit(item) for item in value]
            if isinstance(value, dict):
                if "$ref" in value:
                    return visit(definitions[value["$ref"].rsplit("/", 1)[-1]])
                return {key: visit(item) for key, item in value.items() if key not in {"title", "$defs"}}
            return value

        return visit(schema)

    for left, right in (
        (hub.CreateInvestigation, ioc.CreateInvestigation),
        (hub.CreateInvestigationStep, ioc.CreateStep),
        (hub.InvestigationSnapshot, ioc.InvestigationSnapshot),
        (hub.InvestigationList, ioc.InvestigationList),
        (hub.NodeMethods, ioc.NodeMethods),
        (hub.StepExecution, ioc.StepExecution),
        (hub.StepDetail, ioc.StepDetail),
    ):
        assert expanded(left) == expanded(right), left.__name__


def test_openapi_describes_saved_request_and_response_types():
    schema = client.get("/openapi.json").json()
    operation = schema["paths"]["/api/investigations"]["post"]
    assert "201" in operation["responses"] and "200" in operation["responses"]
    assert operation["responses"]["201"]["content"]["application/json"]["schema"]["$ref"].endswith(
        "/InvestigationSnapshot"
    )
    assert "CreateInvestigationStep" in schema["components"]["schemas"]
