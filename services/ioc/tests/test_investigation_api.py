"""Offline HTTP contracts over the real persisted investigation application."""
from pathlib import Path
from uuid import uuid4
import io

import pytest
from fastapi import FastAPI
from fastapi.testclient import TestClient

from ioc_hunter.access import AuthenticationRequired
from ioc_hunter.api.errors import install_error_handlers
from ioc_hunter.api.investigations import router
from ioc_hunter.workflow.service import InvestigationService
from ioc_hunter.main import main

EXAMPLE = Path(__file__).resolve().parents[1] / "examples" / "manual-workflow"
REPORT = (EXAMPLE / "report.txt").read_text(encoding="utf-8")


class TestIdentityProvider:
    """Injected test identity; production verification belongs to a future module."""
    __test__ = False

    def resolve(self, authorization):
        identities = {"Bearer alice": "alice", "Bearer bob": "bob"}
        if authorization not in identities:
            raise AuthenticationRequired()
        return identities[authorization]


@pytest.fixture
def api(tmp_path):
    app = FastAPI()
    app.state.investigation_service = InvestigationService(
        tmp_path / "store", replay_path=EXAMPLE / "replay.json",
    )
    app.state.identity_provider = TestIdentityProvider()
    app.include_router(router)
    install_error_handlers(app)
    with TestClient(app) as client:
        yield client, app.state.investigation_service


def create(client, *, user="alice", key=None, **changes):
    return client.post("/v1/investigations", headers={
        "Authorization": f"Bearer {user}", "Idempotency-Key": key or uuid4().hex,
    }, json={"text": REPORT, **changes})


def headers(user="alice"):
    return {"Authorization": f"Bearer {user}"}


def domain(snapshot):
    return next(node for node in snapshot["graph"]["nodes"] if node["value"] == "example.com")


def test_create_history_native_passages_and_idempotency(api):
    client, _ = api
    key = uuid4().hex
    first = create(client, key=key)
    assert first.status_code == 201, first.text
    saved = first.json()
    run_id = saved["run"]["id"]
    assert first.headers["location"] == f"/v1/investigations/{run_id}"
    assert saved["run"]["status"] == "ready"
    assert saved["graph"]["edges"] == []
    assert saved["steps"] == []
    assert "display" not in saved
    for index, passage in enumerate(saved["extraction"]["passages"]):
        assert passage["sentence_index"] == index
        assert passage["text"] == saved["extraction"]["sentences"][index]
    assert domain(saved)["passage_ids"]
    again = create(client, key=key)
    assert again.status_code == 200
    assert again.json()["run"]["id"] == run_id
    assert client.get("/v1/investigations", headers=headers()).json()["total"] == 1
    conflict = create(client, key=key, text="Different report names example.com.")
    assert conflict.status_code == 409
    assert conflict.json()["error"]["code"] == "idempotency_conflict"


def test_selected_step_receipt_replay_snapshot_and_export(api):
    client, _ = api
    saved = create(client).json()
    run_id, node_id = saved["run"]["id"], domain(saved)["id"]
    base = f"/v1/investigations/{run_id}"
    methods = client.get(f"{base}/nodes/{node_id}/methods", headers=headers())
    assert methods.status_code == 200, methods.text
    choices = {row["id"]: row for row in methods.json()["methods"]}
    assert choices["rapiddns.domain_to_ipv4"]["selectable"]
    step_id = uuid4().hex
    body = {"step_id": step_id, "input_node_id": node_id,
            "method_id": "rapiddns.domain_to_ipv4", "expected_graph_revision": saved["run"]["graph_revision"]}
    response = client.post(f"{base}/steps", headers=headers(), json=body)
    assert response.status_code == 201, response.text
    result = response.json()
    assert not result["replayed"]
    step = result["step"]
    assert step["id"] == step_id
    assert step["lookup_id"] == step["lookup"]["id"]
    assert step["admission"]["accepted"]
    assert step["delta"]["new_edges"] == 2
    repeated = client.post(f"{base}/steps", headers=headers(), json=body)
    assert repeated.status_code == 200, repeated.text
    assert repeated.json()["replayed"]
    assert repeated.json()["step"] == step
    detail = client.get(f"{base}/steps/{step_id}?include_snapshots=true", headers=headers())
    assert detail.status_code == 200
    assert detail.json()["step"] == step
    assert detail.json()["snapshots"]
    snapshot = client.get(base, headers=headers()).json()
    assert snapshot["steps"][0]["id"] == step_id
    assert "lookup" not in snapshot["steps"][0]
    exported = client.get(f"{base}/export", headers=headers())
    assert exported.status_code == 200
    assert "attachment" in exported.headers["content-disposition"]
    assert exported.json()["evidence"]["snapshots"]
    assert exported.json()["steps"][0]["lookup_id"] == step["lookup_id"]


def test_owner_scope_including_same_creation_key(api):
    client, _ = api
    key = uuid4().hex
    alice = create(client, key=key).json()
    bob = create(client, key=key, user="bob").json()
    assert alice["run"]["id"] != bob["run"]["id"]
    assert client.get("/v1/investigations", headers=headers("bob")).json()["total"] == 1
    base = f"/v1/investigations/{alice['run']['id']}"
    node_id = domain(alice)["id"]
    for path in (base, f"{base}/nodes/{node_id}/methods", f"{base}/export"):
        assert client.get(path, headers=headers("bob")).status_code == 404
    for path, body in ((f"{base}/resume", {}), (f"{base}/close", {"action": "finish"})):
        assert client.post(path, headers=headers("bob"), json=body).status_code == 404


@pytest.mark.parametrize("change", [
    {"sentences": ["Caller-controlled sentence."]}, {"owner_id": "bob"},
    {"limits": {"max_steps": True}}, {"limits": {"max_seconds": 0}}, {"text": "  "},
])
def test_invalid_creation_is_rejected_before_persistence(api, change):
    client, _ = api
    response = create(client, **change)
    assert response.status_code == 422
    assert response.json()["error"]["code"] == "invalid_request"
    assert client.get("/v1/investigations", headers=headers()).json()["total"] == 0


def test_authentication_and_methodless_node(api):
    client, _ = api
    assert client.get("/v1/investigations").status_code == 401
    saved = create(client).json()
    hash_node = next(node for node in saved["graph"]["nodes"] if node["type"] == "sha256")
    response = client.get(
        f"/v1/investigations/{saved['run']['id']}/nodes/{hash_node['id']}/methods", headers=headers(),
    )
    assert response.status_code == 200
    assert response.json()["methods"] == []


def test_close_and_resume_preserve_closed_state(api):
    client, _ = api
    saved = create(client).json()
    base = f"/v1/investigations/{saved['run']['id']}"
    first = client.post(f"{base}/close", headers=headers(), json={"action": "finish"})
    assert first.status_code == 200
    assert first.json()["run"]["status"] == "completed"
    assert client.post(f"{base}/close", headers=headers(), json={"action": "finish"}).status_code == 200
    assert client.post(f"{base}/close", headers=headers(), json={"action": "cancel"}).status_code == 409
    resumed = client.post(f"{base}/resume", headers=headers(), json={})
    assert resumed.status_code == 200
    assert resumed.json()["run"]["status"] == "completed"
    assert client.get(f"{base}/export", headers=headers()).status_code == 200


def test_api_created_run_continues_through_actual_terminal_and_exports_identically(api, monkeypatch, tmp_path):
    client, service = api
    saved = create(client).json()
    run_id = saved["run"]["id"]
    monkeypatch.setenv("IOC_HUNTER_ACTOR_ID", "alice")
    choices = [domain(saved)["id"], "rapiddns.domain_to_ipv4", "back", "save"]
    monkeypatch.setattr("sys.stdin", io.StringIO("\n".join(choices) + "\n"))
    assert main(["investigate", "--resume", run_id, "--store", str(service.directory)]) == 0
    reopened = client.get(f"/v1/investigations/{run_id}", headers=headers()).json()
    assert reopened["run"]["id"] == run_id
    assert len(reopened["graph"]["edges"]) == 2
    target = tmp_path / "terminal-export.json"
    assert main(["export", run_id, "--store", str(service.directory), "--output", str(target)]) == 0
    import json
    assert json.loads(target.read_text()) == client.get(
        f"/v1/investigations/{run_id}/export", headers=headers(),
    ).json()


def test_terminal_created_run_can_be_read_and_hunted_through_http(api, monkeypatch):
    client, service = api
    monkeypatch.setenv("IOC_HUNTER_ACTOR_ID", "alice")
    monkeypatch.setattr("sys.stdin", io.StringIO("save\n"))
    assert main([
        "investigate", str(EXAMPLE / "report.txt"), "--mode", "replay",
        "--replay", str(EXAMPLE / "replay.json"), "--store", str(service.directory),
    ]) == 0
    listing = client.get("/v1/investigations", headers=headers()).json()
    assert listing["total"] == 1
    run_id = listing["items"][0]["run"]["id"]
    saved = client.get(f"/v1/investigations/{run_id}", headers=headers()).json()
    response = client.post(f"/v1/investigations/{run_id}/steps", headers=headers(), json={
        "step_id": uuid4().hex, "input_node_id": domain(saved)["id"],
        "method_id": "rapiddns.domain_to_ipv4", "expected_graph_revision": saved["run"]["graph_revision"],
    })
    assert response.status_code == 201, response.text
    assert response.json()["step"]["delta"]["new_edges"] == 2


def test_provider_failure_is_a_saved_step_not_an_http_failure(api, tmp_path):
    client, _ = api
    import json
    manifest = tmp_path / "challenge.json"
    manifest.write_text(json.dumps({"version": 1, "documents": [{
        "source": "rapiddns", "request_url": "https://rapiddns.io/subdomain/example.com?page=1",
        "operation": "dns", "error_status": "challenge", "error": "Synthetic provider challenge",
    }]}))
    client.app.state.investigation_service = InvestigationService(tmp_path / "challenge-store", replay_path=manifest)
    saved = create(client).json()
    run_id = saved["run"]["id"]
    response = client.post(f"/v1/investigations/{run_id}/steps", headers=headers(), json={
        "step_id": uuid4().hex, "input_node_id": domain(saved)["id"],
        "method_id": "rapiddns.domain_to_ipv4", "expected_graph_revision": saved["run"]["graph_revision"],
    })
    assert response.status_code == 201, response.text
    result = response.json()
    assert result["step"]["status"] == "completed"
    assert result["step"]["outcome_status"] == "challenge"
    assert not result["step"]["admission"]["accepted"]
    assert result["step"]["lookup"]["id"] == result["step"]["lookup_id"]
    assert result["run"]["status"] == "ready"


def test_each_saved_run_keeps_its_own_replay_manifest(api, tmp_path):
    import json
    client, service = api
    contents = json.loads((EXAMPLE / "replay.json").read_text())
    contents["description"] = "Independent synthetic investigation fixture"
    for document in contents["documents"]:
        if "body_file" in document:
            document["body"] = (EXAMPLE / document.pop("body_file")).read_text()
    other_manifest = tmp_path / "other-replay.json"
    other_manifest.write_text(json.dumps(contents))
    other_service = InvestigationService(service.directory, replay_path=other_manifest)
    saved, _ = other_service.create("alice", {"text": REPORT}, "other-fixture")
    run_id, node_id = saved["run"]["id"], domain(saved)["id"]
    # This HTTP service is configured for the original example, but reopens the
    # saved investigation with its own distinct valid manifest.
    methods = client.get(f"/v1/investigations/{run_id}/nodes/{node_id}/methods", headers=headers())
    assert methods.status_code == 200
    assert methods.json()["execution_allowed"]
    response = client.post(f"/v1/investigations/{run_id}/steps", headers=headers(), json={
        "step_id": uuid4().hex, "input_node_id": node_id,
        "method_id": "rapiddns.domain_to_ipv4", "expected_graph_revision": 1,
    })
    assert response.status_code == 201, response.text
    assert response.json()["step"]["delta"]["new_edges"] == 2
