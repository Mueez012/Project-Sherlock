"""Real extraction/lookup/validation/persistence with explicit offline transports."""

import json
from pathlib import Path
import socket
from unittest.mock import patch

import pytest

from ioc_hunter.transport import FetchRequest, LookupError
from ioc_hunter.workflow.models import RunConfig
from ioc_hunter.workflow.policies import PaperAdmissionPolicy
from ioc_hunter.workflow.replay import ReplayTransport
from ioc_hunter.workflow.runner import build_runner


EXAMPLE = Path(__file__).resolve().parents[1] / "examples" / "manual-workflow"
METHOD = "rapiddns.domain_to_ipv4"
REPORT = (EXAMPLE / "report.txt").read_text()


@pytest.fixture
def runner(tmp_path):
    return build_runner(tmp_path / "store", RunConfig(mode="replay"), EXAMPLE / "replay.json")


def seed(run_result, value="example.com"):
    return next(node for node in run_result["graph"]["nodes"] if node["value"] == value)


def test_real_report_to_graph_reopens_exports_and_step_retry_is_idempotent(runner, tmp_path):
    with patch.object(socket.socket, "connect", side_effect=AssertionError("Replay attempted network")):
        run = runner.create_run(REPORT, source="synthetic report")
        before = runner.get_result(run["id"])
        assert len(before["graph"]["nodes"]) == 3
        assert not before["graph"]["edges"]
        domain = seed(before)
        assert domain["passage_ids"]
        assert domain["context"] == ["The loader contacted example.com for its configuration."]
        assert before["extraction"]["excluded_sections"][0]["heading"] == "References"
        step = runner.execute_step(run["id"], domain["id"], METHOD, step_id="explicit-step")
        assert step["admission"]["accepted"]
        assert step["admission"]["reward"] is None
        assert step["delta"] == {"new_nodes": 1, "new_edges": 2, "evidence_links": 3}
        assert step["lookup"]["id"] == step["lookup_id"]
        assert step["lookup"]["rejected"][0]["reason"] == "dns_domain_mismatch"
        assert step["lookup"]["rejected"][0]["details"]["observed_domain"] == "sub.example.com"
        after = runner.get_result(run["id"])
        assert len(after["graph"]["nodes"]) == 4
        assert len(after["graph"]["edges"]) == 2
        assert seed(after)["used"]
        assert seed(after, "192.0.2.10")["origin"] == "report"
        assert seed(after, "192.0.2.12")["origin"] == "lookup"
        assert not any(node["value"] == "192.0.2.11" for node in after["graph"]["nodes"])
        count = len(runner.client.http.requests)
        assert runner.execute_step(run["id"], domain["id"], METHOD, step_id="explicit-step") == step
        assert len(runner.client.http.requests) == count
        reopened = build_runner(runner.client.store.directory, run_id=run["id"])
        assert reopened.resume(run["id"])["graph_revision"] == after["run"]["graph_revision"]
        assert reopened.get_result(run["id"])["graph"] == after["graph"]
        exported = reopened.export_result(run["id"], tmp_path / "export.json")
        assert json.loads((tmp_path / "export.json").read_text(encoding="utf-8")) == exported
        assert exported["mode"] == "replay"
        assert exported["evidence"]["lookups"][0]["id"] == step["lookup_id"]
        snapshots = exported["evidence"]["snapshots"]
        assert snapshots
        assert any("sub.example.com" in document["body"] for document in snapshots.values())


def test_new_only_validated_outputs_are_retained_but_not_admitted(runner):
    run = runner.create_run("The loader contacted example.com.")
    domain = seed(runner.get_result(run["id"]))
    step = runner.execute_step(run["id"], domain["id"], METHOD)
    assert len(step["lookup"]["outputs"]) == 2
    assert not step["admission"]["accepted"]
    assert step["admission"]["reason"] == "no_known_unused_overlap"
    assert step["delta"]["new_nodes"] == step["delta"]["new_edges"] == 0
    assert len(runner.get_result(run["id"])["graph"]["nodes"]) == 1


def test_used_candidate_no_longer_satisfies_overlap_and_discovered_ioc_is_selectable(runner):
    run = runner.create_run(REPORT)
    domain = seed(runner.get_result(run["id"]))
    runner.execute_step(run["id"], domain["id"], METHOD)
    discovered = seed(runner.get_result(run["id"]), "192.0.2.12")
    step = runner.execute_step(run["id"], discovered["id"], "rapiddns.ipv4_to_domain")
    assert step["lookup"]["outputs"][0]["value"] == "example.com"
    assert not step["admission"]["accepted"]  # example.com is already used.
    assert step["delta"]["new_edges"] == 0


def test_repeated_discoveries_merge_evidence_and_never_duplicate_graph(runner):
    run = runner.create_run(REPORT)
    domain = seed(runner.get_result(run["id"]))
    first = runner.execute_step(run["id"], domain["id"], METHOD)
    second = runner.execute_step(run["id"], domain["id"], METHOD)
    assert first["lookup_id"] != second["lookup_id"]
    assert second["admission"]["accepted"]
    assert second["delta"] == {"new_nodes": 0, "new_edges": 0, "evidence_links": 0}
    graph = runner.get_result(run["id"])["graph"]
    assert len(graph["edges"]) == 2
    assert all(len(edge["lookup_ids"]) == 2 for edge in graph["edges"])


def test_unsupported_hash_stays_visible_and_cannot_start_lookup(runner):
    run = runner.create_run(REPORT)
    hash_node = next(node for node in runner.get_result(run["id"])["graph"]["nodes"] if node["type"] == "sha256")
    assert runner.list_methods(run["id"], hash_node["id"]) == []
    with pytest.raises(ValueError, match="compatible"):
        runner.execute_step(run["id"], hash_node["id"], METHOD)
    assert not runner.repository.steps(run["id"])


def test_saved_receipt_is_recovered_after_graph_commit_interruption_without_refetch(runner):
    run = runner.create_run(REPORT)
    domain = seed(runner.get_result(run["id"]))
    with patch.object(runner.repository, "commit_step", side_effect=KeyboardInterrupt):
        with pytest.raises(KeyboardInterrupt):
            runner.execute_step(run["id"], domain["id"], METHOD)
    step = runner.repository.steps(run["id"])[0]
    assert step["status"] == "running"
    assert runner.client.store.get_record(step["lookup_id"])["outputs"]
    assert not runner.repository.edges(run["id"])
    with patch.object(runner.client, "lookup_detailed", side_effect=AssertionError("Unexpected refetch")):
        runner.resume(run["id"])
    assert len(runner.repository.edges(run["id"])) == 2
    assert runner.repository.steps(run["id"])[0]["status"] == "completed"
    revision = runner.repository.get_run(run["id"])["graph_revision"]
    runner.resume(run["id"])
    assert runner.repository.get_run(run["id"])["graph_revision"] == revision


def test_interrupted_acquisition_is_explicit_and_never_automatically_retried(runner):
    run = runner.create_run(REPORT)
    domain = seed(runner.get_result(run["id"]))
    with patch.object(runner.client, "lookup_detailed", side_effect=KeyboardInterrupt):
        with pytest.raises(KeyboardInterrupt):
            runner.execute_step(run["id"], domain["id"], METHOD)
    with patch.object(runner.client, "lookup_detailed", side_effect=AssertionError("Unexpected retry")):
        runner.resume(run["id"])
    step = runner.repository.steps(run["id"])[0]
    assert step["outcome_status"] == "interrupted_unknown"
    assert not step["admission"]["accepted"]
    assert runner.repository.get_run(run["id"])["status"] == "ready"


def test_real_lookup_interruption_saves_receipt_and_resumes_as_unknown(runner):
    run = runner.create_run(REPORT)
    domain = seed(runner.get_result(run["id"]))
    with patch.object(runner.client, "_run", side_effect=KeyboardInterrupt):
        with pytest.raises(KeyboardInterrupt):
            runner.execute_step(run["id"], domain["id"], METHOD)
    step = runner.repository.steps(run["id"])[0]
    record = runner.client.store.get_record(step["lookup_id"])
    assert record["status"] == "interrupted_unknown"
    assert not record["complete"]
    with patch.object(runner.client, "lookup_detailed", side_effect=AssertionError("Unexpected automatic retry")):
        runner.resume(run["id"])
    step = runner.repository.get_step(step["id"])
    assert step["outcome_status"] == "interrupted_unknown"
    assert step["error"]
    assert not runner.repository.edges(run["id"])


def test_budgets_step_limit_and_whole_batch_node_limit(tmp_path):
    limited = build_runner(tmp_path / "steps", RunConfig(mode="replay", max_steps=1), EXAMPLE / "replay.json")
    run = limited.create_run(REPORT)
    domain = seed(limited.get_result(run["id"]))
    limited.execute_step(run["id"], domain["id"], METHOD)
    assert limited.repository.get_run(run["id"])["stop_reason"] == "step_limit"
    with pytest.raises(ValueError, match="completed"):
        limited.execute_step(run["id"], domain["id"], METHOD)
    limited = build_runner(tmp_path / "nodes", RunConfig(mode="replay", max_nodes=3), EXAMPLE / "replay.json")
    run = limited.create_run(REPORT)
    step = limited.execute_step(run["id"], seed(limited.get_result(run["id"]))["id"], METHOD)
    assert step["admission"]["overlap_ids"]
    assert step["admission"]["reason"] == "node_limit"
    assert not limited.repository.edges(run["id"])


def test_mode_fixture_integrity_and_missing_requests_fail_closed(runner, tmp_path):
    run = runner.create_run(REPORT)
    live = build_runner(runner.client.store.directory)
    with pytest.raises(ValueError, match="mode"):
        live.resume(run["id"])
    manifest = tmp_path / "changed.json"
    manifest.write_text(json.dumps({"version": 1, "documents": []}))
    with pytest.raises(ValueError, match="changed"):
        build_runner(runner.client.store.directory, replay_path=manifest, run_id=run["id"])
    with patch.object(socket.socket, "connect", side_effect=AssertionError("Network attempted")):
        with pytest.raises(LookupError) as exc:
            runner.client.http.fetch(FetchRequest("rapiddns", "https://rapiddns.io/subdomain/missing.example?page=1", "dns"))
        assert exc.value.status == "replay_missing"


@pytest.mark.parametrize("case,expected_status,admitted", [
    ("partial", "partial", True), ("empty", "empty", False), ("error", "challenge", False),
])
def test_partial_empty_and_failed_steps_preserve_distinct_outcomes(tmp_path, case, expected_status, admitted):
    entry = {"source": "rapiddns", "request_url": "https://rapiddns.io/subdomain/example.com?page=1",
             "operation": "dns", "format": "html"}
    if case == "partial":
        entry["body"] = (EXAMPLE / "rapiddns.html").read_text() + "<p>Limited access</p>"
    elif case == "empty":
        entry["body"] = "<table><tr><th>Domain</th><th>Address</th><th>Type</th></tr></table>No entries found"
    else:
        entry["error_status"] = "challenge"
        entry["error"] = "Synthetic recorded challenge"
    manifest = tmp_path / "replay.json"
    manifest.write_text(json.dumps({"version": 1, "documents": [entry]}))
    runner = build_runner(tmp_path / "store", RunConfig(mode="replay"), manifest)
    run = runner.create_run(REPORT)
    domain = seed(runner.get_result(run["id"]))
    step = runner.execute_step(run["id"], domain["id"], METHOD)
    assert step["outcome_status"] == expected_status
    assert step["admission"]["accepted"] is admitted
    assert step["lookup"]["id"] == step["lookup_id"]
    assert runner.repository.get_run(run["id"])["status"] == "ready"
    if case == "partial":
        assert not step["lookup"]["complete"]
        assert len(runner.repository.edges(run["id"])) == 2
    elif case == "error":
        assert step["admission"]["reason"] == "lookup_failed"
        assert step["error"]
    else:
        assert step["lookup"]["outcome_reason"] == "no_matching_records"


def test_live_client_cannot_read_synthetic_replay_cache(runner):
    run = runner.create_run(REPORT)
    domain = seed(runner.get_result(run["id"]))
    runner.execute_step(run["id"], domain["id"], METHOD)
    with runner.client.store.connect() as db:
        keys = [row[0] for row in db.execute("SELECT key FROM cache")]
        assert db.execute("SELECT COUNT(*) FROM budgets").fetchone()[0] == 0
    assert keys
    from ioc_hunter.models import IOC
    from ioc_hunter.methods import get_method
    from ioc_hunter.providers import requests_for
    _, request = requests_for(IOC("example.com", "domain"), get_method(METHOD))[0]
    live_key = runner.client.store.cache_key(request, "http", "anonymous")
    assert live_key not in keys
    assert runner.client.store.cached(live_key) is None


def test_initial_node_limit_and_extraction_failure_are_saved(tmp_path):
    runner = build_runner(tmp_path / "store", RunConfig(mode="replay", max_nodes=1), EXAMPLE / "replay.json")
    run = runner.create_run(REPORT)
    assert run["status"] == "failed"
    assert run["stop_reason"] == "initial_node_limit"
    assert run["extraction"]["iocs"]  # No silent truncation of the original extraction.
    assert runner.get_result(run["id"])["graph"]["nodes"] == []
    with patch("ioc_hunter.workflow.runner.extract_report", side_effect=ValueError("Synthetic extraction failure")):
        run = runner.create_run(REPORT)
    assert run["status"] == "failed"
    assert runner.get_result(run["id"])["report"]["original_text"] == REPORT
    assert run["diagnostics"][0]["kind"] == "extraction_failed"


def test_replay_access_denial_is_an_error_even_if_body_contains_valid_records(tmp_path):
    entry = {"source": "rapiddns", "request_url": "https://rapiddns.io/subdomain/example.com?page=1",
             "operation": "dns", "format": "html", "status_code": 403,
             "body": (EXAMPLE / "rapiddns.html").read_text()}
    manifest = tmp_path / "replay.json"
    manifest.write_text(json.dumps({"version": 1, "documents": [entry]}))
    runner = build_runner(tmp_path / "store", RunConfig(mode="replay"), manifest)
    run = runner.create_run(REPORT)
    step = runner.execute_step(run["id"], seed(runner.get_result(run["id"]))["id"], METHOD)
    assert step["outcome_status"] == "access_denied"
    assert not step["admission"]["accepted"]
    assert not runner.repository.edges(run["id"])
    assert step["lookup"]["responses"]  # Error response snapshots remain auditable.


def test_paper_policy_matches_printed_gate_not_graph_cycles():
    policy = PaperAdmissionPolicy()
    assert policy.evaluate({"b", "c"}, {"a", "b"}, {"a"})["accepted"]
    assert not policy.evaluate({"c"}, {"a", "b"}, {"a"})["accepted"]
    assert not policy.evaluate({"a"}, {"a", "b"}, {"a"})["accepted"]
    assert not policy.evaluate({"b"}, {"a", "b"}, {"a", "b"})["accepted"]


@pytest.mark.parametrize("options", [{"max_steps": 0}, {"max_pages": -1}, {"max_outputs": True},
                                     {"max_seconds": float("nan")}, {"mode": "demo"}])
def test_invalid_limits_are_rejected(options):
    with pytest.raises(ValueError):
        RunConfig(**options)
