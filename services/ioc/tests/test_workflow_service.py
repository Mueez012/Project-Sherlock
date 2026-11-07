"""Offline cross-interface engine invariants; no provider acquisition is live."""
from concurrent.futures import ThreadPoolExecutor
import json
from pathlib import Path
import subprocess
import sys
from threading import Barrier, Event
from unittest.mock import patch

import pytest

from ioc_hunter.lookup import LookupClient
from ioc_hunter.storage import EvidenceStore
from ioc_hunter.transport import LookupError, RateLimiter
from ioc_hunter.workflow.coordination import ExecutionCoordinator
from ioc_hunter.workflow.errors import WorkflowServiceError
from ioc_hunter.workflow.replay import ReplayTransport
from ioc_hunter.workflow.repository import WorkflowRepository, WorkflowConflict
from ioc_hunter.workflow.runner import build_runner
from ioc_hunter.workflow.service import InvestigationService


EXAMPLE = Path(__file__).resolve().parents[1] / "examples" / "manual-workflow"
REPORT = (EXAMPLE / "report.txt").read_text()
METHOD = "rapiddns.domain_to_ipv4"


@pytest.fixture
def service(tmp_path):
    return InvestigationService(tmp_path / "store", replay_path=EXAMPLE / "replay.json")


def create(service, actor="alice", key="create", **options):
    return service.create(actor, {"text": REPORT, **options}, key)[0]


def domain(snapshot):
    return next(node["id"] for node in snapshot["graph"]["nodes"] if node["value"] == "example.com")


def failure(code, action):
    with pytest.raises(WorkflowServiceError) as captured:
        action()
    assert captured.value.code == code
    return captured.value


def test_creation_identity_owner_filter_and_independent_results(service):
    first = create(service)
    again, replayed = service.create("alice", {"text": REPORT, "source": "cti report", "limits": {"max_seconds": 600.0}}, "create")
    assert replayed and again == first
    failure("idempotency_conflict", lambda: service.create("alice", {"text": "Other report"}, "create"))
    other = create(service, "bob")
    assert other["run"]["id"] != first["run"]["id"]
    assert service.list("alice")["total"] == service.list("bob")["total"] == 1
    assert service.list("alice")["items"][0]["run"]["id"] == first["run"]["id"]
    assert failure("not_found", lambda: service.read("bob", first["run"]["id"])).status == 404
    failure("not_found", lambda: service.export("bob", first["run"]["id"]))


def test_scoped_step_identity_replay_after_close_and_native_export(service):
    a, b = create(service), create(service, "bob")
    results = []
    for actor, snapshot in (("alice", a), ("bob", b)):
        run_id = snapshot["run"]["id"]
        execution = service.execute(actor, run_id, domain(snapshot), METHOD, "same-client-key", 1)
        assert execution["step"]["id"] == "same-client-key"
        assert execution["step"]["lookup"]["id"] == execution["step"]["lookup_id"]
        assert execution["step"]["delta"] == {"new_nodes": 1, "new_edges": 2, "evidence_links": 3}
        results.append(execution)
        service.close(actor, run_id, "finish")
        repeated = service.execute(actor, run_id, domain(snapshot), METHOD, "same-client-key", 0)
        assert repeated["replayed"] and repeated["step"] == execution["step"]
        assert service.close(actor, run_id, "finish")["run"]["status"] == "completed"
        failure("run_closed", lambda: service.close(actor, run_id, "cancel"))
        exported = service.export(actor, run_id)
        assert exported == build_runner(service.directory).get_result(run_id, include_evidence=True)
        detail = service.step(actor, run_id, "same-client-key", True)
        assert detail["snapshots"] and detail["step"] == execution["step"]
    assert results[0]["step"]["lookup_id"] != results[1]["step"]["lookup_id"]
    with pytest.raises(WorkflowConflict, match="ambiguous"):
        service.repository.get_step("same-client-key")


def test_preflight_does_not_mutate_selection_and_receipts_are_retained(service):
    snapshot = create(service)
    run_id, node_id = snapshot["run"]["id"], domain(snapshot)
    failure("stale_graph_revision", lambda: service.execute("alice", run_id, node_id, METHOD, "stale", 0))
    assert not service.read("alice", run_id)["steps"]
    failure("not_found", lambda: service.methods("alice", run_id, "foreign-node"))
    hashed = next(node for node in snapshot["graph"]["nodes"] if node["type"] == "sha256")
    assert service.methods("alice", run_id, hashed["id"])["methods"] == []
    execution = service.execute("alice", run_id, node_id, METHOD, "step", 1)
    assert execution["step"]["admission"]["reward"] is None
    assert execution["step"]["lookup"]["rejected"][0]["reason"] == "dns_domain_mismatch"
    failure("idempotency_conflict", lambda: service.execute("alice", run_id, hashed["id"], METHOD, "step", 2))
    failure("not_found", lambda: service.step("bob", run_id, "step", True))


def test_limits_explicit_recovery_and_read_never_recovers(service):
    snapshot = create(service)
    run_id = snapshot["run"]["id"]
    runner = service._runner(service.repository.get_run(run_id))
    with patch.object(runner.client, "lookup_detailed", side_effect=KeyboardInterrupt):
        with pytest.raises(KeyboardInterrupt):
            runner.execute_step(run_id, domain(snapshot), METHOD, step_id="orphan")
    assert service.read("alice", run_id)["steps"][0]["status"] == "running"
    failure("recovery_required", lambda: service.close("alice", run_id, "finish"))
    recovered = service.resume("alice", run_id)
    assert recovered["steps"][0]["outcome_status"] == "interrupted_unknown"
    assert recovered["graph"]["edges"] == []
    run = service.repository.get_run(run_id)
    run["elapsed_seconds"] = run["config"]["max_seconds"]
    service.repository.save_run(run)
    failure("limit_reached", lambda: service.execute("alice", run_id, domain(snapshot), METHOD, "budget", run["graph_revision"]))
    assert service.read("alice", run_id)["run"]["stop_reason"] == "time_limit"
    assert len(service.read("alice", run_id)["steps"]) == 1


def test_saved_receipt_recovery_and_saved_replay_reads_without_fixtures(service):
    snapshot = create(service)
    run_id = snapshot["run"]["id"]
    runner = service._runner(service.repository.get_run(run_id))
    with patch.object(runner.repository, "commit_step", side_effect=KeyboardInterrupt):
        with pytest.raises(KeyboardInterrupt):
            runner.execute_step(run_id, domain(snapshot), METHOD, step_id="saved-receipt")
    recovered = service.resume("alice", run_id)
    assert len(recovered["graph"]["edges"]) == 2
    run = service.repository.get_run(run_id)
    run["replay"]["manifest"] = str(service.directory / "missing.json")
    service.repository.save_run(run)
    reopened = InvestigationService(service.directory)
    assert reopened.read("alice", run_id)["steps"]
    assert reopened.export("alice", run_id)["evidence"]["snapshots"]
    methods = reopened.methods("alice", run_id, domain(snapshot))
    assert methods["execution_block_reason"] == "saved_configuration_unavailable"
    assert all(not row["selectable"] for row in methods["methods"])


def test_different_runs_acquire_concurrently_but_same_run_cannot_recover(tmp_path):
    release, entered = Event(), Event()
    barrier = Barrier(2, action=entered.set)
    class BlockingReplay(ReplayTransport):
        def fetch(self, request):
            barrier.wait(timeout=15)
            assert release.wait(timeout=15)
            return super().fetch(request)
    store = EvidenceStore(tmp_path / "parallel")
    replay = BlockingReplay(EXAMPLE / "replay.json")
    client = LookupClient(store=store, http=replay, browser=replay, interval=0, cache_ttl=0)
    service = InvestigationService(store.directory, replay_path=EXAMPLE / "replay.json",
                                   client_factory=lambda *_: client)
    a, b = create(service, limits={"max_outputs": 1}), create(service, "bob", limits={"max_outputs": 2})
    with ThreadPoolExecutor(max_workers=2) as pool:
        future_a = pool.submit(service.execute, "alice", a["run"]["id"], domain(a), METHOD, "step", 1)
        future_b = pool.submit(service.execute, "bob", b["run"]["id"], domain(b), METHOD, "step", 1)
        assert entered.wait(10)
        try:
            failure("operation_in_progress", lambda: service.resume("alice", a["run"]["id"]))
            failure("operation_in_progress", lambda: service.close("alice", a["run"]["id"], "finish"))
            failure("step_in_progress", lambda: service.execute("alice", a["run"]["id"], domain(a), METHOD, "step", 1))
            assert service.read("alice", a["run"]["id"])["run"]["status"] == "running"
        finally:
            release.set()
        result_a, result_b = future_a.result(20), future_b.result(20)
    assert len(result_a["step"]["lookup"]["outputs"]) == 1
    assert len(result_b["step"]["lookup"]["outputs"]) == 2
    assert client.max_outputs == 1000


def test_os_execution_lock_blocks_another_process_and_releases(tmp_path):
    coordinator = ExecutionCoordinator(tmp_path)
    script = (
        "from pathlib import Path\n"
        "from ioc_hunter.workflow.coordination import ExecutionCoordinator\n"
        "from ioc_hunter.workflow.errors import WorkflowServiceError\n"
        "import sys\n"
        "try:\n"
        " with ExecutionCoordinator(Path(sys.argv[1])).claim('run:shared'): pass\n"
        "except WorkflowServiceError: sys.exit(7)\n"
    )
    with coordinator.claim("run:shared"):
        blocked = subprocess.run([sys.executable, "-c", script, str(tmp_path)], timeout=15)
    assert blocked.returncode == 7
    assert subprocess.run([sys.executable, "-c", script, str(tmp_path)], timeout=15).returncode == 0


def test_schema_one_migration_preserves_steps_and_legacy_owner(tmp_path):
    store = EvidenceStore(tmp_path)
    with store.connect() as db:
        db.executescript("CREATE TABLE wf_schema(id INTEGER PRIMARY KEY,version INTEGER);"
                         "INSERT INTO wf_schema VALUES(1,1);"
                         "CREATE TABLE wf_runs(id TEXT PRIMARY KEY,record TEXT);"
                         "CREATE TABLE wf_steps(id TEXT PRIMARY KEY,run_id TEXT,sequence INTEGER,record TEXT);")
        db.execute("INSERT INTO wf_runs VALUES(?,?)", ("legacy", json.dumps({"id": "legacy"})))
        db.execute("INSERT INTO wf_steps VALUES(?,?,?,?)", ("old-step", "legacy", 1, json.dumps({"id": "old-step", "run_id": "legacy"})))
    repository = WorkflowRepository(store)
    assert repository.get_step("old-step", "legacy")["id"] == "old-step"
    assert repository.owner("legacy") == "local"
    assert repository.owned_runs("local") == [{"id": "legacy"}]
    assert not repository.owned_runs("someone-else")
    with store.connect() as db:
        assert db.execute("SELECT version FROM wf_schema").fetchone()[0] == 2


def test_provider_pacing_shared_across_clients_without_a_lookup_mutex(tmp_path):
    store = EvidenceStore(tmp_path)
    first, second = RateLimiter(3, store=store), RateLimiter(3, store=store)
    sleeps = []
    with patch("ioc_hunter.transport.limits.time.time", return_value=100), \
            patch("ioc_hunter.transport.limits.time.sleep", side_effect=sleeps.append):
        first.wait("rapiddns")
        second.wait("rapiddns")
        second.wait("alienvault")
    assert sleeps == [3]
    with store.connect() as db:
        assert db.execute("SELECT next_at FROM provider_pacing WHERE source='rapiddns'").fetchone()[0] == 106


def test_new_provider_cooldown_invalidates_an_already_reserved_slot(tmp_path):
    store = EvidenceStore(tmp_path)
    first, second = RateLimiter(3, store=store), RateLimiter(3, store=store)
    with patch("ioc_hunter.transport.limits.time.time", return_value=100):
        first.wait("rapiddns")
        with patch("ioc_hunter.transport.limits.time.sleep", side_effect=lambda _: first.cooldown("rapiddns", 60)):
            with pytest.raises(LookupError) as captured:
                second.wait("rapiddns")
    assert captured.value.status == "rate_limited"

