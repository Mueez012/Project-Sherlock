"""Cancellation of HTTP transport must not surrender a live lookup's claim."""
import asyncio
from pathlib import Path
from threading import Event, Lock
from uuid import uuid4

from fastapi import FastAPI
import httpx
import pytest

from ioc_hunter.api.dependencies import actor
from ioc_hunter.api.errors import install_error_handlers
from ioc_hunter.api.investigations import router
from ioc_hunter.lookup import LookupClient
from ioc_hunter.storage import EvidenceStore
from ioc_hunter.workflow.replay import ReplayTransport
from ioc_hunter.workflow.service import InvestigationService


EXAMPLE = Path(__file__).resolve().parents[1] / "examples" / "manual-workflow"
REPORT = (EXAMPLE / "report.txt").read_text(encoding="utf-8")


def test_cancelled_http_request_keeps_worker_claim_and_other_runs_continue(tmp_path):
    started, release, counter_guard = Event(), Event(), Lock()
    acquisitions = []

    class BlockingReplay(ReplayTransport):
        def fetch(self, request):
            with counter_guard:
                acquisitions.append(request.url)
                first = len(acquisitions) == 1
            if first:
                started.set()
                assert release.wait(timeout=20), "The test did not release its offline lookup"
            return super().fetch(request)

    store = EvidenceStore(tmp_path / "store")
    replay = BlockingReplay(EXAMPLE / "replay.json")
    lookup = LookupClient(store=store, http=replay, browser=replay, interval=0, cache_ttl=0)
    backend = InvestigationService(
        store.directory, replay_path=EXAMPLE / "replay.json", client_factory=lambda *_: lookup,
    )
    app = FastAPI()
    app.state.investigation_service = backend
    app.dependency_overrides[actor] = lambda: "alice"
    app.include_router(router)
    install_error_handlers(app)

    async def scenario():
        async with httpx.AsyncClient(transport=httpx.ASGITransport(app=app), base_url="http://test") as client:
            async def create():
                response = await client.post("/v1/investigations", headers={"Idempotency-Key": uuid4().hex},
                                             json={"text": REPORT, "limits": {"max_steps": 1}})
                assert response.status_code == 201, response.text
                return response.json()

            def step_request(snapshot):
                return {"step_id": uuid4().hex, "method_id": "rapiddns.domain_to_ipv4",
                        "input_node_id": next(node["id"] for node in snapshot["graph"]["nodes"]
                                              if node["value"] == "example.com"),
                        "expected_graph_revision": snapshot["run"]["graph_revision"]}

            a, b = await create(), await create()
            base = f"/v1/investigations/{a['run']['id']}"
            body = step_request(a)
            pending = asyncio.create_task(client.post(f"{base}/steps", json=body))
            try:
                assert await asyncio.to_thread(started.wait, 10)
                pending.cancel()
                with pytest.raises(asyncio.CancelledError):
                    await pending

                # Cancellation ended the HTTP coroutine, while the real worker
                # remains blocked inside provider acquisition and owns this run.
                for suffix, payload in (("resume", {}), ("close", {"action": "finish"})):
                    response = await client.post(f"{base}/{suffix}", json=payload)
                    assert response.status_code == 409, response.text
                    assert response.json()["error"]["code"] == "operation_in_progress"
                duplicate = await client.post(f"{base}/steps", json=body)
                assert duplicate.status_code == 409
                assert duplicate.json()["error"]["code"] == "step_in_progress"
                saved = await client.get(base)
                assert saved.status_code == 200
                assert saved.json()["run"]["status"] == "running"
                assert saved.json()["steps"][0]["status"] == "running"

                # An unrelated investigation can finish on the same service and
                # shared client before the first investigation is released.
                other = await asyncio.wait_for(client.post(
                    f"/v1/investigations/{b['run']['id']}/steps", json=step_request(b)), timeout=10)
                assert other.status_code == 201, other.text
                assert other.json()["run"]["status"] == "completed"
                assert not release.is_set()
                assert len(acquisitions) == 2
            finally:
                release.set()

            # Poll saved state only; neither GET nor a lost response initiates
            # recovery/acquisition. The original worker performs its one commit.
            async def finished():
                while True:
                    result = await client.get(base)
                    assert result.status_code == 200
                    if result.json()["run"]["status"] == "completed":
                        return result.json()
                    await asyncio.sleep(0.02)

            final = await asyncio.wait_for(finished(), timeout=10)
            assert len(final["steps"]) == 1
            assert final["steps"][0]["status"] == "completed"
            assert final["steps"][0]["outcome_status"] == "ok"
            assert len(final["graph"]["edges"]) == 2
            repeated = await client.post(f"{base}/steps", json=body)
            assert repeated.status_code == 200, repeated.text
            assert repeated.json()["replayed"]
            assert len(acquisitions) == 2

    asyncio.run(scenario())
