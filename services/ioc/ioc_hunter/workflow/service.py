"""One saved investigation engine for the terminal and HTTP adapters.

There are no users: every investigation belongs to one built-in owner (OWNER). The database keeps its owner
tables unchanged, so existing stores keep working and a later multi-user decision needs no migration.
"""

import json
from dataclasses import asdict
from hashlib import sha256
from uuid import uuid4

from ..config import resolve_store_directory
from ..evidence import utc_now
from ..lookup import LookupClient
from ..methods import get_method, list_runnable_methods, method_status
from ..storage import EvidenceStore
from .coordination import ExecutionCoordinator
from .errors import WorkflowServiceError
from .models import RunConfig
from .replay import ReplayTransport
from .repository import WorkflowRepository
from .runner import TERMINAL_STATUSES, WorkflowRunner

OWNER = "local"


class InvestigationService:
    def __init__(self, directory=None, *, client_factory=None, replay_path=None):
        self.directory = resolve_store_directory(directory)
        self.store = EvidenceStore(self.directory)
        self.repository = WorkflowRepository(self.store)
        self.coordinator = ExecutionCoordinator(self.directory)
        self.client_factory = client_factory
        self.replay_path = replay_path

    @staticmethod
    def _error(code, message, status=409, **context):
        raise WorkflowServiceError(code, message, status, **context)

    def _load(self, run_id):
        try:
            return self.repository.get_run(run_id)
        except KeyError:
            self._error("not_found", "Investigation not found.", 404, run_id=run_id)

    def _runner(self, run=None, config=None):
        try:
            config = (
                RunConfig(**run["config"])
                if run
                else config or RunConfig(mode="replay" if self.replay_path else "live")
            )
            # A saved run keeps its own fixture identity, even when this service
            # is configured with another fixture for creating new replay runs.
            manifest = run.get("replay", {}).get("manifest") if run else self.replay_path
            if self.client_factory:
                client = self.client_factory(self.store, config, manifest)
            elif config.mode == "replay":
                if not manifest:
                    raise ValueError("Original replay manifest is unavailable")
                replay = ReplayTransport(manifest)
                client = LookupClient(
                    store=self.store,
                    http=replay,
                    browser=replay,
                    api_keys={},
                    interval=0,
                    max_pages=config.max_pages,
                    max_outputs=config.max_outputs,
                )
            else:
                client = LookupClient(store=self.store, max_pages=config.max_pages, max_outputs=config.max_outputs)
            runner = WorkflowRunner(client, config)
            if run:
                runner._check_mode(run)
            return runner
        except (ValueError, OSError, ImportError) as exc:
            self._error("saved_configuration_unavailable", str(exc))

    def _snapshot(self, run_id):
        native = self.repository.snapshot(run_id)
        run = {key: value for key, value in native["run"].items() if key not in {"report", "extraction", "replay"}}
        return {
            "version": 1,
            "run": run,
            "report": native["report"],
            "extraction": native["extraction"],
            "graph": native["graph"],
            "steps": [
                {key: value for key, value in step.items() if key not in {"lookup", "run_id"}}
                for step in native["steps"]
            ],
        }

    @staticmethod
    def _request(request, mode):
        if not isinstance(request, dict) or set(request) - {
            "text",
            "source",
            "include_references",
            "extended_types",
            "limits",
        }:
            raise WorkflowServiceError("invalid_request", "Unknown investigation request fields.", 422)
        text, source = request.get("text"), request.get("source", "cti report")
        if not isinstance(text, str) or not text.strip() or len(text) > 2_000_000:
            raise WorkflowServiceError(
                "invalid_request", "Report must be nonblank text of at most 2,000,000 characters.", 422
            )
        if not isinstance(source, str) or len(source) > 2000:
            raise WorkflowServiceError(
                "invalid_request", "Report source must be text of at most 2,000 characters.", 422
            )
        options = {name: request.get(name, False) for name in ("include_references", "extended_types")}
        if any(type(value) is not bool for value in options.values()):
            raise WorkflowServiceError("invalid_request", "Extraction switches must be booleans.", 422)
        limits = request.get("limits", {})
        if not isinstance(limits, dict) or set(limits) - {
            "max_steps",
            "max_nodes",
            "max_seconds",
            "max_pages",
            "max_outputs",
        }:
            raise WorkflowServiceError("invalid_request", "Unknown investigation limits.", 422)
        try:
            config = RunConfig(mode=mode, **limits)
            config = RunConfig(**{**asdict(config), "max_seconds": float(config.max_seconds)})
        except (ValueError, TypeError) as exc:
            raise WorkflowServiceError("invalid_request", str(exc), 422) from exc
        normalized = {"text": text, "source": source, **options, "config": asdict(config)}
        digest = sha256(
            json.dumps(normalized, sort_keys=True, ensure_ascii=False, allow_nan=False).encode()
        ).hexdigest()
        return normalized, config, digest

    def create(self, request, key):
        if not isinstance(key, str) or not key.strip() or len(key) > 1000:
            self._error("invalid_request", "A nonempty creation request key is required.", 422)
        normalized, config, digest = self._request(request, "replay" if self.replay_path else "live")
        resource = "create:" + sha256(json.dumps([OWNER, key]).encode()).hexdigest()
        with self.coordinator.claim(resource, code="creation_in_progress"):
            previous = self.repository.creation(OWNER, key)
            if previous:
                if previous["digest"] != digest:
                    self._error("idempotency_conflict", "Creation key belongs to different report/options.")
                return self.read(previous["run_id"]), True
            run_id = uuid4().hex
            with self.coordinator.claim("run:" + run_id):
                runner = self._runner(config=config)
                runner.create_run(
                    normalized["text"],
                    normalized["source"],
                    include_references=normalized["include_references"],
                    extended_types=normalized["extended_types"],
                    run_id=run_id,
                    owner_id=OWNER,
                    creation_key=key,
                    payload_digest=digest,
                )
            return self._snapshot(run_id), False

    def read(self, run_id):
        self._load(run_id)
        return self._snapshot(run_id)

    def list(self, limit=50, offset=0, status=None):
        if type(limit) is not int or not 1 <= limit <= 200 or type(offset) is not int or offset < 0:
            self._error("invalid_request", "Invalid pagination.", 422)
        if status is not None and status not in TERMINAL_STATUSES | {"extracting", "ready", "running"}:
            self._error("invalid_request", "Invalid investigation status.", 422)
        runs = self.repository.list_runs()
        if status:
            runs = [run for run in runs if run["status"] == status]
        runs.sort(key=lambda run: run["id"])
        runs.sort(key=lambda run: run["updated_at"], reverse=True)
        items = []
        for run in runs[offset : offset + limit]:
            snapshot = self._snapshot(run["id"])
            items.append(
                {
                    "run": snapshot["run"],
                    "report": {key: snapshot["report"][key] for key in ("id", "source", "sha256")},
                    "counts": {
                        "nodes": len(snapshot["graph"]["nodes"]),
                        "edges": len(snapshot["graph"]["edges"]),
                        "steps": len(snapshot["steps"]),
                    },
                }
            )
        return {"items": items, "limit": limit, "offset": offset, "total": len(runs)}

    def _node(self, run_id, node_id):
        node = next((node for node in self.repository.nodes(run_id) if node["id"] == node_id), None)
        if node is None:
            self._error("not_found", "Investigation node not found.", 404)
        return node

    def methods(self, run_id, node_id):
        run = self._load(run_id)
        node = self._node(run_id, node_id)
        missing = False
        try:
            rows = self._runner(run).list_methods(run_id, node_id)
        except WorkflowServiceError:
            missing = True
            rows = [
                {
                    **asdict(method),
                    "implemented": True,
                    "description": method.description,
                    "availability": method_status(method),
                    "selectable": False,
                    "unavailable_reason": "saved_configuration_unavailable",
                }
                for method in list_runnable_methods(node["type"])
            ]
        steps = self.repository.steps(run_id)
        config = run["config"]
        reason = ""
        if run["status"] in TERMINAL_STATUSES:
            reason = "run_closed"
        elif run["status"] == "extracting":
            reason = "extraction_in_progress"
        elif self.coordinator.busy("run:" + run_id):
            reason = "operation_in_progress"
        elif missing:
            reason = "saved_configuration_unavailable"
        elif any(step["status"] != "completed" for step in steps):
            reason = "recovery_required"
        elif len(steps) >= config["max_steps"]:
            reason = "step_limit"
        elif run["elapsed_seconds"] >= config["max_seconds"]:
            reason = "time_limit"
        return {
            "run_id": run_id,
            "node_id": node_id,
            "execution_allowed": not bool(reason),
            "execution_block_reason": reason,
            "methods": rows,
        }

    def _previous(self, run_id, step_id, node_id, method_id):
        try:
            step = self.repository.get_step(step_id, run_id)
        except KeyError:
            return None
        if (step["input_node_id"], step["method_id"]) != (node_id, method_id):
            self._error("idempotency_conflict", "Step key belongs to a different selection.")
        return step

    def _execution(self, run_id, step, replayed):
        snapshot = self._snapshot(run_id)
        return {"step": step, "run": snapshot["run"], "graph": snapshot["graph"], "replayed": replayed}

    def execute(self, run_id, node_id, method_id, step_id, expected_revision):
        self._load(run_id)
        if not isinstance(step_id, str) or not step_id.strip():
            self._error("invalid_request", "A nonempty step request ID is required.", 422)
        if type(expected_revision) is not int or expected_revision < 0:
            self._error("invalid_request", "Expected graph revision must be a nonnegative integer.", 422)
        previous = self._previous(run_id, step_id, node_id, method_id)
        if previous and previous["status"] == "completed":
            return self._execution(run_id, previous, True)
        with self.coordinator.claim("run:" + run_id, code="step_in_progress"):
            run = self._load(run_id)
            previous = self._previous(run_id, step_id, node_id, method_id)
            if previous and previous["status"] == "completed":
                return self._execution(run_id, previous, True)
            if run["status"] in TERMINAL_STATUSES:
                self._error("run_closed", "This investigation is closed.")
            if run["status"] == "extracting" or any(
                step["status"] != "completed" for step in self.repository.steps(run_id)
            ):
                self._error("recovery_required", "Recover the interrupted operation before starting another step.")
            if run["graph_revision"] != expected_revision:
                self._error(
                    "stale_graph_revision",
                    "Reload the investigation before another lookup.",
                    details={
                        "expected_graph_revision": expected_revision,
                        "current_graph_revision": run["graph_revision"],
                    },
                )
            node = self._node(run_id, node_id)
            try:
                method = get_method(method_id)
            except ValueError as exc:
                self._error("invalid_request", str(exc), 422)
            if method.input_type != node["type"] or not method.implemented:
                self._error("invalid_request", "Choose an implemented method compatible with this node.", 422)
            runner = self._runner(run)
            row = next(row for row in runner.list_methods(run_id, node_id) if row["id"] == method_id)
            if not row["selectable"]:
                self._error("method_unavailable", row["unavailable_reason"])
            config = RunConfig(**run["config"])
            if len(self.repository.steps(run_id)) >= config.max_steps or run["elapsed_seconds"] >= config.max_seconds:
                run["status"] = "completed"
                run["stop_reason"] = (
                    "step_limit" if len(self.repository.steps(run_id)) >= config.max_steps else "time_limit"
                )
                run["updated_at"] = utc_now()
                self.repository.save_run(run)
                self._error("limit_reached", "Investigation stopped: " + run["stop_reason"])
            try:
                step = runner.execute_step(run_id, node_id, method_id, step_id=step_id)
            except (ValueError, KeyError) as exc:
                self._error("internal_error", "Saved lookup could not be committed: " + str(exc), 500)
            return self._execution(run_id, step, False)

    def step(self, run_id, step_id, include_snapshots=False):
        self._load(run_id)
        native = self.repository.snapshot(run_id, include_evidence=include_snapshots)
        step = next((step for step in native["steps"] if step["id"] == step_id), None)
        if step is None:
            self._error("not_found", "Investigation step not found.", 404)
        keys = {response["snapshot_id"] for response in (step.get("lookup") or {}).get("responses", [])}
        snapshots = {
            key: value for key, value in native.get("evidence", {}).get("snapshots", {}).items() if key in keys
        }
        return {"step": step, "snapshots": snapshots}

    def resume(self, run_id):
        self._load(run_id)
        with self.coordinator.claim("run:" + run_id):
            run = self._load(run_id)
            if run["status"] not in TERMINAL_STATUSES:
                try:
                    self._runner(run).resume(run_id)
                except (ValueError, KeyError) as exc:
                    self._error("internal_error", "Saved investigation could not be recovered: " + str(exc), 500)
            return self._snapshot(run_id)

    def close(self, run_id, action):
        if action not in {"finish", "cancel"}:
            self._error("invalid_request", "Close action must be finish or cancel.", 422)
        self._load(run_id)
        with self.coordinator.claim("run:" + run_id):
            run = self._load(run_id)
            target = "completed" if action == "finish" else "cancelled"
            if run["status"] in TERMINAL_STATUSES:
                if run["status"] != target:
                    self._error("run_closed", "This investigation has another terminal outcome.")
                return self._snapshot(run_id)
            if run["status"] == "extracting" or any(
                step["status"] != "completed" for step in self.repository.steps(run_id)
            ):
                self._error("recovery_required", "Recover interrupted work before closing.")
            run.update(
                status=target,
                stop_reason="user_finished" if action == "finish" else "user_cancelled",
                updated_at=utc_now(),
            )
            self.repository.save_run(run)
            return self._snapshot(run_id)

    def export(self, run_id, include_evidence=True):
        self._load(run_id)
        return self.repository.snapshot(run_id, include_evidence=include_evidence)
