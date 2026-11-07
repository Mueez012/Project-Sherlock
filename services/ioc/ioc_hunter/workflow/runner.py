"""Reusable report -> selected lookup -> paper-admitted graph workflow.

The terminal is one caller. Ranking, LLM selection, coverage/tried counters,
SecureBERT and Hub orchestration are deliberately separate future integrations.
"""

from dataclasses import asdict
from datetime import datetime
from hashlib import sha256
import json
from pathlib import Path
import time
from uuid import uuid4

from ..evidence import LookupRecord, utc_now
from ..config import resolve_store_directory
from ..extraction import extract_report
from ..lookup import LookupClient
from ..methods import get_method, list_runnable_methods, method_status
from ..models import IOC, identity
from ..storage import EvidenceStore
from ..transport import LookupError
from ..validation import validate_edge
from .models import RunConfig, graph_edge, graph_node, node_id
from .policies import PaperAdmissionPolicy
from .replay import ReplayTransport
from .repository import WorkflowRepository


TERMINAL_STATUSES = {"completed", "cancelled", "failed"}
UNRESOLVED_LIVE_METHODS = {"virustotal.domain_to_url"}


class WorkflowRunner:
    def __init__(self, client: LookupClient, config: RunConfig | None = None, *, policy=None):
        self.client = client
        self.config = config or RunConfig()
        self.repository = WorkflowRepository(client.store)
        self.policy = policy or PaperAdmissionPolicy()
        replay = isinstance(client.http, ReplayTransport) and client.http is client.browser
        if (self.config.mode == "replay") != replay:
            raise ValueError("Replay mode requires fixture transports for both HTTP and browser")

    def create_run(self, text: str, source: str = "cti report", *, include_references=False,
                   extended_types=False, run_id=None, owner_id=None, creation_key=None,
                   payload_digest=None) -> dict:
        if not isinstance(text, str) or not text.strip():
            raise ValueError("Report must contain nonempty text")
        if len(text) > 2_000_000:
            raise ValueError("Report exceeds the 2,000,000-character limit")
        if not isinstance(source, str) or len(source) > 2000:
            raise ValueError("Report source must be text of at most 2,000 characters")
        run_id, report_id = run_id or uuid4().hex, uuid4().hex
        now = utc_now()
        run = {
            "id": run_id, "status": "extracting", "mode": self.config.mode,
            "policy": self.policy.name, "config": asdict(self.config), "graph_revision": 0,
            "created_at": now, "updated_at": now, "elapsed_seconds": 0.0,
            "stop_reason": "", "diagnostics": [],
            "report": {"id": report_id, "source": source, "original_text": text,
                       "sha256": sha256(text.encode()).hexdigest(), "ingested_at": now},
            "extraction_options": {"include_references": include_references, "extended_types": extended_types},
            "extraction": None,
        }
        if self.config.mode == "replay":
            run["replay"] = {"manifest": str(self.client.http.path), "sha256": self.client.http.digest}
        # Persist the original report before extraction so failures remain inspectable.
        self.repository.create_run(run, [], owner_id=owner_id, creation_key=creation_key,
                                   payload_digest=payload_digest)
        started = time.monotonic()
        try:
            result = extract_report(text, source=source, include_references=include_references,
                                    extended_types=extended_types)
            extraction = asdict(result)
            extraction["passages"] = [
                {"id": f"{report_id}:s{index + 1}", "text": sentence, "sentence_index": index}
                for index, sentence in enumerate(result.sentences)
            ]
            run["extraction"] = extraction
            nodes = {}
            for ioc in result.iocs:
                try:
                    canonical = identity(ioc)
                    passages = []
                    for index, matches in enumerate(result.matches):
                        if any(self._canonical_match(kind, value) == canonical for kind, value in matches):
                            passages.append(extraction["passages"][index]["id"])
                    node = graph_node(ioc, origin="report", passages=passages)
                    if node["id"] in nodes:
                        previous = nodes[node["id"]]
                        for key in ("context", "sources", "passage_ids"):
                            previous[key] = list(dict.fromkeys(previous[key] + node[key]))
                    else:
                        nodes[node["id"]] = node
                except (ValueError, TypeError) as exc:
                    run["diagnostics"].append({"kind": "invalid_extracted_ioc", "ioc": asdict(ioc),
                                               "message": str(exc)})
            if len(nodes) > self.config.max_nodes:
                run["status"], run["stop_reason"] = "failed", "initial_node_limit"
                run["diagnostics"].append({"kind": "initial_node_limit", "count": len(nodes),
                                           "limit": self.config.max_nodes})
                nodes = {}
            else:
                run["status"] = "ready"
                if not nodes:
                    run["diagnostics"].append({"kind": "no_iocs", "message": "No usable IOCs were extracted."})
            run["elapsed_seconds"] = time.monotonic() - started
            run["updated_at"] = utc_now()
            # Extraction has no lookup step; add its initial graph in a dedicated repository operation.
            self.repository.finish_extraction(run, list(nodes.values()))
        except (ValueError, ImportError, OSError) as exc:
            run["status"], run["stop_reason"] = "failed", "extraction_failed"
            run["elapsed_seconds"] = time.monotonic() - started
            run["diagnostics"].append({"kind": "extraction_failed", "message": str(exc)})
            run["updated_at"] = utc_now()
            self.repository.save_run(run)
        return self.repository.get_run(run_id)

    @staticmethod
    def _canonical_match(kind, value):
        try:
            return identity(IOC(value, kind))
        except (ValueError, TypeError):
            return None

    def list_runs(self) -> list[dict]:
        return self.repository.list_runs()

    def list_methods(self, run_id: str, input_node_id: str) -> list[dict]:
        run = self.repository.get_run(run_id)
        self._check_mode(run)
        node = self._node(run_id, input_node_id)
        query = IOC(node["value"], node["type"], node["context"])
        rows = []
        for method in list_runnable_methods(node["type"]):
            status = method_status(method, api_keys=self.client.api_keys)
            selectable = method.id not in UNRESOLVED_LIVE_METHODS
            reason = "unresolved_live_route" if not selectable else ""
            if run["mode"] == "replay":
                selectable = self.client.http.supports(query, method)
                status["fixture_available"] = selectable
                reason = "" if selectable else "no_replay_fixture"
            rows.append({**asdict(method), "implemented": True, "description": method.description,
                         "availability": status, "selectable": selectable, "unavailable_reason": reason})
        return rows

    def _node(self, run_id, input_node_id):
        return next((node for node in self.repository.nodes(run_id) if node["id"] == input_node_id), None) or self._missing_node()

    @staticmethod
    def _missing_node():
        raise ValueError("Choose an IOC from this investigation's graph")

    def _check_mode(self, run):
        if run["mode"] != self.config.mode:
            raise ValueError("Saved run mode differs; reopen with its original mode")
        if run["policy"] != self.policy.name:
            raise ValueError("Saved investigation requires its original admission policy")
        if run["mode"] == "replay" and run.get("replay", {}).get("sha256") != self.client.http.digest:
            raise ValueError("Replay fixtures changed; the saved run requires its original fixtures")

    def execute_step(self, run_id: str, input_node_id: str, method_id: str, *, step_id=None) -> dict:
        run = self.repository.get_run(run_id)
        self._check_mode(run)
        if step_id:
            try:
                previous = self.repository.get_step(step_id, run_id)
            except KeyError:
                previous = None
            if previous:
                if (previous["run_id"], previous["input_node_id"], previous["method_id"]) != (run_id, input_node_id, method_id):
                    raise ValueError("Step ID belongs to a different lookup")
                if previous["status"] == "completed":
                    return previous
                self.resume(run_id)
                return self.repository.get_step(step_id, run_id)
        if run["status"] in TERMINAL_STATUSES:
            raise ValueError("This investigation is " + run["status"] + "; start a new one for further hunting")
        steps = self.repository.steps(run_id)
        if any(step["status"] != "completed" for step in steps):
            raise ValueError("Resume the unfinished step before starting another lookup")
        config = RunConfig(**run["config"])
        if len(steps) >= config.max_steps or run["elapsed_seconds"] >= config.max_seconds:
            run["status"] = "completed"
            run["stop_reason"] = "step_limit" if len(steps) >= config.max_steps else "time_limit"
            run["updated_at"] = utc_now()
            self.repository.save_run(run)
            raise ValueError("Investigation stopped: " + run["stop_reason"])
        node = self._node(run_id, input_node_id)
        method = get_method(method_id)
        if method.input_type != node["type"] or not method.implemented:
            raise ValueError("Select an implemented method compatible with this IOC")
        if not next(row for row in self.list_methods(run_id, input_node_id) if row["id"] == method_id)["selectable"]:
            raise ValueError("This method is unavailable for the current live/replay configuration")
        step = {
            "id": step_id or uuid4().hex, "run_id": run_id, "sequence": len(steps) + 1,
            "input_node_id": input_node_id, "method_id": method_id, "lookup_id": uuid4().hex,
            "status": "running", "started_at": utc_now(), "finished_at": "",
            "outcome_status": "pending", "lookup": None, "admission": None, "delta": {}, "error": "",
        }
        run["status"], run["updated_at"] = "running", utc_now()
        self.repository.begin_step(run, step)
        # Respect persisted limits when a run is reopened with a different default configuration.
        query = IOC(node["value"], node["type"], list(node["context"]), "; ".join(node["sources"]))
        try:
            record = self.client.lookup_detailed(query, method_id, lookup_id=step["lookup_id"],
                                                 max_pages=config.max_pages, max_outputs=config.max_outputs)
        except LookupError as exc:
            record = LookupRecord.from_dict(self.client.store.get_record(exc.lookup_id))
        # KeyboardInterrupt/process termination leaves a durable pending attempt for resume().
        return self._apply_receipt(run_id, step, record)

    def _apply_receipt(self, run_id, step, record):
        run = self.repository.get_run(run_id)
        seed = self._node(run_id, step["input_node_id"])
        if record.id != step["lookup_id"] or record.method_id != step["method_id"]:
            raise ValueError("Saved receipt does not match this workflow attempt")
        query = IOC(seed["value"], seed["type"])
        if identity(query) != identity(record.input_ioc):
            raise ValueError("Saved receipt belongs to another input IOC")
        method = get_method(step["method_id"])
        good_status = record.status in {"ok", "empty", "partial"}
        observations = {evidence.id: evidence for evidence in record.evidence}
        accepted, labels = {}, {}
        outputs = {node_id(ioc): ioc for ioc in record.outputs}
        # Interrupted acquisitions can contain some evidence but no finalized outputs.
        # Retain them as diagnostics, never promote their unfinished mappings.
        for association in record.accepted if good_status else []:
            target_id = node_id(IOC(association["value"], association["type"]))
            target = outputs.get(target_id)
            evidence = observations.get(association["evidence_id"])
            if target is None or evidence is None:
                raise ValueError("Accepted relationship has no retained output or evidence")
            verdict = validate_edge(query, target, method, evidence)
            if (not verdict.accepted or association["method_id"] != method.id
                    or association["ontology_label"] != verdict.ontology_label):
                raise ValueError("Retained relationship no longer passes its field/ontology checks")
            accepted.setdefault(target_id, []).append(evidence.id)
            labels[target_id] = verdict.ontology_label
        nodes = self.repository.nodes(run_id)
        known = {node["id"] for node in nodes}
        used = {node["id"] for node in nodes if node["used"]}
        admission = self.policy.evaluate(set(accepted), known, used)
        if not good_status:
            admission.update(accepted=False, reason="lookup_failed")
        elif len(accepted) != len(outputs):
            admission.update(accepted=False, reason="missing_accepted_evidence")
        config = RunConfig(**run["config"])
        if admission["accepted"] and len(known | set(accepted)) > config.max_nodes:
            admission.update(accepted=False, reason="node_limit")
        proposed_nodes, proposed_edges = [], []
        if admission["accepted"]:
            for target_id, evidence_ids in accepted.items():
                target = outputs[target_id]
                proposed_nodes.append(graph_node(target, origin="lookup", evidence_ids=evidence_ids,
                                                  lookup_ids=[record.id]))
                proposed_edges.append(graph_edge(seed["id"], target_id, method.id,
                                                   labels[target_id],
                                                   evidence_ids, record.id))
            # The selected endpoint also receives the exact supporting lookup provenance.
            proposed_nodes.append({**seed, "evidence_ids": list(dict.fromkeys(
                evidence_id for evidence_ids in accepted.values() for evidence_id in evidence_ids)),
                "lookup_ids": [record.id]})
        outcome_status = "interrupted_unknown" if record.status == "pending" else record.status
        error = record.error or ("Acquisition ended before a final outcome was recorded."
                                 if record.status == "pending" else "")
        step.update(status="completed", outcome_status=outcome_status, lookup=record.to_dict(),
                    admission=admission, error=error, finished_at=utc_now())
        try:
            duration = max(0, (datetime.fromisoformat(record.finished_at) - datetime.fromisoformat(record.started_at)).total_seconds())
        except (ValueError, TypeError):
            duration = 0
        run["elapsed_seconds"] += duration
        run["status"], run["stop_reason"] = "ready", ""
        if step["sequence"] >= config.max_steps or run["elapsed_seconds"] >= config.max_seconds:
            run["status"] = "completed"
            run["stop_reason"] = "step_limit" if step["sequence"] >= config.max_steps else "time_limit"
        run["updated_at"] = utc_now()
        self.repository.commit_step(run, step, proposed_nodes, proposed_edges)
        return self.repository.get_step(step["id"], run_id)

    def resume(self, run_id: str) -> dict:
        run = self.repository.get_run(run_id)
        self._check_mode(run)
        if run["status"] in TERMINAL_STATUSES:
            return run
        if run["status"] == "extracting":
            # The preserved report can be submitted again; do not invent a completed extraction.
            run["status"], run["stop_reason"] = "failed", "interrupted_extraction"
            self.repository.save_run(run)
            return self.repository.get_run(run_id)
        for step in self.repository.steps(run_id):
            if step["status"] == "completed":
                continue
            try:
                record = LookupRecord.from_dict(self.client.store.get_record(step["lookup_id"]))
            except KeyError:
                # We cannot know whether an interrupted external request reached its provider.
                # Retain that uncertain attempt, and require another explicit user selection to retry.
                run = self.repository.get_run(run_id)
                step.update(status="completed", outcome_status="interrupted_unknown", finished_at=utc_now(),
                            error="Acquisition ended without a saved receipt; it was not retried automatically.",
                            admission={"accepted": False, "reason": "interrupted_unknown", "overlap_ids": [],
                                       "reward": None, "reward_status": "not_evaluated"})
                run["status"], run["updated_at"] = "ready", utc_now()
                config = RunConfig(**run["config"])
                if step["sequence"] >= config.max_steps or run["elapsed_seconds"] >= config.max_seconds:
                    run["status"] = "completed"
                    run["stop_reason"] = "step_limit" if step["sequence"] >= config.max_steps else "time_limit"
                self.repository.commit_step(run, step, [], [])
            else:
                self._apply_receipt(run_id, step, record)
        return self.repository.get_run(run_id)

    def finish(self, run_id: str, cancelled=False) -> dict:
        run = self.resume(run_id)
        if run["status"] not in TERMINAL_STATUSES:
            run["status"] = "cancelled" if cancelled else "completed"
            run["stop_reason"] = "user_cancelled" if cancelled else "user_finished"
            run["updated_at"] = utc_now()
            self.repository.save_run(run)
        return self.repository.get_run(run_id)

    def get_result(self, run_id: str, include_evidence=False) -> dict:
        return self.repository.snapshot(run_id, include_evidence)

    def export_result(self, run_id: str, path: str | Path, include_evidence=True) -> dict:
        result = self.get_result(run_id, include_evidence=include_evidence)
        path = Path(path)
        path.parent.mkdir(parents=True, exist_ok=True)
        temporary = path.with_name(path.name + ".tmp")
        temporary.write_text(json.dumps(result, indent=2, ensure_ascii=False), encoding="utf-8")
        temporary.replace(path)
        return result


def build_runner(store_directory=None, config: RunConfig | None = None, replay_path=None, *, run_id=None):
    store = EvidenceStore(resolve_store_directory(store_directory))
    saved = WorkflowRepository(store).get_run(run_id) if run_id else None
    if saved:
        if config and config.mode != saved["mode"]:
            raise ValueError("Cannot change a saved investigation's mode")
        config = RunConfig(**saved["config"])
        replay_path = replay_path or saved.get("replay", {}).get("manifest")
    config = config or RunConfig(mode="replay" if replay_path else "live")
    if config.mode == "replay":
        if not replay_path:
            raise ValueError("Replay mode requires --replay MANIFEST.json")
        replay = ReplayTransport(replay_path)
        client = LookupClient(store=store, http=replay, browser=replay, api_keys={}, interval=0,
                              max_pages=config.max_pages, max_outputs=config.max_outputs)
    else:
        if replay_path:
            raise ValueError("A replay manifest cannot be used in live mode")
        client = LookupClient(store=store, max_pages=config.max_pages, max_outputs=config.max_outputs)
    runner = WorkflowRunner(client, config)
    if saved:
        runner._check_mode(saved)
    return runner
