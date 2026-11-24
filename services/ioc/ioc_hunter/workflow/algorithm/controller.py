"""Algorithm 1 decisions above the existing transactional workflow executor."""
from dataclasses import asdict, replace
from hashlib import sha256
from pathlib import Path
import time

from ...evidence import utc_now
from ...methods import get_method, list_runnable_methods
from ...models import IOC
from ..coordination import ExecutionCoordinator
from ..models import stable_id
from ..policies import PaperAdmissionPolicy
from ..runner import TERMINAL_STATUSES, UNRESOLVED_LIVE_METHODS
from .models import AlgorithmConfig, POLICY, VERSION, fingerprint, initial_state
from .scoring import rank_methods
from .selector import build_selector, selection_request, validate_selection


class AlgorithmAdmissionPolicy(PaperAdmissionPolicy):
    name = POLICY


def _catalogue(config, mode):
    methods = [get_method(mid) for mid in config.method_ids] if config.method_ids else list_runnable_methods()
    if not config.method_ids and mode == "live":
        methods = [m for m in methods if m.id not in UNRESOLVED_LIVE_METHODS]
    if any(not method.implemented for method in methods):
        raise ValueError("Automatic runs require implemented methods")
    if mode == "live" and any(m.id in UNRESOLVED_LIVE_METHODS for m in methods):
        raise ValueError("Configured method has an unresolved live route")
    return [{**asdict(m), "description": m.description} for m in sorted(methods, key=lambda m: m.id)]


def _effective(config, mode):
    catalogue = _catalogue(config, mode)
    selector = dict(config.selector)
    if selector.get("kind") == "fixture":
        path = Path(selector["path"]).resolve()
        selector.update(path=str(path), sha256=sha256(path.read_bytes()).hexdigest())
    return replace(config, method_ids=tuple(m["id"] for m in catalogue), selector=selector), catalogue


def configure_runner(runner, run):
    """Restore saved policy, accounting and provider settings for every caller."""
    state = run["algorithm"]
    if state.get("version") != VERSION:
        raise ValueError("Unsupported saved algorithm version")
    if fingerprint(state["config"]) != state["config_fingerprint"]:
        raise ValueError("Saved algorithm configuration changed")
    config = AlgorithmConfig(**state["config"])
    if _catalogue(config, run["mode"]) != state["catalogue"]:
        raise ValueError("Method catalogue changed; create a new experiment")
    if fingerprint(state["catalogue"]) != state["catalogue_fingerprint"]:
        raise ValueError("Saved method catalogue changed")
    if config.selector.get("kind") == "fixture":
        if sha256(Path(config.selector["path"]).read_bytes()).hexdigest() != config.selector["sha256"]:
            raise ValueError("Selector fixtures changed; create a new experiment")
    runner.policy = AlgorithmAdmissionPolicy()
    runner.client.configure_limits(config.provider_limits, frozen_cache=config.frozen_cache,
                                   cache_namespace=run.get("dataset", {}).get("build_id", ""))
    runner.completion_hook = _feedback(runner.client)
    return runner


def _feedback(client):
    def completed(run, step, record, admission):
        state = run["algorithm"]
        decision = next(d for d in state["decisions"] if d["id"] == state["current_decision_id"])
        index = state["next_method_index"]
        if index >= len(decision["selected"]) or step["id"] != stable_id(decision["id"], index):
            raise ValueError("Workflow attempt does not match the saved algorithm cursor")
        history = state["method_history"][step["method_id"]]
        history["tried"] += 1
        reward = int(admission["accepted"])
        history["coverage"] += reward
        admission.update(reward=reward, reward_status="evaluated",
                         paper_overlap_pass=bool(admission.get("overlap_ids")))
        step["algorithm"] = {"decision_id": decision["id"], "round_index": state["round_index"],
                             "method_index": index, "history_after": dict(history)}
        state.update(next_method_index=index + 1, pending_step_id=None, wait=None)
        if index + 1 == len(decision["selected"]):
            state["phase"] = "finish_round"
        if run["status"] not in TERMINAL_STATUSES and admission["reason"] == "node_limit":
            run.update(status="completed", stop_reason="node_limit")
        if run["status"] in TERMINAL_STATUSES:
            state.update(phase="finished", outcome="limited")
            return
        status = step["outcome_status"]
        errors = (record.transport_errors if record else [])
        deferred_read = (record.acquisition if record else {}).get("defer_reason")
        if status in {"rate_limited", "budget_exhausted"} or any(
                error.get("status") in {"rate_limited", "budget_exhausted"} for error in errors
                ) or deferred_read in {"rate_limited", "budget_exhausted"}:
            wait = client.rate_status(get_method(step["method_id"]).source)
            state["wait"] = {**wait, "source": get_method(step["method_id"]).source,
                             "reason": status if status != "partial" else "provider_cooldown"}
    return completed


class AlgorithmController:
    def __init__(self, runner, selector=None):
        self.runner = runner
        self.repository = runner.repository
        self.selector = selector
        self.coordinator = ExecutionCoordinator(runner.client.store.directory)

    def create(self, artifact, config, *, experiment_id, owner_id="local"):
        config, catalogue = _effective(config, self.runner.config.mode)
        run_id = stable_id("algorithm1", artifact["build_id"], experiment_id, artifact["report_key"])
        with self.coordinator.claim("run:" + run_id):
            try:
                run = self.repository.get_run(run_id)
            except KeyError:
                self.runner.client.configure_limits(config.provider_limits, frozen_cache=config.frozen_cache,
                                                   cache_namespace=artifact["build_id"])
                state = initial_state(config, catalogue, [ioc["id"] for ioc in artifact["iocs"]])
                state["experiment_id"] = experiment_id
                self.runner.policy = AlgorithmAdmissionPolicy()
                run = self.runner.create_prepared_run(artifact, run_id=run_id, owner_id=owner_id, algorithm=state)
            if run["algorithm"]["config_fingerprint"] != fingerprint(config.to_dict()):
                raise ValueError("Experiment configuration differs from its saved run")
            if run["dataset"]["extraction_id"] != artifact["extraction_id"]:
                raise ValueError("Prepared extraction differs from the saved run")
            configure_runner(self.runner, run)
        return run

    def _save(self, run, *, used_node_id=None):
        run["updated_at"] = utc_now()
        saved = self.repository.transition_algorithm(run, used_node_id=used_node_id)
        run["graph_revision"] = saved["graph_revision"]
        return run

    def run(self, run_id, *, wait=False, on_progress=None):
        """Continue one report. Long waits are durable and optionally waited out."""
        with self.coordinator.claim("run:" + run_id):
            run = self.repository.get_run(run_id)
            configure_runner(self.runner, run)
            self.runner.resume(run_id)
            reported_revision = None
            while True:
                run = self.repository.get_run(run_id)
                state = run["algorithm"]
                if on_progress and run["graph_revision"] != reported_revision:
                    on_progress(self.runner.get_result(run_id))
                    reported_revision = run["graph_revision"]
                if run["status"] in TERMINAL_STATUSES:
                    return self.runner.get_result(run_id)
                pending_wait = state.get("wait")
                if pending_wait:
                    retry_at = pending_wait.get("retry_at")
                    if retry_at and retry_at > time.time():
                        if not wait:
                            return self.runner.get_result(run_id)
                        started = time.monotonic()
                        try:
                            time.sleep(min(30, max(0, retry_at - time.time())))
                        finally:
                            state["wait_seconds"] = state.get("wait_seconds", 0) + max(0, time.monotonic() - started)
                            self._save(run)
                        continue
                    if pending_wait.get("reason") == "selector_error":
                        # A new invocation may retry the unsaved model decision.
                        state["wait"] = None
                        self._save(run)
                        continue
                    state["wait"] = None
                    self._save(run)
                    continue
                if run["elapsed_seconds"] >= run["config"]["max_seconds"]:
                    run.update(status="completed", stop_reason="time_limit")
                    state.update(phase="finished", outcome="limited")
                    self._save(run)
                    continue
                phase = state["phase"]
                if phase == "choose_ioc":
                    node = next((n for n in self.repository.nodes(run_id) if not n["used"]), None)
                    if node is None:
                        run.update(status="completed", stop_reason="candidate_exhausted")
                        state.update(phase="finished", outcome="complete")
                        self._save(run)
                    else:
                        state.update(active_node_id=node["id"], round_index=0, phase="select_methods",
                                     next_method_index=0, pending_step_id=None, current_decision_id=None)
                        self._save(run, used_node_id=node["id"])
                elif phase == "select_methods":
                    if not self._select(run):
                        return self.runner.get_result(run_id)
                elif phase == "execute_methods":
                    if not self._execute(run):
                        current_wait = self.repository.get_run(run_id)["algorithm"].get("wait") or {}
                        if wait and current_wait.get("retry_at"):
                            continue
                        return self.runner.get_result(run_id)
                elif phase == "finish_round":
                    state["round_index"] += 1
                    state.update(phase="choose_ioc" if state["round_index"] == 5 else "select_methods",
                                 current_decision_id=None, next_method_index=0, pending_step_id=None)
                    if state["phase"] == "choose_ioc":
                        state["active_node_id"] = None
                    self._save(run)
                else:
                    raise ValueError("Unknown saved algorithm phase")

    def _select(self, run):
        state = run["algorithm"]
        node = self.runner._node(run["id"], state["active_node_id"])
        decision_id = stable_id(run["id"], node["id"], state["round_index"])
        decision = next((d for d in state["decisions"] if d["id"] == decision_id), None)
        if decision is None:
            shortlist = rank_methods(state["catalogue"], state["method_history"], node["type"], state["config"]["alpha"])
            decision = {"id": decision_id, "input_node_id": node["id"], "round_index": state["round_index"],
                        "status": "pending", "shortlist": shortlist, "request": selection_request(node, shortlist),
                        "selected": [], "attempts": []}
            state["decisions"].append(decision)
            state["current_decision_id"] = decision_id
            self._save(run)
        if decision["shortlist"]:
            if self.selector is None:
                self.selector = build_selector(state["config"]["selector"])
            for _ in range(2):
                started = time.monotonic()
                try:
                    response = self.selector.select(decision["request"])
                    chosen = validate_selection(response["selection"], decision["shortlist"])
                    elapsed = time.monotonic() - started
                    decision["attempts"].append({"status": "ok", "seconds": elapsed,
                        "response": response["selection"], "usage": response.get("usage"), "model": response.get("model")})
                    decision["selected"] = chosen
                    break
                except Exception as exc:
                    elapsed = time.monotonic() - started
                    # Do not persist arbitrary endpoint exception text containing secrets.
                    decision["attempts"].append({"status": "error", "seconds": elapsed, "error": type(exc).__name__})
                finally:
                    elapsed = time.monotonic() - started
                    state["selector_seconds"] += elapsed
                    run["elapsed_seconds"] += elapsed
                self._save(run)
            else:
                decision["status"] = "failed"
                state["wait"] = {"reason": "selector_error", "retry_at": None}
                self._save(run)
                return False
        decision["status"] = "selected"
        state.update(phase="execute_methods" if decision["selected"] else "finish_round", next_method_index=0)
        self._save(run)
        return True

    def _execute(self, run):
        state = run["algorithm"]
        completed = sum(step["status"] == "completed" for step in self.repository.steps(run["id"]))
        if completed >= run["config"]["max_steps"]:
            run.update(status="completed", stop_reason="step_limit")
            state.update(phase="finished", outcome="limited")
            self._save(run)
            return True
        decision = next(d for d in state["decisions"] if d["id"] == state["current_decision_id"])
        method_id = decision["selected"][state["next_method_index"]]["method_id"]
        node = self.runner._node(run["id"], state["active_node_id"])
        query = IOC(node["value"], node["type"], node["context"])
        delayed = self.runner.client.lookup_wait(query, method_id)
        if delayed:
            state["wait"] = {**delayed, "source": get_method(method_id).source}
            self._save(run)
            return False
        step_id = stable_id(decision["id"], state["next_method_index"])
        if state["pending_step_id"] != step_id:
            state["pending_step_id"] = step_id
            self._save(run)
        step = self.runner.execute_step(run["id"], node["id"], method_id, step_id=step_id)
        if step["status"] != "completed":
            current = self.repository.get_run(run["id"])
            accounting = (step.get("lookup") or {}).get("acquisition", {})
            current["algorithm"]["wait"] = {"reason": accounting.get("defer_reason", "local_cooldown"),
                                            "retry_at": accounting.get("retry_at"),
                                            "source": get_method(method_id).source}
            self._save(current)
            return False
        return True
