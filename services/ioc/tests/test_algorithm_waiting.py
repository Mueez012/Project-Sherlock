"""Controller, workflow and provider gates together; no external acquisitions."""
from datetime import datetime, timezone
from unittest.mock import patch

import pytest

from ioc_hunter import LookupClient, LookupError
from ioc_hunter.storage import EvidenceStore
from ioc_hunter.workflow.algorithm.controller import AlgorithmController
from ioc_hunter.workflow.algorithm.dataset import prepare_report
from ioc_hunter.workflow.algorithm.models import AlgorithmConfig
from ioc_hunter.workflow.models import RunConfig
from ioc_hunter.workflow.runner import WorkflowRunner

from test_algorithm_limits import Transport, document

METHOD = "rapiddns.domain_to_ipv4"


class Selector:
    def __init__(self):
        self.calls = []

    def select(self, request):
        self.calls.append(request)
        return {"selection": {"methods": [{"method_id": METHOD, "reason": "Use DNS evidence"}]},
                "model": "fake-selector"}


def artifact(report_id=77):
    text = "Observed example.com and 192.0.2.10."
    return prepare_report({"report_id": report_id, "text": text, "sentences": [text],
                           "group": "held-out label", "label": 0, "cut_by_excel": False},
                          split="train", build_id="waiting-build")


def make_controller(tmp_path, *responses, selector=None, max_steps=1, max_seconds=600, frozen=False):
    transport = Transport(*responses)
    lookup = LookupClient(store=EvidenceStore(tmp_path), http=transport, browser=transport,
                          api_keys={}, interval=0, cache_ttl=0, max_pages=1)
    runner = WorkflowRunner(lookup, RunConfig(max_steps=max_steps, max_seconds=max_seconds, max_pages=1))
    selector = selector or Selector()
    controller = AlgorithmController(runner, selector)
    config = AlgorithmConfig(alpha=1, method_ids=(METHOD,), frozen_cache=frozen,
                             selector={"kind": "api", "endpoint": "http://127.0.0.1:1/chat/completions",
                                       "model": "fake-selector"},
                             provider_limits={"rapiddns": {"interval": 0, "daily_limit": 10}})
    return controller, config, selector, transport


def clear_gate(controller):
    with controller.runner.client.store.connect() as db:
        db.execute("UPDATE provider_pacing SET next_at=0,cooldown_until=0")


def test_known_cooldown_preserves_selection_without_a_step_or_tried_count(tmp_path):
    controller, config, selector, transport = make_controller(tmp_path, document())
    run = controller.create(artifact(), config, experiment_id="preflight")
    controller.runner.client.limiter.cooldown("rapiddns", 120)
    blocked = controller.run(run["id"])
    state = blocked["run"]["algorithm"]
    assert not blocked["steps"] and not transport.requests
    assert state["method_history"][METHOD] == {"tried": 0, "coverage": 0}
    assert state["next_method_index"] == 0 and state["wait"]["reason"] == "cooldown"
    assert len(selector.calls) == 1 and state["decisions"][0]["status"] == "selected"
    retry_at = state["wait"]["retry_at"]
    clear_gate(controller)
    with patch("ioc_hunter.workflow.algorithm.controller.time.time", return_value=retry_at + 1):
        finished = controller.run(run["id"])
    assert len(finished["steps"]) == len(transport.requests) == len(selector.calls) == 1
    assert finished["run"]["algorithm"]["method_history"][METHOD] == {"tried": 1, "coverage": 1}


def test_zero_dispatch_race_reuses_logical_step_with_new_immutable_receipt(tmp_path):
    controller, config, selector, transport = make_controller(tmp_path, document())
    run = controller.create(artifact(), config, experiment_id="race")
    lookup = controller.runner.client

    def race(source, **kwargs):
        lookup.limiter.cooldown(source, 120)
        raise LookupError("rate_limited", "Another client established a cooldown", retry_after=120)

    with patch.object(lookup.limiter, "wait", side_effect=race):
        blocked = controller.run(run["id"])
    pending = blocked["steps"][0]
    deferred_id = pending["lookup_id"]
    assert pending["status"] == "running" and pending["outcome_status"] == "deferred"
    assert pending["lookup"]["acquisition"]["fetch_attempts"] == 0 and not transport.requests
    assert blocked["run"]["algorithm"]["method_history"][METHOD]["tried"] == 0
    retry_at = blocked["run"]["algorithm"]["wait"]["retry_at"]
    clear_gate(controller)
    with patch("ioc_hunter.workflow.algorithm.controller.time.time", return_value=retry_at + 1):
        finished = controller.run(run["id"])
    step = finished["steps"][0]
    assert len(finished["steps"]) == len(transport.requests) == len(selector.calls) == 1
    assert step["id"] == pending["id"] and step["lookup_id"] != deferred_id
    assert step["deferred_lookup_ids"] == [deferred_id]
    assert lookup.store.get_record(deferred_id)["status"] == "deferred"
    exported = controller.runner.get_result(run["id"], include_evidence=True)
    assert {receipt["id"] for receipt in exported["evidence"]["lookups"]} == {deferred_id, step["lookup_id"]}
    assert finished["run"]["algorithm"]["method_history"][METHOD] == {"tried": 1, "coverage": 1}


@pytest.mark.parametrize("retry_after", [0, 90])
def test_dispatched_429_counts_once_and_advances_before_source_pause(tmp_path, retry_after):
    maximum = 1 if retry_after == 0 else 20
    controller, config, selector, transport = make_controller(
        tmp_path, LookupError("rate_limited", "Provider quota", retry_after=retry_after), max_steps=maximum)
    run = controller.create(artifact(), config, experiment_id="remote-429")
    result = controller.run(run["id"])
    state = result["run"]["algorithm"]
    assert len(result["steps"]) == len(transport.requests) == len(selector.calls) == 1
    assert result["steps"][0]["outcome_status"] == "rate_limited"
    assert state["method_history"][METHOD] == {"tried": 1, "coverage": 0}
    assert state["next_method_index"] == 1
    if retry_after:
        assert state["wait"]["reason"] == "rate_limited"
        assert state["wait"]["wait_seconds"] > 80
        assert state["phase"] == "finish_round" and result["run"]["status"] == "ready"
    else:
        assert result["run"]["stop_reason"] == "step_limit"
        assert controller.runner.client.rate_status("rapiddns")["ready"]


def clock_patches(clock):
    class ClockDatetime:
        @classmethod
        def now(cls, tz):
            return datetime.fromtimestamp(clock[0], tz)

    def sleep(seconds):
        assert 0 < seconds <= 30
        clock[0] += seconds

    return (patch("ioc_hunter.workflow.algorithm.controller.time.time", side_effect=lambda: clock[0]),
            patch("ioc_hunter.workflow.algorithm.controller.time.monotonic", side_effect=lambda: clock[0]),
            patch("ioc_hunter.workflow.algorithm.controller.time.sleep", side_effect=sleep),
            patch("ioc_hunter.evidence.datetime", ClockDatetime))


def test_wait_mode_automatically_continues_after_long_cooldown(tmp_path):
    controller, config, selector, transport = make_controller(tmp_path, document())
    run = controller.create(artifact(), config, experiment_id="auto-wait")
    clock = [datetime(2026, 11, 11, tzinfo=timezone.utc).timestamp()]
    p_time, p_mono, p_sleep, p_datetime = clock_patches(clock)
    with p_time, p_mono, p_sleep as sleeper, p_datetime:
        controller.runner.client.limiter.cooldown("rapiddns", 45)
        result = controller.run(run["id"], wait=True)
    assert sum(call.args[0] for call in sleeper.call_args_list) == pytest.approx(45)
    assert result["run"]["algorithm"]["wait_seconds"] == pytest.approx(45)
    assert len(selector.calls) == len(transport.requests) == len(result["steps"]) == 1
    assert result["run"]["status"] == "completed" and not result["run"]["algorithm"]["wait"]


def test_short_rate_wait_does_not_exhaust_active_processing_budget(tmp_path):
    controller, config, selector, transport = make_controller(tmp_path, document(), max_seconds=1)
    run = controller.create(artifact(), config, experiment_id="short-wait")
    clock = [datetime(2026, 11, 11, tzinfo=timezone.utc).timestamp()]
    p_time, p_mono, p_sleep, p_datetime = clock_patches(clock)
    with p_time, p_mono, p_sleep, p_datetime:
        with controller.runner.client.store.connect() as db:
            db.execute("INSERT INTO provider_pacing VALUES ('rapiddns',?,0)", (clock[0] + 7,))
        result = controller.run(run["id"], wait=True)
    receipt = result["steps"][0]["lookup"]
    assert receipt["acquisition"]["rate_wait_seconds"] == 7
    assert result["run"]["elapsed_seconds"] == 0
    assert result["run"]["stop_reason"] == "step_limit"


def test_fresh_report_client_reuses_shared_profile_and_frozen_evidence(tmp_path):
    first, config, _, first_transport = make_controller(tmp_path, document(), frozen=True)
    run = first.create(artifact(77), config, experiment_id="shared")
    original = first.run(run["id"])
    second, config, _, second_transport = make_controller(tmp_path, frozen=True)
    second_run = second.create(artifact(78), config, experiment_id="shared")
    result = second.run(second_run["id"])
    assert second_run["id"] != run["id"]
    assert len(first_transport.requests) == 1 and not second_transport.requests
    assert result["steps"][0]["lookup"]["acquisition"]["frozen_lookup_id"] == original["steps"][0]["lookup_id"]
    assert second.runner.client.rate_status("rapiddns")["daily_limit"] == 10
    assert second.runner.client.rate_status("rapiddns")["used"] == 1
    assert result["run"]["algorithm"]["method_history"][METHOD] == {"tried": 1, "coverage": 1}
