"""Participation must preserve isolates and distinguish an IOC's own queries."""
from copy import deepcopy

from ioc_hunter.models import IOC
from ioc_hunter.workflow.models import graph_edge, graph_node, node_id
from ioc_hunter.workflow.algorithm.statistics import summarize


def fixture():
    a, b, c, x, y, z = [IOC(f"{name}.example", "domain") for name in "abcxyz"]
    graph_nodes = [graph_node(ioc, origin="report") for ioc in (a, b, c, z)] + [graph_node(x, origin="lookup")]
    edge = lambda target: graph_edge(node_id(b), node_id(target), "method", "label", [], "q2")
    step = lambda number, query, outputs, accepted, reason: {
        "id": f"s{number}", "lookup_id": f"q{number}", "input_node_id": node_id(query),
        "method_id": "method", "status": "completed", "outcome_status": "ok",
        "admission": {"accepted": accepted, "reason": reason},
        "lookup": {"id": f"q{number}", "status": "ok", "input_ioc": {"type": query.type, "value": query.value},
                   "outputs": [{"type": item.type, "value": item.value} for item in outputs],
                   "acquisition": {"fetch_attempts": 1, "cache_reads": 0, "rate_wait_seconds": 15}}}
    return {
        "run": {"id": "run", "graph_revision": 3, "status": "completed", "stop_reason": "candidate_exhausted"},
        "extraction": {"sentences": ["A", "B", "C", "Z"],
                       "iocs": [{"type": item.type, "value": item.value} for item in (a, b, c, z)],
                       "matches": [[("domain", item.value)] for item in (a, b, c, z)]},
        "graph": {"nodes": graph_nodes, "edges": [edge(item) for item in (a, c, x)]},
        "steps": [step(1, a, [y], False, "no_known_unused_overlap"), step(2, b, [c, a, x], True, "known_unused_overlap")],
    }


def by_value(result, value):
    return next(item for item in result["ioc_participation"] if item["value"] == value + ".example")


def test_own_zero_coverage_can_participate_nonadmitted_and_isolated_stay_visible():
    snapshot = fixture()
    before = deepcopy(snapshot)
    result = summarize(snapshot)
    assert snapshot == before
    a, x, y, z = [by_value(result, name) for name in "axyz"]
    assert a["attempts_as_input"] == 1 and a["admissions_as_input"] == 0
    assert a["in_graph"] and a["neighbor_count"] == 1 and a["component_report_seed_count"] == 3
    assert x["in_graph"] and x["sentence_indices"] == []
    assert not y["in_graph"] and y["neighbor_count"] is None
    assert y["lookup_ids"] == ["q1"] and y["reason_codes"] == ["no_known_unused_overlap"]
    assert z["in_graph"] and z["neighbor_count"] == 0
    assert result["graph"]["isolated_report_iocs"] == 1
    assert result["graph"]["validated_non_admitted_iocs"] == 1
    assert result["methods"]["method"]["batch_rate"] == 0.5


def test_current_membership_updates_after_later_admission_without_losing_history():
    snapshot = fixture()
    y = IOC("y.example", "domain")
    snapshot["graph"]["nodes"].append(graph_node(y, origin="lookup"))
    snapshot["graph"]["edges"].append(graph_edge(node_id(y), node_id(IOC("b.example", "domain")), "m2", "label", [], "q3"))
    result = summarize(snapshot)
    assert by_value(result, "y")["in_graph"]
    assert by_value(result, "y")["reason_codes"] == ["no_known_unused_overlap"]
    assert result["graph"]["validated_non_admitted_iocs"] == 0


def test_unknown_accounting_and_budget_unattempted_are_not_empty_success():
    snapshot = fixture()
    snapshot["run"].update(stop_reason="step_limit")
    del snapshot["steps"][0]["lookup"]["acquisition"]
    snapshot["steps"][1]["outcome_status"] = "rate_limited"
    snapshot["steps"][1]["lookup"]["status"] = "rate_limited"
    snapshot["steps"][1]["admission"]["accepted"] = False
    result = summarize(snapshot)
    assert result["lookups"]["accounting_unknown_receipts"] == 1
    assert result["lookups"]["fetch_attempts"] is None
    assert result["lookups"]["known_fetch_attempts"] == 1
    assert result["lookups"]["outcomes"]["rate_limited"] == 1
    assert "rate_limited" in by_value(result, "b")["reason_codes"]
    assert by_value(result, "z")["reason_codes"] == ["budget_stopped_before_attempt"]


def test_deferred_action_never_adds_tried_counter():
    snapshot = fixture()
    snapshot["steps"][0]["outcome_status"] = "deferred"
    snapshot["steps"][0]["lookup"]["status"] = "deferred"
    result = summarize(snapshot)
    assert result["lookups"]["attempts"] == 1
    assert by_value(result, "a")["attempts_as_input"] == 0


def test_selector_usage_tokens_cost_and_waiting_are_reported_without_guessing():
    snapshot = fixture()
    snapshot["run"]["algorithm"] = {"wait_seconds": 60, "decisions": [{"shortlist": [], "selected": [], "attempts": [
        {"status": "ok", "seconds": 2.0, "model": "m", "usage": {
            "prompt_tokens": 100, "completion_tokens": 20, "total_tokens": 120, "cost": 0.01}},
        {"status": "error", "seconds": 1.0, "error": "TimeoutError"}]}]}
    metrics = summarize(snapshot)
    assert metrics["selector"]["calls"] == 2
    assert metrics["selector"]["successful_calls"] == 1
    assert metrics["selector"]["failed_calls"] == 1
    assert metrics["selector"]["seconds"] == 3
    assert metrics["selector"]["known_total_tokens"] == 120
    assert metrics["selector"]["total_tokens"] is None
    assert metrics["selector"]["known_cost"] == 0.01 and metrics["selector"]["cost"] is None
    assert metrics["timing"]["known_rate_wait_seconds"] == 30
    assert metrics["timing"]["controller_wait_seconds"] == 60
    assert metrics["timing"]["throttle_wait_seconds"] == 90
