"""Read-only metrics and IOC participation from a saved workflow snapshot."""
from __future__ import annotations

from collections import Counter
from datetime import datetime
import math

from ...models import IOC, identity
from ..models import node_id

METRICS_VERSION = "algorithm1-v1"
USABLE = {"ok", "empty", "partial"}


def _identity(item):
    try:
        kind, value = identity(IOC(item["value"], item["type"]))
        return node_id(IOC(value, kind)), kind, value
    except (KeyError, ValueError, TypeError):
        return None


def _count(value):
    if isinstance(value, dict):
        return sum(number for number in value.values() if isinstance(number, (int, float)))
    return value if isinstance(value, (int, float)) else 0


def summarize(snapshot):
    """Derive metrics without changing histories, graph state or receipts.

    Counts of associations and exact occurrences are deliberately separate.
    Missing acquisition accounting is unknown, rather than zero requests.
    """
    run = snapshot.get("run", {})
    graph = snapshot.get("graph", {})
    nodes = {item["id"]: item for item in graph.get("nodes", [])}
    edges = graph.get("edges", [])
    extraction = snapshot.get("extraction") or {}
    if isinstance(extraction.get("extraction"), dict):
        extraction = extraction["extraction"]
    entities, seeds = {}, set()

    def entity(item, origin):
        ident = _identity(item)
        if ident is None:
            return None
        key, kind, value = ident
        row = entities.setdefault(key, {
            "ioc_id": key, "type": kind, "value": value, "origin": origin,
            "sentence_indices": [], "in_graph": key in nodes, "neighbor_count": None,
            "component_report_seed_count": None, "attempts_as_input": 0,
            "admissions_as_input": 0, "reason_codes": [], "step_ids": [], "lookup_ids": [],
        })
        if origin == "report":
            row["origin"] = "report"
            seeds.add(key)
        return row

    for item in extraction.get("iocs", []):
        row = entity(item, "report")
        if row:
            row["sentence_indices"] = list(item.get("sentence_indices", []))
    for item in nodes.values():
        row = entity(item, item.get("origin", "lookup"))
        if row:
            row["sentence_indices"] = list(dict.fromkeys(row["sentence_indices"] + item.get("sentence_indices", [])))
    for index, pairs in enumerate(extraction.get("matches", [])):
        for kind, value in pairs:
            row = entity({"type": kind, "value": value}, "report")
            if row and index not in row["sentence_indices"]:
                row["sentence_indices"].append(index)

    adjacency = {key: set() for key in nodes}
    for edge in edges:
        left, right = edge.get("left"), edge.get("right")
        if left in adjacency and right in adjacency:
            adjacency[left].add(right)
            adjacency[right].add(left)
    components, component_seeds = [], {}
    remaining = set(nodes)
    while remaining:
        first = min(remaining)
        component, pending = set(), [first]
        while pending:
            current = pending.pop()
            if current in component:
                continue
            component.add(current)
            pending.extend(adjacency[current] - component)
        remaining -= component
        components.append(component)
        count = len(component & seeds)
        component_seeds.update({key: count for key in component})

    receipts = {item.get("id"): item for item in snapshot.get("evidence", {}).get("lookups", [])}
    outcomes, methods = Counter(), {}
    fetches, cache_reads, rate_wait = 0, 0, 0.0
    accounting_known, accounting_unknown = 0, 0
    acquisition_wall, acquisition_active, unknown_durations = 0.0, 0.0, 0
    reads = Counter()
    selector_attempts = []

    def append_unique(row, field, value):
        if value and value not in row[field]:
            row[field].append(value)

    for step in snapshot.get("steps", []):
        record = step.get("lookup") or receipts.get(step.get("lookup_id")) or {}
        outcome = step.get("outcome_status") or record.get("status", "pending")
        finalized = step.get("status") == "completed" and outcome not in {"pending", "deferred"}
        input_id = step.get("input_node_id")
        if input_id not in entities and record.get("input_ioc"):
            row = entity(record["input_ioc"], "lookup")
            input_id = row["ioc_id"] if row else input_id
        admission = step.get("admission") or {}
        input_row = entities.get(input_id)
        if input_row:
            append_unique(input_row, "step_ids", step.get("id"))
            append_unique(input_row, "lookup_ids", step.get("lookup_id") or record.get("id"))
            if finalized:
                input_row["attempts_as_input"] += 1
                input_row["admissions_as_input"] += bool(admission.get("accepted"))
            if outcome not in {"ok", "pending"}:
                append_unique(input_row, "reason_codes", outcome)
            append_unique(input_row, "reason_codes", record.get("outcome_reason"))
            if not admission.get("accepted"):
                append_unique(input_row, "reason_codes", admission.get("reason"))
        if record.get("status") in USABLE or outcome in USABLE:
            for output in record.get("outputs", []):
                row = entity(output, "lookup")
                if not row:
                    continue
                append_unique(row, "step_ids", step.get("id"))
                append_unique(row, "lookup_ids", step.get("lookup_id") or record.get("id"))
                if not admission.get("accepted"):
                    append_unique(row, "reason_codes", admission.get("reason") or "batch_not_admitted")
        if not finalized:
            continue
        outcomes[outcome] += 1
        method_id = step.get("method_id", record.get("method_id", "unknown"))
        method = methods.setdefault(method_id, {"tried": 0, "coverage": 0, "outcomes": Counter(),
                                                "exposed_rounds": 0, "selected_rounds": 0})
        method["tried"] += 1
        method["coverage"] += bool(admission.get("accepted"))
        method["outcomes"][outcome] += 1
        accounting = record.get("acquisition")
        if isinstance(accounting, dict) and "fetch_attempts" in accounting:
            accounting_known += 1
            fetches += _count(accounting.get("fetch_attempts"))
            cache_reads += _count(accounting.get("cache_reads"))
            rate_wait += _count(accounting.get("rate_wait_seconds"))
            for name in ("external_fetch_attempts", "parsed_pages", "followups_scheduled", "followups_executed", "retry_attempts"):
                reads[name] += _count(accounting.get(name))
        else:
            accounting_unknown += 1
        try:
            duration = max(0, (datetime.fromisoformat(record["finished_at"]) -
                              datetime.fromisoformat(record["started_at"])).total_seconds())
            acquisition_wall += duration
            acquisition_active += max(0, duration - _count((accounting or {}).get("rate_wait_seconds")))
        except (KeyError, TypeError, ValueError):
            unknown_durations += 1

    algorithm = run.get("algorithm") or {}
    decisions = algorithm.get("decisions", [])
    if isinstance(decisions, dict):
        decisions = list(decisions.values())
    for decision in decisions:
        selector_attempts.extend(decision.get("attempts", []))
        compatible = decision.get("shortlist", decision.get("ranked_methods", []))
        exposed = set(item if isinstance(item, str) else item.get("method_id", item.get("id")) for item in compatible)
        selected = decision.get("selected_method_ids", decision.get("selected_methods", decision.get("selected", [])))
        selected = set(item if isinstance(item, str) else item.get("method_id", item.get("id")) for item in selected)
        for method_id in exposed | selected:
            if not method_id:
                continue
            method = methods.setdefault(method_id, {"tried": 0, "coverage": 0, "outcomes": Counter(),
                                                    "exposed_rounds": 0, "selected_rounds": 0})
            method["exposed_rounds"] += method_id in exposed
            method["selected_rounds"] += method_id in selected
        input_row = entities.get(decision.get("input_node_id", decision.get("node_id", decision.get("active_node_id"))))
        if input_row and not selected:
            append_unique(input_row, "reason_codes", decision.get("reason") or (
                "selector_error" if decision.get("status") == "failed" else
                "not_selected" if exposed else "no_compatible_methods"))

    active = entities.get(algorithm.get("active_node_id"))
    if active and algorithm.get("wait"):
        append_unique(active, "reason_codes", algorithm["wait"].get("reason"))

    for key, row in entities.items():
        if key in nodes:
            row["in_graph"] = True
            row["neighbor_count"] = len(adjacency[key])
            row["component_report_seed_count"] = component_seeds[key]
        if row["origin"] == "report" and not row["attempts_as_input"] and not row["reason_codes"]:
            reason = "budget_stopped_before_attempt" if run.get("stop_reason") in {
                "step_limit", "time_limit", "node_limit", "initial_node_limit"} else "not_yet_processed"
            append_unique(row, "reason_codes", reason)
        row["sentence_indices"].sort()
    for method in methods.values():
        method["batch_rate"] = method["coverage"] / method["tried"] if method["tried"] else None
        method["selection_rate"] = method["selected_rounds"] / method["exposed_rounds"] if method["exposed_rounds"] else None
        method["outcomes"] = dict(method["outcomes"])
    participation = sorted(entities.values(), key=lambda item: (item["origin"] != "report", item["type"], item["value"]))
    largest = max(components, key=lambda part: (len(part), sorted(part)), default=set())
    attempts = sum(outcomes.values())
    admitted = sum(method["coverage"] for method in methods.values())
    usable = sum(outcomes[status] for status in USABLE)
    token_totals, known_usage, unknown_usage = Counter(), 0, 0
    known_cost, unknown_cost, cost_total = 0, 0, 0.0
    for attempt in selector_attempts:
        usage = attempt.get("usage")
        if not isinstance(usage, dict):
            unknown_usage += 1
            unknown_cost += 1
            continue
        values = {"input_tokens": usage.get("input_tokens", usage.get("prompt_tokens")),
                  "output_tokens": usage.get("output_tokens", usage.get("completion_tokens")),
                  "total_tokens": usage.get("total_tokens")}
        valid = lambda number: type(number) in {int, float} and math.isfinite(number) and number >= 0
        if values["total_tokens"] is None and valid(values["input_tokens"]) and valid(values["output_tokens"]):
            values["total_tokens"] = values["input_tokens"] + values["output_tokens"]
        if all(valid(number) for number in values.values()):
            known_usage += 1
            token_totals.update(values)
        else:
            unknown_usage += 1
        cost = usage.get("cost", usage.get("total_cost"))
        if valid(cost):
            known_cost += 1
            cost_total += cost
        else:
            unknown_cost += 1
    selector_seconds = sum(_count(attempt.get("seconds")) for attempt in selector_attempts)
    controller_wait = _count(algorithm.get("wait_seconds"))
    selector_metrics = {
        "calls": len(selector_attempts), "successful_calls": sum(item.get("status") == "ok" for item in selector_attempts),
        "failed_calls": sum(item.get("status") != "ok" for item in selector_attempts), "seconds": selector_seconds,
        "models": sorted({str(item["model"]) for item in selector_attempts if item.get("model")}),
        "usage_known_calls": known_usage, "usage_unknown_calls": unknown_usage,
        "known_cost": cost_total, "cost": (cost_total if not selector_attempts or known_cost and not unknown_cost else None),
        "cost_known_calls": known_cost, "cost_unknown_calls": unknown_cost,
    }
    for name in ("input_tokens", "output_tokens", "total_tokens"):
        selector_metrics[name] = token_totals[name] if not selector_attempts or known_usage and not unknown_usage else None
        selector_metrics["known_" + name] = token_totals[name]
    return {
        "metrics_version": METRICS_VERSION, "run_id": run.get("id"),
        "graph_revision": run.get("graph_revision", 0), "status": run.get("status"),
        "stop_reason": run.get("stop_reason", ""),
        "extraction": {"unique_iocs": len(seeds), "sentences": len(extraction.get("sentences", [])),
                       "ioc_sentence_associations": sum(len(entities[key]["sentence_indices"]) for key in seeds)},
        "lookups": {"attempts": attempts, "outcomes": dict(outcomes), "admitted_batches": admitted,
                    "batch_rate": admitted / attempts if attempts else None,
                    "admission_among_usable": admitted / usable if usable else None,
                    "fetch_attempts": fetches if accounting_known and not accounting_unknown else None,
                    "cache_reads": cache_reads if accounting_known and not accounting_unknown else None,
                    "rate_wait_seconds": rate_wait if accounting_known and not accounting_unknown else None,
                    "known_fetch_attempts": fetches, "known_cache_reads": cache_reads,
                    "known_rate_wait_seconds": rate_wait,
                    **{name: reads[name] if accounting_known and not accounting_unknown else None for name in (
                        "external_fetch_attempts", "parsed_pages", "followups_scheduled", "followups_executed", "retry_attempts")},
                    "accounting_known_receipts": accounting_known, "accounting_unknown_receipts": accounting_unknown,
                    "accounting_scope": "top_level_fetches_not_browser_xhr_or_provider_quota"},
        "methods": methods,
        "selector": selector_metrics,
        "timing": {"processing_seconds": run.get("elapsed_seconds"), "selector_seconds": selector_seconds,
                   "acquisition_wall_seconds": acquisition_wall if not unknown_durations else None,
                   "acquisition_active_seconds": acquisition_active if not unknown_durations and not accounting_unknown else None,
                   "known_acquisition_wall_seconds": acquisition_wall,
                   "known_rate_wait_seconds": rate_wait, "controller_wait_seconds": controller_wait,
                   "known_throttle_wait_seconds": rate_wait + controller_wait,
                   "throttle_wait_seconds": rate_wait + controller_wait if not accounting_unknown else None,
                   "unknown_duration_receipts": unknown_durations},
        "graph": {"nodes": len(nodes), "edges": len(edges), "components": len(components),
                  "report_seeds": len(seeds), "discovered_nodes": len(set(nodes) - seeds),
                  "isolated_report_iocs": sum(key in adjacency and not adjacency[key] for key in seeds),
                  "seed_containing_components": sum(bool(part & seeds) for part in components),
                  "largest_component_nodes": len(largest), "largest_component_report_seeds": len(largest & seeds),
                  "validated_non_admitted_iocs": sum(not row["in_graph"] for row in participation)},
        "ioc_participation": participation,
    }
