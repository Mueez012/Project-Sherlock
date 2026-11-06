"""Interactive manual investigation, using the same durable runner as other clients."""
from __future__ import annotations

import json
from pathlib import Path
from typing import Callable


UNRESOLVED_METHOD = "virustotal.domain_to_url"


def read_pasted_report(*, input_fn: Callable[[str], str] = input,
                       output_fn: Callable[[str], None] = print) -> str:
    """Read multiline report text without treating blank lines as the end."""
    output_fn("Paste the report. Enter .done on a line by itself to finish.")
    lines = []
    while True:
        line = input_fn("report> ")
        if line == ".done":
            break
        lines.append(line)
    text = "\n".join(lines)
    if not text.strip():
        raise ValueError("The report is empty.")
    return text


def _select(value: str, rows: list[dict]) -> dict | None:
    if value.isdecimal():
        index = int(value) - 1
        return rows[index] if 0 <= index < len(rows) else None
    return next((row for row in rows if row["id"] == value), None)


class InvestigationTerminal:
    """A prompt adapter only; extraction, lookup and graph rules live in the runner."""

    def __init__(self, runner, *, input_fn: Callable[[str], str] = input,
                 output_fn: Callable[[str], None] = print):
        self.runner = runner
        self.input = input_fn
        self.output = output_fn

    def _write(self, text: str = "") -> None:
        self.output(text)

    def _nodes(self, result: dict, start: int = 0) -> list[dict]:
        nodes = result["graph"]["nodes"]
        self._write(f"\nInvestigation {result['run']['id']} | {result.get('mode', result['run'].get('mode', 'unknown'))} | "
                    f"{result['run']['status']} | {len(nodes)} IOCs, {len(result['graph']['edges'])} edges")
        if result["run"].get("stop_reason"):
            self._write("Stop reason: " + result["run"]["stop_reason"])
        for index, node in enumerate(nodes[start:start + 50], start + 1):
            methods = self.runner.list_methods(result["run"]["id"], node["id"])
            supported = any(method.get("implemented", True) for method in methods)
            flags = [node.get("origin", "unknown"), "used" if node.get("used") else "unused"]
            if not supported:
                flags.append("no implemented methods")
            elif not any(method.get("selectable", True) for method in methods):
                flags.append("no selectable methods")
            value = node["value"].replace("\n", " ")
            preview = value if len(value) <= 140 else value[:137] + "..."
            self._write(f"  {index}. {node['type']}: {preview} [{', '.join(flags)}]")
        if len(nodes) > 50:
            self._write(f"Showing {start + 1}-{min(start + 50, len(nodes))} of {len(nodes)}. "
                        "Use iocs START_NUMBER to see another page; ioc NUMBER shows full details.")
        if not nodes:
            self._write("No IOCs were extracted. The report and extraction diagnostics remain saved.")
        return nodes

    def _steps(self, result: dict) -> None:
        steps = result["steps"]
        if not steps:
            self._write("No lookup steps yet.")
        for index, step in enumerate(steps, 1):
            admission = "admitted" if step["admission"]["accepted"] else "not admitted"
            self._write(f"  {index}. {step['method_id']} | {step['outcome_status']} | {admission} | {step['id']}")

    def _step_summary(self, step: dict) -> None:
        receipt = step.get("lookup") or {}
        outputs = receipt.get("outputs", [])
        rejected = receipt.get("rejected", [])
        admission = step["admission"]
        delta = step.get("delta", {})
        self._write(f"\nStep {step['sequence']}: {step['method_id']} | {step['outcome_status']}")
        self._write(f"Lookup {step.get('lookup_id') or '(not started)'} | "
                    f"{len(outputs)} validated outputs, {len(rejected)} rejections")
        if receipt.get("cache_hit"):
            self._write("Retrieval used a saved source response from the cache.")
        for candidate in outputs[:8]:
            self._write(f"  {candidate['type']}: {candidate['value']}")
        if len(outputs) > 8:
            self._write(f"  {len(outputs) - 8} more outputs; use details for the complete receipt.")
        if receipt.get("complete") is False:
            self._write("Partial retrieval: " + ", ".join(receipt.get("partial_reasons", []) or ["provider results incomplete"]))
        if step.get("error") or receipt.get("error"):
            self._write("Error: " + str(step.get("error") or receipt["error"]))
        self._write(f"Graph admission: {'accepted' if admission['accepted'] else 'not admitted'} "
                    f"({admission['reason']}). Paper reward: not evaluated.")
        if outputs and not admission["accepted"]:
            self._write("Validated outputs are retained as evidence; this step did not admit them to the graph.")
        self._write(f"Graph changes: {delta.get('new_nodes', 0)} new nodes, "
                    f"{delta.get('new_edges', 0)} new edges, {delta.get('evidence_links', 0)} evidence links.")
        for rejected_row in rejected[:3]:
            self._write("Rejected: " + str(rejected_row.get("message") or rejected_row.get("reason", "unsupported evidence")))
        if len(rejected) > 3:
            self._write(f"{len(rejected) - 3} more rejections; use details to inspect the receipt.")
        self._write("Use details or details STEP_NUMBER to inspect evidence and rejection fields.")

    def _methods(self, run_id: str, node: dict, *, mode: str) -> None:
        catalogue = self.runner.list_methods(run_id, node["id"])
        implemented = [row for row in catalogue if row.get("implemented", True)]
        if not implemented:
            self._write(f"No implemented methods for {node['type']}. This IOC remains in the investigation.")
            return
        show_all = False
        while True:
            rows = [row for row in implemented if show_all or (
                row.get("selectable", True) and not (mode == "live" and row["id"] == UNRESOLVED_METHOD))]
            self._write(f"\nMethods for {node['type']}: {node['value']}")
            self._write("Local implementation/configuration is shown below; live provider access is not checked.")
            for index, method in enumerate(rows, 1):
                availability = method.get("availability") or {}
                local = []
                if availability.get("primary_transport"):
                    local.append(str(availability["primary_transport"]))
                if availability.get("browser_library_installed") is False:
                    local.append("browser library missing")
                if availability.get("api_key_configured"):
                    local.append("API key configured")
                local.append("live access unchecked" if mode == "live" else "fixture replay")
                if method["id"] == UNRESOLVED_METHOD:
                    local.append("unresolved live method")
                if not method.get("selectable", True):
                    local.append("unavailable: " + method.get("unavailable_reason", "not selectable"))
                self._write(f"  {index}. {method['id']} [{', '.join(local)}]")
            if not rows:
                self._write("No selectable methods in this run. Enter all to inspect unavailable methods, or back.")
            if mode == "live" and any(row["id"] == UNRESOLVED_METHOD for row in implemented):
                self._write("VirusTotal domain-to-URL remains unresolved. Hidden from default choices; enter all to inspect it.")
            choice = self.input("Method number/id, details, all, or back> ").strip()
            if choice.lower() in {"back", "b", ""}:
                return
            if choice.lower() == "all":
                show_all = True
                continue
            if choice.lower() == "details":
                steps = self.runner.get_result(run_id)["steps"]
                self._write(json.dumps(steps[-1], indent=2, ensure_ascii=False) if steps else "No lookup steps yet.")
                continue
            method = _select(choice, rows)
            if method is None:
                self._write("Choose a listed method number or full method ID, or enter back.")
                continue
            if not method.get("selectable", True) or (mode == "live" and method["id"] == UNRESOLVED_METHOD):
                self._write("Method unavailable for this run: " + method.get("unavailable_reason", "unresolved_live_route"))
                continue
            try:
                step = self.runner.execute_step(run_id, node["id"], method["id"])
            except (ValueError, KeyError, RuntimeError) as exc:
                self._write(f"Step not started: {exc}")
                return
            self._step_summary(step)
            # The runner may have completed the run after a configured limit.
            if self.runner.get_result(run_id)["run"]["status"] in {"completed", "cancelled", "failed"}:
                return

    def run(self, run_id: str) -> dict:
        """Operate an existing run; save leaves it resumable, finish/cancel close it."""
        self._write("Manual IOC investigation. Choose an IOC and a compatible method for each lookup.")
        self._write("Commands: iocs [START_NUMBER], ioc NUMBER, steps, details [STEP_NUMBER], export PATH, save, finish, cancel, help.")
        initial = self.runner.get_result(run_id)
        excluded = (initial.get("extraction") or {}).get("excluded_sections", [])
        if excluded:
            self._write(f"Excluded {len(excluded)} reference/navigation sections during extraction; retained in saved diagnostics.")
        for diagnostic in initial["run"].get("diagnostics", [])[:5]:
            self._write("Diagnostic: " + str(diagnostic.get("message") or diagnostic.get("kind", "see saved run")))
        page_start = 0
        try:
            while True:
                result = self.runner.get_result(run_id)
                nodes = self._nodes(result, page_start)
                if result["run"]["status"] in {"completed", "cancelled", "failed"}:
                    self._write("This investigation is closed. Its saved results can be inspected or exported.")
                    return result
                choice = self.input("IOC number/id or command> ").strip()
                command, _, argument = choice.partition(" ")
                command = command.lower()
                if command in {"save", "quit", "q", "exit"}:
                    self._write(f"Saved investigation {run_id}. Resume with investigate --resume {run_id} using the same store.")
                    return self.runner.get_result(run_id)
                if command in {"finish", "cancel"}:
                    self.runner.finish(run_id, cancelled=command == "cancel")
                    self._write("Investigation " + ("cancelled." if command == "cancel" else "completed."))
                    return self.runner.get_result(run_id)
                if command in {"help", "?", ""}:
                    self._write("Choose an IOC number or full ID, then a method. Use back to choose another IOC.")
                    self._write("save leaves the run resumable; finish completes it; cancel records cancellation. Neither removes evidence.")
                    continue
                if command == "iocs":
                    if argument.strip():
                        if not argument.strip().isdecimal() or not 1 <= int(argument.strip()) <= len(nodes):
                            self._write("Use iocs START_NUMBER with a listed IOC number.")
                            continue
                        page_start = int(argument.strip()) - 1
                    else:
                        page_start = 0
                    continue
                if command == "ioc":
                    node = _select(argument.strip(), nodes)
                    self._write(json.dumps(node, indent=2, ensure_ascii=False) if node else "Choose a listed IOC number or full ID.")
                    continue
                if command == "steps":
                    self._steps(result)
                    continue
                if command == "details":
                    steps = result["steps"]
                    step = _select(argument.strip(), steps) if argument.strip() else (steps[-1] if steps else None)
                    if step is None:
                        self._write("No matching step. Use steps to see saved step numbers and IDs.")
                    else:
                        self._write(json.dumps(step, indent=2, ensure_ascii=False))
                    continue
                if command == "export":
                    if not argument.strip():
                        self._write("Use export PATH, for example export investigation.json.")
                        continue
                    try:
                        self.runner.export_result(run_id, Path(argument.strip().strip('"')), include_evidence=True)
                        self._write(f"Exported investigation to {argument.strip()}.")
                    except (OSError, ValueError) as exc:
                        self._write(f"Export failed: {exc}")
                    continue
                node = _select(choice, nodes)
                if node is None:
                    self._write("Choose a listed IOC number or full ID, or enter help.")
                    continue
                self._methods(run_id, node, mode=result.get("mode", result["run"].get("mode", "live")))
        except (EOFError, KeyboardInterrupt):
            self._write(f"\nSaved investigation {run_id}. Resume it using the same store.")
            return self.runner.get_result(run_id)
