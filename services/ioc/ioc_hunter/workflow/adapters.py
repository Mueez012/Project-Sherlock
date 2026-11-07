"""Terminal compatibility adapter over the shared investigation application."""

import json
from dataclasses import asdict
from pathlib import Path
from uuid import uuid4

from .errors import WorkflowServiceError
from .service import InvestigationService


class TerminalWorkflowAdapter:
    """Translate the existing prompt interface without duplicating workflow rules."""

    def __init__(self, service: InvestigationService, actor_id: str, config=None):
        self.service = service
        self.actor_id = actor_id
        self.config = config

    def create_run(self, text, source="cti report", *, include_references=False, extended_types=False):
        limits = asdict(self.config) if self.config else {}
        limits.pop("mode", None)
        result, _ = self.service.create(
            self.actor_id,
            {
                "text": text,
                "source": source,
                "include_references": include_references,
                "extended_types": extended_types,
                "limits": limits,
            },
            uuid4().hex,
        )
        return result["run"]

    def list_runs(self):
        # CLI retains its unpaginated interface while respecting shared ownership.
        first = self.service.list(self.actor_id, limit=200)
        runs = [item["run"] | {"report": item["report"]} for item in first["items"]]
        for offset in range(200, first["total"], 200):
            page = self.service.list(self.actor_id, limit=200, offset=offset)
            runs.extend(item["run"] | {"report": item["report"]} for item in page["items"])
        return runs

    def get_result(self, run_id, include_evidence=False):
        # Terminal details and HTTP downloads use the exact same saved assembly.
        return self.service.export(self.actor_id, run_id, include_evidence=include_evidence)

    def list_methods(self, run_id, input_node_id):
        return self.service.methods(self.actor_id, run_id, input_node_id)["methods"]

    def execute_step(self, run_id, input_node_id, method_id, *, step_id=None):
        revision = self.service.read(self.actor_id, run_id)["run"]["graph_revision"]
        return self.service.execute(
            self.actor_id,
            run_id,
            input_node_id,
            method_id,
            step_id or uuid4().hex,
            revision,
        )["step"]

    def resume(self, run_id):
        saved = self.service.read(self.actor_id, run_id)
        if self.config and self.config.mode != saved["run"]["mode"]:
            raise WorkflowServiceError("saved_configuration_unavailable", "Cannot change a saved investigation's mode.")
        return self.service.resume(self.actor_id, run_id)["run"]

    def finish(self, run_id, cancelled=False):
        return self.service.close(self.actor_id, run_id, "cancel" if cancelled else "finish")["run"]

    def export_result(self, run_id, path, include_evidence=True):
        result = self.service.export(self.actor_id, run_id, include_evidence=include_evidence)
        target = Path(path)
        target.parent.mkdir(parents=True, exist_ok=True)
        temporary = target.with_name(target.name + ".tmp")
        temporary.write_text(json.dumps(result, indent=2, ensure_ascii=False), encoding="utf-8")
        temporary.replace(target)
        return result
