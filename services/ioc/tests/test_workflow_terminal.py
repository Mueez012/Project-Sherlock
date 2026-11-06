"""Scripted manual input and an offline real-runner terminal investigation."""
from copy import deepcopy
import io
import json
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

from ioc_hunter.main import main
from ioc_hunter.workflow.terminal import InvestigationTerminal, read_pasted_report


class FakeRunner:
    """Only exercises terminal controls; persistence is tested with the real runner below."""

    def __init__(self, mode="live"):
        self.result = {
            "run": {"id": "run-test", "status": "ready", "mode": mode}, "mode": mode,
            "graph": {"nodes": [
                {"id": "domain-node", "type": "domain", "value": "example.com", "origin": "report", "used": False},
                {"id": "hash-node", "type": "sha256", "value": "a" * 64, "origin": "report", "used": False},
            ], "edges": []}, "steps": [],
        }
        self.calls = []

    def get_result(self, run_id, include_evidence=False):
        return deepcopy(self.result)

    def list_methods(self, run_id, node_id):
        if node_id == "hash-node":
            return []
        return [{"id": method, "implemented": True, "selectable": method != "virustotal.domain_to_url",
                 "unavailable_reason": "unresolved_live_route", "availability": {"primary_transport": "browser"}}
                for method in ["rapiddns.domain_to_ipv4", "virustotal.domain_to_url"]]

    def execute_step(self, run_id, node_id, method_id):
        self.calls.append((run_id, node_id, method_id))
        self.result["graph"]["nodes"][0]["used"] = True
        step = {
            "id": "step-1", "sequence": 1, "method_id": method_id, "lookup_id": "lookup-1",
            "status": "completed", "outcome_status": "partial",
            "admission": {"accepted": False, "reason": "no_unused_overlap", "reward": None},
            "delta": {"new_nodes": 0, "new_edges": 0, "evidence_links": 0},
            "lookup": {"outputs": [{"type": "ipv4", "value": "192.0.2.10"}], "complete": False,
                       "partial_reasons": ["page_limit"], "rejected": [
                           {"message": "DNS evidence belongs to sub.example.com", "details": {"observed_domain": "sub.example.com"}},
                       ]},
        }
        self.result["steps"].append(step)
        return deepcopy(step)

    def finish(self, run_id, cancelled=False):
        self.result["run"]["status"] = "cancelled" if cancelled else "completed"
        return self.result["run"]

    def export_result(self, run_id, path, include_evidence=True):
        Path(path).write_text(json.dumps(self.result), encoding="utf-8")
        return self.result


class TerminalControlTests(unittest.TestCase):
    def run_script(self, runner, answers):
        output = []
        script = iter(answers)
        result = InvestigationTerminal(runner, input_fn=lambda prompt: next(script), output_fn=output.append).run("run-test")
        return result, "\n".join(output)

    def test_paste_keeps_paragraphs_and_requires_explicit_end(self):
        script = iter(["First paragraph.", "", "Second paragraph.", ".done"])
        result = read_pasted_report(input_fn=lambda prompt: next(script), output_fn=lambda message: None)
        self.assertEqual(result, "First paragraph.\n\nSecond paragraph.")

    def test_unresolved_method_hidden_and_not_runnable_after_all(self):
        runner = FakeRunner()
        result, output = self.run_script(runner, ["1", "2", "all", "2", "1", "details", "back", "save"])
        self.assertEqual(runner.calls, [("run-test", "domain-node", "rapiddns.domain_to_ipv4")])
        self.assertIn("unresolved", output)
        self.assertIn("Method unavailable for this run", output)
        self.assertIn("Choose a listed method", output)
        self.assertIn("Validated outputs are retained as evidence", output)
        self.assertIn("Partial retrieval: page_limit", output)
        self.assertIn("DNS evidence belongs to sub.example.com", output)
        self.assertIn('"observed_domain": "sub.example.com"', output)
        self.assertEqual(result["run"]["status"], "ready")

    def test_unsupported_seed_stays_visible_and_cancel_preserves_run(self):
        runner = FakeRunner()
        result, output = self.run_script(runner, ["2", "cancel"])
        self.assertIn("no implemented methods", output)
        self.assertEqual(result["run"]["status"], "cancelled")
        self.assertEqual(len(result["graph"]["nodes"]), 2)
        self.assertEqual(runner.calls, [])

    def test_eof_leaves_run_resumable(self):
        runner, output = FakeRunner(), []
        def eof(prompt):
            raise EOFError
        result = InvestigationTerminal(runner, input_fn=eof, output_fn=output.append).run("run-test")
        self.assertEqual(result["run"]["status"], "ready")
        self.assertIn("Saved investigation", "\n".join(output))

    def test_cli_rejects_missing_dataset_row_before_runner_creation(self):
        with patch("sys.stderr", new_callable=io.StringIO):
            with self.assertRaises(SystemExit) as caught:
                main(["investigate", "--dataset", "reports.csv"])
        self.assertEqual(caught.exception.code, 2)


class RealWorkflowTerminalTests(unittest.TestCase):
    def test_terminal_selection_persists_reopens_and_exports_real_evidence(self):
        from ioc_hunter.workflow.models import RunConfig
        from ioc_hunter.workflow.models import node_id
        from ioc_hunter.workflow.runner import build_runner
        from ioc_hunter.models import IOC

        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            example = Path(__file__).resolve().parents[1] / "examples" / "manual-workflow"
            manifest = example / "replay.json"
            runner = build_runner(root / "store", config=RunConfig(mode="replay"), replay_path=manifest)
            run = runner.create_run((example / "report.txt").read_text(encoding="utf-8"))
            before = runner.get_result(run["id"])
            seed = next(node for node in before["graph"]["nodes"] if node["type"] == "domain")
            unsupported = next(node for node in before["graph"]["nodes"] if node["type"] == "sha256")
            discovered = node_id(IOC("192.0.2.12", "ipv4"))
            script = iter([unsupported["id"], seed["id"], "rapiddns.domain_to_ipv4", "back",
                           discovered, "rapiddns.ipv4_to_domain", "back", "save"])
            output = []
            InvestigationTerminal(runner, input_fn=lambda prompt: next(script), output_fn=output.append).run(run["id"])
            reopened = build_runner(root / "store", run_id=run["id"])
            reopened.resume(run["id"])
            result = reopened.get_result(run["id"], include_evidence=True)
            self.assertEqual(len(result["steps"]), 2)
            self.assertEqual(result["mode"], "replay")
            self.assertEqual(result["steps"][0]["method_id"], "rapiddns.domain_to_ipv4")
            self.assertEqual(result["steps"][0]["outcome_status"], "ok")
            self.assertTrue(result["steps"][0]["admission"]["accepted"])
            self.assertFalse(result["steps"][1]["admission"]["accepted"])
            self.assertEqual(len(result["graph"]["edges"]), 2)
            self.assertIn("sub.example.com", "\n".join(output))
            self.assertIn("No implemented methods for sha256", "\n".join(output))
            self.assertTrue(any(node["id"] == unsupported["id"] for node in result["graph"]["nodes"]))
            def eof(prompt):
                raise EOFError
            interrupted = InvestigationTerminal(reopened, input_fn=eof, output_fn=lambda message: None).run(run["id"])
            self.assertEqual(interrupted["run"]["id"], run["id"])
            self.assertEqual(interrupted["run"]["status"], "ready")
            again = build_runner(root / "store", run_id=run["id"])
            again.resume(run["id"])
            cancelled = InvestigationTerminal(again, input_fn=lambda prompt: "cancel", output_fn=lambda message: None).run(run["id"])
            self.assertEqual(cancelled["run"]["status"], "cancelled")
            self.assertEqual(cancelled["graph"], result["graph"])
            self.assertEqual(len(cancelled["steps"]), 2)
            export = root / "investigation.json"
            again.export_result(run["id"], export)
            saved = json.loads(export.read_text(encoding="utf-8"))
            self.assertEqual(saved["mode"], "replay")
            self.assertTrue(saved["evidence"]["lookups"])


if __name__ == "__main__":
    unittest.main()
