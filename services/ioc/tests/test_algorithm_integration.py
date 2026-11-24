"""Real Algorithm 1 + extraction + workflow receipts, entirely offline."""
import json
from pathlib import Path
import socket
from unittest.mock import patch

import pytest

from ioc_hunter.workflow.algorithm.batch import run_dataset
from ioc_hunter.workflow.algorithm.controller import AlgorithmController
from ioc_hunter.workflow.algorithm.dataset import prepare_dataset, prepare_report
from ioc_hunter.workflow.algorithm.models import AlgorithmConfig
from ioc_hunter.workflow.algorithm.statistics import summarize
from ioc_hunter.workflow.models import RunConfig
from ioc_hunter.workflow.runner import build_runner


EXAMPLE = Path(__file__).resolve().parents[1] / "examples" / "manual-workflow"
METHOD = "rapiddns.domain_to_ipv4"
V6 = "rapiddns.domain_to_ipv6"


class SelectedMethods:
    def __init__(self, *methods):
        self.methods = methods
        self.calls = []

    def select(self, request):
        self.calls.append(request)
        allowed = {method["id"] for method in request["methods"]}
        return {"selection": {"methods": [{"method_id": method, "reason": "offline test selection"}
                                          for method in self.methods if method in allowed]},
                "usage": None, "model": "test-selector"}


def artifact(identifier=17, *, text=None):
    text = text or (EXAMPLE / "report.txt").read_text(encoding="utf-8")
    return prepare_report({"report_id": identifier, "text": text,
                           "sentences": text.splitlines(), "group": "Test Actor", "label": 0,
                           "cut_by_excel": False}, split="train", build_id="integration")


@pytest.fixture
def runner(tmp_path):
    return build_runner(tmp_path / "store", RunConfig(mode="replay", max_steps=30), EXAMPLE / "replay.json")


def test_five_rounds_full_batch_repeated_coverage_and_isolated_seed(runner):
    selector = SelectedMethods(METHOD)
    controller = AlgorithmController(runner, selector)
    prepared = artifact()
    with patch.object(socket.socket, "connect", side_effect=AssertionError("Unexpected external request")):
        run = controller.create(prepared, AlgorithmConfig(alpha=1.0, method_ids=(METHOD,)), experiment_id="one")
        result = controller.run(run["id"])
    assert result["run"]["stop_reason"] == "candidate_exhausted"
    assert result["run"]["algorithm"]["method_history"][METHOD] == {"tried": 5, "coverage": 5}
    assert len(selector.calls) == 5
    assert len(result["steps"]) == 5
    assert len(result["graph"]["nodes"]) == 4
    assert len(result["graph"]["edges"]) == 2
    assert result["steps"][0]["delta"]["new_nodes"] == 1
    assert all(step["delta"]["new_nodes"] == step["delta"]["new_edges"] == 0 for step in result["steps"][1:])
    assert all(step["admission"]["reward"] == 1 for step in result["steps"])
    assert all(node["used"] for node in result["graph"]["nodes"])
    assert {passage["id"] for passage in result["extraction"]["passages"]} == {
        item["id"] for item in prepared["sentences"]}
    stats = summarize(result)
    sha = next(item for item in stats["ioc_participation"] if item["type"] == "sha256")
    assert sha["in_graph"] and sha["neighbor_count"] == 0
    assert "no_compatible_methods" in sha["reason_codes"]
    assert stats["methods"][METHOD]["selected_rounds"] == 5


def test_resume_after_committed_first_method_keeps_selection_order(runner):
    selector = SelectedMethods(METHOD, V6)
    controller = AlgorithmController(runner, selector)
    run = controller.create(artifact(), AlgorithmConfig(alpha=1.0, method_ids=(METHOD, V6)), experiment_id="resume")
    commit = runner.repository.commit_step
    interrupted = False

    def commit_then_interrupt(*args, **kwargs):
        nonlocal interrupted
        result = commit(*args, **kwargs)
        if not interrupted:
            interrupted = True
            raise KeyboardInterrupt()
        return result

    with patch.object(runner.repository, "commit_step", side_effect=commit_then_interrupt):
        with pytest.raises(KeyboardInterrupt):
            controller.run(run["id"])
    saved = runner.repository.get_run(run["id"])
    assert saved["algorithm"]["next_method_index"] == 1
    assert saved["algorithm"]["method_history"][METHOD] == {"tried": 1, "coverage": 1}
    resumed_selector = SelectedMethods(METHOD, V6)
    reopened = build_runner(runner.client.store.directory, run_id=run["id"])
    result = AlgorithmController(reopened, resumed_selector).run(run["id"])
    assert result["run"]["stop_reason"] == "candidate_exhausted"
    assert len(resumed_selector.calls) == 4  # The saved first-round selection is reused.
    assert [step["method_id"] for step in result["steps"]] == [METHOD, V6] * 5
    assert result["run"]["algorithm"]["method_history"][METHOD] == {"tried": 5, "coverage": 5}
    assert result["run"]["algorithm"]["method_history"][V6] == {"tried": 5, "coverage": 0}
    # Reopening completed work makes no further acquisition or counter updates.
    assert AlgorithmController(reopened, resumed_selector).run(run["id"])["run"] == result["run"]


def test_valid_empty_selections_finish_rounds_without_lookup_steps(runner):
    selector = SelectedMethods()
    controller = AlgorithmController(runner, selector)
    run = controller.create(artifact(), AlgorithmConfig(alpha=0, method_ids=(METHOD,)), experiment_id="empty")
    result = controller.run(run["id"])
    assert result["run"]["stop_reason"] == "candidate_exhausted"
    assert not result["steps"] and not result["graph"]["edges"]
    assert len(selector.calls) == 5
    assert len(result["run"]["algorithm"]["decisions"]) == 15
    assert result["run"]["algorithm"]["method_history"][METHOD] == {"tried": 0, "coverage": 0}


def test_no_compatible_methods_finishes_without_calling_selector(runner):
    class ForbiddenSelector:
        def select(self, request):
            raise AssertionError("No compatible method should not call model")

    prepared = artifact(text="Observed 192.0.2.10.")
    controller = AlgorithmController(runner, ForbiddenSelector())
    run = controller.create(prepared, AlgorithmConfig(alpha=1, method_ids=(METHOD,)), experiment_id="no-method")
    result = controller.run(run["id"])
    assert result["run"]["stop_reason"] == "candidate_exhausted"
    assert len(result["run"]["algorithm"]["decisions"]) == 5
    assert not result["steps"] and result["graph"]["nodes"][0]["used"]


def test_new_only_outputs_remain_in_participation_without_graph_admission(runner):
    controller = AlgorithmController(runner, SelectedMethods(METHOD))
    run = controller.create(artifact(text="The loader contacted example.com."),
                            AlgorithmConfig(alpha=1, method_ids=(METHOD,)), experiment_id="new-only")
    result = controller.run(run["id"])
    assert len(result["graph"]["nodes"]) == 1 and not result["graph"]["edges"]
    assert result["run"]["algorithm"]["method_history"][METHOD] == {"tried": 5, "coverage": 0}
    stats = summarize(result)
    assert stats["graph"]["validated_non_admitted_iocs"] == 2
    outside = [item for item in stats["ioc_participation"] if not item["in_graph"]]
    assert all(item["reason_codes"] == ["no_known_unused_overlap"] for item in outside)


def test_incremental_batch_skips_completed_runs_and_rebuilds_missing_export(tmp_path):
    source, build, store = tmp_path / "d2", tmp_path / "build", tmp_path / "store"
    source.mkdir()
    text = (EXAMPLE / "report.txt").read_text(encoding="utf-8")
    reports = [{"report_id": ident, "text": text, "sentences": text.splitlines(),
                "group": "Test Actor", "label": 0, "cut_by_excel": False} for ident in (17, 18)]
    (source / "train.jsonl").write_text("".join(json.dumps(report) + "\n" for report in reports), encoding="utf-8")
    prepare_dataset(source, build)
    selector_path = tmp_path / "selector.json"
    selector_path.write_text(json.dumps({"example.com": [{"method_id": METHOD, "reason": "offline"}]}), encoding="utf-8")
    config = {"alpha": 1.0, "method_ids": [METHOD], "mode": "replay", "replay": str(EXAMPLE / "replay.json"),
              "selector": {"kind": "fixture", "path": str(selector_path)}, "limits": {"max_steps": 30}}
    first = run_dataset(build, "batch", config=config, store_directory=store, max_reports=1)
    assert first["processed"] == 1 and first["summary"]["reports"] == 1
    second = run_dataset(build, "batch", store_directory=store)
    assert second["processed"] == 1 and second["summary"]["reports"] == 2
    path = build / "experiments" / "batch" / "reports" / "17.json"
    original = json.loads(path.read_text(encoding="utf-8"))
    path.unlink()
    with patch("ioc_hunter.workflow.algorithm.selector.FixtureSelector.select",
               side_effect=AssertionError("Completed report requested model again")):
        third = run_dataset(build, "batch", store_directory=store)
    assert third["processed"] == 0
    assert json.loads(path.read_text(encoding="utf-8")) == original
    assert (build / "experiments" / "batch" / "summaries" / "reports.csv").exists()
