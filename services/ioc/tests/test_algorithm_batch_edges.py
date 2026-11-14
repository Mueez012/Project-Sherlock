"""Batch identity, failed local inputs and durable controller wait boundaries."""
import json
from pathlib import Path
from unittest.mock import patch

import pytest

from ioc_hunter.workflow.algorithm.batch import run_dataset
from ioc_hunter.workflow.algorithm.controller import AlgorithmController
from ioc_hunter.workflow.algorithm.dataset import atomic_json, load_prepared, prepare_dataset, prepare_report
from ioc_hunter.workflow.algorithm.models import AlgorithmConfig
from ioc_hunter.workflow.models import RunConfig
from ioc_hunter.workflow.runner import build_runner

EXAMPLE = Path(__file__).resolve().parents[1] / "examples" / "manual-workflow"
METHOD = "rapiddns.domain_to_ipv4"


def row(identifier=17):
    text = "The loader contacted example.com.\nThe server was 192.0.2.10."
    return {"report_id": identifier, "text": text, "sentences": text.splitlines(),
            "group": "TOP_SECRET_ACTOR_LABEL", "label": 24, "cut_by_excel": False}


def setup_batch(tmp_path):
    source, build, store = tmp_path / "d2", tmp_path / "build", tmp_path / "store"
    source.mkdir()
    (source / "train.jsonl").write_text(json.dumps(row()) + "\n", encoding="utf-8")
    prepare_dataset(source, build)
    selector = tmp_path / "selector.json"
    selector.write_text(json.dumps({"example.com": [{"method_id": METHOD, "reason": "fixture"}]}), encoding="utf-8")
    config = {"alpha": 1.0, "method_ids": [METHOD], "mode": "replay", "replay": str(EXAMPLE / "replay.json"),
              "selector": {"kind": "fixture", "path": str(selector)}, "limits": {"max_steps": 30}}
    return source, build, store, config, selector


def test_changed_experiment_config_and_source_settings_rejected(tmp_path):
    source, build, store, config, _ = setup_batch(tmp_path)
    first = run_dataset(build, "identity", config=config, store_directory=store)
    with pytest.raises(ValueError, match="configuration changed"):
        run_dataset(build, "identity", config={**config, "alpha": 2.0}, store_directory=store)
    again = run_dataset(build, "identity", store_directory=store)
    assert again["items"]["17"]["run_id"] == first["items"]["17"]["run_id"]
    assert again["processed"] == 0
    (source / "train.jsonl").write_text(json.dumps(row(18)) + "\n", encoding="utf-8")
    with pytest.raises(ValueError, match="settings changed"):
        prepare_dataset(source, build)


def test_invalid_report_is_recorded_and_following_reports_are_prepared(tmp_path):
    source, build = tmp_path / "source", tmp_path / "build"
    source.mkdir()
    invalid = {**row(17), "text": ""}
    (source / "train.jsonl").write_text(json.dumps(invalid) + "\n" + json.dumps(row(18)) + "\n", encoding="utf-8")
    result = prepare_dataset(source, build)
    assert result["counts"] == {"prepared": 1, "failed": 1, "total": 2}
    assert result["reports"][0]["status"] == "failed"
    assert result["reports"][1]["status"] == "prepared"


def test_changed_selector_fixture_rejected_even_after_completed_report(tmp_path):
    _, build, store, config, selector = setup_batch(tmp_path)
    run_dataset(build, "selector-content", config=config, store_directory=store)
    selector.write_text(json.dumps({"example.com": []}), encoding="utf-8")
    with pytest.raises(ValueError, match="content changed"):
        run_dataset(build, "selector-content", store_directory=store)


def test_changed_replay_body_rejected_for_same_experiment(tmp_path):
    _, build, store, config, _ = setup_batch(tmp_path)
    replay_dir = tmp_path / "replay"
    replay_dir.mkdir()
    replay = replay_dir / "replay.json"
    replay.write_text((EXAMPLE / "replay.json").read_text(encoding="utf-8"), encoding="utf-8")
    body = replay_dir / "rapiddns.html"
    body.write_text((EXAMPLE / "rapiddns.html").read_text(encoding="utf-8"), encoding="utf-8")
    config["replay"] = str(replay)
    run_dataset(build, "replay-content", config=config, store_directory=store)
    body.write_text(body.read_text(encoding="utf-8") + "<!-- changed -->", encoding="utf-8")
    with pytest.raises(ValueError, match="content changed"):
        run_dataset(build, "replay-content", store_directory=store)


def test_invalid_provider_profile_does_not_publish_experiment(tmp_path):
    _, build, store, config, _ = setup_batch(tmp_path)
    config["provider_limits"] = {"rapiddns": {"interval": -1}}
    with pytest.raises(ValueError, match="interval"):
        run_dataset(build, "invalid-profile", config=config, store_directory=store)
    assert not (build / "experiments" / "invalid-profile" / "experiment.json").exists()


def test_actor_labels_not_in_selector_request_and_passage_tampering_rejected(tmp_path):
    class InspectSelector:
        def select(self, request):
            assert "TOP_SECRET_ACTOR_LABEL" not in json.dumps(request)
            assert "group" not in request and "label" not in request
            return {"selection": {"methods": []}, "usage": None, "model": "test"}

    prepared = prepare_report(row(), split="train", build_id="labels")
    runner = build_runner(tmp_path / "store", RunConfig(mode="replay"), EXAMPLE / "replay.json")
    controller = AlgorithmController(runner, InspectSelector())
    run = controller.create(prepared, AlgorithmConfig(alpha=1, method_ids=(METHOD,)), experiment_id="labels")
    assert controller.run(run["id"])["run"]["stop_reason"] == "candidate_exhausted"
    prepared["extraction"]["passages"][0]["id"] = "wrong-sentence"
    path = tmp_path / "artifact.json"
    atomic_json(path, prepared)
    with pytest.raises(ValueError, match="passages differ"):
        load_prepared(path)


def test_selector_error_resume_retries_without_an_extra_noop_invocation(tmp_path):
    class BadSelector:
        def select(self, request):
            raise ValueError("simulated endpoint outage")

    class EmptySelector:
        def select(self, request):
            return {"selection": {"methods": []}, "usage": None, "model": "test"}

    runner = build_runner(tmp_path / "store", RunConfig(mode="replay"), EXAMPLE / "replay.json")
    prepared = prepare_report(row(), split="train", build_id="retry")
    first = AlgorithmController(runner, BadSelector())
    run = first.create(prepared, AlgorithmConfig(alpha=1, method_ids=(METHOD,)), experiment_id="retry")
    paused = first.run(run["id"])
    assert paused["run"]["algorithm"]["wait"]["reason"] == "selector_error"
    resumed = AlgorithmController(runner, EmptySelector()).run(run["id"])
    assert resumed["run"]["stop_reason"] == "candidate_exhausted"


def test_wait_true_waits_at_first_preflight_block_then_keeps_current_action(tmp_path):
    class Select:
        def select(self, request):
            return {"selection": {"methods": [{"method_id": METHOD, "reason": "test"}]},
                    "usage": None, "model": "test"}

    runner = build_runner(tmp_path / "store", RunConfig(mode="replay", max_steps=30), EXAMPLE / "replay.json")
    controller = AlgorithmController(runner, Select())
    run = controller.create(prepare_report(row(), split="train", build_id="waiting"),
                            AlgorithmConfig(alpha=1, method_ids=(METHOD,)), experiment_id="waiting")
    clock = [100.0]

    def sleep(seconds):
        clock[0] += seconds

    delayed = {"reason": "local_cooldown", "retry_at": 101.0}
    with patch.object(runner.client, "lookup_wait", side_effect=[delayed] + [None] * 5), \
            patch("ioc_hunter.workflow.algorithm.controller.time.time", side_effect=lambda: clock[0]), \
            patch("ioc_hunter.workflow.algorithm.controller.time.sleep", side_effect=sleep):
        result = controller.run(run["id"], wait=True)
    assert result["run"]["stop_reason"] == "candidate_exhausted"
    assert clock[0] >= 101
    assert result["run"]["algorithm"]["method_history"][METHOD] == {"tried": 5, "coverage": 5}
