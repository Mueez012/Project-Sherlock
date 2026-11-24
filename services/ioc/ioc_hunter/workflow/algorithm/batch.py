"""One sequential corpus worker; SQLite remains the investigation checkpoint."""
from collections import Counter
import csv
from copy import deepcopy
import io
import json
import math
from pathlib import Path
import re
import statistics

from ...config import resolve_store_directory
from ...lookup import LookupClient
from ...storage import EvidenceStore
from ..coordination import ExecutionCoordinator
from ..models import RunConfig, stable_id
from ..repository import WorkflowRepository
from ..replay import ReplayTransport
from ..runner import TERMINAL_STATUSES, build_runner
from .controller import AlgorithmController, _effective
from .dataset import atomic_json, iter_prepared
from .models import AlgorithmConfig, fingerprint
from .selector import build_selector
from .statistics import summarize


def _settings(config):
    if not isinstance(config, dict) or set(config) - {
            "alpha", "method_ids", "selector", "provider_limits", "frozen_cache", "limits", "mode", "replay"}:
        raise ValueError("Unknown experiment configuration fields")
    algorithm = AlgorithmConfig(**{k: v for k, v in config.items() if k not in {"limits", "mode", "replay"}})
    limits = RunConfig(mode=config.get("mode", "replay" if config.get("replay") else "live"), **config.get("limits", {}))
    selector = build_selector(algorithm.selector)
    return algorithm, limits, selector


def normalize_config(config, base_directory=None):
    if not isinstance(config, dict):
        raise ValueError("Experiment configuration must be an object")
    result = deepcopy(config)
    base = Path(base_directory or Path.cwd())
    if result.get("replay"):
        result["replay"] = str((base / result["replay"]).resolve())
    selector = result.get("selector", {})
    if selector.get("kind") == "fixture":
        selector["path"] = str((base / selector["path"]).resolve())
    return result


def _outcome(snapshot):
    run = snapshot["run"]
    if run["status"] == "failed":
        return "limited" if run["stop_reason"] == "initial_node_limit" else "failed"
    if run["status"] == "cancelled":
        return "cancelled"
    if run["status"] == "completed":
        return "complete" if run["stop_reason"] == "candidate_exhausted" else "limited"
    return "in_progress"


def _export(repository, run_id, directory, key):
    # One transaction produces graph, steps and exact receipts at one revision.
    snapshot = repository.snapshot(run_id, include_evidence=True)
    snapshot["statistics"] = summarize(snapshot)
    snapshot["dataset_outcome"] = _outcome(snapshot)
    atomic_json(directory / "reports" / f"{key}.json", snapshot)
    return snapshot


def _write_summaries(directory, items):
    metrics, methods, outcomes = [], {}, Counter()
    durations, node_counts, edge_counts = [], [], []
    for key in items:
        path = directory / "reports" / f"{key}.json"
        if not path.is_file():
            continue
        report = json.loads(path.read_text(encoding="utf-8"))
        metric = report["statistics"]
        metrics.append(metric)
        outcomes[report["dataset_outcome"]] += 1
        durations.append(report["run"]["elapsed_seconds"])
        node_counts.append(len(report["graph"]["nodes"]))
        edge_counts.append(len(report["graph"]["edges"]))
        for mid, values in metric["methods"].items():
            method = methods.setdefault(mid, {"tried": 0, "coverage": 0, "exposed_rounds": 0, "selected_rounds": 0})
            for column in method:
                if column != "batch_rate":
                    method[column] += values.get(column, 0)
    for method in methods.values():
        method["batch_rate"] = method["coverage"] / method["tried"] if method["tried"] else None
    def distribution(values):
        ordered = sorted(values)
        return {"median": statistics.median(ordered) if ordered else None,
                "p90": ordered[min(len(ordered) - 1, max(0, math.ceil(len(ordered) * .9) - 1))] if ordered else None}
    attempts = sum(metric["lookups"]["attempts"] for metric in metrics)
    admissions = sum(metric["lookups"]["admitted_batches"] for metric in metrics)
    corpus = {"metrics_version": "algorithm1-v1", "outcomes": dict(outcomes), "reports": len(metrics),
              "logical_attempts": attempts, "admitted_batches": admissions,
              "pooled_batch_rate": admissions / attempts if attempts else None,
              "known_fetch_attempts": sum(m["lookups"]["known_fetch_attempts"] for m in metrics),
              "isolated_report_iocs": sum(m["graph"]["isolated_report_iocs"] for m in metrics),
              "validated_non_admitted_iocs": sum(m["graph"]["validated_non_admitted_iocs"] for m in metrics),
              "processing_seconds": distribution(durations), "graph_nodes": distribution(node_counts),
              "graph_edges": distribution(edge_counts), "methods": methods}
    atomic_json(directory / "summaries" / "corpus.json", corpus)
    columns = ("report_key", "run_id", "outcome", "stop_reason", "graph_revision", "nodes", "edges")
    buffer = io.StringIO(newline="")
    writer = csv.DictWriter(buffer, fieldnames=columns, extrasaction="ignore")
    writer.writeheader()
    writer.writerows(items.values())
    target = directory / "summaries" / "reports.csv"
    temporary = target.with_suffix(".csv.tmp")
    temporary.write_text(buffer.getvalue(), encoding="utf-8")
    temporary.replace(target)
    buffer = io.StringIO(newline="")
    writer = csv.DictWriter(buffer, fieldnames=("method_id", "tried", "coverage", "batch_rate", "exposed_rounds", "selected_rounds"))
    writer.writeheader()
    writer.writerows({"method_id": mid, **row} for mid, row in sorted(methods.items()))
    target = directory / "summaries" / "methods.csv"
    temporary = target.with_suffix(".csv.tmp")
    temporary.write_text(buffer.getvalue(), encoding="utf-8")
    temporary.replace(target)
    return corpus


def run_dataset(build_dir, experiment_id, *, config=None, store_directory=None, wait=False,
                report_ids=None, max_reports=None, on_progress=None):
    """Create/continue an experiment. Stops at the first provider/model pause."""
    if not isinstance(experiment_id, str) or not re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9_.-]{0,99}", experiment_id):
        raise ValueError("Use a simple experiment ID without path separators")
    if max_reports is not None and (type(max_reports) is not int or max_reports < 1):
        raise ValueError("max_reports must be positive")
    build_dir = Path(build_dir).resolve()
    build_manifest = json.loads((build_dir / "manifest.json").read_text(encoding="utf-8"))
    directory = build_dir / "experiments" / experiment_id
    experiment_path = directory / "experiment.json"
    store_directory = resolve_store_directory(store_directory)
    coordinator = ExecutionCoordinator(store_directory)
    selected_ids = None if report_ids is None else set(report_ids)
    if config is not None:
        config = normalize_config(config)
    with coordinator.claim("batch:" + str(directory)):
        if experiment_path.exists():
            experiment = json.loads(experiment_path.read_text(encoding="utf-8"))
            if experiment["build_id"] != build_manifest["build_id"]:
                raise ValueError("Experiment belongs to another prepared dataset build")
            if config is not None and fingerprint(config) != experiment["config_fingerprint"]:
                raise ValueError("Experiment configuration changed; use a new experiment ID")
            config = experiment["config"]
            if experiment["store_directory"] != str(store_directory):
                raise ValueError("Resume requires the experiment's original shared store")
        elif config is None:
            raise ValueError("A new experiment requires a configuration file")
        algorithm, limits, selector = _settings(config)
        effective, catalogue = _effective(algorithm, limits.mode)
        source_fingerprints = {"algorithm": fingerprint(effective.to_dict()), "catalogue": fingerprint(catalogue),
                               "replay": ReplayTransport(config["replay"]).digest if config.get("replay") else None}
        if experiment_path.exists() and experiment["source_fingerprints"] != source_fingerprints:
            raise ValueError("Experiment method/selector/replay content changed; use a new experiment ID")
        # Validate every rate profile before publishing a run or experiment.
        LookupClient(store=EvidenceStore(store_directory), provider_limits=algorithm.provider_limits,
                     frozen_cache=algorithm.frozen_cache, cache_namespace=build_manifest["build_id"])
        if not experiment_path.exists():
            atomic_json(experiment_path, {"schema_version": 1, "experiment_id": experiment_id,
                        "build_id": build_manifest["build_id"],
                        "source_fingerprints": source_fingerprints,
                        "config": config, "config_fingerprint": fingerprint(config),
                        "store_directory": str(store_directory)})
        repository = WorkflowRepository(EvidenceStore(store_directory))
        progress_path = directory / "progress.json"
        try:
            items = json.loads(progress_path.read_text(encoding="utf-8")).get("items", {}) if progress_path.exists() else {}
            if not isinstance(items, dict):
                items = {}
        except (ValueError, OSError):
            items = {}  # Progress is a cache; deterministic SQLite IDs recover the work.
        processed = 0
        for artifact in iter_prepared(build_dir):
            if selected_ids is not None and artifact["report"]["report_id"] not in selected_ids:
                continue
            key = artifact["report_key"]
            run_id = stable_id("algorithm1", artifact["build_id"], experiment_id, key)
            try:
                saved = repository.get_run(run_id)
            except KeyError:
                saved = None
            if (saved is None or saved["status"] not in TERMINAL_STATUSES) and max_reports is not None and processed >= max_reports:
                break
            if saved and saved["status"] in TERMINAL_STATUSES:
                snapshot = _export(repository, run_id, directory, key)
            else:
                runner = build_runner(store_directory, limits, config.get("replay"), run_id=run_id if saved else None)
                controller = AlgorithmController(runner, selector)
                controller.create(artifact, algorithm, experiment_id=experiment_id)
                try:
                    controller.run(run_id, wait=wait, on_progress=on_progress)
                except KeyboardInterrupt:
                    _export(repository, run_id, directory, key)
                    raise
                snapshot = _export(repository, run_id, directory, key)
                processed += 1
            item = {"report_key": key, "report_id": artifact["report"]["report_id"], "run_id": run_id,
                    "outcome": snapshot["dataset_outcome"], "stop_reason": snapshot["run"]["stop_reason"],
                    "graph_revision": snapshot["run"]["graph_revision"],
                    "nodes": len(snapshot["graph"]["nodes"]), "edges": len(snapshot["graph"]["edges"])}
            items[key] = item
            # The small index is saved per report. Reading every raw evidence
            # export to rebuild corpus statistics per report would be quadratic.
            corpus = {"outcomes": dict(Counter(row["outcome"] for row in items.values())), "reports": len(items)}
            atomic_json(progress_path, {"experiment_id": experiment_id, "items": items, "summary": corpus})
            if item["outcome"] == "in_progress":
                break
        corpus = _write_summaries(directory, items)
        corpus["preparation"] = build_manifest.get("counts", {})
        atomic_json(directory / "summaries" / "corpus.json", corpus)
        return {"experiment_id": experiment_id, "directory": str(directory), "processed": processed,
                "items": items, "summary": corpus}


def experiment_statistics(build_dir, experiment_id):
    """Rebuild report/method/corpus summaries from portable committed exports."""
    if not re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9_.-]{0,99}", experiment_id):
        raise ValueError("Invalid experiment ID")
    build_dir = Path(build_dir)
    directory = build_dir / "experiments" / experiment_id
    if not (directory / "experiment.json").is_file():
        raise ValueError("Unknown saved experiment")
    items = {}
    for path in sorted((directory / "reports").glob("*.json")):
        report = json.loads(path.read_text(encoding="utf-8"))
        run = report["run"]
        key = run["dataset"]["report_key"]
        items[key] = {"report_key": key, "run_id": run["id"], "outcome": report["dataset_outcome"],
                      "stop_reason": run["stop_reason"], "graph_revision": run["graph_revision"],
                      "nodes": len(report["graph"]["nodes"]), "edges": len(report["graph"]["edges"])}
    result = _write_summaries(directory, items)
    manifest = json.loads((build_dir / "manifest.json").read_text(encoding="utf-8"))
    result["preparation"] = manifest.get("counts", {})
    atomic_json(directory / "summaries" / "corpus.json", result)
    return result


def export_dataset(build_dir, output_path):
    """Rebuild a portable extraction JSONL without model/provider access."""
    target = Path(output_path)
    target.parent.mkdir(parents=True, exist_ok=True)
    temporary = target.with_name(target.name + ".tmp")
    count = 0
    with temporary.open("w", encoding="utf-8", newline="\n") as handle:
        for artifact in iter_prepared(build_dir):
            handle.write(json.dumps(artifact, ensure_ascii=False, allow_nan=False) + "\n")
            count += 1
    temporary.replace(target)
    return {"reports": count, "output": str(target.resolve())}
