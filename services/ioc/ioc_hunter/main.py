"""IOC extraction, one-call enrichment and durable manual investigations."""
import argparse
from dataclasses import asdict
import json
from pathlib import Path
import sys
from .lookup import LookupClient
from .methods import list_methods, list_candidates, method_status
from .extraction import extract_report
from .models import IOC
from .storage import EvidenceStore
from .transport import LookupError


def _add_store(parser):
    parser.add_argument("--store", type=Path, help="Evidence and investigation storage directory")


def _workflow(args, parser):
    from .workflow.models import RunConfig
    from .workflow.runner import build_runner
    from .workflow.terminal import InvestigationTerminal, read_pasted_report

    if args.command == "investigate":
        inputs = bool(args.report) + bool(args.dataset) + bool(args.paste) + bool(args.resume)
        if inputs != 1:
            parser.error("investigate requires exactly one report file, --dataset, --paste or --resume")
        if args.dataset and (args.row is None or args.row < 1):
            parser.error("--dataset requires an explicit --row (1-based, excluding the header)")
        if args.row is not None and not args.dataset:
            parser.error("--row requires --dataset")
        limit_names = ("max_steps", "max_nodes", "max_seconds", "max_pages", "max_outputs")
        if args.resume and (args.include_references or args.extended_types
                            or any(getattr(args, name) is not None for name in limit_names)):
            parser.error("Resumed investigations retain their saved extraction settings and limits")
        mode = args.mode or ("replay" if args.replay else "live")
        if not args.resume and mode == "replay" and not args.replay:
            parser.error("--mode replay requires --replay FIXTURE_MANIFEST")
        if args.replay and mode != "replay":
            parser.error("--replay requires --mode replay")
        limits = {name: getattr(args, name) for name in limit_names if getattr(args, name) is not None}
        config = None if args.resume and args.mode is None else RunConfig(mode=mode, **limits)
        runner = build_runner(args.store, config=config, replay_path=args.replay, run_id=args.resume)
        if args.resume:
            run = runner.resume(args.resume)
        else:
            if args.dataset:
                from .extraction.datasets import load_reports
                reports = load_reports(args.dataset)
                if args.row > len(reports):
                    raise ValueError(f"--row must be between 1 and {len(reports)}")
                text = reports[args.row - 1].get("cti_content")
                if not isinstance(text, str) or not text.strip():
                    raise ValueError(f"Dataset row {args.row} has no non-empty cti_content")
                source = f"{args.dataset.resolve()}#row={args.row}"
            elif args.paste:
                text = read_pasted_report()
                source = "pasted report"
            else:
                text = args.report.read_text(encoding="utf-8-sig")
                if not text.strip():
                    raise ValueError("The report is empty.")
                source = str(args.report.resolve())
            run = runner.create_run(text, source=source, include_references=args.include_references,
                                    extended_types=args.extended_types)
        result = InvestigationTerminal(runner).run(run["id"])
        return 1 if result["run"]["status"] == "failed" else 0
    runner = build_runner(args.store)
    if args.command == "runs":
        summaries = [
            {**{key: run.get(key) for key in ("id", "status", "mode", "created_at", "updated_at", "stop_reason")},
             "source": run.get("report", {}).get("source", "")}
            for run in runner.list_runs()
        ]
        print(json.dumps(summaries, indent=2, ensure_ascii=False))
    else:
        runner.export_result(args.run_id, args.output, include_evidence=True)
        print(f"Exported investigation {args.run_id} to {args.output}")
    return 0


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    sub = parser.add_subparsers(dest="command", required=True)
    methods = sub.add_parser("methods")
    methods.add_argument("--type")
    selection = methods.add_mutually_exclusive_group()
    selection.add_argument("--implemented", action="store_true")
    selection.add_argument("--candidates", action="store_true")
    methods.add_argument("--availability", action="store_true",
                         help="Include local configuration status; does not test live access")
    extract = sub.add_parser("extract", help="Extract IOCs from a text report without prompts")
    extract.add_argument("report", type=Path)
    extract.add_argument("--include-references", action="store_true")
    extract.add_argument("--extended-types", action="store_true")
    lookup = sub.add_parser("lookup")
    lookup.add_argument("value")
    lookup.add_argument("--type", required=True)
    lookup.add_argument("--method", required=True)
    lookup.add_argument("--store", type=Path)
    lookup.add_argument("--max-pages", type=int, default=5)
    evidence = sub.add_parser("evidence")
    evidence.add_argument("lookup_id")
    evidence.add_argument("--store", type=Path)
    investigate = sub.add_parser("investigate", help="Interactive, saved report-to-IOC enrichment")
    investigate.add_argument("report", nargs="?", type=Path, help="UTF-8 report text file")
    investigate.add_argument("--dataset", type=Path, help="CSV/XLSX dataset with a cti_content column")
    investigate.add_argument("--row", type=int, help="Explicit 1-based data row, excluding the header")
    investigate.add_argument("--paste", action="store_true", help="Paste multiline text, ending with .done")
    investigate.add_argument("--resume", metavar="RUN_ID")
    investigate.add_argument("--mode", choices=("live", "replay"),
                             help="New runs default to live (or replay with --replay); resumed runs retain their mode")
    investigate.add_argument("--replay", type=Path, metavar="FIXTURE_MANIFEST")
    investigate.add_argument("--include-references", action="store_true")
    investigate.add_argument("--extended-types", action="store_true")
    investigate.add_argument("--max-steps", type=int, help="Lookup step limit (default 20)")
    investigate.add_argument("--max-nodes", type=int, help="Graph node limit (default 1000)")
    investigate.add_argument("--max-seconds", type=float, help="Active processing time limit (default 600 seconds)")
    investigate.add_argument("--max-pages", type=int, help="Per-lookup page limit (default 2)")
    investigate.add_argument("--max-outputs", type=int, help="Per-lookup validated output limit (default 1000)")
    _add_store(investigate)
    runs = sub.add_parser("runs", help="List persisted investigations")
    _add_store(runs)
    export = sub.add_parser("export", help="Export a saved investigation, graph and evidence")
    export.add_argument("run_id", metavar="RUN_ID")
    export.add_argument("--output", type=Path, required=True)
    _add_store(export)
    sub.add_parser("mcp")
    args = parser.parse_args(argv)
    if hasattr(sys.stdout, "reconfigure"):
        sys.stdout.reconfigure(encoding="utf-8")
    if args.command in {"investigate", "runs", "export"}:
        try:
            return _workflow(args, parser)
        except (OSError, ValueError, KeyError, RuntimeError, ImportError) as exc:
            print(str(exc), file=sys.stderr)
            return 1
        except (EOFError, KeyboardInterrupt):
            print("Stopped before the investigation was created.", file=sys.stderr)
            return 1
    if args.command == "methods":
        selected = (list_candidates(args.type) if args.candidates else
                    list_methods(args.type, implemented_only=args.implemented))
        result = [{**asdict(m), "implemented": m.implemented, "description": m.description}
                  for m in selected]
        if args.availability:
            for row, method in zip(result, selected):
                row["availability"] = method_status(method)
    elif args.command == "extract":
        try:
            result = asdict(extract_report(
                args.report.read_text(encoding="utf-8-sig"), source=str(args.report),
                include_references=args.include_references, extended_types=args.extended_types))
        except (OSError, ValueError, ImportError) as exc:
            print(str(exc), file=sys.stderr)
            return 1
    elif args.command == "mcp":
        from .mcp_server import main as serve
        serve()
        return 0
    else:
        store = EvidenceStore(args.store) if args.store else None
        client = LookupClient(store=store, max_pages=getattr(args, "max_pages", 5))
        try:
            if args.command == "lookup":
                query = IOC(args.value, args.type)
                receipt = client.lookup_detailed(query, args.method)
                result = [asdict(ioc) for ioc in receipt.outputs]
                record = asdict(receipt)
                print(json.dumps({"lookup_id": record["id"], "status": record["status"], "complete": record["complete"]}), file=sys.stderr)
            else:
                result = client.store.get_record(args.lookup_id)
        except LookupError as exc:
            print(json.dumps({"status": exc.status, "error": str(exc), "lookup_id": exc.lookup_id}), file=sys.stderr)
            return 1
        except (ValueError, KeyError) as exc:
            print(str(exc), file=sys.stderr)
            return 2
    print(json.dumps(result, indent=2, ensure_ascii=False))
    return 0

if __name__ == "__main__":
    raise SystemExit(main())
