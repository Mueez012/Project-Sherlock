"""CLI for method discovery and one-call enrichment; no hunting loop."""
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
    sub.add_parser("mcp")
    args = parser.parse_args(argv)
    if hasattr(sys.stdout, "reconfigure"):
        sys.stdout.reconfigure(encoding="utf-8")
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
                result = [asdict(ioc) for ioc in client.lookup(query, args.method)]
                record = client.latest_record(query, args.method)
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
