"""Opt-in live audit of every implemented method, with inspectable raw artifacts.

Never runs during unittest discovery. Sources run independently; calls within
each source retain the normal rate limiter. No scans or file submissions occur.
"""
import argparse
from concurrent.futures import ThreadPoolExecutor, as_completed
from datetime import datetime, timezone
import json
from pathlib import Path
import sys
from time import monotonic

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from ioc_hunter import IOC, LookupClient, LookupError, list_runnable_methods
from ioc_hunter.config import api_keys_from_environment
from ioc_hunter.providers import PROVIDERS
from ioc_hunter.storage import EvidenceStore

INPUTS = {
    "domain": "example.com",
    "ipv4": "1.1.1.1",
    "ipv6": "2606:4700:4700::1111",
    "url": "http://example.com/",
}


def write_json(path, value):
    path.write_text(json.dumps(value, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")


def outcome(record):
    if record["status"] in {"ok", "empty", "partial"}:
        if record["outputs"]:
            return "validated outputs (partial)" if not record["complete"] else "validated outputs"
        return "no accepted outputs (partial)" if not record["complete"] else "no accepted outputs"
    return "failed: " + record["status"]


def audit_source(source, directory, inputs, max_pages, api_keys, method_ids, query_iocs=None):
    store = EvidenceStore(directory / "stores" / source)
    # Fresh retrieval per method: this audit must not reuse successful cached calls.
    client = LookupClient(store=store, cache_ttl=0, max_pages=max_pages,
                          api_keys=api_keys, interval=15)
    results = []
    for method in list_runnable_methods():
        if method.source != source or (method_ids and method.id not in method_ids):
            continue
        target = directory / method.id
        target.mkdir()
        query = query_iocs[method.input_type] if query_iocs else IOC(inputs[method.input_type], method.input_type)
        print(f"START {method.id} {query.value}", flush=True)
        start = monotonic()
        try:
            client.lookup(query, method.id)
            record = client.latest_record(query, method.id)
        except LookupError as exc:
            record = store.get_record(exc.lookup_id)
        raw_files = []
        for index, ref in enumerate(record["responses"], 1):
            doc = store.get_snapshot(ref["snapshot_id"])
            extension = "json" if doc["format"] == "json" else "html"
            filename = f"raw-{index:02d}.{extension}"
            # Exactly the retained decoded body; no JSON prettification/redaction.
            (target / filename).write_bytes(doc["body"].encode("utf-8"))
            metadata = {k: v for k, v in doc.items() if k != "body"}
            metadata["snapshot_id"] = ref["snapshot_id"]
            write_json(target / f"raw-{index:02d}.metadata.json", metadata)
            raw_files.append(filename)
        write_json(target / "receipt.json", record)
        write_json(target / "outputs.json", record["outputs"])
        row = {
            "method": method.id, "input_type": query.type, "input": query.value,
            "status": record["status"], "outcome": outcome(record),
            "accepted_count": len(record["outputs"]),
            "candidate_rows": len(record["evidence"]),
            "rejected_rows": len(record["rejected"]),
            "complete": record["complete"] if record["status"] in {"ok", "empty", "partial"} else None,
            "cache_hit": record["cache_hit"], "error": record["error"],
            "elapsed_seconds": round(monotonic() - start, 2),
            "lookup_id": record["id"], "raw_files": raw_files,
            "transport_errors": record["transport_errors"],
        }
        write_json(target / "summary.json", row)
        results.append(row)
        print(json.dumps(row), flush=True)
        if record["status"] == "rate_limited":
            print(f"STOP {source}: rate limited; remaining methods were not attempted", flush=True)
            break
    return results


def report(directory, rows, manifest):
    lines = ["# Live method audit", "", f"Started (UTC): {manifest['started_at']}", "",
             "This audit contacts the actual providers. It does not use fixtures. Responses are uncached.",
             f"Each lookup is capped at {manifest['max_pages']} page(s); partial is not exhaustive coverage.",
             "One public input per type is tested. A successful sample does not prove all inputs or access routes work.",
             "No accepted outputs does not prove the method is broken or positively verified.", "",
             "API keys configured (values never exported): `" + json.dumps(manifest["api_keys_configured"]) + "`.", "",
             "| Method | Input | Outcome | Accepted | Rejected rows | Artifacts |",
             "| --- | --- | --- | --- | ---: | --- |"]
    for row in rows:
        folder = row["method"]
        links = [f"[outputs]({folder}/outputs.json)", f"[receipt]({folder}/receipt.json)"]
        links += [f"[raw {i}]({folder}/{filename})" for i, filename in enumerate(row["raw_files"], 1)]
        lines.append(f"| `{folder}` | `{row['input']}` | {row['outcome']} | {row['accepted_count']} | {row['rejected_rows']} | {' / '.join(links)} |")
    lines += ["", "## Reading the artifacts", "",
              "- `outputs.json`: validated IOC objects returned by the method.",
              "- `receipt.json`: evidence, rejections, errors, source URLs and lookup ID.",
              "- `raw-NN.json` or `.html`: the exact UTF-8 decoded body retained by the transport, before parsing. Open HTML as text to inspect it.",
              "- `raw-NN.metadata.json`: URL, HTTP status, retrieval time, format and snapshot ID.",
              "- `summary.json`: concise counts and status for each method; root `results.json` contains all summaries.",
              "- A transport error can occur before a Document is returned. In that case there is no raw body to export; the receipt records the error. Failed page parsing can still have a raw HTML/JSON artifact.",
              "- Rejections count candidate evidence rows, not unique IPs. A different row can independently support an accepted IOC.",
              "- No code fixes or API-key assumptions are hidden in these results."]
    (directory / "REPORT.md").write_text("\n".join(lines) + "\n", encoding="utf-8")


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output", type=Path)
    parser.add_argument("--max-pages", type=int, default=1)
    parser.add_argument("--source", choices=tuple(PROVIDERS), action="append")
    parser.add_argument("--method", choices=[m.id for m in list_runnable_methods()], action="append",
                        help="Limit a follow-up check to selected implemented methods")
    for kind, default in INPUTS.items():
        parser.add_argument("--" + kind, default=default)
    args = parser.parse_args()
    if args.max_pages < 1:
        parser.error("--max-pages must be positive")
    stamp = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")
    directory = (args.output or ROOT / "output" / f"live-methods-{stamp}").resolve()
    directory.mkdir(parents=True, exist_ok=False)
    inputs = {kind: getattr(args, kind) for kind in INPUTS}
    keys = api_keys_from_environment()
    sources = list(dict.fromkeys(args.source or list(PROVIDERS)))
    if args.method:
        sources = [source for source in sources if any(m.startswith(source + ".") for m in args.method)]
        if not sources or any(m.split(".", 1)[0] not in sources for m in args.method):
            parser.error("Selected methods must belong to the selected sources")
    manifest = {"started_at": datetime.now(timezone.utc).isoformat(), "inputs": inputs,
                "sources": sources, "method_ids": args.method, "max_pages": args.max_pages, "cache_ttl": 0,
                "api_keys_configured": {k: bool(v) for k, v in keys.items()},
                "python": sys.version}
    write_json(directory / "manifest.json", manifest)
    print(f"ARTIFACTS {directory}", flush=True)
    rows = []
    with ThreadPoolExecutor(max_workers=len(sources)) as pool:
        futures = [pool.submit(audit_source, source, directory, inputs, args.max_pages, keys, args.method)
                   for source in sources]
        for future in as_completed(futures):
            rows.extend(future.result())
            rows.sort(key=lambda row: row["method"])
            write_json(directory / "results.json", rows)
            report(directory, rows, manifest)
    print(f"FINISHED {len(rows)} methods: {directory / 'REPORT.md'}", flush=True)


if __name__ == "__main__":
    main()
