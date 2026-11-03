"""Opt-in real CTI extraction -> website lookup -> validation audit.

Only an IOC returned by extract_report can be selected. Does not visit IOC sites,
submit scans or construct an investigation graph. Not run by unittest discovery.
"""
import argparse
from concurrent.futures import ThreadPoolExecutor, as_completed
from dataclasses import asdict
from datetime import datetime, timezone
from hashlib import sha256
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
from ioc_hunter.extraction.pipeline import extract_report
from ioc_hunter.extraction.datasets import load_reports
from ioc_hunter.methods import list_runnable_methods
from ioc_hunter.models import normalize
from live_methods_audit import audit_source, report, write_json


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--dataset", type=Path, default=ROOT.parent / "ThreatMamba-Datasets/ThreatMAMBA-main/cleaned_CTI2Attacker(main).csv")
    parser.add_argument("--row", type=int, required=True, help="One-based data row, excluding the header")
    parser.add_argument("--value", required=True, help="Must match an actually extracted IOC")
    parser.add_argument("--type", choices=["domain", "ipv4", "ipv6", "url"], required=True)
    parser.add_argument("--source", choices=["rapiddns", "alienvault", "virustotal"], action="append")
    parser.add_argument("--max-pages", type=int, default=2)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    rows = load_reports(args.dataset)
    if not 1 <= args.row <= len(rows) or args.max_pages < 1:
        parser.error("Invalid row or page limit")
    row = rows[args.row-1]
    source = f"{args.dataset.resolve()}#row={args.row};index={row.get('index','')}"
    extracted = extract_report(row["cti_content"], source=source)
    selected = next((ioc for ioc in extracted.iocs if ioc.type == args.type and normalize(ioc.type, ioc.value) == normalize(args.type, args.value)), None)
    if selected is None:
        parser.error("Requested seed was not returned by the extractor; no lookup was made")
    assert selected.context and all(context in extracted.original_text for context in selected.context)
    directory = args.output.resolve()
    directory.mkdir(parents=True, exist_ok=False)
    (directory / "report.txt").write_text(extracted.original_text, encoding="utf-8")
    write_json(directory / "extraction.json", asdict(extracted))
    write_json(directory / "selected-ioc.json", asdict(selected))
    methods = [m for m in list_runnable_methods(selected.type) if not args.source or m.source in args.source]
    sources = sorted({m.source for m in methods})
    manifest = {"started_at":datetime.now(timezone.utc).isoformat(), "dataset":str(args.dataset.resolve()),
                "row":args.row,"dataset_index":row.get("index"),"group_name":row.get("group_name"),
                "report_sha256":sha256(extracted.original_text.encode()).hexdigest(),
                "extracted_count":len(extracted.iocs),"selected_ioc":asdict(selected),
                "inputs":{selected.type:selected.value},"sources":sources,
                "method_ids":[m.id for m in methods],"max_pages":args.max_pages,"cache_ttl":0,
                "api_keys_configured":{"alienvault":False,"virustotal":False}}
    write_json(directory / "manifest.json",manifest)
    print(f"EXTRACTED {len(extracted.iocs)} IOCs; SELECTED {selected.type} {selected.value}; ARTIFACTS {directory}",flush=True)
    results=[]
    with ThreadPoolExecutor(max_workers=len(sources)) as pool:
        futures=[pool.submit(audit_source,source,directory,manifest["inputs"],args.max_pages,{},manifest["method_ids"],{selected.type:selected}) for source in sources]
        for future in as_completed(futures):
            results.extend(future.result())
            results.sort(key=lambda row:row["method"])
            write_json(directory / "results.json",results)
            report(directory,results,manifest)
    print(f"FINISHED {len(results)} method attempts",flush=True)


if __name__ == "__main__":
    main()
