"""Opt-in network smoke check; never runs during unittest discovery."""
import argparse
import json
from pathlib import Path
import sys
sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from ioc_hunter import IOC, LookupClient, LookupError
from ioc_hunter.storage import EvidenceStore

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("source", choices=("rapiddns", "alienvault", "virustotal"))
    parser.add_argument("--value", default="example.com")
    parser.add_argument("--type", default="domain")
    parser.add_argument("--output-type", default="ipv4")
    args = parser.parse_args()
    client = LookupClient(store=EvidenceStore(Path(__file__).resolve().parents[1] / "output" / "live-smoke"), max_pages=1)
    query = IOC(args.value, args.type)
    method = f"{args.source}.{args.type}_to_{args.output_type}"
    try:
        result = client.lookup(query, method)
        record = client.latest_record(query, method)
        print(json.dumps({"method": method, "status": record["status"], "count": len(result),
                          "complete": record["complete"], "lookup_id": record["id"], "cache_hit": record["cache_hit"]}))
    except LookupError as exc:
        print(json.dumps({"method": method, "status": exc.status, "error": str(exc), "lookup_id": exc.lookup_id}))
        sys.exit(1)
