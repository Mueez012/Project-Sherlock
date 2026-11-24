"""Turn an exported D2 IOC build (reports.jsonl) into the per-attacker IOC dataset.

Writes four files next to each other:
  ioc_dataset.json      attacker -> counts and every IOC with its report, sentences and context
  iocs.csv              one row per IOC occurrence (attacker, report, type, value, sentences, context)
  attacker_summary.csv  one row per attacker group with report and IOC counts by type
  reports_without_iocs.csv  reports that produced no IOCs, for checking extraction
"""
import argparse
import csv
import json
from collections import Counter, defaultdict
from pathlib import Path

TYPES = ["domain", "url", "ipv4", "ipv6", "md5", "sha1", "sha256", "email", "cve"]


def main():
    p = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    p.add_argument("--reports", type=Path, required=True, help="reports.jsonl from 'ioc_hunter dataset export'")
    p.add_argument("--out", type=Path, required=True)
    a = p.parse_args()
    a.out.mkdir(parents=True, exist_ok=True)

    groups = defaultdict(lambda: {"reports": 0, "reports_with_iocs": 0, "iocs": []})
    empty = []
    with open(a.reports, encoding="utf-8") as fh:
        for line in fh:
            if not line.strip():
                continue
            art = json.loads(line)
            rep = art["report"]
            g = groups[rep["group"]]
            g["reports"] += 1
            if art["iocs"]:
                g["reports_with_iocs"] += 1
            else:
                empty.append((rep["group"], rep["report_id"], rep.get("split", "")))
            for ioc in art["iocs"]:
                g["iocs"].append({"report_id": rep["report_id"], "split": rep.get("split", ""),
                                  "type": ioc["type"], "value": ioc["value"],
                                  "sentence_indices": ioc.get("sentence_indices", []),
                                  "context": ioc.get("context", []), "ioc_id": ioc.get("id")})

    dataset, summary = {}, []
    for name in sorted(groups):
        g = groups[name]
        by_type = Counter(i["type"] for i in g["iocs"])
        unique = {(i["type"], i["value"]) for i in g["iocs"]}
        dataset[name] = {"reports": g["reports"], "reports_with_iocs": g["reports_with_iocs"],
                         "ioc_occurrences": len(g["iocs"]), "unique_iocs": len(unique),
                         "by_type": dict(by_type), "iocs": g["iocs"]}
        summary.append([name, g["reports"], g["reports_with_iocs"], len(g["iocs"]), len(unique)]
                       + [by_type.get(t, 0) for t in TYPES])

    (a.out / "ioc_dataset.json").write_text(json.dumps(dataset, indent=1, ensure_ascii=False), encoding="utf-8")
    with open(a.out / "iocs.csv", "w", newline="", encoding="utf-8") as fh:
        w = csv.writer(fh)
        w.writerow(["attacker", "report_id", "split", "ioc_type", "ioc_value", "sentence_indices", "context"])
        for name in sorted(dataset):
            for i in dataset[name]["iocs"]:
                w.writerow([name, i["report_id"], i["split"], i["type"], i["value"],
                            " ".join(map(str, i["sentence_indices"])), " | ".join(i["context"])])
    with open(a.out / "attacker_summary.csv", "w", newline="", encoding="utf-8") as fh:
        w = csv.writer(fh)
        w.writerow(["attacker", "reports", "reports_with_iocs", "ioc_occurrences", "unique_iocs"] + TYPES)
        w.writerows(summary)
    with open(a.out / "reports_without_iocs.csv", "w", newline="", encoding="utf-8") as fh:
        w = csv.writer(fh)
        w.writerow(["attacker", "report_id", "split"])
        w.writerows(sorted(empty))

    total_reports = sum(r[1] for r in summary)
    print(f"{len(summary)} attacker groups, {total_reports} reports, "
          f"{sum(r[2] for r in summary)} with IOCs, {sum(r[3] for r in summary)} IOC occurrences, "
          f"{sum(r[4] for r in summary)} unique per attacker")
    print(f"Written to {a.out.resolve()}")


if __name__ == "__main__":
    main()
