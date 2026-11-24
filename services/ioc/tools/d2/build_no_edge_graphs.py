"""Write the final IOC graph for every D2 report that cannot form a connection.

Under the paper's admission rule a lookup only adds an edge when it returns an IOC that matches
another not-yet-hunted IOC of the same report, and the lookup methods used here only return
domains, URLs, IPs and emails. So a report with fewer than two distinct domain/URL/IP IOCs can
never gain an edge: its final graph is its extracted IOCs, all isolated. This writes those graphs
in the same node shape as the algorithm's export, and lists the remaining (connectable) reports.
"""
import argparse
import csv
import json
from collections import Counter
from pathlib import Path

LINKABLE = {"domain", "url", "ipv4", "ipv6"}


def main():
    p = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    p.add_argument("--build", type=Path, required=True, help="Build folder from 'ioc_hunter dataset prepare'")
    p.add_argument("--out", type=Path, required=True)
    a = p.parse_args()
    reports_dir = a.out / "no-edge-graphs"
    reports_dir.mkdir(parents=True, exist_ok=True)

    index, connectable, kinds = [], [], Counter()
    for path in sorted((a.build / "reports").glob("*.json"), key=lambda q: q.stem):
        art = json.loads(path.read_text(encoding="utf-8"))
        rep, key, iocs = art["report"], art["report_key"], art["iocs"]
        linkable = {(i["type"], i["value"]) for i in iocs if i["type"] in LINKABLE}
        if len(linkable) >= 2:
            connectable.append((rep["group"], key, len(linkable)))
            kinds["connectable"] += 1
            continue
        kind = "no_iocs" if not iocs else ("one_linkable_ioc" if linkable else "hashes_only")
        kinds[kind] += 1
        nodes = [{"id": i["id"], "type": i["type"], "value": i["value"], "context": i.get("context", []),
                  "sources": [i.get("source", f"d2:{rep['report_id']}")],
                  "passage_ids": [f"{key}:s{s}" for s in i.get("sentence_indices", [])],
                  "sentence_indices": i.get("sentence_indices", []),
                  "origin": "report", "isolated": True} for i in iocs]
        graph = {"version": 1, "policy": "algorithm1/paper-admission-v1",
                 "dataset_outcome": "complete_without_lookups",
                 "reason": kind + ": fewer than two distinct domain/URL/IP IOCs, so no edge is possible",
                 "report": {"report_key": key, "report_id": rep["report_id"], "group": rep["group"],
                            "split": rep.get("split", ""), "label": rep.get("label")},
                 "graph": {"nodes": nodes, "edges": []}}
        (reports_dir / f"{key}.json").write_text(json.dumps(graph, ensure_ascii=False, indent=1), encoding="utf-8")
        index.append([rep["group"], key, rep.get("split", ""), kind, len(iocs)])

    with open(a.out / "no_edge_index.csv", "w", newline="", encoding="utf-8") as fh:
        w = csv.writer(fh)
        w.writerow(["attacker", "report_key", "split", "reason", "ioc_count"])
        w.writerows(sorted(index))
    # Round-robin across attackers so a partial run still covers every group early.
    by_group = {}
    for group, key, n in sorted(connectable, key=lambda r: (r[0], -r[2], r[1])):
        by_group.setdefault(group, []).append(key)
    order = []
    while any(by_group.values()):
        for group in sorted(by_group):
            if by_group[group]:
                order.append(by_group[group].pop(0))
    (a.out / "connectable_reports.txt").write_text("\n".join(order) + "\n", encoding="utf-8")
    with open(a.out / "connectable_reports.csv", "w", newline="", encoding="utf-8") as fh:
        w = csv.writer(fh)
        w.writerow(["attacker", "report_key", "linkable_iocs"])
        w.writerows(sorted(connectable))

    print(f"no IOCs: {kinds['no_iocs']}   hashes only: {kinds['hashes_only']}   "
          f"one linkable IOC: {kinds['one_linkable_ioc']}   -> {len(index)} final graphs written")
    print(f"connectable reports left for the live algorithm: {kinds['connectable']} "
          f"({sum(r[2] for r in connectable)} linkable IOCs)")
    print(f"Written to {a.out.resolve()}")


if __name__ == "__main__":
    main()
