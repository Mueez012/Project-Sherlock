"""Final-boss stage 2: force one real overlap per lookup method and run Algorithm 1 live on it.

For every method whose input and output can both appear as IOCs in a report, take one output that
the method really returned in stage 1, write a two-sentence synthetic report containing the seed
and that output, and run Algorithm 1 on it with only that method enabled. A working method must
re-find the output live, the overlap rule must admit it, and the graph must gain an edge.
"""
import argparse
import json
import subprocess
import sys
from ipaddress import ip_address
from pathlib import Path

from ioc_hunter.methods import list_runnable_methods

EXTRACTABLE = {"domain", "ipv4", "ipv6", "url", "md5", "sha1", "sha256", "email"}


def same(kind, a, b):
    if kind in {"ipv4", "ipv6"}:
        try:
            return ip_address(a) == ip_address(b)
        except ValueError:
            return False
    if kind == "url":
        return a.rstrip("/") == b.rstrip("/")
    return a.lower() == b.lower()


def call(cmd, log, timeout=None):
    with open(log, "a", encoding="utf-8") as fh:
        fh.write("\n$ " + " ".join(map(str, cmd)) + "\n")
        fh.flush()
        return subprocess.run(list(map(str, cmd)), stdout=subprocess.PIPE, stderr=fh, text=True, timeout=timeout)


def stats_for(py, build, exp, log):
    res = call(py + ["algorithm", "stats", "--build", build, "--experiment", exp], log)
    return json.loads(res.stdout)


def main():
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument("--stage1", type=Path, required=True, help="Folder written by tests/live_methods_audit.py")
    p.add_argument("--out", type=Path, required=True)
    p.add_argument("--interval", type=float, default=15, help="Seconds between lookups per provider")
    p.add_argument("--run-timeout", type=int, default=1800, help="Seconds allowed per method")
    p.add_argument("--provider", action="append", help="Only test these providers (repeatable)")
    a = p.parse_args()
    out = a.out.resolve()
    out.mkdir(parents=True, exist_ok=True)
    log = out / "stage2.log"
    py = [sys.executable, "-B", "-m", "ioc_hunter"]
    build, store = out / "build", out / "store"
    stage1 = {r["method"]: r for r in json.loads((a.stage1 / "results.json").read_text(encoding="utf-8"))}

    rows, plan = [], []
    for method in sorted(list_runnable_methods(), key=lambda m: m.id):
        r = stage1.get(method.id)
        row = {"method": method.id, "provider": method.source, "input": method.input_type,
               "output": method.output_type, "stage1": r["outcome"] if r else "not run",
               "stage1_outputs": r["accepted_count"] if r else 0}
        rows.append(row)
        if method.input_type not in EXTRACTABLE or method.output_type not in EXTRACTABLE:
            bad = method.output_type if method.output_type not in EXTRACTABLE else method.input_type
            row["stage2"] = f"n/a ({bad} never appears as a report IOC)"
            continue
        if a.provider and method.source not in a.provider:
            row["stage2"] = "skipped (provider not selected)"
            continue
        if not r or not r["accepted_count"]:
            row["stage2"] = "not testable (no live outputs in stage 1)"
            continue
        outputs = json.loads((a.stage1 / method.id / "outputs.json").read_text(encoding="utf-8"))
        row.update(report_id=len(plan) + 1, seed=r["input"], expected=outputs[0]["value"],
                   _all=[o["value"] for o in outputs], _method=method)
        plan.append(row)

    d2 = out / "d2"
    d2.mkdir(exist_ok=True)
    with open(d2 / "train.jsonl", "w", encoding="utf-8") as fh:
        for row in plan:
            # Seed first: the algorithm hunts IOCs in report order, and an overlap only counts
            # against IOCs that have not been hunted yet.
            sentences = [f"The implant contacted {row['seed']} during the first stage.",
                         f"Analysts later observed {row['expected']} in the same campaign."]
            fh.write(json.dumps({"report_id": row["report_id"], "group": "forced-" + row["method"],
                                 "label": 0, "cut_by_excel": False, "text": "\n".join(sentences),
                                 "sentences": sentences}) + "\n")
    if plan:
        res = call(py + ["dataset", "prepare", "--source", d2, "--output", build, "--extended-types"], log)
        if res.returncode:
            sys.exit("Preparation failed; see " + str(log))

    resume_done = False
    for n, row in enumerate(plan, 1):
        m = row["_method"]
        print(f"[{n}/{len(plan)}] {m.id}: {row['seed']} -> expecting {row['expected']}", flush=True)
        iocs = json.loads((build / "reports" / f"{row['report_id']}.json").read_text(encoding="utf-8"))["iocs"]
        has_seed = any(i["type"] == m.input_type and same(m.input_type, i["value"], row["seed"]) for i in iocs)
        has_exp = any(i["type"] == m.output_type and same(m.output_type, i["value"], row["expected"]) for i in iocs)
        if not (has_seed and has_exp):
            row["stage2"] = "not testable (extractor did not keep " + ("the seed" if not has_seed else "the expected output") + ")"
            continue
        selection = {row["seed"]: [{"method_id": m.id, "reason": "Forced live test"}]}
        for i in iocs:
            if i["type"] == m.input_type:
                selection.setdefault(i["value"], [])
        if m.input_type == m.output_type:
            for value in row["_all"]:
                selection.setdefault(value, [])
        exp_dir = out / "experiments" / m.id
        exp_dir.mkdir(parents=True, exist_ok=True)
        (exp_dir / "selector.json").write_text(json.dumps(selection, indent=2), encoding="utf-8")
        config = {"alpha": 1.0, "method_ids": [m.id],
                  "selector": {"kind": "fixture", "path": "selector.json"},
                  "provider_limits": {m.source: {"interval": a.interval, "daily_limit": 300}},
                  "limits": {"max_steps": 100, "max_nodes": 5000, "max_seconds": a.run_timeout,
                             "max_pages": 2, "max_outputs": 5000}}
        (exp_dir / "config.json").write_text(json.dumps(config, indent=2), encoding="utf-8")
        exp = "forced-" + m.id.replace(".", "-") + "-v1"
        try:
            call(py + ["algorithm", "run", "--build", build, "--experiment", exp, "--config",
                       exp_dir / "config.json", "--store", store, "--report-id", row["report_id"], "--wait"],
                 log, timeout=a.run_timeout + 300)
            s = stats_for(py, build, exp, log)
        except subprocess.TimeoutExpired:
            row["stage2"] = "FAIL (timed out)"
            continue
        except (ValueError, KeyError) as exc:
            row["stage2"] = f"FAIL (no statistics: {exc})"
            continue
        mstat = s.get("methods", {}).get(m.id, {})
        row.update(tried=mstat.get("tried", 0), coverage=mstat.get("coverage", 0),
                   nodes=s["graph_nodes"]["median"], edges=s["graph_edges"]["median"],
                   fetches=s.get("known_fetch_attempts"), valid_not_admitted=s.get("validated_non_admitted_iocs"),
                   outcome=",".join(s.get("outcomes", {})))
        ok = row["coverage"] >= 1 and row["edges"] >= 1
        row["stage2"] = "PASS" if ok else "FAIL"
        if ok and not resume_done:
            before = s["logical_attempts"]
            call(py + ["algorithm", "resume", "--build", build, "--experiment", exp, "--store", store,
                       "--report-id", row["report_id"]], log, timeout=600)
            after = stats_for(py, build, exp, log)["logical_attempts"]
            rows.append({"method": "resume check (" + m.id + ")", "provider": "-", "input": "-", "output": "-",
                         "stage1": "-", "stage1_outputs": "-",
                         "stage2": "PASS" if after == before else f"FAIL ({before} -> {after} lookups)"})
            resume_done = True

    for row in rows:
        row.pop("_all", None)
        row.pop("_method", None)
    (out / "verdict.json").write_text(json.dumps(rows, indent=2), encoding="utf-8")
    lines = ["| Method | In -> out | Stage 1 lookup | Outputs | Stage 2 forced hit | Coverage | Nodes | Edges |",
             "| --- | --- | --- | ---: | --- | ---: | ---: | ---: |"]
    for r in rows:
        lines.append(f"| `{r['method']}` | {r['input']} -> {r['output']} | {r['stage1']} | {r['stage1_outputs']} | "
                     f"{r['stage2']} | {r.get('coverage', '')} | {r.get('nodes', '')} | {r.get('edges', '')} |")
    (out / "VERDICT.md").write_text("\n".join(lines) + "\n", encoding="utf-8")

    real = [r for r in rows if r["provider"] != "-"]
    print("\n=== FINAL BOSS VERDICT ===")
    for prov in sorted({r["provider"] for r in real}):
        mine = [r for r in real if r["provider"] == prov]
        live = sum(1 for r in mine if r["stage1_outputs"])
        passed = sum(1 for r in mine if r["stage2"] == "PASS")
        forced = sum(1 for r in mine if r["stage2"] in {"PASS", "FAIL"} or r["stage2"].startswith("FAIL"))
        print(f"{prov:15} lookups returning data: {live}/{len(mine)}   forced hits passed: {passed}/{forced}")
    for r in rows:
        if r["stage2"].startswith("FAIL") or r["method"].startswith("resume"):
            print(f"  {r['method']}: {r['stage2']}")
    print(f"Full table: {out / 'VERDICT.md'}")


if __name__ == "__main__":
    main()
