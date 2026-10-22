"""Latency and agreement check through the RUNNING API (plan step 9).

  python -m ttp_api.benchmark --api http://127.0.0.1:8001 --reports 20

1. Latency: one small, one medium and one large report from CTI2Attacker_TTP.csv,
   timed end to end (upload -> completed), plus ms per analysed sentence.
2. Agreement: N reports, our technique set vs the authors' published TTP list
   (sub-techniques rolled up, only our 189 techniques counted). This measures
   AGREEMENT with another extractor, not accuracy against ground truth.
Results: reports/api_benchmark.json. Report texts are read locally and never written out.
"""
from __future__ import annotations

import argparse
import json
import time
from pathlib import Path

import httpx
import pandas as pd

from ttp_extraction.inference.extract_report import AUTHORS_TTP, flatten


def run(client: httpx.Client, text: str, name: str, timeout: float = 900) -> dict:
    t0 = time.perf_counter()
    r = client.post("/api/v1/analyses/text", json={"text": text, "incident_name": name})
    r.raise_for_status()
    job = r.json()["id"]
    while True:
        status = client.get(f"/api/v1/analyses/{job}").json()
        if status["status"] in ("completed", "failed"):
            break
        if time.perf_counter() - t0 > timeout:
            raise TimeoutError(job)
        time.sleep(0.25)
    wall = time.perf_counter() - t0
    if status["status"] == "failed":
        return {"failed": status["error"], "wall_s": wall}
    result = client.get(f"/api/v1/analyses/{job}/result").json()
    client.delete(f"/api/v1/analyses/{job}")
    return {"result": result, "wall_s": wall}


def main() -> None:
    p = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    p.add_argument("--api", default="http://127.0.0.1:8001")
    p.add_argument("--reports", type=int, default=20)
    p.add_argument("--seed", type=int, default=0)
    p.add_argument("--out", type=Path, default=Path("reports/api_benchmark.json"))
    args = p.parse_args()

    df = pd.read_csv(AUTHORS_TTP).drop_duplicates("original_index")
    df = df[df.Context.astype(str).str.len() > 200].copy()
    df["n_chars"] = df.Context.astype(str).str.len()
    vocab = json.loads(Path("artifacts/label_vocab.json").read_text(encoding="utf-8"))
    space = set(vocab["techniques"])
    client = httpx.Client(base_url=args.api, timeout=60)
    model = client.get("/api/v1/model").json()

    # 1. latency: 5 reports around the 10th, 50th and 95th length percentile; medians reported
    latency = []
    for label, q in (("small", 0.10), ("medium", 0.50), ("large", 0.95)):
        rows5 = df.iloc[(df.n_chars - df.n_chars.quantile(q)).abs().argsort().iloc[:5]]
        runs = []
        for row in rows5.itertuples():
            out = run(client, str(row.Context), f"bench-{label}")
            res = out.get("result")
            if not res:
                continue
            n = res["document"]["n_sentences_analyzed"]
            runs.append({"characters": int(row.n_chars), "sentences": n, "wall_s": out["wall_s"],
                         "server_ms": res["processing_ms"], "ms_per_sentence": res["processing_ms"] / max(n, 1),
                         "timings_ms": res.get("timings_ms", {})})
        med = lambda k: float(pd.Series([r[k] for r in runs]).median())
        stages = {st: int(pd.Series([r["timings_ms"].get(st, 0) for r in runs]).median())
                  for st in (runs[0]["timings_ms"] if runs else {})}
        latency.append({"size": label, "reports": len(runs), "median_characters": int(med("characters")),
                        "median_sentences": int(med("sentences")), "median_wall_s": round(med("wall_s"), 2),
                        "median_server_ms": int(med("server_ms")),
                        "median_ms_per_sentence": round(med("ms_per_sentence"), 1),
                        "median_stage_ms": stages, "runs": runs})
        print({k: v for k, v in latency[-1].items() if k != "runs"}, flush=True)

    # 2. agreement on N random reports
    sample = df.sample(n=min(args.reports, len(df)), random_state=args.seed)
    tp = fp = fn = 0
    rows = []
    for r in sample.itertuples():
        out = run(client, str(r.Context), f"agree-{r.original_index}")
        if "result" not in out:
            rows.append({"id": int(r.original_index), "failed": out["failed"]})
            continue
        ours = {t["id"] for t in out["result"]["techniques"]}
        theirs = {str(t).split(".")[0] for t in flatten(json.loads(r.TTPs))} & space
        a, b, c = len(ours & theirs), len(ours - theirs), len(theirs - ours)
        tp, fp, fn = tp + a, fp + b, fn + c
        rows.append({"id": int(r.original_index), "ours": len(ours), "theirs": len(theirs), "both": a,
                     "jaccard": round(a / (a + b + c), 3) if a + b + c else 1.0,
                     "sentences": out["result"]["document"]["n_sentences_analyzed"],
                     "wall_s": round(out["wall_s"], 2)})
        print(rows[-1], flush=True)
    P, R = tp / max(tp + fp, 1), tp / max(tp + fn, 1)
    ok = [x for x in rows if "jaccard" in x]
    summary = {
        "model": {k: model.get(k) for k in ("version", "run_id", "model_type", "threshold_mode")},
        "device": "cpu",
        "latency": latency,
        "agreement": {
            "reports": len(ok), "failed": len(rows) - len(ok),
            "micro_precision": round(100 * P, 1), "micro_recall": round(100 * R, 1),
            "micro_f1": round(100 * 2 * P * R / (P + R), 1) if P + R else 0.0,
            "mean_jaccard": round(sum(x["jaccard"] for x in ok) / max(len(ok), 1), 3),
            "mean_techniques_ours": round(sum(x["ours"] for x in ok) / max(len(ok), 1), 1),
            "mean_techniques_theirs": round(sum(x["theirs"] for x in ok) / max(len(ok), 1), 1),
            "note": "agreement with the authors' published TTP lists (CTI2Attacker_TTP.csv), not ground truth",
            "per_report": rows,
        },
    }
    args.out.write_text(json.dumps(summary, indent=2), encoding="utf-8")
    print(json.dumps({k: v for k, v in summary["agreement"].items() if k != "per_report"}, indent=2))


if __name__ == "__main__":
    main()
