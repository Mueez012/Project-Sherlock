"""Run a list of training jobs, a few at a time on one GPU. Safe to restart.

Jobs file: one job per line, `<run-name> <train.py flags...>`; blank lines and
lines starting with # are ignored. A job whose runs/<run-name>/summary.json
exists is skipped; an interrupted job continues with --resume.

  python -m ttp_extraction.training.queue --jobs configs/single_change_jobs.txt --parallel 1
"""
from __future__ import annotations

import argparse
import os
import shlex
import subprocess
import sys
import time
from pathlib import Path


def read_jobs(path: Path) -> list[tuple[str, list[str]]]:
    jobs = []
    for line in path.read_text(encoding="utf-8").splitlines():
        line = line.strip()
        if line and not line.startswith("#"):
            name, *flags = shlex.split(line)
            jobs.append((name, flags))
    return jobs


def main() -> None:
    p = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    p.add_argument("--jobs", type=Path, required=True)
    p.add_argument("--csv", default="ThreatMAMBA-main/CTI2TTPs.csv")
    p.add_argument("--runs", type=Path, default=Path("runs"))
    p.add_argument("--logs", type=Path, default=Path("reports/logs"))
    p.add_argument("--parallel", type=int, default=1)
    args = p.parse_args()

    args.logs.mkdir(parents=True, exist_ok=True)
    pending = [(n, f) for n, f in read_jobs(args.jobs)
               if not (args.runs / n / "summary.json").exists()]
    print(f"{len(pending)} jobs to run", flush=True)
    running: list[tuple[str, subprocess.Popen, float]] = []
    while pending or running:
        while pending and len(running) < args.parallel:
            name, flags = pending.pop(0)
            resume = ["--resume"] if (args.runs / name / "last.pt").exists() else []
            cmd = [sys.executable, "-W", "ignore", "-m", "ttp_extraction.training.train",
                   "--csv", args.csv, "--runs", str(args.runs), "--run-name", name, *flags, *resume]
            log = (args.logs / f"{name}.log").open("a", encoding="utf-8")
            running.append((name, subprocess.Popen(cmd, stdout=log, stderr=subprocess.STDOUT,
                                                  env={**os.environ, "PYTHONUNBUFFERED": "1"}), time.time()))
            print(f"{time.strftime('%H:%M:%S')} start {name} {' '.join(flags + resume)}", flush=True)
        time.sleep(10)
        for job in list(running):
            name, proc, started = job
            if proc.poll() is not None:
                running.remove(job)
                status = "ok" if proc.returncode == 0 else f"FAILED ({proc.returncode})"
                print(f"{time.strftime('%H:%M:%S')} {status} {name} "
                      f"after {(time.time() - started) / 60:.1f} min", flush=True)


if __name__ == "__main__":
    main()
