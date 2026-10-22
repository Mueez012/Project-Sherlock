"""Job storage and the single background worker.

JobStore is a small interface with two implementations:
  InMemoryJobStore   default; jobs are lost when the server restarts
  SQLiteJobStore     optional (TTP_API_JOB_STORE=sqlite); survives restarts
Both are thread-safe. One worker thread runs jobs one at a time: the model
already uses every CPU core, so parallel jobs would only slow each other down.
"""
from __future__ import annotations

import contextlib
import json
import logging
import secrets
import sqlite3
import threading
import time
from concurrent.futures import ThreadPoolExecutor
from dataclasses import asdict, dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Callable, Protocol

log = logging.getLogger("ttp_api.jobs")
ACTIVE = ("queued", "extracting_text", "splitting", "encoding", "classifying", "aggregating")
FINISHED = ("completed", "failed")


def now() -> datetime:
    return datetime.now(timezone.utc)


def new_id() -> str:
    """Time-sortable id: an_<12 hex ms timestamp><8 random hex>."""
    return f"an_{int(time.time() * 1000):012x}{secrets.token_hex(4)}"


@dataclass
class Job:
    id: str
    incident_name: str
    options: dict
    filename: str | None = None
    media_type: str | None = None
    size_bytes: int = 0
    sha256: str = ""
    status: str = "queued"
    stage: str = "queued"
    progress: float = 0.0
    message: str = "Waiting in queue"
    created_at: datetime = field(default_factory=now)
    updated_at: datetime = field(default_factory=now)
    completed_at: datetime | None = None
    error: dict | None = None
    result: dict | None = None
    temp_path: str | None = None       # raw upload; deleted when the job ends

    def to_dict(self) -> dict:
        d = asdict(self)
        for k in ("created_at", "updated_at", "completed_at"):
            d[k] = d[k].isoformat() if d[k] else None
        return d

    @classmethod
    def from_dict(cls, d: dict) -> "Job":
        d = dict(d)
        for k in ("created_at", "updated_at", "completed_at"):
            d[k] = datetime.fromisoformat(d[k]) if d.get(k) else None
        return cls(**d)


class JobStore(Protocol):
    def add(self, job: Job) -> None: ...
    def get(self, job_id: str) -> Job | None: ...
    def update(self, job_id: str, **changes) -> Job | None: ...
    def list(self, limit: int = 50) -> list[Job]: ...
    def delete(self, job_id: str) -> bool: ...
    def count_active(self) -> int: ...


class InMemoryJobStore:
    def __init__(self, keep: int = 200):
        self._jobs: dict[str, Job] = {}
        self._lock = threading.Lock()
        self.keep = keep

    def add(self, job: Job) -> None:
        with self._lock:
            self._jobs[job.id] = Job.from_dict(job.to_dict())    # own copy
            finished = [j for j in self._jobs.values() if j.status in FINISHED]
            for old in sorted(finished, key=lambda j: j.created_at)[: max(0, len(self._jobs) - self.keep)]:
                del self._jobs[old.id]

    def get(self, job_id: str) -> Job | None:
        with self._lock:
            job = self._jobs.get(job_id)
            return Job.from_dict(job.to_dict()) if job else None   # copy: callers cannot mutate

    def update(self, job_id: str, **changes) -> Job | None:
        with self._lock:
            job = self._jobs.get(job_id)
            if job is None:
                return None
            for k, v in changes.items():
                setattr(job, k, v)
            job.updated_at = now()
            return job

    def list(self, limit: int = 50) -> list[Job]:
        with self._lock:
            jobs = sorted(self._jobs.values(), key=lambda j: j.created_at, reverse=True)[:limit]
            return [Job.from_dict(j.to_dict()) for j in jobs]

    def delete(self, job_id: str) -> bool:
        with self._lock:
            return self._jobs.pop(job_id, None) is not None

    def count_active(self) -> int:
        with self._lock:
            return sum(j.status in ACTIVE for j in self._jobs.values())


class SQLiteJobStore:
    def __init__(self, path: Path, keep: int = 200):
        path.parent.mkdir(parents=True, exist_ok=True)
        self._db = sqlite3.connect(str(path), check_same_thread=False)
        self._db.execute("CREATE TABLE IF NOT EXISTS jobs (id TEXT PRIMARY KEY, created TEXT, status TEXT, body TEXT)")
        self._lock = threading.Lock()
        self.keep = keep
        # Jobs that were running when the server stopped can never finish.
        with self._lock, self._db:
            for (job_id, body) in self._db.execute("SELECT id, body FROM jobs").fetchall():
                job = Job.from_dict(json.loads(body))
                if job.status in ACTIVE:
                    job.status = job.stage = "failed"
                    job.error = {"code": "model_error", "message": "the server restarted during this job"}
                    self._write(job)

    def _write(self, job: Job) -> None:
        self._db.execute("INSERT OR REPLACE INTO jobs VALUES (?, ?, ?, ?)",
                         (job.id, job.created_at.isoformat(), job.status, json.dumps(job.to_dict())))

    def add(self, job: Job) -> None:
        with self._lock, self._db:
            self._write(job)
            self._db.execute("DELETE FROM jobs WHERE status IN ('completed','failed') AND id NOT IN "
                             "(SELECT id FROM jobs ORDER BY created DESC LIMIT ?)", (self.keep,))

    def get(self, job_id: str) -> Job | None:
        with self._lock:
            row = self._db.execute("SELECT body FROM jobs WHERE id = ?", (job_id,)).fetchone()
        return Job.from_dict(json.loads(row[0])) if row else None

    def update(self, job_id: str, **changes) -> Job | None:
        with self._lock, self._db:
            row = self._db.execute("SELECT body FROM jobs WHERE id = ?", (job_id,)).fetchone()
            if row is None:
                return None
            job = Job.from_dict(json.loads(row[0]))
            for k, v in changes.items():
                setattr(job, k, v)
            job.updated_at = now()
            self._write(job)
            return job

    def list(self, limit: int = 50) -> list[Job]:
        with self._lock:
            rows = self._db.execute("SELECT body FROM jobs ORDER BY created DESC LIMIT ?", (limit,)).fetchall()
        return [Job.from_dict(json.loads(r[0])) for r in rows]

    def delete(self, job_id: str) -> bool:
        with self._lock, self._db:
            return self._db.execute("DELETE FROM jobs WHERE id = ?", (job_id,)).rowcount > 0

    def count_active(self) -> int:
        with self._lock:
            marks = ",".join("?" * len(ACTIVE))
            return self._db.execute(f"SELECT COUNT(*) FROM jobs WHERE status IN ({marks})", ACTIVE).fetchone()[0]


class JobRunner:
    """One worker thread; `submit(job_id, fn)` runs fn(job_id) in the background."""

    def __init__(self, store: JobStore):
        self.store = store
        self._pool = ThreadPoolExecutor(max_workers=1, thread_name_prefix="ttp-worker")

    def submit(self, job_id: str, fn: Callable[[str], None]) -> None:
        self._pool.submit(self._run, job_id, fn)

    def _run(self, job_id: str, fn: Callable[[str], None]) -> None:
        job = self.store.get(job_id)
        if job is None:                 # deleted while queued
            return
        try:
            fn(job_id)
        except Exception:               # the pipeline reports its own failures; this is a last resort
            log.exception("job %s crashed", job_id)
            self.store.update(job_id, status="failed", stage="failed", completed_at=now(),
                              error={"code": "model_error", "message": "unexpected error during analysis"})
        finally:
            job = self.store.get(job_id)
            if job and job.temp_path:
                with contextlib.suppress(OSError):
                    Path(job.temp_path).unlink(missing_ok=True)
                self.store.update(job_id, temp_path=None)

    def shutdown(self) -> None:
        self._pool.shutdown(wait=False, cancel_futures=True)
