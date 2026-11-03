"""Local response cache and immutable lookup history; not a graph database."""
from contextlib import contextmanager
from dataclasses import asdict
from datetime import datetime, timezone
from hashlib import sha256
import json
from pathlib import Path
import sqlite3
import time
from .evidence import LookupRecord
from .transport import Document, FetchRequest, LookupError

class EvidenceStore:
    def __init__(self, directory: str | Path):
        self.directory = Path(directory)
        self.directory.mkdir(parents=True, exist_ok=True)
        self.database = self.directory / "lookups.sqlite3"
        with self.connect() as db:
            db.executescript('''
                CREATE TABLE IF NOT EXISTS snapshots(id TEXT PRIMARY KEY, document TEXT NOT NULL);
                CREATE TABLE IF NOT EXISTS cache(key TEXT PRIMARY KEY, snapshot TEXT NOT NULL, expires REAL NOT NULL);
                CREATE TABLE IF NOT EXISTS lookups(id TEXT PRIMARY KEY, lookup_key TEXT NOT NULL, record TEXT NOT NULL, created REAL NOT NULL);
                CREATE TABLE IF NOT EXISTS budgets(day TEXT, source TEXT, calls INTEGER NOT NULL, PRIMARY KEY(day, source));
            ''')
    @contextmanager
    def connect(self):
        db = sqlite3.connect(self.database, timeout=30)
        try:
            with db:
                yield db
        finally:
            db.close()
    @staticmethod
    def cache_key(request: FetchRequest, transport: str, access_scope: str = "anonymous"):
        # Secret headers influence isolation, but neither they nor their raw values are stored.
        serialized = json.dumps([request.integration_version, request.source, request.url,
                                 request.operation, request.continuation_url, transport, request.headers, access_scope], sort_keys=True)
        return sha256(serialized.encode()).hexdigest()
    def snapshot(self, doc: Document) -> str:
        data = json.dumps(asdict(doc), ensure_ascii=False, sort_keys=True)
        key = sha256(data.encode()).hexdigest()
        with self.connect() as db:
            db.execute("INSERT OR IGNORE INTO snapshots VALUES (?, ?)", (key, data))
        return key
    def cache(self, key, snapshot, ttl):
        with self.connect() as db:
            db.execute("INSERT OR REPLACE INTO cache VALUES (?, ?, ?)", (key, snapshot, time.time() + ttl))
    def cached(self, key) -> Document | None:
        with self.connect() as db:
            row = db.execute("SELECT s.document FROM cache c JOIN snapshots s ON s.id=c.snapshot WHERE c.key=? AND c.expires>?", (key, time.time())).fetchone()
        return Document(**json.loads(row[0])) if row else None
    def consume_budget(self, source: str, limit: int):
        day = datetime.now(timezone.utc).date().isoformat()
        with self.connect() as db:
            db.execute("BEGIN IMMEDIATE")
            row = db.execute("SELECT calls FROM budgets WHERE day=? AND source=?", (day, source)).fetchone()
            count = row[0] if row else 0
            if count >= limit:
                raise LookupError("budget_exhausted", f"Local daily request budget reached for {source}")
            db.execute("INSERT OR REPLACE INTO budgets VALUES (?, ?, ?)", (day, source, count + 1))
    def save_record(self, record: LookupRecord, lookup_key: str):
        with self.connect() as db:
            db.execute("INSERT INTO lookups VALUES (?, ?, ?, ?)", (record.id, lookup_key, json.dumps(record.to_dict(), ensure_ascii=False), time.time()))
    def get_record(self, lookup_id: str) -> dict:
        with self.connect() as db:
            row = db.execute("SELECT record FROM lookups WHERE id=?", (lookup_id,)).fetchone()
        if not row:
            raise KeyError("Unknown lookup ID")
        return json.loads(row[0])
    def latest(self, lookup_key: str) -> dict | None:
        with self.connect() as db:
            row = db.execute("SELECT record FROM lookups WHERE lookup_key=? ORDER BY created DESC LIMIT 1", (lookup_key,)).fetchone()
        return json.loads(row[0]) if row else None
    def get_snapshot(self, snapshot_id: str) -> dict:
        with self.connect() as db:
            row = db.execute("SELECT document FROM snapshots WHERE id=?", (snapshot_id,)).fetchone()
        if not row:
            raise KeyError("Unknown snapshot ID")
        return json.loads(row[0])
