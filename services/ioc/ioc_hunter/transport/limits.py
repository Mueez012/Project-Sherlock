"""Provider pacing, optionally coordinated across clients/processes in one store.

Only reservation writes are serialized. Neither sleeping nor provider acquisition
holds a SQL transaction or another provider's lock.
"""
from threading import Lock
import time
from .models import LookupError

class RateLimiter:
    def __init__(self, interval=15.0, *, store=None):
        self.interval, self.next_at, self.lock = interval, {}, Lock()
        self.store = store
        if store is not None:
            with store.connect() as db:
                db.execute("BEGIN IMMEDIATE")
                db.execute("CREATE TABLE IF NOT EXISTS provider_pacing "
                           "(source TEXT PRIMARY KEY, next_at REAL NOT NULL, cooldown_until REAL NOT NULL DEFAULT 0)")
                columns = {row[1] for row in db.execute("PRAGMA table_info(provider_pacing)")}
                if "cooldown_until" not in columns:
                    db.execute("ALTER TABLE provider_pacing ADD COLUMN cooldown_until REAL NOT NULL DEFAULT 0")
    def wait(self, source):
        if self.store is not None:
            with self.store.connect() as db:
                db.execute("BEGIN IMMEDIATE")
                row = db.execute("SELECT next_at,cooldown_until FROM provider_pacing WHERE source=?", (source,)).fetchone()
                now = time.time()
                delay = max(0, max(row) - now) if row else 0
                if delay > 30:
                    raise LookupError("rate_limited", "Local source cooldown is active", retry_after=delay)
                db.execute("INSERT INTO provider_pacing(source,next_at) VALUES (?,?) ON CONFLICT(source) "
                           "DO UPDATE SET next_at=excluded.next_at", (source, now + delay + self.interval))
            if delay:
                time.sleep(delay)
            # Another request may receive a provider block while we wait for our
            # reserved slot. Do not bypass that cooldown with an old reservation.
            with self.store.connect() as db:
                row = db.execute("SELECT cooldown_until FROM provider_pacing WHERE source=?", (source,)).fetchone()
            remaining = max(0, row[0] - time.time()) if row else 0
            if remaining:
                raise LookupError("rate_limited", "Local source cooldown is active", retry_after=remaining)
            return
        with self.lock:
            now = time.monotonic()
            delay = max(0, self.next_at.get(source, 0) - now)
            if delay > 30:
                raise LookupError("rate_limited", "Local source cooldown is active", retry_after=delay)
            self.next_at[source] = now + delay + self.interval
        if delay:
            time.sleep(delay)
    def cooldown(self, source, seconds):
        if self.store is not None:
            with self.store.connect() as db:
                db.execute("BEGIN IMMEDIATE")
                until = time.time() + seconds
                db.execute("INSERT INTO provider_pacing(source,next_at,cooldown_until) VALUES (?,?,?) ON CONFLICT(source) "
                           "DO UPDATE SET next_at=MAX(next_at,excluded.next_at), "
                           "cooldown_until=MAX(cooldown_until,excluded.cooldown_until)",
                           (source, until, until))
            return
        with self.lock:
            self.next_at[source] = max(self.next_at.get(source, 0), time.monotonic() + seconds)
