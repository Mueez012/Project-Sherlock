"""Per-client source pacing and cooldowns."""
from threading import Lock
import time
from .models import LookupError

class RateLimiter:
    def __init__(self, interval=15.0):
        self.interval, self.next_at, self.lock = interval, {}, Lock()
    def wait(self, source):
        with self.lock:
            now = time.monotonic()
            delay = max(0, self.next_at.get(source, 0) - now)
            if delay > 30:
                raise LookupError("rate_limited", "Local source cooldown is active", retry_after=delay)
            if delay:
                time.sleep(delay)
            self.next_at[source] = time.monotonic() + self.interval
    def cooldown(self, source, seconds):
        with self.lock:
            self.next_at[source] = max(self.next_at.get(source, 0), time.monotonic() + seconds)
