"""Per-resource execution locks shared by threads and local worker processes.

The OS releases a file lock on process exit. We never expire a live worker's
claim, and never hold a database transaction during extraction/provider work.
All writers to a shared store must use this coordinator and a filesystem with
working OS advisory locks. Lock files are permanent names, not ownership flags.
"""

import os
from contextlib import contextmanager
from hashlib import sha256
from threading import Lock

from .errors import WorkflowServiceError

_registry_guard = Lock()
_registry = {}


class ExecutionCoordinator:
    def __init__(self, directory):
        self.directory = directory / ".workflow-locks"
        self.directory.mkdir(parents=True, exist_ok=True)

    @contextmanager
    def claim(self, resource, *, code="operation_in_progress"):
        path = self.directory / (sha256(resource.encode()).hexdigest() + ".lock")
        with _registry_guard:
            guard = _registry.setdefault(os.path.normcase(str(path.resolve())), Lock())
        if not guard.acquire(blocking=False):
            raise WorkflowServiceError(code, "This investigation operation is still executing.")
        handle, locked = None, False
        try:
            handle = path.open("a+b")
            handle.seek(0, os.SEEK_END)
            if handle.tell() == 0:
                handle.write(b"\0")
                handle.flush()
            handle.seek(0)
            try:
                if os.name == "nt":
                    import msvcrt

                    msvcrt.locking(handle.fileno(), msvcrt.LK_NBLCK, 1)
                else:
                    import fcntl

                    fcntl.flock(handle.fileno(), fcntl.LOCK_EX | fcntl.LOCK_NB)
                locked = True
            except OSError as exc:
                raise WorkflowServiceError(code, "This investigation operation is still executing.") from exc
            yield
        finally:
            if handle is not None:
                if locked:
                    handle.seek(0)
                    if os.name == "nt":
                        import msvcrt

                        msvcrt.locking(handle.fileno(), msvcrt.LK_UNLCK, 1)
                    else:
                        import fcntl

                        fcntl.flock(handle.fileno(), fcntl.LOCK_UN)
                handle.close()
            guard.release()

    def busy(self, resource):
        try:
            with self.claim(resource):
                return False
        except WorkflowServiceError:
            return True
