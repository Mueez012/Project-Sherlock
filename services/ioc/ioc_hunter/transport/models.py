"""Transport request/response contracts and provider access errors."""
from dataclasses import dataclass, field
from datetime import datetime, timezone
from email.utils import parsedate_to_datetime
from urllib.parse import urlsplit
from ..evidence import utc_now

HOSTS = {"rapiddns": {"rapiddns.io", "www.rapiddns.io"},
         "alienvault": {"otx.alienvault.com"},
         "virustotal": {"www.virustotal.com", "virustotal.com"}}

class LookupError(RuntimeError):
    def __init__(self, status: str, message: str, *, retry_after: float | None = None, lookup_id: str = "", document=None):
        super().__init__(message)
        self.status, self.retry_after, self.lookup_id = status, retry_after, lookup_id
        self.document = document

@dataclass(frozen=True)
class FetchRequest:
    source: str
    url: str
    operation: str
    response_paths: tuple[str, ...] = ()
    headers: dict = field(default_factory=dict, repr=False)
    page_labels: tuple[str, ...] = ()
    bootstrap_paths: tuple[str, ...] = ()
    result_selector: str = ""
    identity_type: str = ""
    integration_version: str = "2"
    page_errors: tuple[tuple[str, str], ...] = ()
    next_selector: str = ""
    continuation_url: str = ""

@dataclass
class Document:
    url: str
    body: str
    format: str
    transport: str = "http"
    fetched_at: str = field(default_factory=utc_now)
    status_code: int = 200
    diagnostics: dict = field(default_factory=dict)

def allowed_url(source: str, url: str) -> bool:
    try:
        p = urlsplit(url)
        return (p.scheme == "https" and p.hostname in HOSTS.get(source, set())
                and p.port in {None, 443} and not p.username and not p.password)
    except (ValueError, TypeError):
        return False

def check_status(status: int, headers=None):
    if status < 400:
        return
    names = {401: "login_required", 403: "access_denied", 404: "not_found", 429: "rate_limited"}
    delay = None
    retry_header = next((value for key, value in (headers or {}).items() if key.lower() == "retry-after"), None)
    if retry_header:
        raw = retry_header
        try:
            delay = max(0.0, float(raw))
        except ValueError:
            try:
                delay = max(0.0, (parsedate_to_datetime(raw) - datetime.now(timezone.utc)).total_seconds())
            except (ValueError, TypeError):
                pass
    raise LookupError(names.get(status, "provider_error"), f"Provider returned HTTP {status}", retry_after=delay)
