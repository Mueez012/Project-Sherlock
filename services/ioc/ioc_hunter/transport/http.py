"""Bounded HTTP retrieval with provider-only redirects."""
from urllib.error import HTTPError, URLError
from urllib.request import Request, build_opener, HTTPRedirectHandler
from .models import Document, FetchRequest, LookupError, allowed_url, check_status

class _SafeRedirect(HTTPRedirectHandler):
    def __init__(self, source):
        self.source = source
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        if not allowed_url(self.source, newurl):
            raise LookupError("unsafe_redirect", "Provider redirected outside its allowed hosts")
        return super().redirect_request(req, fp, code, msg, headers, newurl)

class HTTPTransport:
    def __init__(self, timeout=25.0, max_bytes=5_000_000):
        self.timeout, self.max_bytes = timeout, max_bytes
    def fetch(self, request: FetchRequest) -> Document:
        if not allowed_url(request.source, request.url):
            raise LookupError("invalid_request", "Only configured provider hosts may be queried")
        req = Request(request.url, headers={"User-Agent": "IOCHunter-Research/0.1", **request.headers})
        try:
            with build_opener(_SafeRedirect(request.source)).open(req, timeout=self.timeout) as response:
                check_status(response.status, response.headers)
                data = response.read(self.max_bytes + 1)
                if len(data) > self.max_bytes:
                    raise LookupError("response_too_large", "Provider response exceeded size limit")
                body = data.decode(response.headers.get_content_charset() or "utf-8", errors="replace")
                fmt = "json" if "json" in response.headers.get("Content-Type", "") or body.lstrip().startswith(("{", "[")) else "html"
                return Document(response.url, body, fmt, "http", status_code=response.status)
        except HTTPError as exc:
            check_status(exc.code, exc.headers)
            raise
        except (URLError, TimeoutError, OSError) as exc:
            raise LookupError("network_error", "Provider connection failed: " + type(exc).__name__) from exc
