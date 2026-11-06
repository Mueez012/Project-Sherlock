"""Capture operation-specific responses from the paper's provider report pages."""
from hashlib import sha256
from contextlib import contextmanager, ExitStack
from ipaddress import ip_address
import json
from pathlib import Path
import time
from threading import local
from urllib.parse import unquote, urlsplit, parse_qs
from .models import Document, FetchRequest, LookupError, allowed_url, check_status


def response_matches(request: FetchRequest, url: str) -> bool:
    """Compare typed IP identities without broadly decoding URL-valued paths."""
    if not allowed_url(request.source, url):
        return False
    def canonical(path):
        if request.identity_type not in {"ipv4", "ipv6"}:
            return path.rstrip("/")
        segments = path.rstrip("/").split("/")
        for index, segment in enumerate(segments):
            try:
                segments[index] = str(ip_address(unquote(segment)))
            except ValueError:
                pass
        return "/".join(segments)
    actual = urlsplit(url).path
    if not any(canonical(actual) == canonical(expected) for expected in request.response_paths):
        return False
    # Never replace the initial page with a prefetched later page.
    query = parse_qs(urlsplit(url).query)
    if request.continuation_url:
        expected = urlsplit(request.continuation_url)
        if not allowed_url(request.source, request.continuation_url) or canonical(expected.path) != canonical(actual):
            return False
        expected_query = parse_qs(expected.query)
        return bool(expected_query) and all(query.get(k) == v for k, v in expected_query.items())
    return not query.get("cursor") and query.get("page", ["1"]) == ["1"]


class BrowserTransport:
    def __init__(self, *, timeout=60.0, storage_state=None, headless=True, max_bytes=5_000_000):
        self.timeout, self.storage_state, self.headless = timeout, storage_state, headless
        self.max_bytes = max_bytes
        self._local = local()

    @contextmanager
    def session(self):
        """One lazy browser session per lookup/thread; close it on every exit."""
        if getattr(self._local, "state", None) is not None:
            yield
            return
        state = {"stack": ExitStack(), "page": None, "url": None, "operation": None}
        self._local.state = state
        try:
            yield
        finally:
            try:
                state["stack"].close()
            finally:
                self._local.state = None

    @contextmanager
    def _page(self, request):
        if getattr(self._local, "state", None) is None:
            with self.session():
                with self._page(request) as page:
                    yield page
            return
        state = self._local.state
        if request.continuation_url and (state["page"] is None or state["url"] != request.url or state["operation"] != request.operation):
            raise LookupError("pagination_unavailable", "Next page requires the original live report session")
        if state["page"] is None:
            from playwright.sync_api import sync_playwright
            runtime = state["stack"].enter_context(sync_playwright())
            browser = runtime.chromium.launch(headless=self.headless, timeout=30000)
            state["stack"].callback(browser.close)
            context = browser.new_context(storage_state=self.storage_state) if self.storage_state else browser.new_context()
            state["page"] = context.new_page()
            page = state["page"]
            def restrict_navigation(route):
                req = route.request
                if req.is_navigation_request() and req.frame == page.main_frame and not allowed_url(request.source, req.url):
                    route.abort()
                else:
                    route.fallback()
            # Keep the navigation guard active even between pagination calls.
            page.route("**/*", restrict_navigation)
        if not request.continuation_url:
            state["url"] = request.url
            state["operation"] = request.operation
        yield state["page"]

    def cache_scope(self):
        if not self.storage_state:
            return "anonymous"
        state = (Path(self.storage_state).read_bytes() if isinstance(self.storage_state, (str, Path))
                 else json.dumps(self.storage_state, sort_keys=True).encode())
        return sha256(state).hexdigest()

    def fetch(self, request: FetchRequest) -> Document:
        if not allowed_url(request.source, request.url):
            raise LookupError("invalid_request", "Only provider pages may be opened")
        try:
            from playwright.sync_api import sync_playwright, Error as BrowserError, TimeoutError as BrowserTimeout
        except ImportError as exc:
            raise LookupError("dependency_missing", "Install the browser extra and run playwright install chromium") from exc
        started = time.monotonic()
        deadline = started + self.timeout
        diagnostics = {"operation": request.operation, "expected_paths": list(request.response_paths),
                       "events": [], "observed_paths": [], "body_errors": [], "terminal_state": "pending"}
        finished, failures, pending = [], [], {}
        def remaining():
            return max(1, (deadline - time.monotonic()) * 1000)
        try:
            with self._page(request) as page:
                try:
                    # Browser startup has its own bounded launch timeout. The
                    # operation deadline covers navigation, activation and data.
                    deadline = time.monotonic() + self.timeout
                    page.set_default_timeout(remaining())
                    def observe(response):
                        path = urlsplit(response.url).path.rstrip("/")
                        if (allowed_url(request.source, response.url) and
                                response.request.resource_type in {"xhr", "fetch"} and
                                len(diagnostics["observed_paths"]) < 100):
                            diagnostics["observed_paths"].append({"path": path, "status": response.status})
                        relevant = response_matches(request, response.url)
                        bootstrap = allowed_url(request.source, response.url) and path in request.bootstrap_paths
                        if (allowed_url(request.source, response.url) and response.status == 429
                                and response.request.resource_type in {"xhr", "fetch"}):
                            failures.append(response)
                            return
                        if not relevant and not bootstrap:
                            return
                        diagnostics["events"].append({"url": response.url, "status": response.status,
                                                       "seconds": round(time.monotonic()-started, 3)})
                        if response.status >= 400:
                            failures.append(response)
                        elif relevant:
                            pending[response.request] = response

                    def complete(req):
                        response = pending.pop(req, None)
                        if response is not None:
                            finished.append(response)

                    def failed(req):
                        if req in pending or response_matches(request, req.url):
                            pending.pop(req, None)
                            diagnostics["body_errors"].append({"url": req.url, "error": req.failure})

                    # Listen before navigation; read bodies only after completion.
                    page.on("response", observe)
                    page.on("requestfinished", complete)
                    page.on("requestfailed", failed)

                    def document(body, format, url, state, status=200):
                        diagnostics["terminal_state"] = state
                        diagnostics["elapsed_seconds"] = round(time.monotonic()-started, 3)
                        return Document(url, body, format, "browser", status_code=status, diagnostics=diagnostics)

                    def failure_snapshot(exc):
                        body = page.content()
                        if len(body.encode()) <= self.max_bytes:
                            exc.document = document(body, "html", page.url, exc.status)
                        return exc

                    try:
                        if request.continuation_url:
                            if not request.next_selector or not response_matches(request, request.continuation_url):
                                raise LookupError("unsafe_pagination", "Continuation left the configured IOC operation")
                            # Click the provider's own control. Never fetch the
                            # captured private next URL directly.
                            next_button = page.locator(request.next_selector)
                            next_button.wait_for(state="visible", timeout=remaining())
                            if next_button.count() != 1 or not next_button.is_enabled():
                                raise LookupError("pagination_unavailable", "Provider next-page control is unavailable")
                            next_button.click(timeout=remaining())
                        else:
                            response = page.goto(request.url, wait_until="domcontentloaded", timeout=remaining())
                            if response:
                                check_status(response.status, response.headers)
                    except BrowserTimeout:
                        pass
                    except LookupError as exc:
                        raise failure_snapshot(exc)
                    clicked = set()
                    while time.monotonic() < deadline or finished or failures:
                        if failures:
                            response = failures[0]
                            try:
                                check_status(response.status, response.headers)
                            except LookupError as exc:
                                raise failure_snapshot(exc)
                        for text, status in request.page_errors:
                            marker = page.get_by_text(text, exact=True)
                            if marker.count() and marker.first.is_visible():
                                raise failure_snapshot(LookupError(status, "Provider page: " + text))
                        while finished:
                            response = finished.pop(0)
                            try:
                                body = response.text()
                            except Exception as exc:
                                diagnostics["body_errors"].append({"url": response.url, "error": type(exc).__name__})
                                continue
                            if len(body.encode()) > self.max_bytes:
                                raise LookupError("response_too_large", "Provider response exceeded size limit")
                            if "json" in response.headers.get("content-type", ""):
                                return document(body, "json", response.url, "response_complete", response.status)
                            return document(body, "html", response.url, "unexpected_content", response.status)
                        for label in (() if request.continuation_url else request.page_labels):
                            if label in clicked or time.monotonic() >= deadline:
                                continue
                            link = page.get_by_text(label, exact=True)
                            for index in range(link.count()):
                                target = link.nth(index)
                                if target.is_visible():
                                    try:
                                        target.click(timeout=min(2000, remaining()))
                                        clicked.add(label)
                                    except BrowserTimeout:
                                        continue
                                    break
                        page.wait_for_timeout(min(200, remaining()))
                    if not allowed_url(request.source, page.url):
                        raise LookupError("login_required", "Provider redirected to an external login")
                    body = page.content()
                    if len(body.encode()) > self.max_bytes:
                        raise LookupError("response_too_large", "Rendered page exceeded size limit")
                    state = "timeout"
                    if request.result_selector and not request.continuation_url:
                        section = page.locator(request.result_selector)
                        if section.count() == 1 and section.evaluate("""root => {
                            const busy = [...root.querySelectorAll('.loading, [aria-busy="true"]')]
                                .some(el => el.getClientRects().length && getComputedStyle(el).visibility !== 'hidden');
                            return !busy && (root.querySelector('tbody tr td') !== null ||
                                /No Entries Found|No results|No records/i.test(root.innerText));
                        }"""):
                            state = "html_ready"
                    return document(body, "html", page.url, state)
                finally:
                    page.remove_listener("response", observe)
                    page.remove_listener("requestfinished", complete)
                    page.remove_listener("requestfailed", failed)
        except LookupError:
            raise
        except Exception as exc:
            if isinstance(exc, BrowserError):
                # Recognize local runtime failures without exporting raw Playwright
                # messages, which can include paths, launch arguments or secrets.
                message = str(exc).lower()
                if "executable doesn't exist" in message:
                    command = "python -m playwright install chromium" + (" --only-shell" if self.headless else "")
                    raise LookupError("browser_binary_missing",
                                      "The Chromium executable matching this Playwright installation is missing. "
                                      "Run '" + command + "' in the same Python environment used to start IOC Hunter.") from exc
                if ("host system is missing dependencies" in message
                        or "error while loading shared libraries" in message):
                    raise LookupError("browser_dependencies_missing",
                                      "Chromium cannot start because required system libraries are missing. "
                                      "Run 'python -m playwright install-deps chromium' in the same environment "
                                      "used to start IOC Hunter.") from exc
            raise LookupError("browser_error", "Browser lookup failed: " + type(exc).__name__) from exc

