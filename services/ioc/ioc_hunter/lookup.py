"""Methods map an input IOC to a list of validated output IOCs.

No candidate set, coverage counter, tried-time counter, expansion evaluator,
edge insertion, scheduling, or graph state lives in this module.
"""
from __future__ import annotations
from contextlib import nullcontext
from dataclasses import replace
import json
from threading import Lock
import time
from uuid import uuid4
from .context import ContextGenerator, generated_context
from .config import DEFAULT_LOOKUP_DIRECTORY, api_keys_from_environment
from .evidence import LookupRecord, utc_now
from .method_spec import MethodSpec
from .methods import get_method, list_methods, list_runnable_methods
from .models import IOC, identity
from .providers import PROVIDERS, parse_document, requests_for
from .storage import EvidenceStore
from .transport import HTTPTransport, BrowserTransport, RateLimiter, LookupError, allowed_url
from .validation import validate_edge

class LookupMethod:
    def __init__(self, client: LookupClient, spec: MethodSpec):
        self.client, self.spec = client, spec
    def __call__(self, ioc: IOC) -> list[IOC]:
        return self.client.lookup(ioc, self.spec.id)

class LookupClient:
    def __init__(self, *, store: EvidenceStore | None = None, http=None, browser=None,
                 api_keys: dict[str, str] | None = None, context_generator: ContextGenerator | None = None,
                 cache_ttl: float = 86400, max_pages: int = 5, max_outputs: int = 1000,
                 interval: float = 15, daily_limit: int = 500):
        if max_pages < 1 or max_outputs < 1 or cache_ttl < 0 or interval < 0 or daily_limit < 1:
            raise ValueError("Invalid lookup limits")
        self.store = store or EvidenceStore(DEFAULT_LOOKUP_DIRECTORY)
        self.http, self.browser = http or HTTPTransport(), browser or BrowserTransport()
        self.api_keys = dict(api_keys) if api_keys is not None else api_keys_from_environment()
        self.context_generator = context_generator
        self.cache_ttl, self.max_pages, self.max_outputs = cache_ttl, max_pages, max_outputs
        self.limiter, self.daily_limit = RateLimiter(interval), daily_limit
        self.source_locks = {source: Lock() for source in PROVIDERS}
    def method(self, method_id: str) -> LookupMethod:
        return LookupMethod(self, get_method(method_id))
    def methods(self, input_type=None):
        return list_methods(input_type)
    def runnable_methods(self, input_type=None):
        return list_runnable_methods(input_type)
    @staticmethod
    def _key(ioc, method_id):
        return json.dumps([method_id, *identity(ioc)])
    def latest_record(self, ioc: IOC, method_id: str) -> dict | None:
        return self.store.latest(self._key(ioc, method_id))
    def lookup(self, ioc: IOC, method_id: str) -> list[IOC]:
        return self.lookup_detailed(ioc, method_id).outputs
    def lookup_detailed(self, ioc: IOC, method_id: str, *, lookup_id: str | None = None) -> LookupRecord:
        """Return this call's saved receipt, optionally using a durable attempt ID.

        Workflow callers must recover a saved receipt before executing its ID again.
        """
        if lookup_id is not None and (not isinstance(lookup_id, str) or not lookup_id.strip()):
            raise ValueError("A lookup ID must be a nonempty string")
        method = get_method(method_id)
        kind, value = identity(ioc)
        if kind != method.input_type:
            raise ValueError("Input IOC type does not match selected method")
        query = IOC(value, kind, list(ioc.context), ioc.source)
        record = LookupRecord(lookup_id if lookup_id is not None else uuid4().hex, method_id, query)
        try:
            if not method.implemented:
                raise LookupError("unsupported_method", method.unavailable_reason)
            with self.source_locks[method.source]:
                session = self.browser.session() if hasattr(self.browser, "session") else nullcontext()
                with session:
                    self._run(query, method, record)
            record.status = "ok" if record.outputs else "empty"
            if not record.outputs and record.evidence:
                record.outcome_reason = "all_candidates_rejected"
            elif not record.outputs and not record.outcome_reason:
                record.outcome_reason = "no_matching_records"
            if not record.complete:
                record.status = "partial"
        except (KeyboardInterrupt, SystemExit):
            record.status = "interrupted_unknown"
            record.complete = False
            record.error = "Acquisition interrupted; provider completion is unknown."
            raise
        except LookupError as exc:
            record.status, record.error = exc.status, str(exc)
            exc.lookup_id = record.id
            raise
        except Exception as exc:
            record.status, record.error = "internal_error", type(exc).__name__
            raise LookupError("internal_error", "Lookup failed: " + type(exc).__name__, lookup_id=record.id) from exc
        finally:
            record.finished_at = utc_now()
            self.store.save_record(record, self._key(query, method_id))
        return record
    def _fetch(self, request, transport, record):
        client = self.http if transport == "http" else self.browser
        scope = client.cache_scope() if hasattr(client, "cache_scope") else "anonymous"
        cache_key = self.store.cache_key(request, transport, scope)
        # A cached first page has no live GUI state for clicking Next. Start
        # paginated GUI reads live; retain their snapshots for audit/single-page use.
        live_pagination = transport == "browser" and request.next_selector and self.max_pages > 1
        document = self.store.cached(cache_key) if self.cache_ttl and not live_pagination else None
        if document:
            record.cache_hit = True
            return document, cache_key
        for attempt in range(3):
            if not getattr(client, "offline", False):
                self.limiter.wait(request.source)
                self.store.consume_budget(request.source, self.daily_limit)
            try:
                document = client.fetch(request)
                if not allowed_url(request.source, document.url):
                    raise LookupError("invalid_response", "Response left provider hosts")
                if document.diagnostics.get("terminal_state") == "timeout":
                    raise LookupError("loading_page", "Requested provider response did not complete before the deadline", document=document)
                return document, cache_key
            except LookupError as exc:
                if exc.document is not None:
                    snapshot_id = self.store.snapshot(exc.document)
                    record.responses.append({"snapshot_id": snapshot_id, "url": exc.document.url, "transport": transport})
                if exc.status == "rate_limited":
                    self.limiter.cooldown(request.source, exc.retry_after or 60)
                retryable = not request.continuation_url and (exc.status in {"network_error", "provider_error"} or (exc.status == "loading_page" and attempt == 0))
                if not retryable or attempt == 2:
                    raise
                record.transport_errors.append({"transport": transport, "status": exc.status,
                                                "message": str(exc), "attempt": attempt + 1,
                                                "retried": True, "retry_after": exc.retry_after})
                time.sleep(2 ** attempt)
    def _run(self, query, method, record):
        observations = []
        routes = requests_for(query, method, self.api_keys.get(method.source, ""))
        last_error = None
        for transport, initial_request in routes:
            request = initial_request
            route_observations = []
            visited = set()
            try:
                for page in range(self.max_pages):
                    page_identity = request.continuation_url or request.url
                    if page_identity in visited:
                        record.complete = False
                        record.partial_reasons.append("repeated_page")
                        break
                    visited.add(page_identity)
                    document, cache_key = self._fetch(request, transport, record)
                    snapshot_id = self.store.snapshot(document)
                    record.responses.append({"snapshot_id": snapshot_id, "url": document.url, "transport": document.transport})
                    parsed = parse_document(query, method, document)
                    ttl = self.cache_ttl if parsed.observations else min(self.cache_ttl, 300)
                    self.store.cache(cache_key, snapshot_id, ttl)
                    route_observations.extend(parsed.observations)
                    record.complete = record.complete and parsed.complete
                    if parsed.reason:
                        record.outcome_reason = parsed.reason
                    if not parsed.complete:
                        record.partial_reasons.append(parsed.reason or "provider_limited")
                    if not parsed.next_url:
                        break
                    if page + 1 == self.max_pages:
                        record.complete = False
                        record.partial_reasons.append("page_limit")
                        break
                    # Continue only through a verified provider UI control;
                    # never call a captured private next URL directly.
                    if transport == "browser":
                        if not request.next_selector:
                            record.complete = False
                            record.partial_reasons.append("browser_pagination_not_verified")
                            break
                        request = replace(request, continuation_url=parsed.next_url)
                    else:
                        request = replace(request, url=parsed.next_url)
                observations = route_observations
                break
            except LookupError as exc:
                last_error = exc
                record.transport_errors.append({"transport": transport, "status": exc.status, "message": str(exc),
                                                "retry_after": exc.retry_after})
                if route_observations:
                    observations = route_observations
                    record.complete = False
                    record.partial_reasons.append("later_page_failed:" + exc.status)
                    break
                # Rate/access blocks do not trigger quota evasion via another route.
                if exc.status in {"rate_limited", "budget_exhausted", "unsafe_redirect", "unsafe_pagination"}:
                    raise
        else:
            raise last_error or LookupError("unsupported_method", "No source transport available")
        outputs, evidence_by_ioc = {}, {}
        accepted_evidence = set()
        for observation in observations:
            ev, target = observation.evidence, observation.ioc
            verdict = validate_edge(query, target, method, ev)
            record.evidence.append(ev)
            if not verdict.accepted:
                record.rejected.append({"type": target.type, "value": target.value,
                                        "reason": verdict.reason, "message": verdict.message,
                                        "details": verdict.details, "evidence_id": ev.id})
                continue
            key = identity(target)
            if key not in outputs:
                if len(outputs) >= self.max_outputs:
                    record.complete = False
                    record.partial_reasons.append("output_limit")
                    continue
                outputs[key] = target
                evidence_by_ioc[key] = []
            else:
                for context in target.context:
                    if context not in outputs[key].context:
                        outputs[key].context.append(context)
            evidence_by_ioc[key].append(ev)
            if (key, ev.id) not in accepted_evidence:
                record.accepted.append({"type": key[0], "value": key[1], "method_id": method.id,
                                        "ontology_label": verdict.ontology_label,
                                        "evidence_id": ev.id, "validation": verdict.reason})
                accepted_evidence.add((key, ev.id))
        for key, target in outputs.items():
            if self.context_generator:
                try:
                    target.context.append(generated_context(target, evidence_by_ioc[key], self.context_generator))
                except Exception as exc:
                    # An LLM failure never discards a supported relationship.
                    record.rejected.append({"type": target.type, "value": target.value, "reason": "context_generation_failed", "error": type(exc).__name__})
        record.outputs = list(outputs.values())
