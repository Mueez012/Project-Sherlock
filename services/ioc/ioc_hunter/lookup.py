"""Methods map an input IOC to a list of validated output IOCs.

No candidate set, coverage counter, tried-time counter, expansion evaluator,
edge insertion, scheduling, or graph state lives in this module.
"""
from __future__ import annotations
from contextlib import nullcontext
from dataclasses import replace
from hashlib import sha256
import json
import math
from threading import local
import time
from uuid import uuid4
from .context import ContextGenerator, generated_context
from .config import resolve_store_directory, api_keys_from_environment
from .evidence import LookupRecord, utc_now
from .method_spec import MethodSpec
from .methods import get_method, list_methods, list_runnable_methods
from .models import IOC, identity
from .providers import parse_document, requests_for
from .providers.base import FollowUp
from .storage import EvidenceStore
from .transport import HTTPTransport, BrowserTransport, RateLimiter, LookupError, allowed_url, HOSTS
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
                 interval: float = 15, daily_limit: int = 500, max_followups: int = 10,
                 provider_limits: dict | None = None, frozen_cache: bool = False, cache_namespace: str = ""):
        if (max_pages < 1 or max_outputs < 1 or cache_ttl < 0 or interval < 0
                or daily_limit < 1 or type(max_followups) is not int or max_followups < 0):
            raise ValueError("Invalid lookup limits")
        self.store = store or EvidenceStore(resolve_store_directory())
        self.http, self.browser = http or HTTPTransport(), browser or BrowserTransport()
        self.api_keys = dict(api_keys) if api_keys is not None else api_keys_from_environment()
        self.context_generator = context_generator
        self.cache_ttl, self.max_pages, self.max_outputs = cache_ttl, max_pages, max_outputs
        self.max_followups = max_followups
        self.limiter, self.daily_limit = RateLimiter(interval, store=self.store), daily_limit
        self._operation = local()
        self.frozen_cache, self.cache_namespace = False, ""
        self.configure_limits(provider_limits, frozen_cache=frozen_cache, cache_namespace=cache_namespace)

    def configure_limits(self, provider_limits=None, *, frozen_cache=None, cache_namespace=None):
        """Configure shared provider gates and build-scoped immutable evidence reuse."""
        if provider_limits is not None and not isinstance(provider_limits, dict):
            raise ValueError("provider_limits must be a provider/profile mapping")
        profiles = {}
        for source, values in (provider_limits or {}).items():
            if source not in HOSTS or not isinstance(values, dict) or set(values) - {
                    "interval", "daily_limit", "backoff_seconds", "max_backoff_seconds"}:
                raise ValueError("Invalid provider limit profile")
            profile = {"interval": self.limiter.interval, "daily_limit": self.daily_limit,
                       "backoff_seconds": 60, "max_backoff_seconds": 3600, **values}
            if type(profile["daily_limit"]) is not int or profile["daily_limit"] < 1:
                raise ValueError("Provider daily_limit must be a positive integer")
            for key in ("interval", "backoff_seconds", "max_backoff_seconds"):
                value = profile[key]
                if (isinstance(value, bool) or not isinstance(value, (int, float))
                        or not math.isfinite(value) or value < (0 if key == "interval" else 1)):
                    raise ValueError("Invalid provider " + key)
            if profile["max_backoff_seconds"] < profile["backoff_seconds"]:
                raise ValueError("Provider max_backoff_seconds is below backoff_seconds")
            profiles[source] = profile
        enabled = self.frozen_cache if frozen_cache is None else frozen_cache
        namespace = self.cache_namespace if cache_namespace is None else cache_namespace
        if type(enabled) is not bool or not isinstance(namespace, str) or (enabled and not namespace.strip()):
            raise ValueError("Frozen evidence reuse requires a nonempty cache_namespace")
        for source, profile in profiles.items():
            self.store.set_provider_limit(source, profile)
        self.frozen_cache, self.cache_namespace = enabled, namespace

    def _profile(self, source):
        return self.store.provider_limit(source) or {
            "interval": self.limiter.interval, "daily_limit": self.daily_limit,
            "backoff_seconds": 60, "max_backoff_seconds": 3600}

    def rate_status(self, source: str) -> dict:
        """Read shared pacing/quota state without consuming a logical attempt."""
        if source not in HOSTS:
            raise ValueError("Unknown provider")
        profile = self._profile(source)
        status = self.limiter.status(source)
        budget = self.store.budget_status(source, profile["daily_limit"])
        if not budget["remaining"]:
            status.update(ready=False, reason="budget_exhausted",
                          retry_at=max(status["retry_at"], budget["reset_at"]))
            status["wait_seconds"] = max(0, status["retry_at"] - time.time())
        return {**status, **budget, "source": source,
                "interval": profile["interval"], "daily_limit": profile["daily_limit"]}

    def _request_cache(self, request, transport):
        client = self.http if transport == "http" else self.browser
        scope = client.cache_scope() if hasattr(client, "cache_scope") else "anonymous"
        key = self.store.cache_key(request, transport, scope)
        live_pages = transport == "browser" and request.next_selector and self.operation_pages > 1
        document = self.store.cached(key) if self.cache_ttl and not live_pages else None
        return document, key

    def _frozen_key(self, query, method):
        if not self.frozen_cache:
            return ""
        routes = requests_for(query, method, self.api_keys.get(method.source, ""))
        route_keys = []
        for transport, request in routes:
            if request.source != method.source or not allowed_url(method.source, request.url):
                raise LookupError("invalid_request", "Frozen lookup route left the provider")
            client = self.http if transport == "http" else self.browser
            scope = client.cache_scope() if hasattr(client, "cache_scope") else "anonymous"
            route_keys.append([self.store.cache_key(request, transport, scope),
                               bool(getattr(client, "offline", False))])
        payload = ["frozen-v1", self.cache_namespace, method.id, method.operation, identity(query),
                   self.operation_pages, self.operation_outputs, self.max_followups, route_keys]
        return sha256(json.dumps(payload, sort_keys=True).encode()).hexdigest()

    def lookup_wait(self, ioc: IOC, method_id: str) -> dict | None:
        """Defer known long local blocks before reserving a workflow step.

        Cached first stages may proceed; a later uncached read still checks the gate.
        """
        method = get_method(method_id)
        query = IOC(identity(ioc)[1], identity(ioc)[0], list(ioc.context), ioc.source)
        if not method.implemented or method.input_type != query.type:
            raise ValueError("Select an implemented method compatible with this IOC")
        key = self._frozen_key(query, method)
        if key and self.store.frozen_lookup(key):
            return None
        routes = requests_for(query, method, self.api_keys.get(method.source, ""))
        if not routes:
            return None
        transport, request = routes[0]
        client = self.http if transport == "http" else self.browser
        if getattr(client, "offline", False) or self._request_cache(request, transport)[0] is not None:
            return None
        status = self.rate_status(method.source)
        return status if (status["reason"] == "budget_exhausted" or status["wait_seconds"] > 30) else None

    @staticmethod
    def _accounting():
        return {"version": 1, "scope": "top_level_fetch", "fetch_attempts": 0,
                "external_fetch_attempts": 0, "fetch_attempts_by_transport": {}, "cache_reads": 0,
                "parsed_pages": 0, "followups_scheduled": 0, "followups_executed": 0,
                "retry_attempts": 0, "rate_wait_seconds": 0.0, "retry_at": None}

    @property
    def operation_pages(self):
        return getattr(self._operation, "limits", (self.max_pages, self.max_outputs))[0]

    @property
    def operation_outputs(self):
        return getattr(self._operation, "limits", (self.max_pages, self.max_outputs))[1]
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
    def lookup_detailed(self, ioc: IOC, method_id: str, *, lookup_id: str | None = None,
                        max_pages=None, max_outputs=None) -> LookupRecord:
        """Use per-call immutable limits; concurrent runs never mutate client defaults."""
        limits = (self.max_pages if max_pages is None else max_pages,
                  self.max_outputs if max_outputs is None else max_outputs)
        if any(type(value) is not int or value < 1 for value in limits):
            raise ValueError("Lookup limits must be positive integers")
        previous = getattr(self._operation, "limits", None)
        self._operation.limits = limits
        try:
            return self._lookup_detailed(ioc, method_id, lookup_id=lookup_id)
        finally:
            if previous is None:
                del self._operation.limits
            else:
                self._operation.limits = previous

    def _lookup_detailed(self, ioc: IOC, method_id: str, *, lookup_id: str | None = None) -> LookupRecord:
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
        record.acquisition = self._accounting()
        frozen_key = ""
        try:
            if not method.implemented:
                raise LookupError("unsupported_method", method.unavailable_reason)
            frozen_key = self._frozen_key(query, method)
            saved = self.store.frozen_lookup(frozen_key) if frozen_key else None
            if saved:
                old = LookupRecord.from_dict(saved)
                record.outputs, record.evidence = old.outputs, old.evidence
                record.accepted, record.rejected = old.accepted, old.rejected
                record.responses = [{**response, "cached": True} for response in old.responses]
                record.status, record.complete = old.status, old.complete
                record.outcome_reason, record.partial_reasons = old.outcome_reason, old.partial_reasons
                record.cache_hit = True
                record.acquisition.update(cache_reads=max(1, len(old.responses)), frozen_lookup_id=old.id)
                return record
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
            if (record.acquisition.get("defer_reason") and not record.acquisition["fetch_attempts"]
                    and not record.outputs):
                raise LookupError("deferred", "Local provider gate deferred an unfinished lookup",
                                  retry_after=max(0, record.acquisition["retry_at"] - time.time()))
        except (KeyboardInterrupt, SystemExit):
            record.status = "interrupted_unknown"
            record.complete = False
            record.error = "Acquisition interrupted; provider completion is unknown."
            raise
        except LookupError as exc:
            record.status, record.error = exc.status, str(exc)
            if exc.retry_after is not None:
                record.acquisition["retry_at"] = time.time() + exc.retry_after
            exc.lookup_id = record.id
            raise
        except Exception as exc:
            record.status, record.error = "internal_error", type(exc).__name__
            raise LookupError("internal_error", "Lookup failed: " + type(exc).__name__, lookup_id=record.id) from exc
        finally:
            record.finished_at = utc_now()
            self.store.save_record(record, self._key(query, method_id))
            if (frozen_key and record.status in {"ok", "empty", "partial"}
                    and not record.transport_errors and not record.acquisition.get("retry_at")):
                self.store.freeze_lookup(frozen_key, record.id)
        return record
    def _fetch(self, request, transport, record):
        client = self.http if transport == "http" else self.browser
        # A cached first page has no live GUI state for clicking Next. Start
        # paginated GUI reads live; retain their snapshots for audit/single-page use.
        document, cache_key = self._request_cache(request, transport)
        if document:
            record.cache_hit = True
            record.acquisition["cache_reads"] += 1
            self._operation.last_cached = True
            return document, cache_key
        for attempt in range(3):
            if not getattr(client, "offline", False):
                profile = self._profile(request.source)
                budget = self.store.budget_status(request.source, profile["daily_limit"])
                try:
                    if not budget["remaining"]:
                        raise LookupError("budget_exhausted", "Local daily provider budget is exhausted",
                                          retry_after=max(0, budget["reset_at"] - time.time()))
                    waited = self.limiter.wait(request.source, interval=profile["interval"])
                    record.acquisition["rate_wait_seconds"] += waited or 0
                    self.store.consume_budget(request.source, profile["daily_limit"])
                except LookupError as exc:
                    record.acquisition["rate_wait_seconds"] += getattr(exc, "rate_wait_seconds", 0)
                    record.acquisition.update(retry_at=time.time() + (exc.retry_after or 1),
                                              defer_reason=exc.status)
                    if not record.acquisition["fetch_attempts"]:
                        exc.status = "deferred"
                    raise
            try:
                self._operation.last_cached = False
                record.acquisition["fetch_attempts"] += 1
                counts = record.acquisition["fetch_attempts_by_transport"]
                counts[transport] = counts.get(transport, 0) + 1
                if not getattr(client, "offline", False):
                    record.acquisition["external_fetch_attempts"] += 1
                if attempt:
                    record.acquisition["retry_attempts"] += 1
                document = client.fetch(request)
                if not allowed_url(request.source, document.url):
                    raise LookupError("invalid_response", "Response left provider hosts")
                if document.diagnostics.get("terminal_state") == "timeout":
                    raise LookupError("loading_page", "Requested provider response did not complete before the deadline", document=document)
                if not getattr(client, "offline", False):
                    self.store.clear_backoff(request.source)
                return document, cache_key
            except LookupError as exc:
                if exc.document is not None:
                    snapshot_id = self.store.snapshot(exc.document)
                    record.responses.append({"snapshot_id": snapshot_id, "url": exc.document.url, "transport": transport})
                if exc.status == "rate_limited":
                    profile = self._profile(request.source)
                    delay = exc.retry_after
                    if delay is None or not math.isfinite(delay):
                        delay = self.store.backoff_delay(request.source, profile["backoff_seconds"],
                                                        profile["max_backoff_seconds"])
                    delay = max(0, delay)
                    exc.retry_after = delay
                    self.limiter.cooldown(request.source, delay)
                    record.acquisition["retry_at"] = time.time() + delay
                retryable = not request.continuation_url and (exc.status in {"network_error", "provider_error"} or (exc.status == "loading_page" and attempt == 0))
                if not retryable or attempt == 2:
                    raise
                record.transport_errors.append({"transport": transport, "status": exc.status,
                                                "message": str(exc), "attempt": attempt + 1,
                                                "retried": True, "retry_after": exc.retry_after})
                time.sleep(2 ** attempt)
    def _run(self, query, method, record):
        routes = requests_for(query, method, self.api_keys.get(method.source, ""))
        observations, children, stopped = self._acquire_routes(query, method, record, routes)
        pending, scheduled = [], set()

        def schedule(items):
            for child in items:
                if not isinstance(child, FollowUp) or not isinstance(child.key, str) or not child.key:
                    raise LookupError("invalid_request", "Provider supplied an invalid follow-up")
                if child.key in scheduled:
                    continue
                if len(scheduled) >= self.max_followups:
                    record.complete = False
                    if "followup_limit" not in record.partial_reasons:
                        record.partial_reasons.append("followup_limit")
                    continue
                scheduled.add(child.key)
                pending.append(child)
                record.acquisition["followups_scheduled"] += 1

        if stopped is None:
            schedule(children)
        else:
            record.outcome_reason = "acquisition_stopped:" + stopped.status
        while pending:
            child = pending.pop(0)
            record.acquisition["followups_executed"] += 1
            try:
                child_routes = self._followup_routes(child, method.source)
                found, descendants, stopped = self._acquire_routes(query, method, record, child_routes)
                observations.extend(found)
                if stopped is not None:
                    record.outcome_reason = "acquisition_stopped:" + stopped.status
                    break
                schedule(descendants)
            except LookupError as exc:
                record.complete = False
                record.partial_reasons.append("followup_failed:" + exc.status)
                record.outcome_reason = "followup_failed"
                if exc.status in {"deferred", "rate_limited", "budget_exhausted", "unsafe_redirect", "unsafe_pagination",
                                  "login_required", "access_denied"}:
                    if not observations:
                        raise
                    break
        self._accept_observations(query, method, record, observations)

    def _followup_routes(self, child, source):
        """Resolve normal configured fallbacks without passing secrets to parsers."""
        if child.routes and (child.ioc is not None or child.method is not None):
            raise LookupError("invalid_request", "Follow-up cannot combine explicit and typed routes")
        if child.routes:
            routes = child.routes
        elif child.ioc is not None and child.method is not None and child.method.source == source:
            routes = requests_for(child.ioc, child.method, self.api_keys.get(source, ""))
        else:
            raise LookupError("invalid_request", "Follow-up lacks a source operation")
        if not routes:
            raise LookupError("invalid_request", "Follow-up has no acquisition routes")
        return [(transport, replace(request, context={**request.context, **child.context}))
                for transport, request in routes]

    def _acquire_routes(self, query, method, record, routes):
        """Acquire one stage; alternatives, pagination and required reads differ."""
        last_error = None
        for transport, initial_request in routes:
            if initial_request.source != method.source or transport not in {"http", "browser"}:
                raise LookupError("invalid_request", "Follow-up left the selected provider")
            request = initial_request
            route_observations, route_followups = [], []
            visited = set()
            parsed_pages = 0
            try:
                for page in range(self.operation_pages):
                    page_identity = request.continuation_url or request.url
                    if page_identity in visited:
                        record.complete = False
                        record.partial_reasons.append("repeated_page")
                        break
                    visited.add(page_identity)
                    document, cache_key = self._fetch(request, transport, record)
                    if request.context:
                        document = replace(document, diagnostics={**document.diagnostics,
                                                                  "request_context": dict(request.context)})
                    snapshot_id = self.store.snapshot(document)
                    record.responses.append({"snapshot_id": snapshot_id, "url": document.url, "transport": document.transport,
                                             "cached": getattr(self._operation, "last_cached", False)})
                    parsed = parse_document(query, method, document)
                    parsed_pages += 1
                    record.acquisition["parsed_pages"] += 1
                    ttl = self.cache_ttl if parsed.observations or parsed.followups else min(self.cache_ttl, 300)
                    self.store.cache(cache_key, snapshot_id, ttl)
                    route_observations.extend(parsed.observations)
                    route_followups.extend(parsed.followups)
                    record.complete = record.complete and parsed.complete
                    if parsed.reason:
                        record.outcome_reason = parsed.reason
                    if not parsed.complete:
                        record.partial_reasons.append(parsed.reason or "provider_limited")
                    if not parsed.next_url:
                        break
                    if page + 1 == self.operation_pages:
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
                return route_observations, route_followups, None
            except LookupError as exc:
                last_error = exc
                record.transport_errors.append({"transport": transport, "status": exc.status, "message": str(exc),
                                                "retry_after": exc.retry_after})
                if parsed_pages:
                    record.complete = False
                    record.partial_reasons.append("later_page_failed:" + exc.status)
                    stopped = exc if exc.status in {
                        "deferred", "rate_limited", "budget_exhausted", "unsafe_redirect", "unsafe_pagination",
                        "login_required", "access_denied"} else None
                    return route_observations, route_followups, stopped
                # Rate/access blocks do not trigger quota evasion via another route.
                if exc.status in {"deferred", "rate_limited", "budget_exhausted", "unsafe_redirect", "unsafe_pagination"}:
                    raise
        raise last_error or LookupError("unsupported_method", "No source transport available")

    def _accept_observations(self, query, method, record, observations):
        """Method-correctness checks and output assembly; graph admission is external."""
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
                if len(outputs) >= self.operation_outputs:
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
