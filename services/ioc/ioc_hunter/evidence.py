"""Serializable lookup evidence, separate from the four-field IOC object."""
from dataclasses import dataclass, field, asdict
from datetime import datetime, timezone
from hashlib import sha256
import json
from .models import IOC

def utc_now() -> str:
    return datetime.now(timezone.utc).isoformat()

@dataclass(frozen=True)
class Evidence:
    id: str
    source: str
    query_type: str
    query_value: str
    operation: str
    page_url: str
    locator: str
    excerpt: str
    fact_type: str
    facts: dict
    response_sha256: str
    retrieved_at: str
    observed_at: str = ""

@dataclass
class Observation:
    ioc: IOC
    evidence: Evidence

@dataclass
class LookupRecord:
    id: str
    method_id: str
    input_ioc: IOC
    status: str = "pending"
    outputs: list[IOC] = field(default_factory=list)
    evidence: list[Evidence] = field(default_factory=list)
    rejected: list[dict] = field(default_factory=list)
    responses: list[dict] = field(default_factory=list)
    transport_errors: list[dict] = field(default_factory=list)
    cache_hit: bool = False
    complete: bool = True
    error: str = ""
    outcome_reason: str = ""
    partial_reasons: list[str] = field(default_factory=list)
    started_at: str = field(default_factory=utc_now)
    finished_at: str = ""

    def to_dict(self) -> dict:
        return asdict(self)

def make_evidence(source, query, operation, document, locator, record, fact_type, facts, observed_at=""):
    excerpt = record if isinstance(record, str) else json.dumps(record, ensure_ascii=False, sort_keys=True)
    digest = sha256(document.body.encode()).hexdigest()
    evidence_id = sha256((source + digest + locator + query.type + query.value).encode()).hexdigest()[:24]
    return Evidence(evidence_id, source, query.type, query.value, operation, document.url,
                    locator, excerpt, fact_type, facts, digest, document.fetched_at, observed_at)
