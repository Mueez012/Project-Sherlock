"""Workflow limits and stable identities, independent of terminal presentation."""

from dataclasses import dataclass
from hashlib import sha256
import json
import math

from ..models import IOC, identity


@dataclass(frozen=True)
class RunConfig:
    mode: str = "live"
    max_steps: int = 20
    max_nodes: int = 1000
    max_seconds: float = 600
    max_pages: int = 2
    max_outputs: int = 1000

    def __post_init__(self):
        if self.mode not in {"live", "replay"}:
            raise ValueError("Mode must be live or replay")
        for name in ("max_steps", "max_nodes", "max_pages", "max_outputs"):
            value = getattr(self, name)
            if type(value) is not int or value < 1:
                raise ValueError(name + " must be a positive integer")
        if (isinstance(self.max_seconds, bool) or not isinstance(self.max_seconds, (int, float))
                or not math.isfinite(self.max_seconds) or self.max_seconds <= 0):
            raise ValueError("max_seconds must be a finite positive number")


def stable_id(*parts) -> str:
    return sha256(json.dumps(parts, ensure_ascii=False, separators=(",", ":")).encode()).hexdigest()[:32]


def node_id(ioc: IOC) -> str:
    return stable_id(*identity(ioc))


def graph_node(ioc: IOC, *, origin: str, passages=(), evidence_ids=(), lookup_ids=()) -> dict:
    kind, value = identity(ioc)
    return {
        "id": node_id(ioc), "type": kind, "value": value,
        "context": list(dict.fromkeys(ioc.context)), "sources": [ioc.source] if ioc.source else [],
        "passage_ids": list(dict.fromkeys(passages)), "evidence_ids": list(dict.fromkeys(evidence_ids)),
        "lookup_ids": list(dict.fromkeys(lookup_ids)), "origin": origin, "used": False,
    }


def graph_edge(left: str, right: str, method_id: str, label: str, evidence_ids, lookup_id: str) -> dict:
    left, right = sorted((left, right))
    return {
        "id": stable_id(left, right, method_id), "left": left, "right": right,
        "method_id": method_id, "ontology_label": label,
        "evidence_ids": list(dict.fromkeys(evidence_ids)), "lookup_ids": [lookup_id],
    }
