"""Small, serializable Algorithm 1 configuration and state."""
from dataclasses import asdict, dataclass, field
from hashlib import sha256
import json
import math

POLICY = "algorithm1/paper-admission-v1"
VERSION = 1


def fingerprint(value):
    return sha256(json.dumps(value, sort_keys=True, ensure_ascii=False,
                             allow_nan=False, separators=(",", ":")).encode()).hexdigest()


@dataclass(frozen=True)
class AlgorithmConfig:
    alpha: float
    method_ids: tuple[str, ...] = ()
    selector: dict = field(default_factory=dict)
    provider_limits: dict = field(default_factory=dict)
    frozen_cache: bool = False
    rounds_per_ioc: int = 5
    shortlist_size: int = 50

    def __post_init__(self):
        if isinstance(self.alpha, bool) or not isinstance(self.alpha, (float, int)) or not math.isfinite(self.alpha) or self.alpha < 0:
            raise ValueError("alpha must be a finite nonnegative number")
        if self.rounds_per_ioc != 5 or self.shortlist_size != 50:
            raise ValueError("Algorithm 1 requires five rounds and a top-50 shortlist")
        if not isinstance(self.method_ids, (list, tuple)) or any(not isinstance(m, str) for m in self.method_ids):
            raise ValueError("method_ids must be a list of method IDs")
        if len(set(self.method_ids)) != len(self.method_ids):
            raise ValueError("Duplicate method IDs")
        if type(self.frozen_cache) is not bool:
            raise ValueError("frozen_cache must be boolean")
        if not isinstance(self.selector, dict) or not isinstance(self.provider_limits, dict):
            raise ValueError("selector and provider_limits must be objects")

    def to_dict(self):
        result = asdict(self)
        result["method_ids"] = list(self.method_ids)
        return result


def initial_state(config, catalogue, seed_ids):
    settings = config.to_dict()
    return {"version": VERSION, "config": settings,
            "config_fingerprint": fingerprint(settings), "catalogue": catalogue,
            "catalogue_fingerprint": fingerprint(catalogue), "phase": "choose_ioc",
            "active_node_id": None, "round_index": 0, "current_decision_id": None,
            "next_method_index": 0, "pending_step_id": None,
            "method_history": {m["id"]: {"tried": 0, "coverage": 0} for m in catalogue},
            "initial_seed_ids": list(seed_ids), "decisions": [], "wait": None,
            "selector_seconds": 0.0, "wait_seconds": 0.0, "outcome": "in_progress"}
