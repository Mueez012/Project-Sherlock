"""Discover provider-declared methods; retain the legacy combined catalogue API."""
from importlib.util import find_spec
from .config import api_keys_from_environment
from .method_spec import MethodSpec
from .method_candidates import SOURCE_TYPES, candidate_methods
from .ontology import allows_ioc_edge
from .providers import PROVIDERS


def _catalogue() -> dict[str, MethodSpec]:
    implemented = {}
    for provider in PROVIDERS.values():
        for method in provider.METHODS:
            if method.id in implemented or method.source != provider.source:
                raise ValueError(f"Invalid or duplicate provider method: {method.id}")
            if not method.implemented or not allows_ioc_edge(method.input_type, method.output_type):
                raise ValueError(f"Implemented method outside ontology: {method.id}")
            implemented[method.id] = method
    return {**candidate_methods(), **implemented}


METHODS = _catalogue()
IMPLEMENTED_METHODS = {key: method for key, method in METHODS.items() if method.implemented}
CANDIDATE_METHODS = {key: method for key, method in METHODS.items() if not method.implemented}

def get_method(method_id: str) -> MethodSpec:
    try:
        return METHODS[method_id]
    except KeyError:
        raise ValueError(f"Unknown method: {method_id}") from None

def list_methods(input_type: str | None = None, *, implemented_only: bool = False) -> list[MethodSpec]:
    return [m for m in sorted(METHODS.values(), key=lambda m: m.id)
            if (input_type is None or m.input_type == input_type) and (not implemented_only or m.implemented)]

def list_runnable_methods(input_type: str | None = None) -> list[MethodSpec]:
    """Implemented operations only; provider access can still fail at runtime."""
    return list_methods(input_type, implemented_only=True)


def list_candidates(input_type: str | None = None) -> list[MethodSpec]:
    return [m for m in list_methods(input_type) if not m.implemented]


def method_status(method: MethodSpec, *, api_keys: dict[str, str] | None = None) -> dict:
    """Inspect local configuration without a request or exposing credentials.

    Installation is not live access verification. Browser binaries and account
    permissions are checked by retrieval, not by this discovery helper.
    """
    provider = PROVIDERS[method.source]
    keys = api_keys if api_keys is not None else api_keys_from_environment()
    return {
        "implementation": "implemented" if method.implemented else "candidate",
        "primary_transport": provider.PRIMARY_TRANSPORT,
        "api_key_configured": bool(keys.get(method.source)),
        "browser_library_installed": find_spec("playwright") is not None,
        "live_access": "not_checked",
    }
