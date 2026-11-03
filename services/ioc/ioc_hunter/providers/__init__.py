"""Provider discovery and compatibility entry points; no source-specific branching."""
from . import rapiddns, alienvault, virustotal
from .base import ParsedPage, Provider
from .common import ResultTables
from ..transport.models import LookupError

PROVIDERS: dict[str, Provider] = {
    provider.source: provider for provider in (rapiddns, alienvault, virustotal)
}


def get_provider(source: str) -> Provider:
    try:
        return PROVIDERS[source]
    except KeyError:
        raise LookupError("unsupported_source", f"No provider adapter registered for {source}") from None


def requests_for(ioc, method, api_key=""):
    return get_provider(method.source).requests_for(ioc, method, api_key)


def parse_document(ioc, method, document):
    return get_provider(method.source).parse_document(ioc, method, document)


__all__ = ["ParsedPage", "Provider", "ResultTables", "PROVIDERS", "get_provider",
           "requests_for", "parse_document"]
