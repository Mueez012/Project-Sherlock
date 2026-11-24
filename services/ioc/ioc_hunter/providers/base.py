"""Minimal provider contract. Modules implement this interface directly."""
from dataclasses import dataclass, field
from typing import Protocol
from ..evidence import Observation
from ..method_spec import MethodSpec
from ..models import IOC
from ..transport.models import Document, FetchRequest

@dataclass(frozen=True)
class FollowUp:
    """A required source read, executed by LookupClient rather than a parser.

    Typed lookups resolve the provider's normal routes and configured API
    fallbacks at execution time. Explicit routes support source-local report
    navigation without introducing public methods outside the ontology.
    """
    key: str
    routes: tuple[tuple[str, FetchRequest], ...] = ()
    ioc: IOC | None = None
    method: MethodSpec | None = None
    context: dict = field(default_factory=dict)

@dataclass
class ParsedPage:
    observations: list[Observation] = field(default_factory=list)
    next_url: str = ""
    complete: bool = True
    reason: str = ""
    followups: list[FollowUp] = field(default_factory=list)

class Provider(Protocol):
    source: str
    PRIMARY_TRANSPORT: str
    API_KEY_ENV: str
    METHODS: tuple[MethodSpec, ...]

    def requests_for(self, ioc: IOC, method: MethodSpec,
                     api_key: str = "") -> list[tuple[str, FetchRequest]]: ...

    def parse_document(self, ioc: IOC, method: MethodSpec,
                       document: Document) -> ParsedPage: ...
