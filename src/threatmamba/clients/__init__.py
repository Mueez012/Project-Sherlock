"""HTTP clients for the service containers. Each satisfies its module's protocol (TTPExtractor, IOCExtractor)."""

from threatmamba.clients.errors import ServiceError
from threatmamba.clients.ttp import TTPServiceExtractor

__all__ = ["ServiceError", "TTPServiceExtractor"]
