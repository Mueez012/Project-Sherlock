"""Identity resolution and ownership checks, independent of workflow and HTTP."""

from .authentication import (
    IdentityProvider,
    resolve_actor,
    resolve_bearer,
    trusted_cli_actor,
)
from .errors import (
    AccessDenied,
    AccessError,
    AuthenticationNotConfigured,
    AuthenticationRequired,
)
from .ownership import require_owner

__all__ = [
    "AccessDenied",
    "AccessError",
    "AuthenticationNotConfigured",
    "AuthenticationRequired",
    "IdentityProvider",
    "require_owner",
    "resolve_actor",
    "resolve_bearer",
    "trusted_cli_actor",
]
