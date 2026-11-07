"""Pluggable identity resolution; application authentication is connected later.

A hosting application may inject an identity provider that verifies credentials
and returns its authenticated actor ID. This module defines that boundary and
an explicitly configured local development identity; it does not implement
login, bearer-token verification or account management.
"""

import os
from collections.abc import Callable
from typing import Protocol

from .errors import AccessError, AuthenticationNotConfigured, AuthenticationRequired
from .ownership import valid_actor_id


class IdentityProvider(Protocol):
    """Synchronous adapter to the hosting application's verified identity."""

    def resolve(self, authorization: str | None) -> str:
        """Verify request identity and return an actor ID or raise AccessError."""
        ...


def resolve_actor(
    authorization: str | None = None,
    *,
    provider: IdentityProvider | Callable[[str | None], str] | None = None,
) -> str:
    """Resolve externally verified identity or explicit local development mode.

    Local development mode requires IOC_HUNTER_LOCAL_ACTOR and the absence of
    an Authorization header. The trusted terminal identity is never used here.
    Provider failures never fall back to the local identity.
    """
    if provider is not None:
        resolver = getattr(provider, "resolve", None)
        if resolver is None and callable(provider):
            resolver = provider
        if not callable(resolver):
            raise AuthenticationNotConfigured()
        try:
            actor = resolver(authorization)
        except AccessError:
            raise
        except Exception:
            # A future adapter must not expose raw credential/provider errors.
            raise AuthenticationNotConfigured() from None
        if not valid_actor_id(actor):
            raise AuthenticationRequired()
        return actor

    local_actor = os.environ.get("IOC_HUNTER_LOCAL_ACTOR")
    if not valid_actor_id(local_actor):
        raise AuthenticationNotConfigured()
    if authorization is not None:
        raise AuthenticationRequired()
    return local_actor


def resolve_bearer(
    authorization: str | None = None,
    *,
    provider: IdentityProvider | Callable[[str | None], str] | None = None,
) -> str:
    """Compatibility alias for resolve_actor; no bearer verification is built in."""
    return resolve_actor(authorization, provider=provider)


def trusted_cli_actor() -> str:
    """Return trusted terminal identity; this value is never an HTTP credential."""
    actor = os.environ.get("IOC_HUNTER_ACTOR_ID", "local")
    if not valid_actor_id(actor):
        raise ValueError("IOC_HUNTER_ACTOR_ID must name a nonempty actor")
    return actor
