"""Composition dependencies; authentication remains outside workflow rules."""

from typing import Annotated

from fastapi import Header, Request

from ..access import resolve_actor
from ..config import resolve_store_directory
from ..workflow.service import InvestigationService


def actor(request: Request, authorization: Annotated[str | None, Header()] = None) -> str:
    return resolve_actor(authorization, provider=getattr(request.app.state, "identity_provider", None))


def service(request: Request) -> InvestigationService:
    configured = getattr(request.app.state, "investigation_service", None)
    if configured is None:
        configured = InvestigationService(resolve_store_directory())
        request.app.state.investigation_service = configured
    return configured
