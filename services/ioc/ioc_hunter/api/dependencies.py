"""Composition dependencies for the investigation routes."""

from fastapi import Request

from ..config import resolve_store_directory
from ..workflow.service import InvestigationService


def service(request: Request) -> InvestigationService:
    configured = getattr(request.app.state, "investigation_service", None)
    if configured is None:
        configured = InvestigationService(resolve_store_directory())
        request.app.state.investigation_service = configured
    return configured
