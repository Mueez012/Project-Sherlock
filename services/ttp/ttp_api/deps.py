"""FastAPI dependencies. Tests replace get_predictor with a fake via app.dependency_overrides."""
from __future__ import annotations

from fastapi import Request

from ttp_api.config import Settings
from ttp_api.errors import ApiError
from ttp_api.jobs import JobRunner, JobStore


def get_settings(request: Request) -> Settings:
    return request.app.state.settings


def get_store(request: Request) -> JobStore:
    return request.app.state.store


def get_runner(request: Request) -> JobRunner:
    return request.app.state.runner


def get_catalog(request: Request) -> dict:
    return request.app.state.catalog


def get_predictor(request: Request):
    predictor = request.app.state.predictor
    if predictor is None:
        status = request.app.state.model_status
        if status == "error":
            raise ApiError(503, "model_unavailable", f"the model failed to load: {request.app.state.model_error}")
        raise ApiError(503, "model_loading", "the model is still loading; try again in a few seconds")
    return predictor
