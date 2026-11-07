"""Thin Hub forwarding routes; no investigation rules or storage live here."""

from collections.abc import Callable
from typing import Annotated
from urllib.parse import quote

from fastapi import APIRouter, Header, Query, Request, Response
from fastapi.exceptions import RequestValidationError
from fastapi.responses import JSONResponse
from fastapi.routing import APIRoute

from threatmamba.api.investigation_models import (
    CloseInvestigation,
    CreateInvestigation,
    CreateInvestigationStep,
    EmptyRequest,
    InvestigationError,
    InvestigationList,
    InvestigationSnapshot,
    NodeMethods,
    StepDetail,
    StepExecution,
)
from threatmamba.clients.errors import ServiceError
from threatmamba.clients.investigations import IOCInvestigationClient
from threatmamba.settings import ioc_url


class InvestigationRoute(APIRoute):
    def get_route_handler(self) -> Callable:
        original = super().get_route_handler()

        async def validated(request: Request) -> Response:
            try:
                return await original(request)
            except RequestValidationError as exc:
                failures = [
                    {"loc": list(item["loc"]), "type": item["type"], "msg": item["msg"]} for item in exc.errors()
                ]
                return JSONResponse(
                    status_code=422,
                    content={
                        "error": {
                            "code": "invalid_request",
                            "message": "The request is invalid.",
                            "run_id": request.path_params.get("run_id"),
                            "step_id": request.path_params.get("step_id"),
                            "details": {"errors": failures},
                        }
                    },
                )

        return validated


router = APIRouter(prefix="/api/investigations", tags=["investigations"], route_class=InvestigationRoute)
Authorization = Annotated[str | None, Header()]
ERRORS = {status: {"model": InvestigationError} for status in (401, 404, 409, 422, 500, 503)}


def _client() -> IOCInvestigationClient:
    return IOCInvestigationClient(ioc_url())


def _path(run_id: str, suffix: str = "") -> str:
    return f"/v1/investigations/{quote(run_id, safe='')}{suffix}"


def _forward(method: str, path: str, *, body=None, params=None, authorization=None, idempotency_key=None) -> Response:
    try:
        upstream = _client().request(
            method, path, body=body, params=params, authorization=authorization, idempotency_key=idempotency_key
        )
    except ServiceError:
        return JSONResponse(
            status_code=503,
            content={
                "error": {
                    "code": "ioc_service_unavailable",
                    "message": "The IOC service is unavailable.",
                    "run_id": None,
                    "step_id": None,
                    "details": {},
                }
            },
        )
    headers = {
        name: upstream.headers[name] for name in ("content-type", "content-disposition") if name in upstream.headers
    }
    location = upstream.headers.get("location")
    if location and location.startswith("/v1/investigations"):
        headers["Location"] = "/api/investigations" + location[len("/v1/investigations") :]
    return Response(content=upstream.content, status_code=upstream.status_code, headers=headers)


@router.post(
    "",
    status_code=201,
    response_model=InvestigationSnapshot,
    responses={**ERRORS, 200: {"model": InvestigationSnapshot}},
)
def create(
    body: CreateInvestigation,
    idempotency_key: Annotated[str, Header(alias="Idempotency-Key", pattern=r"^[0-9a-f]{32}$")],
    authorization: Authorization = None,
) -> Response:
    # The IOC service remains responsible for authenticating the forwarded identity.
    return _forward(
        "POST",
        "/v1/investigations",
        body=body.model_dump(),
        authorization=authorization,
        idempotency_key=idempotency_key,
    )


@router.get("", response_model=InvestigationList, responses=ERRORS)
def list_investigations(
    authorization: Authorization = None,
    limit: Annotated[int, Query(ge=1, le=200)] = 50,
    offset: Annotated[int, Query(ge=0)] = 0,
    status: Annotated[str | None, Query(pattern="^(extracting|ready|running|completed|cancelled|failed)$")] = None,
) -> Response:
    params = {"limit": limit, "offset": offset}
    if status is not None:
        params["status"] = status
    return _forward("GET", "/v1/investigations", params=params, authorization=authorization)


@router.get("/{run_id}", response_model=InvestigationSnapshot, responses=ERRORS)
def read(run_id: str, authorization: Authorization = None) -> Response:
    return _forward("GET", _path(run_id), authorization=authorization)


@router.get("/{run_id}/nodes/{node_id}/methods", response_model=NodeMethods, responses=ERRORS)
def methods(run_id: str, node_id: str, authorization: Authorization = None) -> Response:
    return _forward("GET", _path(run_id, f"/nodes/{quote(node_id, safe='')}/methods"), authorization=authorization)


@router.post(
    "/{run_id}/steps",
    status_code=201,
    response_model=StepExecution,
    responses={**ERRORS, 200: {"model": StepExecution}},
)
def execute(run_id: str, body: CreateInvestigationStep, authorization: Authorization = None) -> Response:
    return _forward("POST", _path(run_id, "/steps"), body=body.model_dump(), authorization=authorization)


@router.get("/{run_id}/steps/{step_id}", response_model=StepDetail, responses=ERRORS)
def step(run_id: str, step_id: str, authorization: Authorization = None, include_snapshots: bool = False) -> Response:
    return _forward(
        "GET",
        _path(run_id, f"/steps/{quote(step_id, safe='')}"),
        params={"include_snapshots": include_snapshots},
        authorization=authorization,
    )


@router.post("/{run_id}/resume", response_model=InvestigationSnapshot, responses=ERRORS)
def resume(run_id: str, body: EmptyRequest, authorization: Authorization = None) -> Response:
    return _forward("POST", _path(run_id, "/resume"), body=body.model_dump(), authorization=authorization)


@router.post("/{run_id}/close", response_model=InvestigationSnapshot, responses=ERRORS)
def close(run_id: str, body: CloseInvestigation, authorization: Authorization = None) -> Response:
    return _forward("POST", _path(run_id, "/close"), body=body.model_dump(), authorization=authorization)


@router.get("/{run_id}/export", responses=ERRORS)
def export(run_id: str, authorization: Authorization = None, include_evidence: bool = True) -> Response:
    return _forward(
        "GET", _path(run_id, "/export"), params={"include_evidence": include_evidence}, authorization=authorization
    )
