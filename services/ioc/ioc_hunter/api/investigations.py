"""Thin investigation routes over the same application used by the terminal."""

import asyncio
import json
from typing import Annotated

from fastapi import APIRouter, Depends, Header, Query, Response

from ..workflow.service import InvestigationService
from . import schemas
from .dependencies import service

router = APIRouter(prefix="/v1/investigations", tags=["investigations"])
Service = Annotated[InvestigationService, Depends(service)]
ERRORS = {status: {"model": schemas.ApiError} for status in (404, 409, 422, 500, 503)}


@router.post(
    "",
    response_model=schemas.InvestigationSnapshot,
    status_code=201,
    responses={**ERRORS, 200: {"model": schemas.InvestigationSnapshot}},
)
async def create(
    body: schemas.CreateInvestigation,
    response: Response,
    backend: Service,
    idempotency_key: Annotated[str, Header(alias="Idempotency-Key", pattern=r"^[0-9a-f]{32}$")],
):
    result, replayed = await asyncio.to_thread(backend.create, body.model_dump(), idempotency_key)
    response.status_code = 200 if replayed else 201
    response.headers["Location"] = f"/v1/investigations/{result['run']['id']}"
    return result


@router.get("", response_model=schemas.InvestigationList, responses=ERRORS)
async def list_investigations(
    backend: Service,
    limit: Annotated[int, Query(ge=1, le=200)] = 50,
    offset: Annotated[int, Query(ge=0)] = 0,
    status: Annotated[str | None, Query(pattern="^(extracting|ready|running|completed|cancelled|failed)$")] = None,
):
    return await asyncio.to_thread(backend.list, limit=limit, offset=offset, status=status)


@router.get("/{run_id}", response_model=schemas.InvestigationSnapshot, responses=ERRORS)
async def read(run_id: str, backend: Service):
    return await asyncio.to_thread(backend.read, run_id)


@router.get("/{run_id}/nodes/{node_id}/methods", response_model=schemas.NodeMethods, responses=ERRORS)
async def methods(run_id: str, node_id: str, backend: Service):
    return await asyncio.to_thread(backend.methods, run_id, node_id)


@router.post(
    "/{run_id}/steps",
    response_model=schemas.StepExecution,
    status_code=201,
    responses={**ERRORS, 200: {"model": schemas.StepExecution}},
)
async def execute(
    run_id: str,
    body: schemas.CreateStep,
    response: Response,
    backend: Service,
):
    result = await asyncio.to_thread(
        backend.execute,
        run_id,
        body.input_node_id,
        body.method_id,
        body.step_id,
        body.expected_graph_revision,
    )
    response.status_code = 200 if result["replayed"] else 201
    response.headers["Location"] = f"/v1/investigations/{run_id}/steps/{result['step']['id']}"
    return result


@router.get("/{run_id}/steps/{step_id}", response_model=schemas.StepDetail, responses=ERRORS)
async def step(
    run_id: str,
    step_id: str,
    backend: Service,
    include_snapshots: bool = False,
):
    return await asyncio.to_thread(backend.step, run_id, step_id, include_snapshots=include_snapshots)


@router.post("/{run_id}/resume", response_model=schemas.InvestigationSnapshot, responses=ERRORS)
async def resume(run_id: str, body: schemas.EmptyRequest, backend: Service):
    return await asyncio.to_thread(backend.resume, run_id)


@router.post("/{run_id}/close", response_model=schemas.InvestigationSnapshot, responses=ERRORS)
async def close(run_id: str, body: schemas.CloseInvestigation, backend: Service):
    return await asyncio.to_thread(backend.close, run_id, body.action)


@router.get("/{run_id}/export", responses=ERRORS)
async def export(run_id: str, backend: Service, include_evidence: bool = True):
    result = await asyncio.to_thread(backend.export, run_id, include_evidence=include_evidence)
    safe_id = result["run"]["id"]
    return Response(
        content=json.dumps(result, indent=2, ensure_ascii=False),
        media_type="application/json",
        headers={"Content-Disposition": f'attachment; filename="investigation-{safe_id}.json"'},
    )
