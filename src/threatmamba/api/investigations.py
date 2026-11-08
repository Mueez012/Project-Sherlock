"""Hub routes for saved IOC investigations: a plain pass-through to the IOC service.

The IOC service validates requests, applies the investigation rules, stores everything and writes every answer,
including its own error format ({"error": {"code", "message", ...}}). The hub forwards each request unchanged
(body, query, Idempotency-Key) to the same path under /v1/investigations and returns the answer unchanged. Its own
only answer is 503 when the IOC service cannot be reached, in the hub's usual {"detail": ...} format.
"""

from urllib.parse import quote

from fastapi import APIRouter, HTTPException, Request, Response

from threatmamba.clients.errors import ServiceError
from threatmamba.clients.investigations import IOCInvestigationClient
from threatmamba.settings import ioc_timeout_s, ioc_url

router = APIRouter(prefix="/api/investigations", tags=["investigations"])
HUB_PREFIX, IOC_PREFIX = "/api/investigations", "/v1/investigations"


def _client() -> IOCInvestigationClient:
    return IOCInvestigationClient(ioc_url(), ioc_timeout_s())


def _part(value: str) -> str:
    return "/" + quote(value, safe="")


async def _forward(request: Request, suffix: str = "") -> Response:
    try:
        upstream = await _client().forward(
            request.method,
            IOC_PREFIX + suffix,
            content=await request.body(),
            params=request.query_params,
            headers=request.headers,
        )
    except ServiceError as e:
        raise HTTPException(status_code=503, detail=f"{e.service} service unavailable: {e.detail}") from e
    headers = {
        name: upstream.headers[name] for name in ("content-type", "content-disposition") if name in upstream.headers
    }
    location = upstream.headers.get("location", "")
    if location.startswith(IOC_PREFIX):
        headers["Location"] = HUB_PREFIX + location[len(IOC_PREFIX) :]
    return Response(content=upstream.content, status_code=upstream.status_code, headers=headers)


@router.post("")
async def create(request: Request) -> Response:
    return await _forward(request)


@router.get("")
async def list_investigations(request: Request) -> Response:
    return await _forward(request)


@router.get("/{run_id}")
async def read(run_id: str, request: Request) -> Response:
    return await _forward(request, _part(run_id))


@router.get("/{run_id}/nodes/{node_id}/methods")
async def methods(run_id: str, node_id: str, request: Request) -> Response:
    return await _forward(request, _part(run_id) + "/nodes" + _part(node_id) + "/methods")


@router.post("/{run_id}/steps")
async def execute(run_id: str, request: Request) -> Response:
    return await _forward(request, _part(run_id) + "/steps")


@router.get("/{run_id}/steps/{step_id}")
async def step(run_id: str, step_id: str, request: Request) -> Response:
    return await _forward(request, _part(run_id) + "/steps" + _part(step_id))


@router.post("/{run_id}/resume")
async def resume(run_id: str, request: Request) -> Response:
    return await _forward(request, _part(run_id) + "/resume")


@router.post("/{run_id}/close")
async def close(run_id: str, request: Request) -> Response:
    return await _forward(request, _part(run_id) + "/close")


@router.get("/{run_id}/export")
async def export(run_id: str, request: Request) -> Response:
    return await _forward(request, _part(run_id) + "/export")
