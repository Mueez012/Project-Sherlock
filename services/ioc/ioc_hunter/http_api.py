"""Thin HTTP door for the hub (Project-Sherlock).

All logic stays in the ioc_hunter library; this file only exposes it, the
same way mcp_server.py does for MCP.

POST /v1/extract: extract_report() result unchanged via dataclasses.asdict,
plus sentence_matches from find_sentence_iocs() when hub sentences are sent.
POST /v1/lookup: one directed lookup with its exact call-scoped stored record.
GET /v1/methods: the method catalogue, as the CLI and MCP list it.
GET /health: 200 when the extraction dependencies are loaded.

Run: uvicorn ioc_hunter.http_api:app --host 0.0.0.0 --port 8002
Needs the extraction extra, plus fastapi and uvicorn; lookups also need the
browser extra.
"""

from __future__ import annotations

import asyncio
from dataclasses import asdict
from importlib.metadata import PackageNotFoundError, version

from fastapi import FastAPI
from fastapi.responses import JSONResponse
from pydantic import BaseModel, Field

from .extraction import extract_report
from .config import resolve_store_directory
from .extraction.pipeline import find_sentence_iocs
from .lookup import LookupClient
from .methods import list_methods
from .models import IOC
from .storage import EvidenceStore
from .transport import LookupError

try:
    VERSION = version("threatmamba-ioc-hunter")
except PackageNotFoundError:
    VERSION = "0.0.0"

app = FastAPI(title="IOC Hunter", version=VERSION)
_client: LookupClient | None = None


def lookup_client() -> LookupClient:
    """Create on first lookup using the shared application-store resolver."""
    global _client
    if _client is None:
        _client = LookupClient(
            store=EvidenceStore(resolve_store_directory())
        )
    return _client


class ExtractRequest(BaseModel):
    text: str = Field(max_length=2_000_000)
    # When the hub supplies its sentences, sentence_matches is returned.
    sentences: list[str] | None = None
    source: str = "cti report"
    include_references: bool = False
    extended_types: bool = False


class LookupRequest(BaseModel):
    value: str
    type: str
    method: str


@app.get("/health")
def health() -> dict:
    return {"status": "ok", "service": "ioc", "version": VERSION}


@app.post("/v1/extract")
def extract(req: ExtractRequest) -> dict:
    try:
        result = asdict(
            extract_report(
                req.text,
                source=req.source,
                include_references=req.include_references,
                extended_types=req.extended_types,
            )
        )
    except ValueError as exc:
        return JSONResponse(status_code=422, content={"detail": str(exc)})
    if req.sentences is not None:
        result["sentence_matches"] = find_sentence_iocs(
            req.sentences, extended=req.extended_types
        )
    return result


@app.post("/v1/lookup")
async def lookup(req: LookupRequest):
    def run() -> dict:
        client = lookup_client()
        query = IOC(req.value, req.type)
        record = client.lookup_detailed(query, req.method)
        return {"iocs": [asdict(i) for i in record.outputs], "lookup": record.to_dict()}

    try:
        # Synchronous Playwright must not run inside the event loop.
        return await asyncio.to_thread(run)
    except LookupError as exc:
        return JSONResponse(
            status_code=502,
            content={
                "status": exc.status,
                "error": str(exc),
                "lookup_id": exc.lookup_id,
            },
        )
    except ValueError as exc:
        return JSONResponse(status_code=422, content={"detail": str(exc)})


@app.get("/v1/methods")
def methods(input_type: str = "", implemented_only: bool = False) -> list[dict]:
    return [
        {**asdict(m), "implemented": m.implemented, "description": m.description}
        for m in list_methods(input_type or None, implemented_only=implemented_only)
    ]


# Keep the historical entry point and primitive contracts; new HTTP adapters live
# separately from the shared workflow application and persistence code.
from .api.errors import install_error_handlers  # noqa: E402
from .api.investigations import router as investigation_router  # noqa: E402

app.include_router(investigation_router)
install_error_handlers(app)
