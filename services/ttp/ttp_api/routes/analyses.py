"""/api/v1/analyses: upload a report, follow the job, fetch and export the result."""
from __future__ import annotations

import asyncio
import contextlib
import hashlib
import json
import logging
import secrets
import tempfile
from functools import partial
from pathlib import Path
from typing import Annotated

from fastapi import APIRouter, Depends, File, Form, Query, Request, Response, UploadFile
from fastapi.responses import StreamingResponse
from pydantic import ValidationError

from ttp_api import exporters
from ttp_api.config import Settings
from ttp_api.deps import get_catalog, get_predictor, get_runner, get_settings, get_store
from ttp_api.errors import ApiError
from ttp_api.jobs import FINISHED, Job, JobRunner, JobStore, new_id
from ttp_api.pipeline import run_analysis
from ttp_api.schemas import (
    AnalysisOptions, AnalysisResult, ExportFormat, JobCreated, JobList, JobStatusOut,
    TextAnalysisRequest,
)
from ttp_extraction.inference.document import EXTENSIONS

router = APIRouter(prefix="/analyses", tags=["analyses"])
log = logging.getLogger("ttp_api.analyses")
BASE = "/api/v1/analyses"
CHUNK = 1 << 20
ERRORS = {
    "create": {413: {"description": "file too large"}, 415: {"description": "unsupported file type"},
               422: {"description": "empty file / no text"}, 429: {"description": "queue full"},
               400: {"description": "bad options"}, 503: {"description": "model still loading"}},
}


def links(job_id: str) -> dict:
    return {"self": f"{BASE}/{job_id}", "result": f"{BASE}/{job_id}/result",
            "events": f"{BASE}/{job_id}/events"}


def status_out(job: Job) -> dict:
    return {"id": job.id, "status": job.status, "stage": job.stage, "progress": round(job.progress, 4),
            "message": job.message, "incident_name": job.incident_name, "filename": job.filename,
            "created_at": job.created_at, "updated_at": job.updated_at, "error": job.error}


def check_queue(store: JobStore, settings: Settings) -> None:
    if store.count_active() >= settings.queue_limit:
        raise ApiError(429, "queue_full", f"{settings.queue_limit} analyses are already waiting; try again later")


def parse_options(raw: str | None) -> AnalysisOptions:
    if not raw:
        return AnalysisOptions()
    try:
        return AnalysisOptions.model_validate(json.loads(raw))
    except (json.JSONDecodeError, ValidationError) as exc:
        message = exc.errors()[0]["msg"] if isinstance(exc, ValidationError) else "options is not valid JSON"
        raise ApiError(400, "bad_options", f"invalid options: {message}")


def check_magic(head: bytes, ext: str, path: Path) -> None:
    """The extension must match the content, never trust the client's name alone."""
    ok = True
    if ext == ".pdf":
        ok = b"%PDF-" in head[:1024]
    elif ext == ".docx":
        ok = head.startswith(b"PK\x03\x04")
    elif ext == ".json":
        try:
            ok = json.loads(path.read_bytes().decode("utf-8-sig")).get("type") == "bundle"
        except (ValueError, AttributeError):
            ok = False
    else:   # text formats
        ok = b"\x00" not in head[:8192]
    if not ok:
        kind = "STIX 2.1 bundle" if ext == ".json" else ext.lstrip(".").upper()
        raise ApiError(415, "unsupported_file", f"the file content is not a valid {kind}")


def start(job: Job, store: JobStore, runner: JobRunner, predictor, catalog, settings, text=None) -> dict:
    store.add(job)
    runner.submit(job.id, partial(run_analysis, store=store, predictor=predictor, catalog=catalog,
                                  settings=settings, text=text))
    log.info("job %s queued: %s, %d bytes, sha256 %s", job.id, job.media_type, job.size_bytes, job.sha256[:16])
    return {"id": job.id, "status": job.status, "created_at": job.created_at, "links": links(job.id)}


@router.post("", status_code=202, response_model=JobCreated, responses=ERRORS["create"],
             summary="Upload a CTI report (PDF, TXT, MD, HTML, DOCX or STIX 2.1 JSON) and start an analysis")
async def create_analysis(
    request: Request,
    file: Annotated[UploadFile, File(description="the report")],
    incident_name: Annotated[str, Form(max_length=200)] = "Untitled analysis",
    options: Annotated[str | None, Form(description="AnalysisOptions as a JSON string")] = None,
    settings: Settings = Depends(get_settings), store: JobStore = Depends(get_store),
    runner: JobRunner = Depends(get_runner), catalog: dict = Depends(get_catalog),
    predictor=Depends(get_predictor),
):
    opts = parse_options(options)
    check_queue(store, settings)
    original = Path(file.filename or "").name
    ext = Path(original).suffix.lower()
    if ext not in EXTENSIONS:
        raise ApiError(415, "unsupported_file",
                       f"'{ext or 'no extension'}' is not supported; use PDF, TXT, MD, HTML, DOCX or STIX JSON")
    tmp_dir = settings.tmp_dir or Path(tempfile.gettempdir()) / "ttp_api_uploads"
    tmp_dir.mkdir(parents=True, exist_ok=True)
    path = tmp_dir / f"{secrets.token_hex(16)}{ext}"     # random name, never the client's
    digest, size, head = hashlib.sha256(), 0, b""
    try:
        with path.open("wb") as out:
            while chunk := await file.read(CHUNK):
                size += len(chunk)
                if size > settings.max_upload_bytes:
                    raise ApiError(413, "file_too_large",
                                   f"the file is larger than {settings.max_upload_mb:g} MB")
                if len(head) < 8192:
                    head += chunk[: 8192 - len(head)]
                digest.update(chunk)
                out.write(chunk)
        if size == 0:
            raise ApiError(422, "empty_file", "the file is empty")
        check_magic(head, ext, path)
    except BaseException:
        path.unlink(missing_ok=True)
        raise
    job = Job(id=new_id(), incident_name=incident_name.strip() or "Untitled analysis",
              options=opts.model_dump(), filename=original, media_type=EXTENSIONS[ext],
              size_bytes=size, sha256=digest.hexdigest(), temp_path=str(path))
    return start(job, store, runner, predictor, catalog, settings)


@router.post("/text", status_code=202, response_model=JobCreated,
             responses={413: {"description": "text too long"}, 422: {"description": "empty text"},
                        429: {"description": "queue full"}},
             summary="Analyse pasted text")
def create_text_analysis(
    body: TextAnalysisRequest,
    settings: Settings = Depends(get_settings), store: JobStore = Depends(get_store),
    runner: JobRunner = Depends(get_runner), catalog: dict = Depends(get_catalog),
    predictor=Depends(get_predictor),
):
    if not body.text.strip():
        raise ApiError(422, "empty_text", "the text is empty")
    if len(body.text) > settings.max_text_chars:
        raise ApiError(413, "text_too_long", f"the text is longer than {settings.max_text_chars} characters")
    check_queue(store, settings)
    data = body.text.encode("utf-8")
    job = Job(id=new_id(), incident_name=body.incident_name.strip() or "Untitled analysis",
              options=body.options.model_dump(), filename=None, media_type="text/plain",
              size_bytes=len(data), sha256=hashlib.sha256(data).hexdigest())
    return start(job, store, runner, predictor, catalog, settings, text=body.text)


@router.get("", response_model=JobList, summary="Recent analyses (newest first)")
def list_analyses(limit: int = Query(50, ge=1, le=200), store: JobStore = Depends(get_store)):
    return {"items": [status_out(j) for j in store.list(limit)]}


def _job(store: JobStore, job_id: str) -> Job:
    job = store.get(job_id)
    if job is None:
        raise ApiError(404, "not_found", f"no analysis with id {job_id}")
    return job


@router.get("/{job_id}", response_model=JobStatusOut, responses={404: {"description": "unknown id"}},
            summary="Job status and progress")
def get_status(job_id: str, store: JobStore = Depends(get_store)):
    return status_out(_job(store, job_id))


@router.get("/{job_id}/events", summary="Server-sent events stream of the job status",
            responses={404: {"description": "unknown id"}}, response_class=StreamingResponse)
async def events(job_id: str, request: Request, store: JobStore = Depends(get_store)):
    _job(store, job_id)

    async def stream():
        last = None
        while not await request.is_disconnected():
            job = store.get(job_id)
            if job is None:
                break
            if job.updated_at != last:
                last = job.updated_at
                payload = JobStatusOut.model_validate(status_out(job)).model_dump_json()
                yield f"event: status\ndata: {payload}\n\n"
                if job.status in FINISHED:
                    break
            else:
                yield ": keep-alive\n\n"
            await asyncio.sleep(0.5)

    return StreamingResponse(stream(), media_type="text/event-stream",
                             headers={"Cache-Control": "no-cache", "X-Accel-Buffering": "no"})


def _finished_result(store: JobStore, job_id: str) -> dict:
    job = _job(store, job_id)
    if job.status == "failed":
        raise ApiError(409, "job_failed", job.error["message"] if job.error else "the analysis failed")
    if job.status != "completed" or job.result is None:
        raise ApiError(409, "not_finished", f"the analysis is still running (stage: {job.stage})")
    return job.result


@router.get("/{job_id}/result", response_model=AnalysisResult,
            responses={404: {"description": "unknown id"}, 409: {"description": "not finished or failed"}},
            summary="The full analysis result")
def get_result(job_id: str, store: JobStore = Depends(get_store)):
    return _finished_result(store, job_id)


@router.get("/{job_id}/export", summary="Download the result: json, csv, navigator (ATT&CK Navigator layer) or stix",
            responses={200: {"content": {"application/json": {}, "text/csv": {}}},
                       400: {"description": "unknown format"}, 404: {"description": "unknown id"},
                       409: {"description": "not finished"}})
def export(job_id: str, format: ExportFormat = Query(...), store: JobStore = Depends(get_store),
           catalog: dict = Depends(get_catalog)):
    result = _finished_result(store, job_id)
    body, media_type = exporters.export(result, format, catalog)
    return Response(body, media_type=media_type, headers={
        "Content-Disposition": f'attachment; filename="{exporters.filename(result, format)}"'})


@router.delete("/{job_id}", status_code=204, responses={404: {"description": "unknown id"}},
               summary="Delete an analysis and its result")
def delete(job_id: str, store: JobStore = Depends(get_store)):
    job = _job(store, job_id)
    store.delete(job_id)
    if job.temp_path:
        with contextlib.suppress(OSError):   # the worker may still hold it; it deletes it itself
            Path(job.temp_path).unlink(missing_ok=True)
    return Response(status_code=204)
