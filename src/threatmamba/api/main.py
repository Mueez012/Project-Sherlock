"""HTTP API and the live interface. Run locally: uv run uvicorn threatmamba.api.main:app --reload

A report comes in as text (POST /api/analyze) or as a file (POST /api/analyze/file: PDF, DOCX, HTML, Markdown, TXT or
a STIX bundle, read by threatmamba.documents). threatmamba.text cuts it into units; the real sentences, in order, are
the timeline. TTP runs on the timeline sentences; IOC extraction reads the whole report, and an indicator found
outside a sentence (an indicator list, a heading) attaches to the nearest sentence before it (paper section III-A).

Each module runs in stub mode (baseline extractor in this process) or real mode (its service container), chosen per
request from TM_TTP_MODE / TM_IOC_MODE (default TM_MODEL_MODE). A real-mode service that fails is an HTTP 503 that
names it; the hub never falls back to a stub on its own.
"""

from collections.abc import Callable
from pathlib import Path

from fastapi import FastAPI, HTTPException, UploadFile
from fastapi.concurrency import run_in_threadpool
from fastapi.responses import FileResponse
from fastapi.staticfiles import StaticFiles

from threatmamba import __version__
from threatmamba.api.investigations import router as investigation_router
from threatmamba.attribution import attribute
from threatmamba.clients import IOCServiceExtractor, ServiceError, TTPServiceExtractor
from threatmamba.contracts import IOC, AnalyzeRequest, AnalyzeResponse, SentenceSpan
from threatmamba.documents import DocumentError, extract_text
from threatmamba.ioc import IOCExtractor, RegexIOCExtractor
from threatmamba.settings import (
    Mode,
    ioc_extended_types,
    ioc_mode,
    ioc_timeout_s,
    ioc_url,
    ttp_mode,
    ttp_timeout_s,
    ttp_url,
)
from threatmamba.text import attach, segment
from threatmamba.ttp import KeywordTTPExtractor, TTPExtractor

WEB_DIR = Path(__file__).resolve().parent.parent / "web"
MAX_UPLOAD_BYTES = 20 * 1024 * 1024
MAX_DOCUMENT_CHARS = 1_000_000

app = FastAPI(title="ThreatMAMBA", version=__version__)
app.include_router(investigation_router)
_ioc_stub = RegexIOCExtractor()
_ttp_stub = KeywordTTPExtractor()


def _ttp() -> TTPExtractor:
    if ttp_mode() is Mode.real:
        return TTPServiceExtractor(ttp_url(), ttp_timeout_s())
    return _ttp_stub


def _ioc() -> IOCExtractor:
    if ioc_mode() is Mode.real:
        return IOCServiceExtractor(ioc_url(), ioc_timeout_s(), extended_types=ioc_extended_types())
    return _ioc_stub


def _mode() -> str:
    modes = {ttp_mode(), ioc_mode()}
    return modes.pop().value if len(modes) == 1 else "mixed"


@app.get("/health")
def health() -> dict[str, object]:
    if ttp_mode() is Mode.stub and ioc_mode() is Mode.stub:
        return {"status": "ok", "mode": "stub", "version": __version__}
    services = {
        "ttp": TTPServiceExtractor(ttp_url()).health() if ttp_mode() is Mode.real else "stub",
        "ioc": IOCServiceExtractor(ioc_url()).health() if ioc_mode() is Mode.real else "stub",
    }
    status = "ok" if all(s in ("ok", "stub") for s in services.values()) else "degraded"
    return {"status": status, "mode": _mode(), "version": __version__, "services": services}


def _service_error(e: ServiceError) -> HTTPException:
    return HTTPException(status_code=503, detail=f"{e.service} service unavailable: {e.detail}")


def _onto_timeline(iocs: list[IOC], timeline: list[int | None]) -> list[IOC]:
    """IOC unit numbers -> timeline sentence numbers (see threatmamba.text.attach)."""
    out = []
    for ioc in iocs:
        numbers = sorted({timeline[i] for i in ioc.sentence_indices if timeline[i] is not None})
        out.append(ioc.model_copy(update={"sentence_indices": numbers}))
    return out


def _analyze_text(
    text: str, page_of: Callable[[int], int | None] | None = None, declared_ttps=(), warnings=()
) -> AnalyzeResponse:
    units = segment(text)
    timeline = attach(units)
    kept = [u for u in units if u.kind == "sentence"]
    sentences = [u.text for u in kept]
    try:
        ttps = _ttp().predict(sentences) if sentences else []
        iocs = _ioc().extract([u.text for u in units], text=text) if units else []
    except ServiceError as e:
        raise _service_error(e) from e
    return AnalyzeResponse(
        mode=_mode(),
        sentences=sentences,
        ttps=ttps,
        iocs=_onto_timeline(iocs, timeline),
        cskg=None,
        attribution=attribute(None),
        text=text,
        spans=[SentenceSpan(start=u.start, end=u.end, page=page_of(u.start) if page_of else None) for u in kept],
        declared_ttps=list(declared_ttps),
        warnings=list(warnings),
    )


@app.post("/api/analyze")
def analyze(req: AnalyzeRequest) -> AnalyzeResponse:
    if req.sentences is None:
        return _analyze_text(req.text or "")
    # Pre-split input (e.g. a D2 report's timeline) is used unchanged; text, if given, is what IOC extraction reads.
    try:
        ttps = _ttp().predict(req.sentences)
        iocs = _ioc().extract(req.sentences, text=req.text)
    except ServiceError as e:
        raise _service_error(e) from e
    return AnalyzeResponse(
        mode=_mode(), sentences=req.sentences, ttps=ttps, iocs=iocs, cskg=None, attribution=attribute(None)
    )


@app.post("/api/analyze/file")
async def analyze_file(file: UploadFile) -> AnalyzeResponse:
    """A report file: PDF, DOCX, HTML, Markdown, TXT or a STIX 2.1 bundle, up to 20 MB."""
    data = await file.read(MAX_UPLOAD_BYTES + 1)
    if len(data) > MAX_UPLOAD_BYTES:
        raise HTTPException(status_code=413, detail="the file is larger than 20 MB")
    try:
        doc = extract_text(data, file.filename or "")
    except DocumentError as e:
        raise HTTPException(status_code=422, detail=f"{e.code}: {e}") from e
    if len(doc.text) > MAX_DOCUMENT_CHARS:
        raise HTTPException(status_code=413, detail=f"the file's text is longer than {MAX_DOCUMENT_CHARS:,} characters")
    return await run_in_threadpool(_analyze_text, doc.text, doc.page_of, doc.declared_ttps, doc.warnings)


@app.get("/", include_in_schema=False)
def index() -> FileResponse:
    return FileResponse(WEB_DIR / "index.html")


app.mount("/static", StaticFiles(directory=WEB_DIR), name="static")
