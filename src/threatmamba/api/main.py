"""HTTP API and the live interface. Run locally: uv run uvicorn threatmamba.api.main:app --reload

Each module runs in stub mode (baseline extractor in this process) or real mode (its service container), chosen per
request from TM_TTP_MODE / TM_IOC_MODE (default TM_MODEL_MODE). A real-mode service that fails is an HTTP 503 that
names it; the hub never falls back to a stub on its own.
"""

from pathlib import Path

from fastapi import FastAPI, HTTPException
from fastapi.responses import FileResponse
from fastapi.staticfiles import StaticFiles

from threatmamba import __version__
from threatmamba.attribution import attribute
from threatmamba.clients import IOCServiceExtractor, ServiceError, TTPServiceExtractor
from threatmamba.contracts import AnalyzeRequest, AnalyzeResponse
from threatmamba.ioc import IOCExtractor, RegexIOCExtractor
from threatmamba.settings import Mode, ioc_mode, ioc_timeout_s, ioc_url, ttp_mode, ttp_timeout_s, ttp_url
from threatmamba.text import split_sentences
from threatmamba.ttp import KeywordTTPExtractor, TTPExtractor

WEB_DIR = Path(__file__).resolve().parent.parent / "web"

app = FastAPI(title="ThreatMAMBA", version=__version__)
_ioc_stub = RegexIOCExtractor()
_ttp_stub = KeywordTTPExtractor()


def _ttp() -> TTPExtractor:
    if ttp_mode() is Mode.real:
        return TTPServiceExtractor(ttp_url(), ttp_timeout_s())
    return _ttp_stub


def _ioc() -> IOCExtractor:
    if ioc_mode() is Mode.real:
        return IOCServiceExtractor(ioc_url(), ioc_timeout_s())
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


@app.post("/api/analyze", response_model=AnalyzeResponse)
def analyze(req: AnalyzeRequest) -> AnalyzeResponse:
    sentences = req.sentences if req.sentences is not None else split_sentences(req.text or "")
    try:
        ttps = _ttp().predict(sentences)
        iocs = _ioc().extract(sentences, text=req.text)
    except ServiceError as e:
        raise HTTPException(status_code=503, detail=f"{e.service} service unavailable: {e.detail}") from e
    return AnalyzeResponse(
        mode=_mode(),
        sentences=sentences,
        ttps=ttps,
        iocs=iocs,
        cskg=None,
        attribution=attribute(None),
    )


@app.get("/", include_in_schema=False)
def index() -> FileResponse:
    return FileResponse(WEB_DIR / "index.html")


app.mount("/static", StaticFiles(directory=WEB_DIR), name="static")
