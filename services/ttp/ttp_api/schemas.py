"""Request/response models: the single source of truth for the API contract.

The frontend generates its TypeScript types from /openapi.json, which FastAPI
builds from these classes.
"""
from __future__ import annotations

from datetime import datetime
from typing import Literal

from pydantic import BaseModel, ConfigDict, Field

JobStatus = Literal["queued", "extracting_text", "splitting", "encoding", "classifying",
                    "aggregating", "completed", "failed"]
ErrorCode = Literal["unsupported_file", "no_text_layer", "no_text", "too_many_sentences",
                    "model_error", "timeout", "cancelled"]
ThresholdMode = Literal["fixed", "per_slice", "per_label", "report_tuned"]
Band = Literal["high", "medium", "low"]
ExportFormat = Literal["json", "csv", "navigator", "stix"]


class AnalysisOptions(BaseModel):
    model_config = ConfigDict(extra="forbid", json_schema_extra={"examples": [
        {"threshold_mode": "fixed", "fixed_threshold": 0.5, "min_evidence_sentences": 1,
         "strong_threshold": 0.8, "include_sentences": True, "apply_hierarchy": True}]})

    threshold_mode: ThresholdMode | None = Field(
        None, description="default: the mode the bundle was validated with")
    fixed_threshold: float | None = Field(None, ge=0.01, le=0.99,
                                          description="used when threshold_mode is 'fixed'")
    min_evidence_sentences: int = Field(1, ge=1, le=20)
    strong_threshold: float = Field(0.8, ge=0.0, le=1.0)
    include_sentences: bool = True
    apply_hierarchy: bool = True


class TextAnalysisRequest(BaseModel):
    model_config = ConfigDict(json_schema_extra={"examples": [{
        "text": "The actor sent spearphishing emails with a malicious Word attachment. "
                "When opened, a macro launched PowerShell to download a backdoor.",
        "incident_name": "Demo incident", "options": {"threshold_mode": "fixed"}}]})

    text: str = Field(..., min_length=1)
    incident_name: str = Field("Untitled analysis", max_length=200)
    options: AnalysisOptions = AnalysisOptions()


class Links(BaseModel):
    self: str
    result: str
    events: str


class JobError(BaseModel):
    code: ErrorCode
    message: str


class JobCreated(BaseModel):
    id: str
    status: JobStatus
    created_at: datetime
    links: Links


class JobStatusOut(BaseModel):
    id: str
    status: JobStatus
    stage: JobStatus
    progress: float = Field(..., ge=0, le=1)
    message: str
    incident_name: str
    filename: str | None = None
    created_at: datetime
    updated_at: datetime
    error: JobError | None = None


class JobList(BaseModel):
    items: list[JobStatusOut]


class DocumentInfo(BaseModel):
    filename: str | None
    media_type: str
    size_bytes: int
    sha256: str
    pages: int | None
    n_characters: int
    n_sentences: int
    n_sentences_analyzed: int
    language: str = "en"
    text: str = Field(..., description="the cleaned text the offsets refer to")
    declared_ttps: list[str] = Field(default_factory=list,
                                     description="ATT&CK ids already present in a STIX upload")


class ModelInfo(BaseModel):
    name: str
    version: str
    run_id: str
    model_type: str
    encoder: str
    threshold_mode: str
    label_space: dict[str, int]


class Summary(BaseModel):
    n_tactics: int
    n_techniques: int
    top_tactic: str | None
    confidence_bands: dict[Band, int]


class Evidence(BaseModel):
    sentence_index: int
    text: str
    probability: float
    char_start: int
    char_end: int
    page: int | None = None


class Tactic(BaseModel):
    id: str
    name: str
    order: int
    url: str | None = None
    confidence: float
    source: Literal["model", "implied_by_technique"]
    sentence_count: int
    technique_ids: list[str]
    evidence: list[Evidence]


class Technique(BaseModel):
    id: str
    name: str
    tactic_ids: list[str]
    url: str
    confidence: float
    band: Band
    mean_confidence: float
    sentence_count: int
    threshold: float
    evidence: list[Evidence]


class SentenceLabel(BaseModel):
    id: str
    p: float
    passed: bool


class Sentence(BaseModel):
    index: int
    text: str
    char_start: int
    char_end: int
    page: int | None = None
    skipped: Literal["short", "ioc_list", "heading"] | None = None
    labels: list[SentenceLabel]


class AnalysisResult(BaseModel):
    id: str
    status: Literal["completed"]
    incident_name: str
    created_at: datetime
    completed_at: datetime
    processing_ms: int
    timings_ms: dict[str, int] = Field(default_factory=dict,
                                       description="milliseconds spent in each stage, in order")
    options: AnalysisOptions
    document: DocumentInfo
    model: ModelInfo
    summary: Summary
    tactics: list[Tactic]
    techniques: list[Technique]
    sentences: list[Sentence]
    warnings: list[str]


class Health(BaseModel):
    status: Literal["ok", "loading", "error"]
    model_loaded: bool
    detail: str | None = None


class AttackTechnique(BaseModel):
    id: str
    name: str
    tactic_ids: list[str]
    url: str | None


class AttackTactic(BaseModel):
    id: str
    name: str
    shortname: str
    order: int
    url: str | None


class AttackCatalog(BaseModel):
    attack_version: str
    tactics: list[AttackTactic]
    techniques: list[AttackTechnique]
