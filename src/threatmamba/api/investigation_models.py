"""Hub request contracts mirror the separately packaged IOC HTTP service."""

from typing import Literal

from pydantic import BaseModel, ConfigDict, Field, field_validator


class StrictRequest(BaseModel):
    model_config = ConfigDict(extra="forbid", strict=True)


class InvestigationLimits(StrictRequest):
    max_steps: int = Field(default=20, gt=0)
    max_nodes: int = Field(default=1000, gt=0)
    max_seconds: float = Field(default=600.0, gt=0, allow_inf_nan=False)
    max_pages: int = Field(default=2, gt=0)
    max_outputs: int = Field(default=1000, gt=0)


class CreateInvestigation(StrictRequest):
    text: str = Field(min_length=1, max_length=2_000_000)
    source: str = Field(default="cti report", max_length=2000)
    include_references: bool = False
    extended_types: bool = False
    limits: InvestigationLimits = Field(default_factory=InvestigationLimits)

    @field_validator("text")
    @classmethod
    def nonblank(cls, value: str) -> str:
        if not value.strip():
            raise ValueError("Report must contain nonempty text")
        return value


class CreateInvestigationStep(StrictRequest):
    step_id: str = Field(pattern=r"^[0-9a-f]{32}$")
    input_node_id: str = Field(pattern=r"^[0-9a-f]{32}$")
    method_id: str = Field(min_length=1, max_length=200)
    expected_graph_revision: int = Field(ge=0)


class CloseInvestigation(StrictRequest):
    action: Literal["finish", "cancel"]


class EmptyRequest(StrictRequest):
    pass


# These transport-only models mirror the IOC service for the Hub's public
# OpenAPI. The proxy returns the service's validated bytes without owning state.
class SavedRunConfig(InvestigationLimits):
    mode: Literal["live", "replay"]


class RunMetadata(BaseModel):
    id: str
    status: Literal["extracting", "ready", "running", "completed", "cancelled", "failed"]
    mode: Literal["live", "replay"]
    policy: str
    config: SavedRunConfig
    graph_revision: int
    created_at: str
    updated_at: str
    elapsed_seconds: float
    stop_reason: str
    diagnostics: list[dict[str, object]]
    extraction_options: dict[str, bool]


class SavedReport(BaseModel):
    id: str
    source: str
    original_text: str
    sha256: str
    ingested_at: str


class SavedIOC(BaseModel):
    value: str
    type: str
    context: list[str]
    source: str


class Passage(BaseModel):
    id: str
    text: str
    sentence_index: int


class SavedExtraction(BaseModel):
    source: str
    original_text: str
    retained_text: str
    excluded_sections: list[dict[str, object]]
    sentences: list[str]
    matches: list[list[tuple[str, str]]]
    iocs: list[SavedIOC]
    passages: list[Passage]


class GraphNode(BaseModel):
    id: str
    type: str
    value: str
    context: list[str]
    sources: list[str]
    passage_ids: list[str]
    evidence_ids: list[str]
    lookup_ids: list[str]
    origin: Literal["report", "lookup"]
    used: bool


class GraphEdge(BaseModel):
    id: str
    left: str
    right: str
    method_id: str
    ontology_label: str
    evidence_ids: list[str]
    lookup_ids: list[str]


class SavedGraph(BaseModel):
    nodes: list[GraphNode]
    edges: list[GraphEdge]


class Admission(BaseModel):
    accepted: bool
    reason: str
    overlap_ids: list[str]
    reward: None = None
    reward_status: Literal["not_evaluated"]


class StepSummary(BaseModel):
    id: str
    sequence: int
    input_node_id: str
    method_id: str
    lookup_id: str
    status: Literal["running", "completed"]
    started_at: str
    finished_at: str
    outcome_status: str
    admission: Admission | None
    delta: dict[str, int]
    error: str


class LookupReceipt(BaseModel):
    id: str
    method_id: str
    input_ioc: SavedIOC
    status: str
    outputs: list[SavedIOC]
    evidence: list[dict[str, object]]
    accepted: list[dict[str, object]]
    rejected: list[dict[str, object]]
    responses: list[dict[str, object]]
    transport_errors: list[dict[str, object]]
    cache_hit: bool
    complete: bool
    error: str
    outcome_reason: str
    partial_reasons: list[str]
    started_at: str
    finished_at: str


class SavedStep(StepSummary):
    run_id: str
    lookup: LookupReceipt | None


class InvestigationSnapshot(BaseModel):
    version: Literal[1]
    run: RunMetadata
    report: SavedReport
    extraction: SavedExtraction | None
    graph: SavedGraph
    steps: list[StepSummary]


class InvestigationListItem(BaseModel):
    run: RunMetadata
    report: dict[str, str]
    counts: dict[str, int]


class InvestigationList(BaseModel):
    items: list[InvestigationListItem]
    limit: int
    offset: int
    total: int


class MethodRow(BaseModel):
    id: str
    input_type: str
    output_type: str
    source: str
    operation: str
    unavailable_reason: str
    baseline: bool
    implemented: bool
    description: str
    availability: dict[str, object]
    selectable: bool


class NodeMethods(BaseModel):
    run_id: str
    node_id: str
    execution_allowed: bool
    execution_block_reason: str
    methods: list[MethodRow]


class StepExecution(BaseModel):
    step: SavedStep
    run: RunMetadata
    graph: SavedGraph
    replayed: bool


class SourceSnapshot(BaseModel):
    url: str
    body: str
    format: str
    transport: str
    fetched_at: str
    status_code: int
    diagnostics: dict[str, object]


class StepDetail(BaseModel):
    step: SavedStep
    snapshots: dict[str, SourceSnapshot]


class ErrorDetail(BaseModel):
    code: str
    message: str
    run_id: str | None
    step_id: str | None
    details: dict[str, object]


class InvestigationError(BaseModel):
    error: ErrorDetail
