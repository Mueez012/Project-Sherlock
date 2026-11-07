"""Wire contracts. Workflow decisions and state live in the shared backend."""

from typing import Literal

from pydantic import BaseModel, ConfigDict, Field, field_validator


class RequestModel(BaseModel):
    model_config = ConfigDict(extra="forbid", strict=True)


class Limits(RequestModel):
    max_steps: int = Field(default=20, gt=0)
    max_nodes: int = Field(default=1000, gt=0)
    max_seconds: float = Field(default=600.0, gt=0, allow_inf_nan=False)
    max_pages: int = Field(default=2, gt=0)
    max_outputs: int = Field(default=1000, gt=0)


class CreateInvestigation(RequestModel):
    text: str = Field(min_length=1, max_length=2_000_000)
    source: str = Field(default="cti report", max_length=2000)
    include_references: bool = False
    extended_types: bool = False
    limits: Limits = Field(default_factory=Limits)

    @field_validator("text")
    @classmethod
    def nonblank(cls, value: str) -> str:
        if not value.strip():
            raise ValueError("Report must contain nonempty text")
        return value


class CreateStep(RequestModel):
    step_id: str = Field(pattern=r"^[0-9a-f]{32}$")
    input_node_id: str = Field(pattern=r"^[0-9a-f]{32}$")
    method_id: str = Field(min_length=1, max_length=200)
    expected_graph_revision: int = Field(ge=0)


class CloseInvestigation(RequestModel):
    action: Literal["finish", "cancel"]


class EmptyRequest(RequestModel):
    pass


class RunConfig(Limits):
    mode: Literal["live", "replay"]


class RunMetadata(BaseModel):
    id: str
    status: Literal["extracting", "ready", "running", "completed", "cancelled", "failed"]
    mode: Literal["live", "replay"]
    policy: str
    config: RunConfig
    graph_revision: int
    created_at: str
    updated_at: str
    elapsed_seconds: float
    stop_reason: str
    diagnostics: list[dict[str, object]]
    extraction_options: dict[str, bool]


class Report(BaseModel):
    id: str
    source: str
    original_text: str
    sha256: str
    ingested_at: str


class IOC(BaseModel):
    value: str
    type: str
    context: list[str]
    source: str


class Passage(BaseModel):
    id: str
    text: str
    sentence_index: int


class Extraction(BaseModel):
    source: str
    original_text: str
    retained_text: str
    excluded_sections: list[dict[str, object]]
    sentences: list[str]
    matches: list[list[tuple[str, str]]]
    iocs: list[IOC]
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


class Graph(BaseModel):
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


class LookupRecord(BaseModel):
    id: str
    method_id: str
    input_ioc: IOC
    status: str
    outputs: list[IOC]
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


class Step(StepSummary):
    run_id: str
    lookup: LookupRecord | None


class InvestigationSnapshot(BaseModel):
    version: Literal[1]
    run: RunMetadata
    report: Report
    extraction: Extraction | None
    graph: Graph
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
    step: Step
    run: RunMetadata
    graph: Graph
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
    step: Step
    snapshots: dict[str, SourceSnapshot]


class ErrorDetail(BaseModel):
    code: str
    message: str
    run_id: str | None
    step_id: str | None
    details: dict[str, object]


class ApiError(BaseModel):
    error: ErrorDetail
