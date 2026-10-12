"""Shared data contracts between modules. Change these only by PR reviewed by every module owner.

Flow:  HandoffReport (Phase 1) -> TTPExtractor -> [TTPHit]
                               -> IOCExtractor/IOCHunter -> [IOC], [IOCEdge]
                               -> CSKG builder -> CSKG  -> attribution -> Attribution
"""

from __future__ import annotations

from enum import StrEnum

from pydantic import BaseModel, Field


class Split(StrEnum):
    train = "train"
    valid = "valid"
    test = "test"


class HandoffMeta(BaseModel):
    group_id: str
    n_chars: int
    truncated_at_excel_limit: bool
    source: str


class HandoffReport(BaseModel):
    """One line of handoff/d2/shard_*.jsonl (Phase 1 output)."""

    doc_id: str = Field(pattern=r"^d2_[0-9a-f]{12}$")
    split: Split
    label: int = Field(ge=0, le=24)
    group_name: str
    group_alias: str
    text: str
    meta: HandoffMeta


class IOCType(StrEnum):
    ipv4 = "ipv4"
    domain = "domain"
    url = "url"
    md5 = "md5"
    sha1 = "sha1"
    sha256 = "sha256"
    email = "email"
    cve = "cve"


class IOC(BaseModel):
    type: IOCType
    value: str
    sentence_index: int = Field(ge=0, description="sentence where it first appears")


class IOCEdge(BaseModel):
    """IOC-to-IOC relation found by IOCHunter; rel is the hunting function name (paper Fig. 3)."""

    src: str
    dst: str
    rel: str


class TTPHit(BaseModel):
    technique_id: str = Field(pattern=r"^T\d{4}$")
    score: float = Field(ge=0.0, le=1.0)
    sentence_index: int = Field(ge=0)


class NodeType(StrEnum):
    IOC = "IOC"
    TTP = "TTP"
    SEQ = "SEQ"


class Node(BaseModel):
    id: str
    type: NodeType
    attrs: dict[str, str | float | int] = {}


class Edge(BaseModel):
    src: str
    dst: str
    rel: str


class CSKG(BaseModel):
    """Phase 2 output: graphs/<doc_id>.json"""

    doc_id: str
    nodes: list[Node]
    edges: list[Edge]


class ActorScore(BaseModel):
    actor: str
    score: float = Field(ge=0.0, le=1.0)


class Attribution(BaseModel):
    ranked: list[ActorScore]
    model: str


class AnalyzeRequest(BaseModel):
    text: str = Field(min_length=1, max_length=200_000)


class AnalyzeResponse(BaseModel):
    mode: str
    sentences: list[str]
    ttps: list[TTPHit]
    iocs: list[IOC]
    cskg: CSKG | None = None
    attribution: Attribution | None = None
