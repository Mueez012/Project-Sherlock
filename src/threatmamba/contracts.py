"""Shared data contracts between modules. Change these only by PR reviewed by every module owner.

Flow:  D2Report (datasets/d2_model_ready) -> TTPExtractor -> [TTPHit]
                                          -> IOCExtractor/IOCHunter -> [IOC], [IOCEdge]
                                          -> CSKG builder -> CSKG  -> attribution -> Attribution
"""

from __future__ import annotations

from enum import StrEnum

from pydantic import BaseModel, Field, model_validator


class D2Report(BaseModel):
    """One line of datasets/d2_model_ready/{train,valid,test}.jsonl (written by datasets/scripts/clean_d2.py)."""

    report_id: int = Field(ge=1, description="line number of the report in the raw CTI2Attacker.csv")
    group: str = Field(min_length=1)
    label: int = Field(ge=0, le=24)
    cut_by_excel: bool
    text: str = Field(min_length=1)
    sentences: list[str] = Field(min_length=1, description="the report split by threatmamba.text.split_sentences")


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
    """One ATT&CK label found in one sentence: a technique (T1566) or a tactic (TA0001), never a sub-technique."""

    technique_id: str = Field(pattern=r"^TA?\d{4}$")
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
    """Raw text, which the hub splits, or sentences already split (e.g. a D2 report), which are used unchanged."""

    text: str | None = Field(default=None, min_length=1, max_length=200_000)
    sentences: list[str] | None = Field(default=None, min_length=1, max_length=20_000)

    @model_validator(mode="after")
    def _text_or_sentences(self) -> AnalyzeRequest:
        if self.text is None and self.sentences is None:
            raise ValueError("send text or sentences")
        return self


class AnalyzeResponse(BaseModel):
    mode: str
    sentences: list[str]
    ttps: list[TTPHit]
    iocs: list[IOC]
    cskg: CSKG | None = None
    attribution: Attribution | None = None
