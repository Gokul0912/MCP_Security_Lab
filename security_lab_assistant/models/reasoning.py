from __future__ import annotations

from dataclasses import dataclass, field

from security_lab_assistant.models.base import JsonObject, SchemaRecord
from security_lab_assistant.product import SCHEMA_VERSIONS


@dataclass(frozen=True)
class ReasoningNodeRecord(SchemaRecord):
    schema_version: str = SCHEMA_VERSIONS["reasoning_graph"]
    node_id: str = ""
    node_type: str = ""
    statement: str = ""
    confidence: float = 0.0
    evidence_refs: tuple[str, ...] = ()


@dataclass(frozen=True)
class ReasoningEdgeRecord(SchemaRecord):
    schema_version: str = SCHEMA_VERSIONS["reasoning_graph"]
    source: str = ""
    target: str = ""
    relation_type: str = ""
    weight: float = 1.0
    rationale: str = ""


@dataclass(frozen=True)
class ConfidenceStateRecord(SchemaRecord):
    schema_version: str = SCHEMA_VERSIONS["reasoning_graph"]
    sequence: int = 0
    confidence_before: float = 0.0
    confidence_after: float = 0.0
    delta: float = 0.0
    reason: str = ""


@dataclass(frozen=True)
class ReasoningGraphRecord(SchemaRecord):
    schema_version: str = SCHEMA_VERSIONS["reasoning_graph"]
    graph_hash: str = ""
    state_hash: str = ""
    nodes: list[JsonObject] = field(default_factory=list)
    edges: list[JsonObject] = field(default_factory=list)
    states: list[JsonObject] = field(default_factory=list)


@dataclass(frozen=True)
class ReplayCheckpointRecord(SchemaRecord):
    schema_version: str = SCHEMA_VERSIONS["replay_state"]
    run_id: str = ""
    workflow_hash: str = ""
    replay_hash: str = ""
    graph_hash: str = ""
    state_hash: str = ""


@dataclass(frozen=True)
class BenchmarkRecord(SchemaRecord):
    schema_version: str = SCHEMA_VERSIONS["benchmark_record"]
    suite: str = ""
    run_id: str = ""
    score: float = 0.0
    passed: bool = False


@dataclass(frozen=True)
class FailureRecordModel(SchemaRecord):
    schema_version: str = SCHEMA_VERSIONS["failure_record"]
    failure_class: str = ""
    code: str = ""
    message: str = ""
    retryable: bool = False
