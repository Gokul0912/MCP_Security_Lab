from __future__ import annotations

from dataclasses import asdict, dataclass, field
from datetime import UTC, datetime
from typing import Any
from uuid import uuid4

from security_lab_assistant.product import RUNTIME_VERSION


JsonObject = dict[str, Any]


@dataclass(frozen=True)
class SchemaRecord:
    schema_version: str
    runtime_version: str = RUNTIME_VERSION
    policy_hash: str = ""
    contract_hash: str = ""
    timestamp: str = field(default_factory=lambda: datetime.now(UTC).isoformat())
    signature: JsonObject = field(default_factory=dict)

    def to_dict(self) -> JsonObject:
        return asdict(self)


@dataclass(frozen=True)
class ToolResult:
    name: str
    ok: bool
    data: JsonObject
    warnings: list[str] = field(default_factory=list)
    started_at: str = field(default_factory=lambda: datetime.now(UTC).isoformat())
    finished_at: str = field(default_factory=lambda: datetime.now(UTC).isoformat())


@dataclass(frozen=True)
class Finding:
    title: str
    severity: str
    evidence: str
    recommendation: str
    affected_asset: str = ""
    category: str = "reconnaissance"
    confidence: str = "medium"


@dataclass
class RunContext:
    target: str
    objective: str
    run_id: str = field(default_factory=lambda: str(uuid4()))
    created_at: str = field(default_factory=lambda: datetime.now(UTC).isoformat())
    status: str = "running"
    phases: list[str] = field(default_factory=list)
    evidence: list[ToolResult] = field(default_factory=list)
    findings: list[Finding] = field(default_factory=list)
    warnings: list[str] = field(default_factory=list)
    runtime: JsonObject = field(default_factory=dict)

    def add_result(self, result: ToolResult) -> ToolResult:
        self.evidence.append(result)
        return result

    def add_phase(self, phase: str) -> None:
        self.phases.append(phase)

    def to_dict(self) -> JsonObject:
        return asdict(self)
