from __future__ import annotations

from dataclasses import dataclass, field
from datetime import UTC, datetime
from typing import Any
from uuid import uuid4


JsonObject = dict[str, Any]


@dataclass(frozen=True)
class ToolResult:
    name: str
    ok: bool
    data: JsonObject
    warnings: list[str] = field(default_factory=list)


@dataclass(frozen=True)
class Finding:
    title: str
    severity: str
    evidence: str
    recommendation: str


@dataclass
class RunContext:
    target: str
    objective: str
    run_id: str = field(default_factory=lambda: str(uuid4()))
    created_at: str = field(default_factory=lambda: datetime.now(UTC).isoformat())
    evidence: list[ToolResult] = field(default_factory=list)
    findings: list[Finding] = field(default_factory=list)

    def add_result(self, result: ToolResult) -> ToolResult:
        self.evidence.append(result)
        return result
