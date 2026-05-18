from __future__ import annotations

from dataclasses import dataclass
from typing import Callable

from security_lab_assistant.models import JsonObject, ToolResult
from security_lab_assistant.policy import LabPolicy, PolicyError


ToolHandler = Callable[[JsonObject, LabPolicy], ToolResult]


@dataclass(frozen=True)
class ToolSpec:
    name: str
    description: str
    input_schema: JsonObject
    handler: ToolHandler
    required_role: str = "analyst"
    required_permission: str = "workflow.run"
    approval_level: str = "none"
    risk_class: str = "low"


def refused(name: str, exc: PolicyError) -> ToolResult:
    return ToolResult(name=name, ok=False, data={"refusal": str(exc)})
