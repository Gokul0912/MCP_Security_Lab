from __future__ import annotations

from security_lab_assistant.models import JsonObject, ToolResult
from security_lab_assistant.policy import LabPolicy, PolicyError
from security_lab_assistant.tools.base import refused


def validate_scope(arguments: JsonObject, policy: LabPolicy) -> ToolResult:
    name = "scope.validate"
    target = str(arguments.get("target", "")).strip()
    if not target:
        return ToolResult(name=name, ok=False, data={"error": "target is required"})
    try:
        addresses = policy.assert_target_allowed(target)
    except PolicyError as exc:
        return refused(name, exc)
    return ToolResult(
        name=name,
        ok=True,
        data={"target": target, "resolved_addresses": addresses, "policy": policy.name},
    )
