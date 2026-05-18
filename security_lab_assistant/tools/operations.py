from __future__ import annotations

import json

from security_lab_assistant.models import JsonObject, ToolResult
from security_lab_assistant.operations import OperationsStore
from security_lab_assistant.policy import LabPolicy, PolicyError
from security_lab_assistant.failures import failure_taxonomy
from security_lab_assistant.platform import platform_metadata, require_permission
from security_lab_assistant.runtimes.contracts import runtime_contracts
from security_lab_assistant.tools.base import refused


def ops_metrics(arguments: JsonObject, policy: LabPolicy) -> ToolResult:
    name = "ops.metrics"
    try:
        require_permission(str(arguments.get("role", "auditor")), "audit.verify")
    except PolicyError as exc:
        return refused(name, exc)
    path = policy.artifact_root() / "metrics" / "metrics.jsonl"
    metrics = []
    if path.exists():
        with path.open("r", encoding="utf-8") as handle:
            for line in handle:
                if line.strip():
                    metrics.append(json.loads(line))
    rollup: dict[str, float] = {}
    for metric in metrics:
        key = str(metric.get("name", "unknown"))
        rollup[key] = rollup.get(key, 0.0) + float(metric.get("value", 0.0))
    return ToolResult(name=name, ok=True, data={"count": len(metrics), "rollup": rollup, "metrics": metrics[-50:]})


def ops_events(arguments: JsonObject, policy: LabPolicy) -> ToolResult:
    name = "ops.events"
    try:
        require_permission(str(arguments.get("role", "auditor")), "audit.verify")
    except PolicyError as exc:
        return refused(name, exc)
    path = policy.artifact_root() / "events" / "workflows.jsonl"
    events = []
    if path.exists():
        with path.open("r", encoding="utf-8") as handle:
            for line in handle:
                if line.strip():
                    events.append(json.loads(line))
    return ToolResult(name=name, ok=True, data={"count": len(events), "events": events[-100:]})


def ops_runtime_contracts(arguments: JsonObject, policy: LabPolicy) -> ToolResult:
    name = "ops.runtime_contracts"
    try:
        require_permission(str(arguments.get("role", "auditor")), "audit.verify")
    except PolicyError as exc:
        return refused(name, exc)
    return ToolResult(name=name, ok=True, data={"contracts": runtime_contracts()})


def ops_workflows(arguments: JsonObject, policy: LabPolicy) -> ToolResult:
    name = "ops.workflows"
    try:
        require_permission(str(arguments.get("role", "operator")), "audit.verify")
    except PolicyError as exc:
        return refused(name, exc)
    limit = int(arguments.get("limit", 50))
    return ToolResult(name=name, ok=True, data={"workflows": OperationsStore(policy).list_workflow_states(limit)})


def ops_queue(arguments: JsonObject, policy: LabPolicy) -> ToolResult:
    name = "ops.queue"
    try:
        require_permission(str(arguments.get("role", "operator")), "audit.verify")
    except PolicyError as exc:
        return refused(name, exc)
    limit = int(arguments.get("limit", 50))
    status = str(arguments.get("status", ""))
    store = OperationsStore(policy)
    recovery = store.recover_expired_leases()
    return ToolResult(
        name=name,
        ok=True,
        data={
            "tasks": store.list_queue_tasks(limit=limit, status=status),
            "leases": store.list_leases(limit=limit),
            "expired_leases": recovery,
        },
    )


def ops_failure_taxonomy(arguments: JsonObject, policy: LabPolicy) -> ToolResult:
    name = "ops.failure_taxonomy"
    try:
        require_permission(str(arguments.get("role", "auditor")), "audit.verify")
    except PolicyError as exc:
        return refused(name, exc)
    return ToolResult(name=name, ok=True, data=failure_taxonomy())


def ops_platform(arguments: JsonObject, policy: LabPolicy) -> ToolResult:
    name = "ops.platform"
    try:
        require_permission(str(arguments.get("role", "readonly")), "runtime.read")
    except PolicyError as exc:
        return refused(name, exc)
    return ToolResult(name=name, ok=True, data=platform_metadata())
