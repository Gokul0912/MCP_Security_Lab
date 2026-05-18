from __future__ import annotations

from security_lab_assistant.models import JsonObject, ToolResult
from security_lab_assistant.policy import LabPolicy, PolicyError
from security_lab_assistant.integrity import deep_verify
from security_lab_assistant.replay import validate_replay
from security_lab_assistant.runtimes.governance import GovernanceRuntime
from security_lab_assistant.storage import list_runs, load_run, search_runs, verify_evidence_lineage
from security_lab_assistant.tools.base import refused
from security_lab_assistant.validation import (
    bounded_optional_string,
    parse_limit,
    parse_status,
    require_run_id,
)


def run_list(arguments: JsonObject, policy: LabPolicy) -> ToolResult:
    name = "run.list"
    try:
        limit = parse_limit(arguments.get("limit"), default=20, maximum=100)
    except PolicyError as exc:
        return refused(name, exc)
    return ToolResult(name=name, ok=True, data={"runs": list_runs(policy, limit=limit)})


def run_get(arguments: JsonObject, policy: LabPolicy) -> ToolResult:
    name = "run.get"
    try:
        run_id = require_run_id(arguments)
        payload = load_run(policy, run_id)
    except (PolicyError, FileNotFoundError) as exc:
        return refused(name, PolicyError(str(exc)))
    return ToolResult(name=name, ok=True, data=payload)


def run_search(arguments: JsonObject, policy: LabPolicy) -> ToolResult:
    name = "run.search"
    try:
        query = bounded_optional_string(arguments.get("query"), "query", maximum=256)
        status = parse_status(arguments.get("status"))
        limit = parse_limit(arguments.get("limit"), default=20, maximum=100)
    except PolicyError as exc:
        return refused(name, exc)
    return ToolResult(name=name, ok=True, data={"runs": search_runs(policy, query=query, status=status, limit=limit)})


def run_verify_audit(arguments: JsonObject, policy: LabPolicy) -> ToolResult:
    try:
        GovernanceRuntime(policy).require_permission(str(arguments.get("role", "auditor")), "audit.verify")
    except PolicyError as exc:
        return refused("run.verify_audit", exc)
    return ToolResult(name="run.verify_audit", ok=True, data=GovernanceRuntime(policy).verify_audit())


def run_verify_artifacts(arguments: JsonObject, policy: LabPolicy) -> ToolResult:
    try:
        GovernanceRuntime(policy).require_permission(str(arguments.get("role", "auditor")), "audit.verify")
    except PolicyError as exc:
        return refused("run.verify_artifacts", exc)
    return ToolResult(name="run.verify_artifacts", ok=True, data=GovernanceRuntime(policy).verify_artifacts())


def run_verify_lineage(arguments: JsonObject, policy: LabPolicy) -> ToolResult:
    name = "run.verify_lineage"
    try:
        GovernanceRuntime(policy).require_permission(str(arguments.get("role", "auditor")), "audit.verify")
        run_id = require_run_id(arguments)
    except PolicyError as exc:
        return refused(name, exc)
    return ToolResult(name=name, ok=True, data=verify_evidence_lineage(policy, run_id))


def run_verify_replay(arguments: JsonObject, policy: LabPolicy) -> ToolResult:
    name = "run.verify_replay"
    try:
        GovernanceRuntime(policy).require_permission(str(arguments.get("role", "auditor")), "audit.verify")
        run_id = require_run_id(arguments)
    except PolicyError as exc:
        return refused(name, exc)
    return ToolResult(name=name, ok=True, data=validate_replay(policy, run_id))


def run_verify_deep(arguments: JsonObject, policy: LabPolicy) -> ToolResult:
    name = "run.verify_deep"
    try:
        GovernanceRuntime(policy).require_permission(str(arguments.get("role", "auditor")), "audit.verify")
    except PolicyError as exc:
        return refused(name, exc)
    quarantine = bool(arguments.get("quarantine", True))
    return ToolResult(name=name, ok=True, data=deep_verify(policy, quarantine=quarantine))
