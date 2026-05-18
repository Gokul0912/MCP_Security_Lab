from __future__ import annotations

from security_lab_assistant.models import JsonObject, ToolResult
from security_lab_assistant.policy import LabPolicy, PolicyError
from security_lab_assistant.storage import list_runs, load_run, search_runs, verify_audit_chain
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
    return ToolResult(name="run.verify_audit", ok=True, data=verify_audit_chain(policy))
