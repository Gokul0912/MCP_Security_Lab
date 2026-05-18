from __future__ import annotations

import json
from pathlib import Path

from security_lab_assistant.models import JsonObject
from security_lab_assistant.policy import LabPolicy
from security_lab_assistant.reasoning import stable_hash
from security_lab_assistant.storage import load_run


def validate_replay(policy: LabPolicy, run_id: str) -> JsonObject:
    run = load_run(policy, run_id)
    runtime = run.get("runtime", {})
    replay = runtime.get("deterministic_replay", {})
    graph = runtime.get("formal_reasoning_graph", {})
    checks = [
        _check_tool_hashes(run, replay),
        _check_workflow_hash(run, replay),
        _check_reasoning_graph(graph),
        _check_replay_hash(replay),
        _check_findings(run),
        _check_execution_manifests(run),
    ]
    failed = [check for check in checks if not check["ok"]]
    return {
        "ok": not failed,
        "run_id": run_id,
        "mode": "formal-replay-validation-v1",
        "checks": checks,
        "failed": failed,
    }


def _check_tool_hashes(run: JsonObject, replay: JsonObject) -> JsonObject:
    evidence = run.get("evidence", [])
    tool_calls = replay.get("tool_calls", [])
    if len(evidence) != len(tool_calls):
        return _result("tool_output_hashes", False, f"evidence count {len(evidence)} != replay tool calls {len(tool_calls)}")
    mismatches = []
    for index, item in enumerate(evidence):
        expected = tool_calls[index].get("output_hash")
        actual = stable_hash(item.get("data", {}))
        if expected != actual:
            mismatches.append({"sequence": index + 1, "tool": item.get("name"), "expected": expected, "actual": actual})
    return _result("tool_output_hashes", not mismatches, "tool output hashes match", {"mismatches": mismatches})


def _check_workflow_hash(run: JsonObject, replay: JsonObject) -> JsonObject:
    tool_calls = replay.get("tool_calls", [])
    expected = replay.get("workflow_hash")
    actual = stable_hash({"target": run.get("target"), "objective": run.get("objective"), "tool_calls": tool_calls})
    if expected != actual:
        alternate = stable_hash({"target": run.get("target"), "objective": run.get("objective"), "steps": tool_calls})
        ok = expected == alternate
        return _result("workflow_hash", ok, "workflow hash matches alternate legacy replay shape" if ok else "workflow hash mismatch", {"expected": expected, "actual": actual, "alternate": alternate})
    return _result("workflow_hash", True, "workflow hash matches")


def _check_reasoning_graph(graph: JsonObject) -> JsonObject:
    if not graph:
        return _result("reasoning_graph", False, "missing reasoning graph")
    nodes = graph.get("nodes", [])
    edges = graph.get("edges", [])
    states = graph.get("states", [])
    graph_hash = stable_hash({"nodes": nodes, "edges": edges})
    state_hash = stable_hash(states)
    ok = graph_hash == graph.get("graph_hash") and state_hash == graph.get("state_hash")
    return _result(
        "reasoning_graph",
        ok,
        "reasoning graph hashes match" if ok else "reasoning graph hash mismatch",
        {"graph_hash": graph_hash, "state_hash": state_hash},
    )


def _check_replay_hash(replay: JsonObject) -> JsonObject:
    if not replay:
        return _result("replay_hash", False, "missing replay payload")
    expected = replay.get("replay_hash")
    payload = dict(replay)
    payload.pop("replay_hash", None)
    actual = stable_hash(payload)
    return _result("replay_hash", expected == actual, "replay hash matches" if expected == actual else "replay hash mismatch", {"expected": expected, "actual": actual})


def _check_findings(run: JsonObject) -> JsonObject:
    findings = run.get("findings", [])
    evidence = run.get("evidence", [])
    if findings and not evidence:
        return _result("findings", False, "findings exist without evidence")
    unsupported = [finding for finding in findings if not finding.get("evidence")]
    return _result("findings", not unsupported, "findings contain evidence text", {"unsupported": unsupported})


def _check_execution_manifests(run: JsonObject) -> JsonObject:
    missing = []
    mismatched = []
    for item in run.get("evidence", []):
        manifest_path = item.get("data", {}).get("_tool_runtime", {}).get("manifest", {}).get("manifest_path", "")
        if not manifest_path:
            missing.append(item.get("name"))
            continue
        path = Path(str(manifest_path))
        if not path.exists():
            missing.append(str(manifest_path))
            continue
        try:
            manifest = json.loads(path.read_text(encoding="utf-8"))
        except json.JSONDecodeError:
            mismatched.append({"manifest": str(path), "reason": "invalid json"})
            continue
        data_without_runtime = dict(item.get("data", {}))
        data_without_runtime.pop("_tool_runtime", None)
        possible_hashes = {
            stable_hash({"ok": item.get("ok"), "data": data_without_runtime, "warnings": item.get("warnings", [])}),
            stable_hash({"name": item.get("name"), "ok": item.get("ok"), "data": data_without_runtime, "warnings": item.get("warnings", [])}),
            stable_hash(
                {
                    "name": item.get("name"),
                    "ok": item.get("ok"),
                    "data": data_without_runtime,
                    "warnings": item.get("warnings", []),
                    "started_at": item.get("started_at"),
                    "finished_at": item.get("finished_at"),
                }
            ),
        }
        if manifest.get("output_hash") not in possible_hashes:
            mismatched.append({"manifest": str(path), "reason": "output hash differs from saved evidence"})
    return _result("execution_manifests", not missing and not mismatched, "execution manifests are present", {"missing": missing, "mismatched": mismatched})


def _result(name: str, ok: bool, message: str, extra: JsonObject | None = None) -> JsonObject:
    return {"name": name, "ok": ok, "message": message, **(extra or {})}
