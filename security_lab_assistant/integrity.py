from __future__ import annotations

import json
import shutil
from datetime import UTC, datetime
from pathlib import Path

from security_lab_assistant.failures import FailureRecord, REPLAY_FAILURE, SIGNATURE_FAILURE
from security_lab_assistant.models import JsonObject
from security_lab_assistant.operations import OperationsStore
from security_lab_assistant.policy import LabPolicy
from security_lab_assistant.replay import validate_replay
from security_lab_assistant.storage import (
    append_audit_event,
    list_runs,
    load_run,
    verify_artifact_signatures,
    verify_audit_chain,
    verify_evidence_lineage,
)


def deep_verify(policy: LabPolicy, *, quarantine: bool = True) -> JsonObject:
    runs = list_runs(policy, limit=1000)
    audit = verify_audit_chain(policy)
    signatures = verify_artifact_signatures(policy)
    run_results = []
    for run in runs:
        run_id = str(run.get("run_id", ""))
        if not run_id:
            continue
        run_results.append(verify_run_deep(policy, run_id, quarantine=quarantine))
    failed_runs = [item for item in run_results if not item.get("ok")]
    ok = bool(audit.get("ok")) and bool(signatures.get("ok")) and not failed_runs
    return {
        "ok": ok,
        "mode": "forensic-runtime-verification-v1",
        "audit": audit,
        "signatures": signatures,
        "runs": run_results,
        "failed_runs": failed_runs,
    }


def verify_run_deep(policy: LabPolicy, run_id: str, *, quarantine: bool = True) -> JsonObject:
    run = load_run(policy, run_id)
    lineage = verify_evidence_lineage(policy, run_id)
    replay = validate_replay(policy, run_id)
    schema = _verify_schema_presence(run)
    benchmark = _verify_benchmark(policy, run)
    policy_consistency = _verify_policy_consistency(policy, run)
    checks = {
        "lineage": lineage,
        "replay": replay,
        "schema": schema,
        "benchmark": benchmark,
        "policy_consistency": policy_consistency,
    }
    ok = all(bool(item.get("ok")) for item in checks.values())
    quarantine_record = {}
    if not ok and quarantine:
        quarantine_record = quarantine_run(policy, run_id, checks)
    return {"ok": ok, "run_id": run_id, "checks": checks, "quarantine": quarantine_record}


def quarantine_run(policy: LabPolicy, run_id: str, checks: JsonObject) -> JsonObject:
    root = policy.artifact_root()
    quarantine_dir = root / "quarantine" / run_id
    quarantine_dir.mkdir(parents=True, exist_ok=True)
    run_path = root / "runs" / f"{run_id}.json"
    copied = []
    if run_path.exists():
        destination = quarantine_dir / run_path.name
        shutil.copy2(run_path, destination)
        copied.append(str(destination))
    record = {
        "run_id": run_id,
        "quarantined_at": datetime.now(UTC).isoformat(),
        "reason": "deep integrity verification failed",
        "checks": checks,
        "copied_artifacts": copied,
        "failure": FailureRecord(
            failure_class=REPLAY_FAILURE if not checks.get("replay", {}).get("ok") else SIGNATURE_FAILURE,
            code="integrity.deep_verification_failed",
            message="Run failed forensic integrity verification and was quarantined.",
            runtime="governance",
            retryable=False,
            workflow_id=run_id,
            artifact_refs=tuple(copied),
            recovery_suggestion="Preserve artifacts, inspect diffs, and do not replay unsafe actions until root cause is understood.",
        ).to_dict(),
    }
    (quarantine_dir / "quarantine.json").write_text(json.dumps(record, indent=2, sort_keys=True), encoding="utf-8")
    OperationsStore(policy).upsert_workflow_state(run_id, "failed", terminal_status="integrity_compromised")
    append_audit_event(policy, "integrity.quarantined", {"run_id": run_id, "quarantine_dir": str(quarantine_dir)})
    return record


def _verify_schema_presence(run: JsonObject) -> JsonObject:
    missing = []
    runtime = run.get("runtime", {})
    if "schema_version" not in runtime.get("deterministic_replay", {}):
        missing.append("runtime.deterministic_replay.schema_version")
    graph = runtime.get("formal_reasoning_graph", {})
    if graph and "schema_version" not in graph:
        missing.append("runtime.formal_reasoning_graph.schema_version")
    return {"ok": not missing, "missing": missing}


def _verify_benchmark(policy: LabPolicy, run: JsonObject) -> JsonObject:
    raw_path = str(run.get("benchmark_path", ""))
    if not raw_path:
        return {"ok": False, "reason": "benchmark path missing", "path": ""}
    path = Path(raw_path)
    if not path.exists() or path.is_dir():
        return {"ok": False, "reason": "benchmark missing", "path": str(path)}
    try:
        payload = json.loads(path.read_text(encoding="utf-8"))
    except json.JSONDecodeError:
        return {"ok": False, "reason": "benchmark invalid json", "path": str(path)}
    required = ["schema_version", "runtime_version", "policy_hash", "contract_hash", "recorded_at"]
    missing = [field for field in required if field not in payload]
    return {"ok": not missing, "path": str(path), "missing": missing}


def _verify_policy_consistency(policy: LabPolicy, run: JsonObject) -> JsonObject:
    from security_lab_assistant.reasoning import stable_hash

    expected = stable_hash(policy.to_dict())
    mismatches = []
    for item in run.get("evidence", []):
        attestation = item.get("data", {}).get("_tool_runtime", {}).get("attestation", {})
        if attestation and attestation.get("policy_hash") != expected:
            mismatches.append({"tool": item.get("name"), "policy_hash": attestation.get("policy_hash")})
    return {"ok": not mismatches, "expected_policy_hash": expected, "mismatches": mismatches}
