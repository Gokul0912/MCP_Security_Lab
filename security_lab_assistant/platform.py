from __future__ import annotations

import hashlib
import hmac
import json
import os
import time
from dataclasses import dataclass
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

from security_lab_assistant.models import JsonObject, RunContext
from security_lab_assistant.policy import LabPolicy, PolicyError
from security_lab_assistant.product import RUNTIME_VERSION, SCHEMA_VERSIONS, product_identity
from security_lab_assistant.reasoning import stable_hash


ROLE_PERMISSIONS = {
    "analyst": {"workflow.run", "run.read", "runtime.read"},
    "reviewer": {"workflow.run", "workflow.approve", "run.read", "runtime.read", "benchmark.read"},
    "admin": {"workflow.run", "workflow.approve", "run.read", "runtime.read", "benchmark.read", "audit.verify", "policy.review"},
    "auditor": {"run.read", "runtime.read", "benchmark.read", "audit.verify"},
    "operator": {"run.read", "runtime.read", "audit.verify", "ops.manage", "queue.manage", "workflow.recover"},
    "readonly": {"run.read", "runtime.read"},
}


@dataclass(frozen=True)
class WorkflowEvent:
    run_id: str
    event_type: str
    sequence: int
    payload: JsonObject
    timestamp: str = ""

    def to_dict(self) -> JsonObject:
        return {
            "run_id": self.run_id,
            "event_type": self.event_type,
            "sequence": self.sequence,
            "timestamp": self.timestamp or datetime.now(UTC).isoformat(),
            "payload": self.payload,
        }


def require_permission(role: str, permission: str) -> None:
    normalized = (role or "analyst").strip().lower()
    if permission not in ROLE_PERMISSIONS.get(normalized, set()):
        raise PolicyError(f"Role '{normalized}' is not allowed to perform '{permission}'.")


def enforce_run_quotas(run: RunContext, policy: LabPolicy) -> None:
    if len(run.evidence) > policy.max_run_evidence_items:
        raise PolicyError(
            f"Run produced {len(run.evidence)} evidence items; policy allows at most {policy.max_run_evidence_items}."
        )


def append_workflow_event(policy: LabPolicy, event: WorkflowEvent) -> None:
    root = _ensure_platform_dirs(policy)
    event_path = root / "events" / "workflows.jsonl"
    if event.sequence > policy.max_workflow_events_per_run:
        raise PolicyError("Workflow event quota exceeded.")
    with event_path.open("a", encoding="utf-8") as handle:
        handle.write(json.dumps(event.to_dict(), sort_keys=True) + "\n")


def record_metric(policy: LabPolicy, name: str, value: float, labels: JsonObject | None = None) -> None:
    root = _ensure_platform_dirs(policy)
    metric = {
        "timestamp": datetime.now(UTC).isoformat(),
        "name": name,
        "value": value,
        "labels": labels or {},
    }
    with (root / "metrics" / "metrics.jsonl").open("a", encoding="utf-8") as handle:
        handle.write(json.dumps(metric, sort_keys=True) + "\n")


def workflow_timer() -> float:
    return time.perf_counter()


def record_workflow_latency(policy: LabPolicy, started: float, labels: JsonObject) -> None:
    record_metric(policy, "workflow_latency_seconds", round(time.perf_counter() - started, 6), labels)


def sign_artifact(policy: LabPolicy, path: Path, artifact_type: str) -> JsonObject:
    root = _ensure_platform_dirs(policy)
    resolved = path.resolve()
    if root.parent not in resolved.parents and resolved != root.parent:
        raise PolicyError("Refusing to sign artifact outside the project root.")
    digest = hashlib.sha256(path.read_bytes()).hexdigest()
    key = _artifact_signing_key(root)
    signature = hmac.new(key, digest.encode("utf-8"), hashlib.sha256).hexdigest()
    manifest = {
        "artifact": str(path),
        "artifact_type": artifact_type,
        "algorithm": "hmac-sha256-over-sha256",
        "digest": digest,
        "signature": signature,
        "signed_at": datetime.now(UTC).isoformat(),
        "key_id": "local-artifact-signing-key-v1",
    }
    manifest_path = root / "signatures" / f"{path.name}.sig.json"
    manifest_path.write_text(json.dumps(manifest, indent=2, sort_keys=True), encoding="utf-8")
    return {**manifest, "manifest_path": str(manifest_path)}


def sign_payload(policy: LabPolicy, payload: JsonObject, payload_type: str) -> JsonObject:
    root = _ensure_platform_dirs(policy)
    canonical = json.dumps(payload, sort_keys=True, separators=(",", ":"), default=str)
    digest = hashlib.sha256(canonical.encode("utf-8")).hexdigest()
    key = _artifact_signing_key(root)
    signature = hmac.new(key, digest.encode("utf-8"), hashlib.sha256).hexdigest()
    return {
        "payload_type": payload_type,
        "algorithm": "hmac-sha256-over-sha256",
        "digest": digest,
        "signature": signature,
        "signed_at": datetime.now(UTC).isoformat(),
        "key_id": "local-artifact-signing-key-v1",
    }


def verify_artifact_signature(policy: LabPolicy, manifest_path: Path) -> JsonObject:
    manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
    artifact = Path(str(manifest["artifact"]))
    if not artifact.exists():
        return {"ok": False, "reason": "artifact missing", "manifest": str(manifest_path)}
    digest = hashlib.sha256(artifact.read_bytes()).hexdigest()
    key = _artifact_signing_key(_ensure_platform_dirs(policy))
    expected = hmac.new(key, digest.encode("utf-8"), hashlib.sha256).hexdigest()
    return {
        "ok": digest == manifest.get("digest") and hmac.compare_digest(expected, str(manifest.get("signature", ""))),
        "artifact": str(artifact),
        "manifest": str(manifest_path),
        "digest": digest,
    }


def build_benchmark_record(run: RunContext) -> JsonObject:
    runtime = run.runtime
    benchmark = runtime.get("benchmark_suite", {})
    quality = runtime.get("reasoning_quality", {})
    replay = runtime.get("deterministic_replay", {})
    return {
        "schema_version": SCHEMA_VERSIONS["benchmark_record"],
        "runtime_version": RUNTIME_VERSION,
        "policy_hash": run.runtime.get("policy_hash", ""),
        "contract_hash": contract_hash(),
        "timestamp": datetime.now(UTC).isoformat(),
        "signature": {},
        "suite": benchmark.get("suite", "security-runtime-product-baseline-v1"),
        "run_id": run.run_id,
        "score": benchmark.get("score", 0.0),
        "reasoning_quality": quality.get("overall_score", 0.0),
        "replay_hash": replay.get("replay_hash", ""),
        "graph_hash": replay.get("graph_hash", ""),
        "passed": benchmark.get("score", 0.0) >= 0.7 and quality.get("overall_score", 0.0) >= 0.45,
        "recorded_at": datetime.now(UTC).isoformat(),
    }


def write_benchmark_record(policy: LabPolicy, record: JsonObject) -> Path:
    root = _ensure_platform_dirs(policy)
    if not record.get("policy_hash"):
        record["policy_hash"] = stable_hash(policy.to_dict())
    record["contract_hash"] = record.get("contract_hash") or contract_hash()
    record["signature"] = sign_payload(policy, record, "benchmark_record")
    path = root / "benchmarks" / f"{record.get('run_id', 'unknown')}.benchmark.json"
    path.write_text(json.dumps(record, indent=2, sort_keys=True), encoding="utf-8")
    return path


def _ensure_platform_dirs(policy: LabPolicy) -> Path:
    root = policy.artifact_root()
    for child in ["events", "metrics", "signatures", "private", "benchmarks", "queues", "executions", "replay"]:
        (root / child).mkdir(parents=True, exist_ok=True)
    return root


def platform_metadata() -> JsonObject:
    return product_identity()


def contract_hash() -> str:
    from security_lab_assistant.runtimes.contracts import runtime_contracts

    return stable_hash(runtime_contracts())


def _artifact_signing_key(root: Path) -> bytes:
    env_key = os.environ.get("SECURITY_LAB_ARTIFACT_SIGNING_KEY")
    if env_key:
        return env_key.encode("utf-8")
    key_path = root / "private" / "artifact_signing.key"
    if not key_path.exists():
        key_path.write_bytes(os.urandom(32))
    return key_path.read_bytes()
