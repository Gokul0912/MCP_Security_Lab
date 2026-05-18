from __future__ import annotations

import hashlib
import json
import os
import sqlite3
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

from security_lab_assistant.models import JsonObject, RunContext
from security_lab_assistant.operations import OperationsStore
from security_lab_assistant.policy import LabPolicy
from security_lab_assistant.product import SCHEMA_VERSIONS
from security_lab_assistant.platform import build_benchmark_record, contract_hash, sign_artifact, sign_payload, verify_artifact_signature, write_benchmark_record
from security_lab_assistant.reasoning import render_reasoning_visualizer_html
from security_lab_assistant.risk import risk_score
from security_lab_assistant.validation import require_run_id


def ensure_artifact_dirs(policy: LabPolicy) -> Path:
    root = policy.artifact_root()
    if root.exists() and root.is_symlink():
        raise RuntimeError("Artifact root must not be a symlink.")
    for child in ["runs", "reports", "audit", "exports", "visualizations", "events", "metrics", "signatures", "private", "benchmarks", "queues", "lineage", "executions"]:
        child_path = root / child
        child_path.mkdir(parents=True, exist_ok=True)
        if child_path.is_symlink():
            raise RuntimeError(f"Artifact directory must not be a symlink: {child}")
    initialize_index(policy)
    return root


def initialize_index(policy: LabPolicy) -> None:
    root = policy.artifact_root()
    root.mkdir(parents=True, exist_ok=True)
    with sqlite3.connect(root / "index.sqlite3") as connection:
        connection.execute(
            """
            CREATE TABLE IF NOT EXISTS runs (
                run_id TEXT PRIMARY KEY,
                target TEXT NOT NULL,
                objective TEXT NOT NULL,
                status TEXT NOT NULL,
                created_at TEXT NOT NULL,
                risk_score INTEGER NOT NULL,
                risk_band TEXT NOT NULL,
                findings_count INTEGER NOT NULL,
                run_path TEXT NOT NULL,
                report_path TEXT,
                sarif_path TEXT,
                payload_json TEXT NOT NULL
            )
            """
        )
        connection.execute(
            """
            CREATE TABLE IF NOT EXISTS audit_events (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                timestamp TEXT NOT NULL,
                event_type TEXT NOT NULL,
                payload_json TEXT NOT NULL,
                previous_hash TEXT NOT NULL DEFAULT '',
                event_hash TEXT NOT NULL DEFAULT ''
            )
            """
        )
        _ensure_column(connection, "audit_events", "previous_hash", "TEXT NOT NULL DEFAULT ''")
        _ensure_column(connection, "audit_events", "event_hash", "TEXT NOT NULL DEFAULT ''")
        connection.commit()
    OperationsStore(policy)


def append_audit_event(policy: LabPolicy, event_type: str, payload: JsonObject) -> None:
    root = ensure_artifact_dirs(policy)
    if any(ord(character) < 32 for character in event_type) or len(event_type) > 128:
        raise ValueError("Invalid audit event type.")
    audit_path = root / "audit" / "events.jsonl"
    previous_hash = _last_audit_hash(audit_path)
    event = {
        "schema_version": SCHEMA_VERSIONS["audit_event"],
        "runtime_version": "trusted-security-runtime-v1",
        "policy_hash": __import__("security_lab_assistant.reasoning", fromlist=["stable_hash"]).stable_hash(policy.to_dict()),
        "contract_hash": contract_hash(),
        "timestamp": datetime.now(UTC).isoformat(),
        "event_type": event_type,
        "payload": payload,
        "previous_hash": previous_hash,
        "signature": {},
    }
    event["signature"] = sign_payload(policy, event, "audit_event")
    event_hash = _audit_hash(event)
    event["event_hash"] = event_hash
    with audit_path.open("a", encoding="utf-8") as handle:
        handle.write(json.dumps(event, sort_keys=True) + "\n")
    with sqlite3.connect(root / "index.sqlite3") as connection:
        connection.execute(
            """
            INSERT INTO audit_events (timestamp, event_type, payload_json, previous_hash, event_hash)
            VALUES (?, ?, ?, ?, ?)
            """,
            (event["timestamp"], event_type, json.dumps(payload, sort_keys=True), previous_hash, event_hash),
        )
        connection.commit()


def save_run(
    policy: LabPolicy,
    run: RunContext,
    report_markdown: str | None = None,
    sarif_payload: JsonObject | None = None,
) -> Path:
    root = ensure_artifact_dirs(policy)
    run_path = root / "runs" / f"{run.run_id}.json"
    payload = run.to_dict()
    risk = risk_score(run)
    payload["risk"] = risk
    if report_markdown is not None:
        report_path = root / "reports" / f"{run.run_id}.md"
        _atomic_write_text(report_path, report_markdown)
        payload["report_path"] = str(report_path)
        payload["report_signature"] = sign_artifact(policy, report_path, "markdown_report")
    if sarif_payload is not None:
        sarif_path = root / "exports" / f"{run.run_id}.sarif.json"
        _atomic_write_text(sarif_path, json.dumps(sarif_payload, indent=2, sort_keys=True))
        payload["sarif_path"] = str(sarif_path)
        payload["sarif_signature"] = sign_artifact(policy, sarif_path, "sarif_export")
    graph = run.runtime.get("formal_reasoning_graph", {})
    if graph:
        visualizer_path = root / "visualizations" / f"{run.run_id}.reasoning.html"
        _atomic_write_text(visualizer_path, render_reasoning_visualizer_html(graph))
        payload["reasoning_visualizer_path"] = str(visualizer_path)
        payload["reasoning_visualizer_signature"] = sign_artifact(policy, visualizer_path, "reasoning_visualizer")
    benchmark_record = build_benchmark_record(run)
    benchmark_path = write_benchmark_record(policy, benchmark_record)
    payload["benchmark_path"] = str(benchmark_path)
    payload["benchmark_signature"] = sign_artifact(policy, benchmark_path, "benchmark_record")
    _atomic_write_text(run_path, json.dumps(payload, indent=2, sort_keys=True))
    sign_artifact(policy, run_path, "run_json")
    _upsert_run_index(policy, payload, str(run_path))
    append_audit_event(policy, "run.saved", {"run_id": run.run_id, "path": str(run_path)})
    return run_path


def load_run(policy: LabPolicy, run_id: str) -> JsonObject:
    safe_run_id = require_run_id({"run_id": run_id})
    path = ensure_artifact_dirs(policy) / "runs" / f"{safe_run_id}.json"
    if not path.exists():
        raise FileNotFoundError(f"Run not found: {safe_run_id}")
    return json.loads(path.read_text(encoding="utf-8"))


def list_runs(policy: LabPolicy, limit: int = 20) -> list[JsonObject]:
    root = ensure_artifact_dirs(policy)
    with sqlite3.connect(root / "index.sqlite3") as connection:
        connection.row_factory = sqlite3.Row
        rows = connection.execute(
            """
            SELECT run_id, target, objective, status, created_at, risk_score, risk_band,
                   findings_count, run_path, report_path, sarif_path
            FROM runs
            ORDER BY created_at DESC
            LIMIT ?
            """,
            (max(0, limit),),
        ).fetchall()
    if rows:
        return [dict(row) for row in rows]

    runs_dir = ensure_artifact_dirs(policy) / "runs"
    paths = sorted(runs_dir.glob("*.json"), key=lambda item: item.stat().st_mtime, reverse=True)
    summaries: list[JsonObject] = []
    for path in paths[: max(0, limit)]:
        try:
            payload: dict[str, Any] = json.loads(path.read_text(encoding="utf-8"))
        except json.JSONDecodeError:
            continue
        summaries.append(
            {
                "run_id": payload.get("run_id"),
                "target": payload.get("target"),
                "objective": payload.get("objective"),
                "status": payload.get("status"),
                "created_at": payload.get("created_at"),
                "risk_score": payload.get("risk", {}).get("score", 0),
                "risk_band": payload.get("risk", {}).get("band", "informational"),
                "findings_count": len(payload.get("findings", [])),
                "path": str(path),
                "report_path": payload.get("report_path"),
                "sarif_path": payload.get("sarif_path"),
            }
        )
    return summaries


def search_runs(policy: LabPolicy, query: str = "", status: str = "", limit: int = 20) -> list[JsonObject]:
    root = ensure_artifact_dirs(policy)
    clauses = []
    params: list[Any] = []
    if query:
        clauses.append("(target LIKE ? OR objective LIKE ?)")
        params.extend([f"%{query}%", f"%{query}%"])
    if status:
        clauses.append("status = ?")
        params.append(status)
    where = f"WHERE {' AND '.join(clauses)}" if clauses else ""
    params.append(max(0, limit))
    with sqlite3.connect(root / "index.sqlite3") as connection:
        connection.row_factory = sqlite3.Row
        rows = connection.execute(
            f"""
            SELECT run_id, target, objective, status, created_at, risk_score, risk_band,
                   findings_count, run_path, report_path, sarif_path
            FROM runs
            {where}
            ORDER BY created_at DESC
            LIMIT ?
            """,
            params,
        ).fetchall()
    return [dict(row) for row in rows]


def verify_audit_chain(policy: LabPolicy) -> JsonObject:
    audit_path = ensure_artifact_dirs(policy) / "audit" / "events.jsonl"
    previous = ""
    count = 0
    if not audit_path.exists():
        return {"ok": True, "events": 0}
    with audit_path.open("r", encoding="utf-8") as handle:
        for index, line in enumerate(handle, start=1):
            event = json.loads(line)
            event_hash = str(event.pop("event_hash", ""))
            if event.get("previous_hash") != previous:
                return {"ok": False, "events": count, "line": index, "reason": "previous hash mismatch"}
            if _audit_hash(event) != event_hash:
                return {"ok": False, "events": count, "line": index, "reason": "event hash mismatch"}
            previous = event_hash
            count += 1
    return {"ok": True, "events": count, "last_hash": previous}


def verify_artifact_signatures(policy: LabPolicy) -> JsonObject:
    signature_dir = ensure_artifact_dirs(policy) / "signatures"
    manifests = sorted(signature_dir.glob("*.sig.json"))
    results = [verify_artifact_signature(policy, manifest) for manifest in manifests]
    failed = [item for item in results if not item.get("ok")]
    return {
        "ok": not failed,
        "signatures": len(results),
        "failed": failed,
    }


def verify_evidence_lineage(policy: LabPolicy, run_id: str) -> JsonObject:
    from security_lab_assistant.runtimes.evidence import EvidenceRuntime

    safe_run_id = require_run_id({"run_id": run_id})
    return EvidenceRuntime(policy).verify_lineage(safe_run_id)


def _upsert_run_index(policy: LabPolicy, payload: JsonObject, run_path: str) -> None:
    root = ensure_artifact_dirs(policy)
    risk = payload.get("risk", {})
    with sqlite3.connect(root / "index.sqlite3") as connection:
        connection.execute(
            """
            INSERT INTO runs (
                run_id, target, objective, status, created_at, risk_score, risk_band,
                findings_count, run_path, report_path, sarif_path, payload_json
            )
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            ON CONFLICT(run_id) DO UPDATE SET
                target = excluded.target,
                objective = excluded.objective,
                status = excluded.status,
                created_at = excluded.created_at,
                risk_score = excluded.risk_score,
                risk_band = excluded.risk_band,
                findings_count = excluded.findings_count,
                run_path = excluded.run_path,
                report_path = excluded.report_path,
                sarif_path = excluded.sarif_path,
                payload_json = excluded.payload_json
            """,
            (
                payload.get("run_id"),
                payload.get("target"),
                payload.get("objective"),
                payload.get("status"),
                payload.get("created_at"),
                int(risk.get("score", 0)),
                risk.get("band", "informational"),
                len(payload.get("findings", [])),
                run_path,
                payload.get("report_path"),
                payload.get("sarif_path"),
                json.dumps(payload, sort_keys=True),
            ),
        )
        connection.commit()


def _ensure_column(connection: sqlite3.Connection, table: str, column: str, declaration: str) -> None:
    columns = {row[1] for row in connection.execute(f"PRAGMA table_info({table})").fetchall()}
    if column not in columns:
        connection.execute(f"ALTER TABLE {table} ADD COLUMN {column} {declaration}")


def _atomic_write_text(path: Path, content: str) -> None:
    if path.exists() and path.is_symlink():
        raise RuntimeError(f"Refusing to write through symlink: {path.name}")
    temp_path = path.with_name(f".{path.name}.tmp")
    temp_path.write_text(content, encoding="utf-8")
    os.replace(temp_path, path)


def _last_audit_hash(path: Path) -> str:
    if not path.exists():
        return ""
    last_line = ""
    with path.open("r", encoding="utf-8") as handle:
        for line in handle:
            if line.strip():
                last_line = line
    if not last_line:
        return ""
    try:
        return str(json.loads(last_line).get("event_hash", ""))
    except json.JSONDecodeError:
        return "CORRUPT"


def _audit_hash(event: JsonObject) -> str:
    canonical = json.dumps(event, sort_keys=True, separators=(",", ":"))
    return hashlib.sha256(canonical.encode("utf-8")).hexdigest()
