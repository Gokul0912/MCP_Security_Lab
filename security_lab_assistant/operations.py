from __future__ import annotations

import json
import sqlite3
from dataclasses import asdict, dataclass, field
from datetime import UTC, datetime, timedelta
from pathlib import Path
from uuid import uuid4

from security_lab_assistant.failures import FailureRecord, LEASE_FAILURE, QUEUE_FAILURE
from security_lab_assistant.models import JsonObject
from security_lab_assistant.platform import contract_hash, sign_payload
from security_lab_assistant.policy import LabPolicy, PolicyError
from security_lab_assistant.product import RUNTIME_VERSION, SCHEMA_VERSIONS
from security_lab_assistant.reasoning import stable_hash


WORKFLOW_TERMINAL_STATES = {"completed", "failed", "cancelled", "dead_lettered"}


@dataclass(frozen=True)
class WorkflowState:
    workflow_id: str
    state: str
    objective: str = ""
    target: str = ""
    previous_state: str = ""
    checkpoint_id: str = ""
    replay_cursor: str = ""
    lineage_pointer: str = ""
    lease_owner: str = ""
    retry_count: int = 0
    terminal_status: str = ""
    created_at: str = field(default_factory=lambda: datetime.now(UTC).isoformat())
    updated_at: str = field(default_factory=lambda: datetime.now(UTC).isoformat())
    schema_version: str = SCHEMA_VERSIONS["workflow_state"]
    runtime_version: str = RUNTIME_VERSION
    policy_hash: str = ""
    contract_hash: str = ""
    timestamp: str = field(default_factory=lambda: datetime.now(UTC).isoformat())
    signature: JsonObject = field(default_factory=dict)

    def to_dict(self) -> JsonObject:
        return asdict(self)


@dataclass(frozen=True)
class QueueTask:
    task_id: str
    workflow_id: str
    task_type: str
    payload: JsonObject
    status: str = "queued"
    priority: int = 0
    attempts: int = 0
    max_attempts: int = 3
    lease_id: str = ""
    worker_id: str = ""
    failure_reason: str = ""
    created_at: str = field(default_factory=lambda: datetime.now(UTC).isoformat())
    updated_at: str = field(default_factory=lambda: datetime.now(UTC).isoformat())
    schema_version: str = SCHEMA_VERSIONS["queue_task"]
    runtime_version: str = RUNTIME_VERSION
    policy_hash: str = ""
    contract_hash: str = ""
    timestamp: str = field(default_factory=lambda: datetime.now(UTC).isoformat())
    signature: JsonObject = field(default_factory=dict)

    def to_dict(self) -> JsonObject:
        return asdict(self)


@dataclass(frozen=True)
class WorkflowLease:
    lease_id: str
    workflow_id: str
    owner_id: str
    acquired_at: str
    expires_at: str
    heartbeat_at: str
    generation: int
    schema_version: str = "workflow-lease-v1"
    runtime_version: str = RUNTIME_VERSION
    policy_hash: str = ""
    contract_hash: str = ""
    timestamp: str = field(default_factory=lambda: datetime.now(UTC).isoformat())
    signature: JsonObject = field(default_factory=dict)

    def to_dict(self) -> JsonObject:
        return asdict(self)


class OperationsStore:
    def __init__(self, policy: LabPolicy) -> None:
        self.policy = policy
        self.root = policy.artifact_root()
        self.root.mkdir(parents=True, exist_ok=True)
        self.db_path = self.root / "index.sqlite3"
        self.events_path = self.root / "queues" / "events.jsonl"
        self.events_path.parent.mkdir(parents=True, exist_ok=True)
        self._initialize()

    def upsert_workflow_state(
        self,
        workflow_id: str,
        state: str,
        *,
        objective: str = "",
        target: str = "",
        checkpoint_id: str = "",
        replay_cursor: str = "",
        lineage_pointer: str = "",
        lease_owner: str = "",
        retry_count: int = 0,
        terminal_status: str = "",
    ) -> WorkflowState:
        existing = self.get_workflow_state(workflow_id)
        now = datetime.now(UTC).isoformat()
        created_at = str(existing.get("created_at", now)) if existing else now
        previous_state = str(existing.get("state", "")) if existing else ""
        if previous_state in WORKFLOW_TERMINAL_STATES and state != previous_state:
            raise PolicyError(f"Workflow {workflow_id} is terminal and cannot transition to {state}.")
        record = WorkflowState(
            workflow_id=workflow_id,
            state=state,
            objective=objective or str(existing.get("objective", "")) if existing else objective,
            target=target or str(existing.get("target", "")) if existing else target,
            previous_state=previous_state,
            checkpoint_id=checkpoint_id or str(existing.get("checkpoint_id", "")) if existing else checkpoint_id,
            replay_cursor=replay_cursor or str(existing.get("replay_cursor", "")) if existing else replay_cursor,
            lineage_pointer=lineage_pointer or str(existing.get("lineage_pointer", "")) if existing else lineage_pointer,
            lease_owner=lease_owner or str(existing.get("lease_owner", "")) if existing else lease_owner,
            retry_count=retry_count or int(existing.get("retry_count", 0)) if existing else retry_count,
            terminal_status=terminal_status or str(existing.get("terminal_status", "")) if existing else terminal_status,
            created_at=created_at,
            updated_at=now,
            policy_hash=stable_hash(self.policy.to_dict()),
            contract_hash=contract_hash(),
        )
        payload = record.to_dict()
        payload["signature"] = sign_payload(self.policy, payload, "workflow_state")
        payload_hash = stable_hash(payload)
        with sqlite3.connect(self.db_path) as connection:
            connection.execute(
                """
                INSERT INTO workflow_states (
                    workflow_id, state, previous_state, objective, target, checkpoint_id,
                    replay_cursor, lineage_pointer, lease_owner, retry_count, terminal_status,
                    created_at, updated_at, schema_version, runtime_version, payload_hash, payload_json
                )
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                ON CONFLICT(workflow_id) DO UPDATE SET
                    state = excluded.state,
                    previous_state = excluded.previous_state,
                    objective = excluded.objective,
                    target = excluded.target,
                    checkpoint_id = excluded.checkpoint_id,
                    replay_cursor = excluded.replay_cursor,
                    lineage_pointer = excluded.lineage_pointer,
                    lease_owner = excluded.lease_owner,
                    retry_count = excluded.retry_count,
                    terminal_status = excluded.terminal_status,
                    updated_at = excluded.updated_at,
                    schema_version = excluded.schema_version,
                    runtime_version = excluded.runtime_version,
                    payload_hash = excluded.payload_hash,
                    payload_json = excluded.payload_json
                """,
                (
                    record.workflow_id,
                    record.state,
                    record.previous_state,
                    record.objective,
                    record.target,
                    record.checkpoint_id,
                    record.replay_cursor,
                    record.lineage_pointer,
                    record.lease_owner,
                    record.retry_count,
                    record.terminal_status,
                    record.created_at,
                    record.updated_at,
                    record.schema_version,
                    record.runtime_version,
                    payload_hash,
                    json.dumps(payload, sort_keys=True),
                ),
            )
            connection.commit()
        self._append_event("workflow.state_transition", payload)
        return record

    def get_workflow_state(self, workflow_id: str) -> JsonObject:
        with sqlite3.connect(self.db_path) as connection:
            connection.row_factory = sqlite3.Row
            row = connection.execute(
                "SELECT payload_json FROM workflow_states WHERE workflow_id = ?",
                (workflow_id,),
            ).fetchone()
        return json.loads(row["payload_json"]) if row else {}

    def list_workflow_states(self, limit: int = 50) -> list[JsonObject]:
        with sqlite3.connect(self.db_path) as connection:
            connection.row_factory = sqlite3.Row
            rows = connection.execute(
                """
                SELECT payload_json FROM workflow_states
                ORDER BY updated_at DESC
                LIMIT ?
                """,
                (max(0, limit),),
            ).fetchall()
        return [json.loads(row["payload_json"]) for row in rows]

    def enqueue_task(
        self,
        task_type: str,
        payload: JsonObject,
        *,
        workflow_id: str = "",
        priority: int = 0,
        max_attempts: int = 3,
    ) -> QueueTask:
        task = QueueTask(
            task_id=str(uuid4()),
            workflow_id=workflow_id or str(payload.get("workflow_id", "")),
            task_type=task_type,
            payload=payload,
            priority=priority,
            max_attempts=max_attempts,
            policy_hash=stable_hash(self.policy.to_dict()),
            contract_hash=contract_hash(),
        )
        self._write_task(task)
        self._append_event("queue.enqueued", task.to_dict())
        return task

    def list_queue_tasks(self, limit: int = 50, status: str = "") -> list[JsonObject]:
        clauses = []
        params: list[object] = []
        if status:
            clauses.append("status = ?")
            params.append(status)
        where = f"WHERE {' AND '.join(clauses)}" if clauses else ""
        params.append(max(0, limit))
        with sqlite3.connect(self.db_path) as connection:
            connection.row_factory = sqlite3.Row
            rows = connection.execute(
                f"""
                SELECT payload_json FROM queue_tasks
                {where}
                ORDER BY priority DESC, created_at ASC
                LIMIT ?
                """,
                params,
            ).fetchall()
        return [json.loads(row["payload_json"]) for row in rows]

    def acquire_lease(self, workflow_id: str, owner_id: str, ttl_seconds: int = 300) -> WorkflowLease:
        now_dt = datetime.now(UTC)
        now = now_dt.isoformat()
        expires = (now_dt + timedelta(seconds=max(1, ttl_seconds))).isoformat()
        existing = self._active_lease(workflow_id, now)
        if existing and existing.get("owner_id") != owner_id:
            raise PolicyError(f"Workflow {workflow_id} is already leased by {existing.get('owner_id')}.")
        generation = int(existing.get("generation", 0)) + 1 if existing else 1
        lease = WorkflowLease(
            lease_id=str(uuid4()),
            workflow_id=workflow_id,
            owner_id=owner_id,
            acquired_at=now,
            expires_at=expires,
            heartbeat_at=now,
            generation=generation,
            policy_hash=stable_hash(self.policy.to_dict()),
            contract_hash=contract_hash(),
        )
        self._write_lease(lease)
        state = self.get_workflow_state(workflow_id)
        if state:
            self.upsert_workflow_state(workflow_id, str(state.get("state", "leased")), lease_owner=owner_id)
        self._append_event("workflow.lease_acquired", lease.to_dict())
        return lease

    def heartbeat_lease(self, lease_id: str, ttl_seconds: int = 300) -> WorkflowLease:
        with sqlite3.connect(self.db_path) as connection:
            connection.row_factory = sqlite3.Row
            row = connection.execute("SELECT payload_json FROM workflow_leases WHERE lease_id = ?", (lease_id,)).fetchone()
        if not row:
            raise PolicyError(f"Lease not found: {lease_id}")
        payload = json.loads(row["payload_json"])
        now_dt = datetime.now(UTC)
        payload["heartbeat_at"] = now_dt.isoformat()
        payload["expires_at"] = (now_dt + timedelta(seconds=max(1, ttl_seconds))).isoformat()
        payload["signature"] = {}
        lease = WorkflowLease(**payload)
        self._write_lease(lease)
        self._append_event("workflow.lease_heartbeat", lease.to_dict())
        return lease

    def list_leases(self, limit: int = 50) -> list[JsonObject]:
        with sqlite3.connect(self.db_path) as connection:
            connection.row_factory = sqlite3.Row
            rows = connection.execute(
                "SELECT payload_json FROM workflow_leases ORDER BY acquired_at DESC LIMIT ?",
                (max(0, limit),),
            ).fetchall()
        return [json.loads(row["payload_json"]) for row in rows]

    def recover_expired_leases(self) -> JsonObject:
        now = datetime.now(UTC).isoformat()
        expired = []
        for lease in self.list_leases(limit=500):
            if str(lease.get("expires_at", "")) < now:
                expired.append(lease)
                self._append_event(
                    "workflow.lease_expired",
                    {
                        **lease,
                        "failure": FailureRecord(
                            failure_class=LEASE_FAILURE,
                            code="lease.expired",
                            message="Workflow lease expired before completion.",
                            runtime="workflow",
                            retryable=True,
                            workflow_id=str(lease.get("workflow_id", "")),
                            recovery_suggestion="Supervisor may reacquire the workflow lease and resume from checkpoint.",
                        ).to_dict(),
                    },
                )
        return {"expired": expired, "count": len(expired)}

    def _write_task(self, task: QueueTask) -> None:
        payload = task.to_dict()
        payload["signature"] = sign_payload(self.policy, payload, "queue_task")
        with sqlite3.connect(self.db_path) as connection:
            connection.execute(
                """
                INSERT INTO queue_tasks (
                    task_id, workflow_id, task_type, status, priority, attempts,
                    max_attempts, lease_id, worker_id, failure_reason, created_at,
                    updated_at, schema_version, payload_hash, payload_json
                )
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                ON CONFLICT(task_id) DO UPDATE SET
                    status = excluded.status,
                    attempts = excluded.attempts,
                    lease_id = excluded.lease_id,
                    worker_id = excluded.worker_id,
                    failure_reason = excluded.failure_reason,
                    updated_at = excluded.updated_at,
                    payload_hash = excluded.payload_hash,
                    payload_json = excluded.payload_json
                """,
                (
                    task.task_id,
                    task.workflow_id,
                    task.task_type,
                    task.status,
                    task.priority,
                    task.attempts,
                    task.max_attempts,
                    task.lease_id,
                    task.worker_id,
                    task.failure_reason,
                    task.created_at,
                    task.updated_at,
                    task.schema_version,
                    stable_hash(payload),
                    json.dumps(payload, sort_keys=True),
                ),
            )
            connection.commit()

    def _write_lease(self, lease: WorkflowLease) -> None:
        payload = lease.to_dict()
        payload["signature"] = sign_payload(self.policy, payload, "workflow_lease")
        with sqlite3.connect(self.db_path) as connection:
            connection.execute(
                """
                INSERT INTO workflow_leases (
                    lease_id, workflow_id, owner_id, acquired_at, expires_at,
                    heartbeat_at, generation, payload_hash, payload_json
                )
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
                ON CONFLICT(lease_id) DO UPDATE SET
                    expires_at = excluded.expires_at,
                    heartbeat_at = excluded.heartbeat_at,
                    generation = excluded.generation,
                    payload_hash = excluded.payload_hash,
                    payload_json = excluded.payload_json
                """,
                (
                    lease.lease_id,
                    lease.workflow_id,
                    lease.owner_id,
                    lease.acquired_at,
                    lease.expires_at,
                    lease.heartbeat_at,
                    lease.generation,
                    stable_hash(payload),
                    json.dumps(payload, sort_keys=True),
                ),
            )
            connection.commit()

    def _active_lease(self, workflow_id: str, now: str) -> JsonObject:
        with sqlite3.connect(self.db_path) as connection:
            connection.row_factory = sqlite3.Row
            row = connection.execute(
                """
                SELECT payload_json FROM workflow_leases
                WHERE workflow_id = ? AND expires_at >= ?
                ORDER BY generation DESC
                LIMIT 1
                """,
                (workflow_id, now),
            ).fetchone()
        return json.loads(row["payload_json"]) if row else {}

    def _append_event(self, event_type: str, payload: JsonObject) -> None:
        previous_hash = _last_hash(self.events_path)
        event = {
            "timestamp": datetime.now(UTC).isoformat(),
            "event_type": event_type,
            "payload": payload,
            "previous_hash": previous_hash,
        }
        event["event_hash"] = stable_hash(event)
        with self.events_path.open("a", encoding="utf-8") as handle:
            handle.write(json.dumps(event, sort_keys=True) + "\n")

    def _initialize(self) -> None:
        with sqlite3.connect(self.db_path) as connection:
            connection.execute(
                """
                CREATE TABLE IF NOT EXISTS workflow_states (
                    workflow_id TEXT PRIMARY KEY,
                    state TEXT NOT NULL,
                    previous_state TEXT NOT NULL,
                    objective TEXT NOT NULL,
                    target TEXT NOT NULL,
                    checkpoint_id TEXT NOT NULL,
                    replay_cursor TEXT NOT NULL,
                    lineage_pointer TEXT NOT NULL,
                    lease_owner TEXT NOT NULL,
                    retry_count INTEGER NOT NULL,
                    terminal_status TEXT NOT NULL,
                    created_at TEXT NOT NULL,
                    updated_at TEXT NOT NULL,
                    schema_version TEXT NOT NULL,
                    runtime_version TEXT NOT NULL,
                    payload_hash TEXT NOT NULL,
                    payload_json TEXT NOT NULL
                )
                """
            )
            connection.execute(
                """
                CREATE TABLE IF NOT EXISTS queue_tasks (
                    task_id TEXT PRIMARY KEY,
                    workflow_id TEXT NOT NULL,
                    task_type TEXT NOT NULL,
                    status TEXT NOT NULL,
                    priority INTEGER NOT NULL,
                    attempts INTEGER NOT NULL,
                    max_attempts INTEGER NOT NULL,
                    lease_id TEXT NOT NULL,
                    worker_id TEXT NOT NULL,
                    failure_reason TEXT NOT NULL,
                    created_at TEXT NOT NULL,
                    updated_at TEXT NOT NULL,
                    schema_version TEXT NOT NULL,
                    payload_hash TEXT NOT NULL,
                    payload_json TEXT NOT NULL
                )
                """
            )
            connection.execute(
                """
                CREATE TABLE IF NOT EXISTS workflow_leases (
                    lease_id TEXT PRIMARY KEY,
                    workflow_id TEXT NOT NULL,
                    owner_id TEXT NOT NULL,
                    acquired_at TEXT NOT NULL,
                    expires_at TEXT NOT NULL,
                    heartbeat_at TEXT NOT NULL,
                    generation INTEGER NOT NULL,
                    payload_hash TEXT NOT NULL,
                    payload_json TEXT NOT NULL
                )
                """
            )
            connection.commit()


def _last_hash(path: Path) -> str:
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
