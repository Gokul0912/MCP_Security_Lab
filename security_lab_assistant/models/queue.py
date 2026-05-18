from __future__ import annotations

from dataclasses import dataclass, field

from security_lab_assistant.models.base import JsonObject, SchemaRecord
from security_lab_assistant.product import SCHEMA_VERSIONS


@dataclass(frozen=True)
class WorkflowStateRecord(SchemaRecord):
    schema_version: str = SCHEMA_VERSIONS["workflow_state"]
    workflow_id: str = ""
    state: str = ""
    previous_state: str = ""
    checkpoint_id: str = ""
    replay_cursor: str = ""
    lineage_pointer: str = ""
    lease_owner: str = ""
    retry_count: int = 0
    terminal_status: str = ""


@dataclass(frozen=True)
class QueueTaskRecord(SchemaRecord):
    schema_version: str = SCHEMA_VERSIONS["queue_task"]
    task_id: str = ""
    workflow_id: str = ""
    task_type: str = ""
    payload: JsonObject = field(default_factory=dict)
    status: str = "queued"
    priority: int = 0
    attempts: int = 0
    max_attempts: int = 3
    lease_id: str = ""


@dataclass(frozen=True)
class WorkflowLeaseRecord(SchemaRecord):
    schema_version: str = "workflow-lease-v1"
    lease_id: str = ""
    workflow_id: str = ""
    owner_id: str = ""
    expires_at: str = ""
    heartbeat_at: str = ""
    generation: int = 0
