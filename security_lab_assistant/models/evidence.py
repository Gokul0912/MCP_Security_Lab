from __future__ import annotations

from dataclasses import dataclass, field

from security_lab_assistant.models.base import JsonObject, SchemaRecord
from security_lab_assistant.product import SCHEMA_VERSIONS


@dataclass(frozen=True)
class LineageRecord(SchemaRecord):
    schema_version: str = SCHEMA_VERSIONS["lineage_record"]
    run_id: str = ""
    event_type: str = ""
    payload: JsonObject = field(default_factory=dict)
    previous_hash: str = ""
    event_hash: str = ""


@dataclass(frozen=True)
class AuditEventRecord(SchemaRecord):
    schema_version: str = SCHEMA_VERSIONS["audit_event"]
    event_type: str = ""
    payload: JsonObject = field(default_factory=dict)
    previous_hash: str = ""
    event_hash: str = ""
