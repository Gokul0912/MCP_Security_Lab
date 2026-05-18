from __future__ import annotations

from dataclasses import dataclass, field

from security_lab_assistant.models.base import JsonObject, SchemaRecord
from security_lab_assistant.product import SCHEMA_VERSIONS


@dataclass(frozen=True)
class ExecutionManifestRecord(SchemaRecord):
    schema_version: str = SCHEMA_VERSIONS["execution_manifest"]
    execution_id: str = ""
    worker_id: str = ""
    tool: str = ""
    status: str = ""
    execution_mode: str = ""
    arguments_hash: str = ""
    output_hash: str = ""
    execution_hash: str = ""
    capability: JsonObject = field(default_factory=dict)
    attestation: JsonObject = field(default_factory=dict)
    quotas: JsonObject = field(default_factory=dict)
