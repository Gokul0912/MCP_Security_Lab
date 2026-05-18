from __future__ import annotations

from dataclasses import asdict, dataclass, field
from datetime import UTC, datetime

from security_lab_assistant.models import JsonObject
from security_lab_assistant.product import SCHEMA_VERSIONS


WORKER_FAILURE = "WorkerFailure"
GOVERNANCE_FAILURE = "GovernanceFailure"
REPLAY_FAILURE = "ReplayFailure"
LINEAGE_FAILURE = "LineageFailure"
ATTESTATION_FAILURE = "AttestationFailure"
POLICY_FAILURE = "PolicyFailure"
QUEUE_FAILURE = "QueueFailure"
LEASE_FAILURE = "LeaseFailure"
SIGNATURE_FAILURE = "SignatureFailure"
REASONING_FAILURE = "ReasoningFailure"
QUOTA_FAILURE = "QuotaFailure"
RECOVERY_FAILURE = "RecoveryFailure"


FAILURE_CLASSES = (
    WORKER_FAILURE,
    GOVERNANCE_FAILURE,
    REPLAY_FAILURE,
    LINEAGE_FAILURE,
    ATTESTATION_FAILURE,
    POLICY_FAILURE,
    QUEUE_FAILURE,
    LEASE_FAILURE,
    SIGNATURE_FAILURE,
    REASONING_FAILURE,
    QUOTA_FAILURE,
    RECOVERY_FAILURE,
)


@dataclass(frozen=True)
class FailureRecord:
    failure_class: str
    code: str
    message: str
    runtime: str
    severity: str = "error"
    retryable: bool = False
    workflow_id: str = ""
    artifact_refs: tuple[str, ...] = field(default_factory=tuple)
    recovery_suggestion: str = ""
    created_at: str = field(default_factory=lambda: datetime.now(UTC).isoformat())
    schema_version: str = SCHEMA_VERSIONS["failure_record"]

    def to_dict(self) -> JsonObject:
        payload = asdict(self)
        payload["artifact_refs"] = list(self.artifact_refs)
        return payload


def failure_taxonomy() -> JsonObject:
    return {
        "schema_version": SCHEMA_VERSIONS["failure_record"],
        "classes": list(FAILURE_CLASSES),
        "required_fields": [
            "failure_class",
            "code",
            "message",
            "runtime",
            "severity",
            "retryable",
            "workflow_id",
            "artifact_refs",
            "recovery_suggestion",
        ],
    }
