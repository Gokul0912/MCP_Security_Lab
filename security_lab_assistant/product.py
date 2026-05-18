from __future__ import annotations

from dataclasses import asdict, dataclass
from typing import Any


JsonObject = dict[str, Any]


PRODUCT_NAME = "Trustworthy Autonomous Security Runtime"
PRODUCT_CATEGORY = "Explainable Security Workflow Runtime"
PRODUCT_ONE_LINER = "A governed runtime for bounded, explainable, replayable security workflows."
RUNTIME_VERSION = "trusted-security-runtime-v1"


SCHEMA_VERSIONS: JsonObject = {
    "audit_event": "audit-event-v1",
    "benchmark_record": "benchmark-record-v1",
    "execution_manifest": "execution-manifest-v1",
    "failure_record": "failure-record-v1",
    "lineage_record": "lineage-record-v1",
    "queue_task": "queue-task-v1",
    "reasoning_graph": "reasoning-graph-v1",
    "replay_state": "replay-state-v1",
    "run_record": "run-record-v1",
    "worker_contract": "worker-contract-v1",
    "workflow_state": "workflow-state-v1",
}


@dataclass(frozen=True)
class ProductIdentity:
    name: str = PRODUCT_NAME
    category: str = PRODUCT_CATEGORY
    one_liner: str = PRODUCT_ONE_LINER
    runtime_version: str = RUNTIME_VERSION

    def to_dict(self) -> JsonObject:
        return {**asdict(self), "schema_versions": dict(SCHEMA_VERSIONS)}


def product_identity() -> JsonObject:
    return ProductIdentity().to_dict()
