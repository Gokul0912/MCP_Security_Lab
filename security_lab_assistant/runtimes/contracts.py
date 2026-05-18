from __future__ import annotations

from dataclasses import asdict, dataclass

from security_lab_assistant.models import JsonObject


@dataclass(frozen=True)
class RuntimeContract:
    name: str
    deterministic: bool
    may_execute_tools: bool
    may_mutate_policy: bool
    evidence_access: str
    authority: tuple[str, ...]
    guarantees: tuple[str, ...]

    def to_dict(self) -> JsonObject:
        return asdict(self)


GOVERNANCE_CONTRACT = RuntimeContract(
    name="governance",
    deterministic=True,
    may_execute_tools=False,
    may_mutate_policy=False,
    evidence_access="metadata-only",
    authority=("policy_enforcement", "rbac", "approvals", "quotas", "signatures", "audit_verification"),
    guarantees=("deterministic_decisions", "immutable_contract", "no_probabilistic_reasoning"),
)

REASONING_CONTRACT = RuntimeContract(
    name="reasoning",
    deterministic=False,
    may_execute_tools=False,
    may_mutate_policy=False,
    evidence_access="read-only",
    authority=("confidence_propagation", "contradiction_modeling", "hypothesis_generation", "graph_building"),
    guarantees=("read_only_evidence", "no_tool_execution", "no_policy_mutation"),
)

TOOL_CONTRACT = RuntimeContract(
    name="tool",
    deterministic=False,
    may_execute_tools=True,
    may_mutate_policy=False,
    evidence_access="write-tool-results",
    authority=("bounded_network_io", "bounded_analysis", "timeout_enforcement"),
    guarantees=("policy_prechecked", "timeout_constrained", "quota_aware"),
)

EVIDENCE_CONTRACT = RuntimeContract(
    name="evidence",
    deterministic=True,
    may_execute_tools=False,
    may_mutate_policy=False,
    evidence_access="append-and-read",
    authority=("artifact_storage", "lineage", "hashing", "signature_verification", "benchmark_records"),
    guarantees=("append_only_lineage", "hash_chained_records", "signed_artifacts"),
)

WORKFLOW_CONTRACT = RuntimeContract(
    name="workflow",
    deterministic=True,
    may_execute_tools=False,
    may_mutate_policy=False,
    evidence_access="orchestrated",
    authority=("state_transitions", "event_streaming", "scheduling", "retry_boundaries"),
    guarantees=("governance_before_tools", "events_for_state_changes", "no_direct_network_io"),
)


def runtime_contracts() -> JsonObject:
    return {
        contract.name: contract.to_dict()
        for contract in [
            GOVERNANCE_CONTRACT,
            REASONING_CONTRACT,
            TOOL_CONTRACT,
            EVIDENCE_CONTRACT,
            WORKFLOW_CONTRACT,
        ]
    }
