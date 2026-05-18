from __future__ import annotations

from dataclasses import dataclass

from security_lab_assistant.models import JsonObject, RunContext
from security_lab_assistant.platform import enforce_run_quotas, require_permission
from security_lab_assistant.policy import LabPolicy
from security_lab_assistant.runtime_intelligence import approval_decision
from security_lab_assistant.runtimes.contracts import GOVERNANCE_CONTRACT, RuntimeContract
from security_lab_assistant.storage import verify_artifact_signatures, verify_audit_chain


@dataclass(frozen=True)
class GovernanceRuntime:
    policy: LabPolicy
    contract: RuntimeContract = GOVERNANCE_CONTRACT

    def require_permission(self, role: str, permission: str) -> None:
        require_permission(role, permission)

    def approve_action(self, action: str, arguments: JsonObject) -> JsonObject:
        decision = approval_decision(action, arguments, self.policy)
        return {**decision, "runtime": self.contract.name, "immutable": True}

    def enforce_run_quotas(self, run: RunContext) -> None:
        enforce_run_quotas(run, self.policy)

    def assert_batch_allowed(self, targets: list[str], approved: bool) -> None:
        self.policy.assert_batch_allowed(targets, approved=approved)

    def verify_audit(self) -> JsonObject:
        return verify_audit_chain(self.policy)

    def verify_artifacts(self) -> JsonObject:
        return verify_artifact_signatures(self.policy)
