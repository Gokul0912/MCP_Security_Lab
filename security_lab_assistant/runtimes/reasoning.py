from __future__ import annotations

from dataclasses import dataclass

from security_lab_assistant.models import JsonObject, RunContext
from security_lab_assistant.policy import LabPolicy
from security_lab_assistant.reasoning import build_reasoning_artifact
from security_lab_assistant.runtime_intelligence import build_runtime_profile
from security_lab_assistant.runtimes.contracts import REASONING_CONTRACT, RuntimeContract


@dataclass(frozen=True)
class ReasoningRuntime:
    contract: RuntimeContract = REASONING_CONTRACT

    def build_artifact(self, run: RunContext) -> JsonObject:
        return build_reasoning_artifact(run)

    def build_profile(self, run: RunContext, policy: LabPolicy) -> JsonObject:
        return build_runtime_profile(run, policy)
