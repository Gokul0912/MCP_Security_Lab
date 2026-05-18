from __future__ import annotations

from dataclasses import dataclass

from security_lab_assistant.models import JsonObject, RunContext
from security_lab_assistant.operations import OperationsStore
from security_lab_assistant.platform import WorkflowEvent, append_workflow_event
from security_lab_assistant.policy import LabPolicy
from security_lab_assistant.runtimes.contracts import RuntimeContract, WORKFLOW_CONTRACT


@dataclass(frozen=True)
class WorkflowRuntime:
    policy: LabPolicy
    contract: RuntimeContract = WORKFLOW_CONTRACT

    def emit(self, run: RunContext, event_type: str, payload: JsonObject) -> JsonObject:
        sequence = len(run.runtime.setdefault("workflow_events", [])) + 1
        event = WorkflowEvent(run_id=run.run_id, event_type=event_type, sequence=sequence, payload=payload).to_dict()
        event["runtime"] = self.contract.name
        run.runtime["workflow_events"].append(event)
        append_workflow_event(self.policy, WorkflowEvent(run.run_id, event_type, sequence, payload))
        return event

    def transition(
        self,
        run: RunContext,
        state: str,
        *,
        checkpoint_id: str = "",
        replay_cursor: str = "",
        lineage_pointer: str = "",
        lease_owner: str = "",
        terminal_status: str = "",
    ) -> JsonObject:
        record = OperationsStore(self.policy).upsert_workflow_state(
            run.run_id,
            state,
            objective=run.objective,
            target=run.target,
            checkpoint_id=checkpoint_id,
            replay_cursor=replay_cursor,
            lineage_pointer=lineage_pointer,
            lease_owner=lease_owner,
            terminal_status=terminal_status,
        )
        run.runtime["workflow_state"] = record.to_dict()
        self.emit(run, f"workflow.{state}", {"state": state, "checkpoint_id": checkpoint_id})
        return record.to_dict()
