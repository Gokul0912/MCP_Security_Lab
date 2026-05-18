from __future__ import annotations

import json
from datetime import UTC, datetime
from uuid import uuid4

from security_lab_assistant.models import JsonObject, ToolResult
from security_lab_assistant.operations import OperationsStore
from security_lab_assistant.policy import LabPolicy, PolicyError
from security_lab_assistant.platform import require_permission
from security_lab_assistant.tools.base import refused
from security_lab_assistant.validation import parse_ports


def workflow_batch_recon(arguments: JsonObject, policy: LabPolicy) -> ToolResult:
    name = "workflow.batch_recon"
    try:
        role = str(arguments.get("role", "analyst"))
        require_permission(role, "workflow.run")
        targets_raw = arguments.get("targets")
        if not isinstance(targets_raw, list) or not all(isinstance(target, str) for target in targets_raw):
            raise PolicyError("targets must be a list of strings.")
        approved = bool(arguments.get("approved", False))
        if approved:
            require_permission(role, "workflow.approve")
        policy.assert_batch_allowed(targets_raw, approved=approved)
        ports = parse_ports(arguments.get("ports", [80, 443, 8000, 8080, 8443]))
        objective = str(arguments.get("objective", "batch baseline web reconnaissance")).strip()
    except PolicyError as exc:
        return refused(name, exc)

    batch_id = str(uuid4())
    store = OperationsStore(policy)
    store.upsert_workflow_state(batch_id, "created", objective=objective, target=",".join(targets_raw))
    queue_task = store.enqueue_task(
        "workflow.batch_recon",
        {
            "workflow_id": batch_id,
            "targets": targets_raw,
            "ports": ports,
            "objective": objective,
            "role": role,
            "approved": approved,
        },
        workflow_id=batch_id,
    )
    lease = store.acquire_lease(batch_id, owner_id=f"batch:{role}")
    store.upsert_workflow_state(batch_id, "running", objective=objective, target=",".join(targets_raw), lease_owner=lease.owner_id)
    results = []
    from security_lab_assistant.workflows.autonomous_recon import run_autonomous_recon

    for target in targets_raw:
        result = run_autonomous_recon({"target": target, "ports": ports, "objective": objective}, policy)
        results.append({"target": target, "ok": result.ok, "run_id": result.data.get("run_id"), "status": result.data.get("status")})

    record = {
        "batch_id": batch_id,
        "queue_task_id": queue_task.task_id,
        "lease_id": lease.lease_id,
        "created_at": datetime.now(UTC).isoformat(),
        "role": role,
        "approved": approved,
        "objective": objective,
        "targets": targets_raw,
        "ports": ports,
        "results": results,
        "status": "completed" if all(item["ok"] for item in results) else "completed_with_errors",
    }
    terminal_state = "completed" if all(item["ok"] for item in results) else "failed"
    store.upsert_workflow_state(
        batch_id,
        terminal_state,
        objective=objective,
        target=",".join(targets_raw),
        checkpoint_id="batch.complete",
        terminal_status=record["status"],
    )
    queue_dir = policy.artifact_root() / "queues"
    queue_dir.mkdir(parents=True, exist_ok=True)
    batch_path = queue_dir / f"{batch_id}.batch.json"
    batch_path.write_text(json.dumps(record, indent=2, sort_keys=True), encoding="utf-8")
    return ToolResult(name=name, ok=all(item["ok"] for item in results), data={**record, "batch_path": str(batch_path)})
