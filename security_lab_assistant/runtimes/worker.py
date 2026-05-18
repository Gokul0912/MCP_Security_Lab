from __future__ import annotations

import json
import os
import sys
import traceback
from dataclasses import asdict, dataclass
from datetime import UTC, datetime

from security_lab_assistant.models import JsonObject
from security_lab_assistant.policy import LabPolicy
from security_lab_assistant.product import SCHEMA_VERSIONS
from security_lab_assistant.reasoning import stable_hash


WORKER_RUNTIME_VERSION = "secure-worker-runtime-v1"


@dataclass(frozen=True)
class WorkerCapabilityContract:
    worker_type: str
    allowed_operations: tuple[str, ...]
    network_scope: tuple[str, ...]
    filesystem_access: str
    timeout_seconds: float
    outbound_byte_cap: int
    memory_limit_mb: int
    concurrent_task_cap: int

    def to_dict(self) -> JsonObject:
        return asdict(self)


def capability_for_tool(tool_name: str, policy: LabPolicy) -> WorkerCapabilityContract:
    if tool_name == "scan.tcp_connect":
        operation = "tcp_connect"
        worker_type = "tcp_scan_worker"
    elif tool_name.startswith("recon.") or tool_name == "web.fetch_text":
        operation = "bounded_fetch"
        worker_type = "recon_worker"
    elif tool_name.startswith("analyze."):
        operation = "local_analysis"
        worker_type = "analysis_worker"
    else:
        operation = "metadata_read"
        worker_type = "metadata_worker"
    return WorkerCapabilityContract(
        worker_type=worker_type,
        allowed_operations=(operation,),
        network_scope=tuple(str(network) for network in policy.allowed_cidrs),
        filesystem_access="none",
        timeout_seconds=max(policy.connect_timeout_seconds, policy.http_timeout_seconds, 1.0) + 2.0,
        outbound_byte_cap=policy.max_http_bytes,
        memory_limit_mb=128,
        concurrent_task_cap=1,
    )


def worker_attestation(tool_name: str, policy: LabPolicy) -> JsonObject:
    capability = capability_for_tool(tool_name, policy).to_dict()
    policy_payload = policy.to_dict()
    return {
        "runtime_version": WORKER_RUNTIME_VERSION,
        "tool": tool_name,
        "contract_schema_version": SCHEMA_VERSIONS["worker_contract"],
        "capability": capability,
        "policy_hash": stable_hash(policy_payload),
        "python": sys.version.split()[0],
        "platform": sys.platform,
    }


def execute_worker_payload(payload: JsonObject) -> JsonObject:
    tool_name = str(payload["tool"])
    arguments = payload.get("arguments", {})
    policy = LabPolicy.from_dict(payload["policy"])  # type: ignore[arg-type]
    os.environ["SECURITY_LAB_WORKER_CHILD"] = "1"
    from security_lab_assistant.tools.registry import TOOLS

    if tool_name not in TOOLS or tool_name.startswith("workflow."):
        raise ValueError(f"Tool is not allowed in worker runtime: {tool_name}")
    result = TOOLS[tool_name].handler(arguments, policy)
    result_payload = asdict(result)
    return {
        "ok": True,
        "result": result_payload,
        "attestation": worker_attestation(tool_name, policy),
        "output_hash": stable_hash(result_payload),
        "finished_at": datetime.now(UTC).isoformat(),
    }


def main() -> None:
    try:
        payload = json.loads(sys.stdin.read())
        response = execute_worker_payload(payload)
    except Exception as exc:
        response = {
            "ok": False,
            "error": str(exc),
            "error_type": exc.__class__.__name__,
            "traceback": traceback.format_exc(limit=4),
            "finished_at": datetime.now(UTC).isoformat(),
        }
    sys.stdout.write(json.dumps(response, sort_keys=True))


if __name__ == "__main__":
    main()
