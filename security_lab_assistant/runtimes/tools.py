from __future__ import annotations

import json
import os
import subprocess
import sys
from dataclasses import dataclass
from datetime import UTC, datetime
from pathlib import Path
from time import perf_counter
from typing import Callable
from uuid import uuid4

from security_lab_assistant.models import JsonObject, ToolResult
from security_lab_assistant.platform import sign_payload
from security_lab_assistant.policy import LabPolicy, PolicyError
from security_lab_assistant.product import SCHEMA_VERSIONS
from security_lab_assistant.reasoning import stable_hash
from security_lab_assistant.runtimes.contracts import RuntimeContract, TOOL_CONTRACT
from security_lab_assistant.runtimes.worker import capability_for_tool, worker_attestation
from security_lab_assistant.secrets import redact_secrets


ToolCallable = Callable[[JsonObject, LabPolicy], ToolResult]


@dataclass(frozen=True)
class ToolRuntime:
    policy: LabPolicy
    contract: RuntimeContract = TOOL_CONTRACT

    def execute(self, name: str, arguments: JsonObject, handler: ToolCallable) -> ToolResult:
        if os.environ.get("SECURITY_LAB_WORKER_CHILD") == "1":
            return self._execute_in_process(name, arguments, handler, fallback_reason="worker_child")
        if name.startswith("workflow."):
            return self._execute_in_process(name, arguments, handler, fallback_reason="workflow_tool")
        return self._execute_in_worker(name, arguments, handler)

    def _execute_in_process(
        self,
        name: str,
        arguments: JsonObject,
        handler: ToolCallable,
        fallback_reason: str,
    ) -> ToolResult:
        started = perf_counter()
        result = handler(arguments, self.policy)
        elapsed_ms = round((perf_counter() - started) * 1000, 2)
        manifest = self._manifest(
            name=name,
            arguments=arguments,
            status="completed",
            elapsed_ms=elapsed_ms,
            result_payload={"ok": result.ok, "data": result.data, "warnings": result.warnings},
            execution_mode="in_process",
            failure_reason=fallback_reason,
        )
        data = {
            **result.data,
            "_tool_runtime": {
                "runtime": self.contract.name,
                "tool": name,
                "elapsed_ms": elapsed_ms,
                "bounded": True,
                "execution_mode": "in_process",
                "fallback_reason": fallback_reason,
                "manifest": manifest,
            },
        }
        return ToolResult(
            name=result.name,
            ok=result.ok,
            data=data,
            warnings=result.warnings,
            started_at=result.started_at,
            finished_at=result.finished_at,
        )

    def _execute_in_worker(self, name: str, arguments: JsonObject, handler: ToolCallable) -> ToolResult:
        started = perf_counter()
        capability = capability_for_tool(name, self.policy)
        payload = {"tool": name, "arguments": redact_secrets(arguments), "policy": self.policy.to_dict()}
        project_root = Path(__file__).resolve().parents[2]
        worker_dir = self.policy.artifact_root() / "workers" / str(uuid4())
        worker_dir.mkdir(parents=True, exist_ok=True)
        worker_env = _worker_environment(project_root, worker_dir)
        try:
            completed = subprocess.run(
                [sys.executable, "-m", "security_lab_assistant.runtimes.worker"],
                input=json.dumps(payload, sort_keys=True),
                capture_output=True,
                text=True,
                timeout=capability.timeout_seconds,
                cwd=str(worker_dir),
                env=worker_env,
            )
        except subprocess.TimeoutExpired:
            elapsed_ms = round((perf_counter() - started) * 1000, 2)
            manifest = self._manifest(
                name=name,
                arguments=arguments,
                status="worker_timeout",
                elapsed_ms=elapsed_ms,
                result_payload={"error": "worker timeout"},
                execution_mode="subprocess",
                failure_reason="timeout",
            )
            return ToolResult(
                name=name,
                ok=False,
                data={
                    "error": "worker_timeout",
                    "_tool_runtime": {
                        "runtime": self.contract.name,
                        "tool": name,
                        "elapsed_ms": elapsed_ms,
                        "bounded": True,
                        "execution_mode": "subprocess",
                        "failure_semantics": "timeout_result_signed_and_workflow_may_continue_or_stop",
                        "manifest": manifest,
                    },
                },
            )
        except OSError as exc:
            return self._execute_in_process(name, arguments, handler, fallback_reason=f"worker_launch_failed:{exc.__class__.__name__}")

        elapsed_ms = round((perf_counter() - started) * 1000, 2)
        output_cap = max(4096, capability.outbound_byte_cap)
        if len(completed.stdout.encode("utf-8")) > output_cap or len(completed.stderr.encode("utf-8")) > output_cap:
            manifest = self._manifest(
                name=name,
                arguments=arguments,
                status="worker_output_quota_exceeded",
                elapsed_ms=elapsed_ms,
                result_payload={"stdout_bytes": len(completed.stdout.encode("utf-8")), "stderr_bytes": len(completed.stderr.encode("utf-8"))},
                execution_mode="subprocess",
                failure_reason="output_quota_exceeded",
            )
            return ToolResult(
                name=name,
                ok=False,
                data={
                    "error": "worker_output_quota_exceeded",
                    "_tool_runtime": {
                        "runtime": self.contract.name,
                        "tool": name,
                        "elapsed_ms": elapsed_ms,
                        "bounded": True,
                        "execution_mode": "subprocess",
                        "worker_dir": str(worker_dir),
                        "failure_semantics": "oversized_worker_output_is_rejected_and_signed",
                        "manifest": manifest,
                    },
                },
            )
        if completed.returncode != 0:
            manifest = self._manifest(
                name=name,
                arguments=arguments,
                status="worker_crash",
                elapsed_ms=elapsed_ms,
                result_payload={"stderr": completed.stderr[-2000:]},
                execution_mode="subprocess",
                failure_reason="nonzero_exit",
            )
            return ToolResult(
                name=name,
                ok=False,
                data={
                    "error": "worker_crash",
                    "_tool_runtime": {
                        "runtime": self.contract.name,
                        "tool": name,
                        "elapsed_ms": elapsed_ms,
                        "bounded": True,
                        "execution_mode": "subprocess",
                        "failure_semantics": "crash_result_signed_and_no_partial_tool_state_trusted",
                        "manifest": manifest,
                    },
                },
            )

        try:
            worker_response = json.loads(completed.stdout)
        except json.JSONDecodeError:
            return self._execute_in_process(name, arguments, handler, fallback_reason="worker_invalid_json")
        if not worker_response.get("ok"):
            manifest = self._manifest(
                name=name,
                arguments=arguments,
                status="worker_error",
                elapsed_ms=elapsed_ms,
                result_payload=worker_response,
                execution_mode="subprocess",
                failure_reason=str(worker_response.get("error_type", "worker_error")),
            )
            return ToolResult(
                name=name,
                ok=False,
                data={
                    "error": worker_response.get("error", "worker error"),
                    "_tool_runtime": {
                        "runtime": self.contract.name,
                        "tool": name,
                        "elapsed_ms": elapsed_ms,
                        "bounded": True,
                        "execution_mode": "subprocess",
                        "failure_semantics": "worker_error_signed_and_returned_as_failed_tool_result",
                        "manifest": manifest,
                    },
                },
            )

        result_payload = worker_response["result"]
        manifest = self._manifest(
            name=name,
            arguments=arguments,
            status="completed",
            elapsed_ms=elapsed_ms,
            result_payload=result_payload,
            execution_mode="subprocess",
            attestation=worker_response.get("attestation", {}),
        )
        data = {
            **result_payload.get("data", {}),
            "_tool_runtime": {
                "runtime": self.contract.name,
                "tool": name,
                "elapsed_ms": elapsed_ms,
                "bounded": True,
                "execution_mode": "subprocess",
                "capability": capability.to_dict(),
                "attestation": worker_response.get("attestation", {}),
                "output_hash": worker_response.get("output_hash", ""),
                "manifest": manifest,
            },
        }
        return ToolResult(
            name=str(result_payload.get("name", name)),
            ok=bool(result_payload.get("ok", False)),
            data=data,
            warnings=list(result_payload.get("warnings", [])),
            started_at=str(result_payload.get("started_at", datetime.now(UTC).isoformat())),
            finished_at=str(result_payload.get("finished_at", datetime.now(UTC).isoformat())),
        )

    def _manifest(
        self,
        name: str,
        arguments: JsonObject,
        status: str,
        elapsed_ms: float,
        result_payload: JsonObject,
        execution_mode: str,
        failure_reason: str = "",
        attestation: JsonObject | None = None,
    ) -> JsonObject:
        root = self.policy.artifact_root()
        execution_dir = root / "executions"
        execution_dir.mkdir(parents=True, exist_ok=True)
        execution_id = str(uuid4())
        attestation_payload = attestation or worker_attestation(name, self.policy)
        manifest = {
            "schema_version": SCHEMA_VERSIONS["execution_manifest"],
            "execution_id": execution_id,
            "worker_id": attestation_payload.get("capability", {}).get("worker_type", "in_process_worker"),
            "tool": name,
            "status": status,
            "execution_mode": execution_mode,
            "failure_reason": failure_reason,
            "arguments_hash": stable_hash(arguments),
            "output_hash": stable_hash(result_payload),
            "execution_hash": stable_hash(
                {
                    "tool": name,
                    "arguments": arguments,
                    "result": result_payload,
                    "attestation": attestation_payload,
                    "status": status,
                }
            ),
            "runtime_version": attestation_payload.get("runtime_version", "in-process-tool-runtime"),
            "policy_hash": stable_hash(self.policy.to_dict()),
            "contract_hash": stable_hash(capability_for_tool(name, self.policy).to_dict()),
                "capability": capability_for_tool(name, self.policy).to_dict(),
                "worker_directory": str(root / "workers"),
            "attestation": attestation_payload,
            "quotas": {
                "timeout_seconds": capability_for_tool(name, self.policy).timeout_seconds,
                "outbound_byte_cap": self.policy.max_http_bytes,
                "concurrent_task_cap": 1,
            },
            "elapsed_ms": elapsed_ms,
            "started_at": datetime.now(UTC).isoformat(),
            "finished_at": datetime.now(UTC).isoformat(),
        }
        manifest["signature"] = sign_payload(self.policy, manifest, "tool_execution_manifest")
        manifest_path = execution_dir / f"{execution_id}.execution.json"
        manifest_path.write_text(json.dumps(manifest, indent=2, sort_keys=True), encoding="utf-8")
        return {
            "execution_id": execution_id,
            "manifest_path": str(manifest_path),
            "execution_hash": manifest["execution_hash"],
            "signature": manifest["signature"],
        }


def _worker_environment(project_root: Path, worker_dir: Path) -> dict[str, str]:
    allowed_keys = ["SYSTEMROOT", "WINDIR", "PATH", "TEMP", "TMP"]
    env = {key: value for key, value in os.environ.items() if key in allowed_keys}
    env["SECURITY_LAB_WORKER_CHILD"] = "1"
    env["PYTHONPATH"] = str(project_root)
    env["SECURITY_LAB_WORKER_DIR"] = str(worker_dir)
    return env
