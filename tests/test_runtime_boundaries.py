from __future__ import annotations

import shutil
import unittest
from pathlib import Path
from uuid import uuid4

from security_lab_assistant.models import RunContext
from security_lab_assistant.policy import LabPolicy, PolicyError, load_default_policy
from security_lab_assistant.product import SCHEMA_VERSIONS
from security_lab_assistant.runtimes import EvidenceRuntime, GovernanceRuntime, ReasoningRuntime, ToolRuntime, WorkflowRuntime
from security_lab_assistant.runtimes.contracts import runtime_contracts
from security_lab_assistant.runtimes.worker import capability_for_tool, worker_attestation
from security_lab_assistant.tools.registry import TOOLS
from security_lab_assistant.workflows.autonomous_recon import run_autonomous_recon


def temp_policy() -> tuple[LabPolicy, Path]:
    base = load_default_policy()
    temp_dir = Path(f".security-lab-test-{uuid4()}")
    policy = LabPolicy(
        name=base.name,
        allowed_cidrs=base.allowed_cidrs,
        allowed_hostnames=base.allowed_hostnames,
        allow_dns_targets=base.allow_dns_targets,
        blocked_ports=base.blocked_ports,
        allowed_schemes=base.allowed_schemes,
        max_redirects=base.max_redirects,
        connect_timeout_seconds=base.connect_timeout_seconds,
        http_timeout_seconds=base.http_timeout_seconds,
        max_tcp_ports_per_scan=base.max_tcp_ports_per_scan,
        max_scan_workers=base.max_scan_workers,
        max_http_bytes=base.max_http_bytes,
        artifacts_dir=temp_dir.name,
    )
    return policy, temp_dir


class RuntimeBoundaryTests(unittest.TestCase):
    def test_runtime_contracts_encode_authority_boundaries(self) -> None:
        contracts = runtime_contracts()
        self.assertFalse(contracts["reasoning"]["may_execute_tools"])
        self.assertFalse(contracts["reasoning"]["may_mutate_policy"])
        self.assertTrue(contracts["tool"]["may_execute_tools"])
        self.assertTrue(contracts["governance"]["deterministic"])
        self.assertEqual(contracts["evidence"]["evidence_access"], "append-and-read")

    def test_reasoning_runtime_has_no_direct_execution_method(self) -> None:
        runtime = ReasoningRuntime()
        self.assertFalse(hasattr(runtime, "execute"))
        self.assertFalse(runtime.contract.may_execute_tools)

    def test_governance_runtime_decisions_are_deterministic(self) -> None:
        policy, temp_dir = temp_policy()
        try:
            runtime = GovernanceRuntime(policy)
            args = {"target": "127.0.0.1"}
            self.assertEqual(runtime.approve_action("scope.validate", args), runtime.approve_action("scope.validate", args))
            with self.assertRaises(PolicyError):
                runtime.require_permission("analyst", "audit.verify")
        finally:
            shutil.rmtree(temp_dir, ignore_errors=True)

    def test_tool_runtime_adds_execution_boundary_metadata(self) -> None:
        policy, temp_dir = temp_policy()
        try:
            result = ToolRuntime(policy).execute(
                "scope.validate",
                {"target": "127.0.0.1"},
                TOOLS["scope.validate"].handler,
            )
            self.assertTrue(result.ok)
            self.assertEqual(result.data["_tool_runtime"]["runtime"], "tool")
            self.assertEqual(result.data["_tool_runtime"]["execution_mode"], "subprocess")
            self.assertTrue(Path(result.data["_tool_runtime"]["manifest"]["manifest_path"]).exists())
            self.assertRegex(result.data["_tool_runtime"]["manifest"]["execution_hash"], r"^[0-9a-f]{64}$")
            manifest_payload = Path(result.data["_tool_runtime"]["manifest"]["manifest_path"]).read_text(encoding="utf-8")
            self.assertIn(SCHEMA_VERSIONS["execution_manifest"], manifest_payload)
        finally:
            shutil.rmtree(temp_dir, ignore_errors=True)

    def test_worker_capability_contract_and_attestation_are_explicit(self) -> None:
        policy, temp_dir = temp_policy()
        try:
            capability = capability_for_tool("scan.tcp_connect", policy)
            self.assertEqual(capability.worker_type, "tcp_scan_worker")
            self.assertEqual(capability.filesystem_access, "none")
            self.assertIn("tcp_connect", capability.allowed_operations)
            attestation = worker_attestation("scan.tcp_connect", policy)
            self.assertEqual(attestation["runtime_version"], "secure-worker-runtime-v1")
            self.assertIn("policy_hash", attestation)
        finally:
            shutil.rmtree(temp_dir, ignore_errors=True)

    def test_tool_runtime_worker_error_returns_signed_failure_manifest(self) -> None:
        policy, temp_dir = temp_policy()
        try:
            result = ToolRuntime(policy).execute(
                "unknown.worker_tool",
                {"target": "127.0.0.1"},
                TOOLS["scope.validate"].handler,
            )
            self.assertFalse(result.ok)
            self.assertIn("not allowed", result.data["error"])
            self.assertTrue(Path(result.data["_tool_runtime"]["manifest"]["manifest_path"]).exists())
        finally:
            shutil.rmtree(temp_dir, ignore_errors=True)

    def test_workflow_and_evidence_runtimes_write_verifiable_boundaries(self) -> None:
        policy, temp_dir = temp_policy()
        try:
            run = RunContext(target="127.0.0.1", objective="boundary test")
            event = WorkflowRuntime(policy).emit(run, "test.event", {"ok": True})
            self.assertEqual(event["runtime"], "workflow")
            lineage = EvidenceRuntime(policy).append_lineage(run, "test.lineage", {"ok": True})
            self.assertTrue(Path(lineage["lineage_path"]).exists())
            self.assertIn("signature", Path(lineage["lineage_path"]).read_text(encoding="utf-8"))
            self.assertTrue(EvidenceRuntime(policy).verify_lineage(run.run_id)["ok"])
        finally:
            shutil.rmtree(temp_dir, ignore_errors=True)

    def test_saved_run_has_verifiable_evidence_lineage(self) -> None:
        policy, temp_dir = temp_policy()
        try:
            result = run_autonomous_recon({"target": "127.0.0.1", "ports": [80]}, policy)
            lineage = TOOLS["run.verify_lineage"].handler(
                {"run_id": result.data["run_id"], "role": "auditor"},
                policy,
            )
            self.assertTrue(lineage.ok)
            self.assertTrue(lineage.data["ok"])
            self.assertGreaterEqual(lineage.data["events"], 2)
        finally:
            shutil.rmtree(temp_dir, ignore_errors=True)


if __name__ == "__main__":
    unittest.main()
