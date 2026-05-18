from __future__ import annotations

import shutil
import unittest
from pathlib import Path
from uuid import uuid4

from security_lab_assistant.policy import LabPolicy, load_default_policy
from security_lab_assistant.product import PRODUCT_NAME, SCHEMA_VERSIONS
from security_lab_assistant.replay import validate_replay
from security_lab_assistant.secrets import redact_secrets, resolve_secret, store_local_secret
from security_lab_assistant.storage import load_run
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


class ProductPlatformTests(unittest.TestCase):
    def test_run_persists_signed_artifacts_metrics_events_and_benchmark(self) -> None:
        policy, temp_dir = temp_policy()
        try:
            result = run_autonomous_recon({"target": "127.0.0.1", "ports": [80]}, policy)
            self.assertTrue(result.ok)
            run = load_run(policy, result.data["run_id"])
            self.assertTrue(Path(run["benchmark_path"]).exists())
            self.assertTrue(Path(run["benchmark_signature"]["manifest_path"]).exists())
            self.assertTrue((temp_dir / "events" / "workflows.jsonl").exists())
            self.assertTrue((temp_dir / "metrics" / "metrics.jsonl").exists())
            verification = TOOLS["run.verify_artifacts"].handler({"role": "auditor"}, policy)
            self.assertTrue(verification.ok)
            self.assertTrue(verification.data["ok"])
        finally:
            shutil.rmtree(temp_dir, ignore_errors=True)

    def test_batch_requires_human_approval(self) -> None:
        policy, temp_dir = temp_policy()
        try:
            result = TOOLS["workflow.batch_recon"].handler(
                {"targets": ["127.0.0.1"], "ports": [80], "role": "analyst"},
                policy,
            )
            self.assertFalse(result.ok)
            self.assertIn("approval", result.data["refusal"])
        finally:
            shutil.rmtree(temp_dir, ignore_errors=True)

    def test_approved_batch_records_queue_file(self) -> None:
        policy, temp_dir = temp_policy()
        try:
            result = TOOLS["workflow.batch_recon"].handler(
                {"targets": ["127.0.0.1"], "ports": [80], "role": "reviewer", "approved": True},
                policy,
            )
            self.assertTrue(result.ok)
            self.assertTrue(Path(result.data["batch_path"]).exists())
            self.assertEqual(result.data["status"], "completed")
        finally:
            shutil.rmtree(temp_dir, ignore_errors=True)

    def test_ops_tools_require_auditor_style_permission(self) -> None:
        policy, temp_dir = temp_policy()
        try:
            denied = TOOLS["ops.metrics"].handler({"role": "analyst"}, policy)
            self.assertFalse(denied.ok)
            allowed = TOOLS["ops.metrics"].handler({"role": "auditor"}, policy)
            self.assertTrue(allowed.ok)
            self.assertIn("rollup", allowed.data)
        finally:
            shutil.rmtree(temp_dir, ignore_errors=True)

    def test_platform_identity_exposes_trustworthy_runtime_positioning(self) -> None:
        policy, temp_dir = temp_policy()
        try:
            result = TOOLS["ops.platform"].handler({"role": "readonly"}, policy)
            self.assertTrue(result.ok)
            self.assertEqual(result.data["name"], PRODUCT_NAME)
            self.assertEqual(result.data["schema_versions"]["workflow_state"], SCHEMA_VERSIONS["workflow_state"])
            self.assertIn("replayable", result.data["one_liner"])
        finally:
            shutil.rmtree(temp_dir, ignore_errors=True)

    def test_workflow_run_persists_operational_state(self) -> None:
        policy, temp_dir = temp_policy()
        try:
            result = run_autonomous_recon({"target": "127.0.0.1", "ports": [80]}, policy)
            self.assertTrue(result.ok)
            workflows = TOOLS["ops.workflows"].handler({"role": "operator"}, policy)
            self.assertTrue(workflows.ok)
            states = workflows.data["workflows"]
            self.assertTrue(any(state["workflow_id"] == result.data["run_id"] for state in states))
            final_state = next(state for state in states if state["workflow_id"] == result.data["run_id"])
            self.assertEqual(final_state["state"], "completed")
            self.assertEqual(final_state["schema_version"], SCHEMA_VERSIONS["workflow_state"])
        finally:
            shutil.rmtree(temp_dir, ignore_errors=True)

    def test_batch_workflow_uses_durable_queue_and_lease_records(self) -> None:
        policy, temp_dir = temp_policy()
        try:
            batch = TOOLS["workflow.batch_recon"].handler(
                {"targets": ["127.0.0.1"], "ports": [80], "role": "reviewer", "approved": True},
                policy,
            )
            self.assertTrue(batch.ok)
            queue = TOOLS["ops.queue"].handler({"role": "operator"}, policy)
            self.assertTrue(queue.ok)
            self.assertTrue(any(task["task_id"] == batch.data["queue_task_id"] for task in queue.data["tasks"]))
            self.assertTrue(any(lease["lease_id"] == batch.data["lease_id"] for lease in queue.data["leases"]))
        finally:
            shutil.rmtree(temp_dir, ignore_errors=True)

    def test_failure_taxonomy_is_structured_for_runtime_failures(self) -> None:
        policy, temp_dir = temp_policy()
        try:
            result = TOOLS["ops.failure_taxonomy"].handler({"role": "auditor"}, policy)
            self.assertTrue(result.ok)
            self.assertIn("WorkerFailure", result.data["classes"])
            self.assertIn("ReplayFailure", result.data["classes"])
            self.assertIn("recovery_suggestion", result.data["required_fields"])
        finally:
            shutil.rmtree(temp_dir, ignore_errors=True)

    def test_replay_validation_matches_saved_run(self) -> None:
        policy, temp_dir = temp_policy()
        try:
            result = run_autonomous_recon({"target": "127.0.0.1", "ports": [80]}, policy)
            replay = validate_replay(policy, result.data["run_id"])
            self.assertTrue(replay["ok"])
            self.assertTrue(any(check["name"] == "workflow_hash" for check in replay["checks"]))
        finally:
            shutil.rmtree(temp_dir, ignore_errors=True)

    def test_deep_verify_covers_replay_lineage_policy_and_benchmark(self) -> None:
        policy, temp_dir = temp_policy()
        try:
            result = run_autonomous_recon({"target": "127.0.0.1", "ports": [80]}, policy)
            self.assertTrue(result.ok)
            deep = TOOLS["run.verify_deep"].handler({"role": "auditor", "quarantine": False}, policy)
            self.assertTrue(deep.ok)
            self.assertTrue(deep.data["ok"])
            self.assertEqual(deep.data["mode"], "forensic-runtime-verification-v1")
        finally:
            shutil.rmtree(temp_dir, ignore_errors=True)

    def test_local_secret_provider_uses_refs_and_redaction(self) -> None:
        policy, temp_dir = temp_policy()
        try:
            stored = store_local_secret(policy, "api-token", "super-secret", actor="admin")
            self.assertTrue(stored["secret_id"].startswith("secretref:"))
            self.assertEqual(resolve_secret(policy, stored["secret_id"], actor="worker"), "super-secret")
            redacted = redact_secrets({"token": stored["secret_id"]})
            self.assertEqual(redacted["token"], "secretref:REDACTED")
        finally:
            shutil.rmtree(temp_dir, ignore_errors=True)


if __name__ == "__main__":
    unittest.main()
