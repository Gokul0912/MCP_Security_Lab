from __future__ import annotations

import shutil
import unittest
from pathlib import Path
from uuid import uuid4

from security_lab_assistant.policy import LabPolicy
from security_lab_assistant.policy import load_default_policy
from security_lab_assistant.tools.registry import TOOLS
from security_lab_assistant.workflows.autonomous_recon import run_autonomous_recon


def temp_policy() -> tuple[LabPolicy, Path]:
    base = load_default_policy()
    temp_dir = Path(f".security-lab-test-{uuid4()}")
    return (
        LabPolicy(
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
        ),
        temp_dir,
    )


class ToolTests(unittest.TestCase):
    def test_scope_tool_refuses_out_of_scope_target(self) -> None:
        result = TOOLS["scope.validate"].handler({"target": "8.8.8.8"}, load_default_policy())
        self.assertFalse(result.ok)
        self.assertIn("outside the lab scope", result.data["refusal"])

    def test_scope_tool_accepts_loopback(self) -> None:
        result = TOOLS["scope.validate"].handler({"target": "127.0.0.1"}, load_default_policy())
        self.assertTrue(result.ok)
        self.assertEqual(result.data["resolved_addresses"], ["127.0.0.1"])

    def test_workflow_stops_before_scanning_out_of_scope_target(self) -> None:
        policy, temp_dir = temp_policy()
        try:
            result = run_autonomous_recon({"target": "8.8.8.8"}, policy)
            self.assertFalse(result.ok)
            self.assertEqual(result.data["stopped_at"], "scope.validate")
        finally:
            shutil.rmtree(temp_dir, ignore_errors=True)

    def test_tcp_scan_enforces_policy_limits(self) -> None:
        result = TOOLS["scan.tcp_connect"].handler(
            {"target": "127.0.0.1", "ports": list(range(1, 40))},
            load_default_policy(),
        )
        self.assertFalse(result.ok)
        self.assertIn("policy allows at most", result.data["refusal"])


if __name__ == "__main__":
    unittest.main()
