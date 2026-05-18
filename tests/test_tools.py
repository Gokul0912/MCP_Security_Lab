from __future__ import annotations

import unittest

from security_lab_assistant.policy import load_default_policy
from security_lab_assistant.tools.registry import TOOLS
from security_lab_assistant.workflows.autonomous_recon import run_autonomous_recon


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
        result = run_autonomous_recon({"target": "8.8.8.8"}, load_default_policy())
        self.assertFalse(result.ok)
        self.assertEqual(result.data["stopped_at"], "scope.validate")

    def test_tcp_scan_enforces_policy_limits(self) -> None:
        result = TOOLS["scan.tcp_connect"].handler(
            {"target": "127.0.0.1", "ports": list(range(1, 40))},
            load_default_policy(),
        )
        self.assertFalse(result.ok)
        self.assertIn("policy allows at most", result.data["refusal"])


if __name__ == "__main__":
    unittest.main()
