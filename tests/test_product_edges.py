from __future__ import annotations

import json
import shutil
import unittest
from pathlib import Path
from uuid import uuid4

from security_lab_assistant.mcp_protocol import handle_request
from security_lab_assistant.output import format_recon_result, format_runs_list
from security_lab_assistant.policy import LabPolicy, PolicyError, load_default_policy
from security_lab_assistant.storage import list_runs, load_run
from security_lab_assistant.tools.registry import TOOLS
from security_lab_assistant.gui import parse_ports_text
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


class ProductEdgeTests(unittest.TestCase):
    def test_url_credentials_are_refused(self) -> None:
        policy = load_default_policy()
        with self.assertRaises(PolicyError):
            policy.assert_url_allowed("http://user:pass@localhost/")

    def test_url_fragments_are_refused(self) -> None:
        policy = load_default_policy()
        with self.assertRaises(PolicyError):
            policy.assert_url_allowed("http://localhost/#secret")

    def test_non_allowlisted_dns_targets_are_refused(self) -> None:
        result = TOOLS["scope.validate"].handler({"target": "example.com"}, load_default_policy())
        self.assertFalse(result.ok)
        self.assertIn("DNS targets are disabled", result.data["refusal"])

    def test_empty_port_scan_is_refused(self) -> None:
        result = TOOLS["scan.tcp_connect"].handler({"target": "127.0.0.1", "ports": []}, load_default_policy())
        self.assertFalse(result.ok)
        self.assertIn("At least one TCP port", result.data["refusal"])

    def test_non_integer_ports_are_refused(self) -> None:
        result = TOOLS["scan.tcp_connect"].handler(
            {"target": "127.0.0.1", "ports": ["abc"]},
            load_default_policy(),
        )
        self.assertFalse(result.ok)
        self.assertIn("Invalid TCP port", result.data["refusal"])

    def test_workflow_persists_run_and_report(self) -> None:
        policy, temp_dir = temp_policy()
        try:
            result = run_autonomous_recon({"target": "127.0.0.1", "ports": [80]}, policy)
            self.assertTrue(result.ok)
            run_id = result.data["run_id"]
            run = load_run(policy, run_id)
            self.assertEqual(run["run_id"], run_id)
            self.assertTrue(Path(run["report_path"]).exists())
            self.assertTrue(Path(run["sarif_path"]).exists())
            self.assertTrue(Path(run["reasoning_visualizer_path"]).exists())
            self.assertIn("risk", run)
            self.assertEqual(len(list_runs(policy)), 1)
        finally:
            shutil.rmtree(temp_dir, ignore_errors=True)

    def test_mcp_rejects_invalid_request_shape(self) -> None:
        response = handle_request(["not", "object"], load_default_policy())  # type: ignore[arg-type]
        self.assertIsNotNone(response)
        assert response is not None
        self.assertEqual(response["error"]["code"], -32600)

    def test_mcp_rejects_non_object_tool_arguments(self) -> None:
        response = handle_request(
            {
                "jsonrpc": "2.0",
                "id": 42,
                "method": "tools/call",
                "params": {"name": "scope.validate", "arguments": "bad"},
            },
            load_default_policy(),
        )
        self.assertIsNotNone(response)
        assert response is not None
        self.assertEqual(response["error"]["code"], -32602)

    def test_json_report_is_parseable_from_persisted_run(self) -> None:
        policy, temp_dir = temp_policy()
        try:
            result = run_autonomous_recon({"target": "127.0.0.1", "ports": [80]}, policy)
            path = Path(result.data["run_path"])
            payload = json.loads(path.read_text(encoding="utf-8"))
            self.assertEqual(payload["status"], "completed")
            self.assertEqual(payload["risk"]["band"], "low")
        finally:
            shutil.rmtree(temp_dir, ignore_errors=True)

    def test_path_traversal_run_id_is_refused(self) -> None:
        result = TOOLS["run.get"].handler({"run_id": "..\\secret"}, load_default_policy())
        self.assertFalse(result.ok)
        self.assertIn("UUID", result.data["refusal"])

    def test_negative_run_limit_is_refused(self) -> None:
        result = TOOLS["run.list"].handler({"limit": -1}, load_default_policy())
        self.assertFalse(result.ok)
        self.assertIn("limit must not be negative", result.data["refusal"])

    def test_gui_port_parser_deduplicates_and_sorts(self) -> None:
        self.assertEqual(parse_ports_text("8080, 80, 8080"), [80, 8080])

    def test_gui_port_parser_rejects_non_integer_values(self) -> None:
        with self.assertRaises(PolicyError):
            parse_ports_text("80, nope")

    def test_readable_recon_output_highlights_summary(self) -> None:
        output = format_recon_result(
            {
                "ok": True,
                "data": {
                    "run_id": "11111111-1111-4111-8111-111111111111",
                    "target": "127.0.0.1",
                    "objective": "baseline",
                    "status": "completed",
                    "open_ports": [8000],
                    "risk": {"score": 47, "band": "medium", "drivers": {"finding_weight": 40}},
                    "severity_counts": {"medium": 1},
                    "warnings": ["missing headers"],
                    "findings": [{"title": "Header review", "severity": "medium"}],
                },
            }
        )
        self.assertIn("Recon Run Summary", output)
        self.assertIn("Open ports  : 8000", output)
        self.assertIn("Risk        : 47/100 (medium)", output)
        self.assertIn("Header review", output)

    def test_readable_runs_output_handles_empty_history(self) -> None:
        self.assertIn("No saved runs yet.", format_runs_list([]))

    def test_absolute_artifact_dir_is_refused(self) -> None:
        base = load_default_policy()
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
            artifacts_dir="C:\\outside",
        )
        with self.assertRaises(PolicyError):
            policy.artifact_root()
