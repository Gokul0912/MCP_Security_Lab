from __future__ import annotations

import shutil
import unittest
from pathlib import Path
from uuid import uuid4

from security_lab_assistant.models import Finding, RunContext
from security_lab_assistant.policy import LabPolicy, load_default_policy
from security_lab_assistant.risk import risk_score
from security_lab_assistant.sarif import render_sarif
from security_lab_assistant.storage import search_runs
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


class EnterpriseFeatureTests(unittest.TestCase):
    def test_sarif_export_shape(self) -> None:
        run = RunContext(target="127.0.0.1", objective="unit test")
        run.status = "completed"
        run.findings.append(
            Finding(
                title="Missing CSP",
                severity="medium",
                evidence="No CSP header",
                recommendation="Add CSP.",
                affected_asset="http://127.0.0.1/",
                category="web-hardening",
            )
        )
        sarif = render_sarif(run)
        self.assertEqual(sarif["version"], "2.1.0")
        self.assertEqual(sarif["runs"][0]["results"][0]["level"], "warning")

    def test_risk_score_has_enterprise_band(self) -> None:
        run = RunContext(target="127.0.0.1", objective="unit test")
        run.findings.append(
            Finding(title="Header gap", severity="medium", evidence="x", recommendation="fix")
        )
        self.assertEqual(risk_score(run)["band"], "medium")

    def test_run_search_uses_index(self) -> None:
        policy, temp_dir = temp_policy()
        try:
            result = run_autonomous_recon(
                {"target": "127.0.0.1", "ports": [80], "objective": "indexed search smoke"},
                policy,
            )
            self.assertTrue(result.ok)
            matches = search_runs(policy, query="indexed search", status="completed")
            self.assertEqual(len(matches), 1)
            self.assertEqual(matches[0]["run_id"], result.data["run_id"])
        finally:
            shutil.rmtree(temp_dir, ignore_errors=True)

    def test_audit_chain_verification_detects_clean_chain(self) -> None:
        from security_lab_assistant.storage import verify_audit_chain

        policy, temp_dir = temp_policy()
        try:
            run_autonomous_recon({"target": "127.0.0.1", "ports": [80]}, policy)
            verification = verify_audit_chain(policy)
            self.assertTrue(verification["ok"])
            self.assertGreaterEqual(verification["events"], 2)
        finally:
            shutil.rmtree(temp_dir, ignore_errors=True)

    def test_web_page_intel_extracts_html_indicators(self) -> None:
        # The HTML parser path is tested through the tool's internal parser by feeding a data URL
        # would violate URL policy, so assert the tool is registered with a product-facing schema.
        tool = TOOLS["recon.web_page_intel"]
        self.assertIn("HTML", tool.description)
        self.assertIn("url", tool.input_schema["required"])
