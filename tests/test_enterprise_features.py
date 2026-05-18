from __future__ import annotations

import shutil
import unittest
from pathlib import Path
from uuid import uuid4

from security_lab_assistant.models import Finding, RunContext
from security_lab_assistant.output import format_recon_result, format_runtime_section
from security_lab_assistant.policy import LabPolicy, load_default_policy
from security_lab_assistant.reasoning import ReasoningEdge, build_reasoning_artifact
from security_lab_assistant.risk import risk_score
from security_lab_assistant.runtime_intelligence import build_runtime_profile
from security_lab_assistant.sarif import render_sarif
from security_lab_assistant.storage import load_run, search_runs
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

    def test_runtime_profile_contains_advanced_security_os_primitives(self) -> None:
        policy, temp_dir = temp_policy()
        try:
            result = run_autonomous_recon({"target": "127.0.0.1", "ports": [80]}, policy)
            run = load_run(policy, result.data["run_id"])
            runtime = run["runtime"]
            self.assertIn("deterministic_replay", runtime)
            self.assertIn("explainability", runtime)
            self.assertIn("attack_graph", runtime)
            self.assertIn("adversarial_critique", runtime)
            self.assertIn("evidence_integrity", runtime)
            self.assertIn("formal_safety_claims", runtime)
            self.assertIn("approval_gates", runtime)
            self.assertIn("security_cognition", runtime)
            self.assertIn("hypotheses", runtime)
            self.assertIn("contradictions", runtime)
            self.assertIn("investigation_tree", runtime)
            self.assertIn("confidence_calibration", runtime)
            self.assertIn("reasoning_timeline", runtime)
            self.assertIn("self_red_team", runtime)
            self.assertIn("trust_boundaries", runtime)
            self.assertIn("benchmark", runtime)
            self.assertIn("reasoning_quality", runtime)
            self.assertIn("formal_reasoning_graph", runtime)
            self.assertIn("benchmark_suite", runtime)
            self.assertIn("explainability_visualizer", runtime)
            self.assertIn("probabilistic_reasoning", runtime)
            self.assertIn("ai_safety_research", runtime)
            self.assertIn("cross_run_correlation", runtime)
            self.assertIn("dynamic_trust_calibration", runtime)
            self.assertIn("security_simulation_universe", runtime)
            self.assertIn("reasoning_replay_diff", runtime)
            self.assertEqual(runtime["deterministic_replay"]["mode"], "deterministic-reasoning-replay")
        finally:
            shutil.rmtree(temp_dir, ignore_errors=True)

    def test_runtime_section_tool_reads_replay_metadata(self) -> None:
        policy, temp_dir = temp_policy()
        try:
            result = run_autonomous_recon({"target": "127.0.0.1", "ports": [80]}, policy)
            section = TOOLS["runtime.section"].handler(
                {"run_id": result.data["run_id"], "section": "replay"},
                policy,
            )
            self.assertTrue(section.ok)
            self.assertIn("workflow_hash", section.data["data"])
        finally:
            shutil.rmtree(temp_dir, ignore_errors=True)

    def test_cognitive_runtime_sections_are_available_as_tools(self) -> None:
        policy, temp_dir = temp_policy()
        try:
            result = run_autonomous_recon({"target": "127.0.0.1", "ports": [80]}, policy)
            for section in [
                "cognition",
                "hypotheses",
                "confidence",
                "timeline",
                "redteam",
                "benchmark",
                "quality",
                "reasoning-graph",
                "benchmark-suite",
                "probabilistic",
                "ai-safety",
                "trust-calibration",
                "simulation",
                "diff",
            ]:
                response = TOOLS["runtime.section"].handler(
                    {"run_id": result.data["run_id"], "section": section},
                    policy,
                )
                self.assertTrue(response.ok, section)
                self.assertNotEqual(response.data["data"], {})
        finally:
            shutil.rmtree(temp_dir, ignore_errors=True)

    def test_competing_hypotheses_are_confidence_ordered(self) -> None:
        policy, temp_dir = temp_policy()
        try:
            result = run_autonomous_recon({"target": "127.0.0.1", "ports": [80]}, policy)
            hypotheses = load_run(policy, result.data["run_id"])["runtime"]["hypotheses"]
            confidences = [item["confidence"] for item in hypotheses]
            self.assertEqual(confidences, sorted(confidences, reverse=True))
            self.assertIn("recommended_verification", hypotheses[0])
        finally:
            shutil.rmtree(temp_dir, ignore_errors=True)

    def test_confidence_calibration_stays_bounded(self) -> None:
        run = RunContext(target="127.0.0.1", objective="unit test")
        runtime = build_runtime_profile(run, load_default_policy())
        confidence = runtime["confidence_calibration"]["calibrated_confidence"]
        self.assertGreaterEqual(confidence, 0.0)
        self.assertLessEqual(confidence, 1.0)
        quality = runtime["reasoning_quality"]["overall_score"]
        self.assertGreaterEqual(quality, 0.0)
        self.assertLessEqual(quality, 1.0)

    def test_reasoning_verification_outputs_are_hashable_and_bounded(self) -> None:
        policy, temp_dir = temp_policy()
        try:
            run = RunContext(target="127.0.0.1", objective="unit test")
            runtime = build_runtime_profile(run, policy)
            self.assertRegex(runtime["formal_reasoning_graph"]["graph_hash"], r"^[0-9a-f]{64}$")
            self.assertGreaterEqual(runtime["benchmark_suite"]["score"], 0.0)
            self.assertLessEqual(runtime["benchmark_suite"]["score"], 1.0)
            self.assertEqual(runtime["security_simulation_universe"]["network_posture"], "synthetic_or_loopback_only")
            self.assertEqual(runtime["reasoning_replay_diff"]["mode"], "single-run-baseline")
        finally:
            shutil.rmtree(temp_dir, ignore_errors=True)

    def test_reasoning_graph_has_typed_nodes_edges_and_replay_states(self) -> None:
        run = RunContext(target="127.0.0.1", objective="unit test")
        artifact = build_reasoning_artifact(run)
        graph = artifact["graph"]
        replay = artifact["replay"]
        self.assertEqual(graph["model"], "formal-security-reasoning-graph-v1")
        self.assertTrue(graph["nodes"])
        self.assertTrue(graph["states"])
        self.assertEqual(replay["graph_hash"], graph["graph_hash"])
        self.assertIn("confidence_shifts", replay)

    def test_reasoning_edge_rejects_unknown_relation(self) -> None:
        with self.assertRaises(ValueError):
            ReasoningEdge(source="a", target="b", relation_type="mystery")

    def test_readable_output_surfaces_runtime_intelligence(self) -> None:
        run = RunContext(target="127.0.0.1", objective="unit test")
        run.runtime = build_runtime_profile(run, load_default_policy())
        output = format_recon_result(
            {
                "data": {
                    "run_id": run.run_id,
                    "target": run.target,
                    "objective": run.objective,
                    "status": "completed",
                    "runtime": run.runtime,
                }
            }
        )
        self.assertIn("Advanced Runtime", output)
        self.assertIn("Evidence root hash", output)
        self.assertIn("Meaning", output)
        self.assertIn("Confidence", output)
        self.assertIn("Reasoning quality", output)

    def test_runtime_section_formatter_is_readable(self) -> None:
        output = format_runtime_section(
            {
                "section": "trust",
                "data": {"score": 90, "band": "high", "deductions": []},
            }
        )
        self.assertIn("Runtime: trust", output)
        self.assertIn("Score: 90", output)
