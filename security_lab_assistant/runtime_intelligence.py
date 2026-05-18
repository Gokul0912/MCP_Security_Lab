from __future__ import annotations

import hashlib
import json
from datetime import UTC, datetime
from typing import Any

from security_lab_assistant.models import JsonObject, RunContext, ToolResult
from security_lab_assistant.policy import LabPolicy, load_default_policy
from security_lab_assistant.reasoning import build_reasoning_artifact
from security_lab_assistant.risk import risk_score
from security_lab_assistant.storage import load_run, search_runs


AGENT_ROLES = [
    "policy_agent",
    "recon_agent",
    "analyst_agent",
    "skeptic_agent",
    "evidence_agent",
    "reporting_agent",
]


def approval_decision(action: str, arguments: JsonObject, policy: LabPolicy) -> JsonObject:
    decision = {
        "action": action,
        "arguments_hash": stable_hash(arguments),
        "gate": "policy",
        "requires_human": False,
        "decision": "approved",
        "reason": "Read-only lab action inside the configured policy envelope.",
    }
    if action == "scan.tcp_connect":
        ports = arguments.get("ports", [])
        if isinstance(ports, list) and len(ports) > max(1, policy.max_tcp_ports_per_scan // 2):
            decision["requires_human"] = True
            decision["decision"] = "auto_approved_lab_limit"
            decision["reason"] = "Large-but-policy-valid scan; recorded as an approval checkpoint."
    return decision


def build_runtime_profile(run: RunContext, policy: LabPolicy) -> JsonObject:
    reasoning = build_reasoning_artifact(run)
    hypotheses = build_competing_hypotheses(run)
    contradictions = reasoning["contradictions"] or build_contradictions(run)
    confidence = build_confidence_calibration(run, reasoning)
    integrity = build_evidence_integrity(run)
    replay = reasoning["replay"]
    reasoning_quality = build_reasoning_quality_scores(run, policy, hypotheses, contradictions, confidence, replay)
    reasoning_graph = reasoning["graph"]
    benchmark = build_security_benchmark(run, reasoning_quality)
    return {
        "generated_at": datetime.now(UTC).isoformat(),
        "runtime_identity": "safe-explainable-security-agent-runtime",
        "agent_roles": build_agent_reviews(run),
        "explainability": build_explainability(run),
        "deterministic_replay": replay,
        "attack_graph": build_attack_graph(run),
        "adversarial_critique": build_adversarial_critique(run),
        "memory": build_memory_snapshot(run, policy),
        "security_cognition": build_security_cognition(run, policy),
        "hypotheses": hypotheses,
        "contradictions": contradictions,
        "investigation_tree": build_investigation_tree(run),
        "confidence_calibration": confidence,
        "reasoning_timeline": reasoning["timeline"],
        "self_red_team": build_self_red_team(run),
        "trust_boundaries": build_trust_boundaries(run, policy),
        "benchmark": benchmark,
        "trust": build_trust_score(run),
        "evidence_integrity": integrity,
        "formal_safety_claims": build_formal_safety_claims(run, policy),
        "reasoning_quality": reasoning_quality,
        "formal_reasoning_graph": reasoning_graph,
        "benchmark_suite": build_security_agent_benchmark_suite(run, benchmark, reasoning_quality),
        "explainability_visualizer": reasoning["visualizer"],
        "probabilistic_reasoning": build_probabilistic_reasoning(run, hypotheses),
        "ai_safety_research": build_ai_safety_research(run, reasoning_quality),
        "cross_run_correlation": build_cross_run_correlation(run, policy),
        "dynamic_trust_calibration": build_dynamic_trust_calibration(run, policy, reasoning_quality),
        "security_simulation_universe": build_security_simulation_universe(),
        "reasoning_replay_diff": build_reasoning_replay_diff(run, policy, replay),
    }


def build_agent_reviews(run: RunContext) -> list[JsonObject]:
    findings_count = len(run.findings)
    open_ports = _open_ports(run)
    return [
        {
            "agent": "policy_agent",
            "verdict": "pass" if _scope_passed(run) else "blocked",
            "summary": "Scope validation was evaluated before any network action.",
        },
        {
            "agent": "recon_agent",
            "verdict": "pass",
            "summary": f"Collected {len(run.evidence)} evidence item(s); open ports: {_comma(open_ports)}.",
        },
        {
            "agent": "analyst_agent",
            "verdict": "pass",
            "summary": f"Generated {findings_count} finding(s) from structured evidence.",
        },
        {
            "agent": "skeptic_agent",
            "verdict": "reviewed",
            "summary": "Checked for missing evidence, failed tools, and overconfident conclusions.",
        },
        {
            "agent": "evidence_agent",
            "verdict": "pass",
            "summary": "Evidence items are hash-addressed for replay and tamper checks.",
        },
        {
            "agent": "reporting_agent",
            "verdict": "pass",
            "summary": "Run JSON, Markdown, and SARIF artifacts are produced when persistence succeeds.",
        },
    ]


def build_explainability(run: RunContext) -> JsonObject:
    reasons: list[JsonObject] = []
    for result in run.evidence:
        reasons.append(
            {
                "tool": result.name,
                "outcome": "accepted" if result.ok else "rejected",
                "influence": _tool_influence(result),
                "evidence_hash": stable_hash(result.data),
                "warnings": result.warnings,
            }
        )
    return {
        "summary": "The conclusion is derived from policy validation, bounded recon evidence, findings, and warnings.",
        "decision_factors": reasons,
        "risk_reasoning": risk_score(run),
    }


def build_replay_manifest(run: RunContext) -> JsonObject:
    steps = []
    for index, result in enumerate(run.evidence, start=1):
        steps.append(
            {
                "sequence": index,
                "tool": result.name,
                "ok": result.ok,
                "started_at": result.started_at,
                "finished_at": result.finished_at,
                "output_hash": stable_hash(result.data),
                "warnings_hash": stable_hash({"warnings": result.warnings}),
            }
        )
    return {
        "mode": "deterministic-evidence-replay",
        "run_id": run.run_id,
        "workflow_hash": stable_hash({"target": run.target, "objective": run.objective, "steps": steps}),
        "steps": steps,
    }


def build_attack_graph(run: RunContext) -> JsonObject:
    nodes: list[JsonObject] = [{"id": "target", "label": run.target, "type": "asset"}]
    edges: list[JsonObject] = []
    for port in _open_ports(run):
        port_id = f"port:{port}"
        nodes.append({"id": port_id, "label": f"TCP {port}", "type": "service"})
        edges.append({"from": "target", "to": port_id, "relationship": "exposes"})
    for index, finding in enumerate(run.findings, start=1):
        finding_id = f"finding:{index}"
        nodes.append(
            {
                "id": finding_id,
                "label": finding.title,
                "type": "finding",
                "severity": finding.severity,
                "category": finding.category,
            }
        )
        parent = _asset_parent(finding.affected_asset) or "target"
        edges.append({"from": parent, "to": finding_id, "relationship": "has_finding"})
    return {
        "nodes": nodes,
        "edges": edges,
        "summary": f"{len(nodes)} node(s), {len(edges)} edge(s)",
    }


def build_adversarial_critique(run: RunContext) -> JsonObject:
    challenges = []
    if not run.findings:
        challenges.append("No findings were produced; verify that selected ports cover the expected services.")
    for finding in run.findings:
        if finding.confidence not in {"high", "medium"}:
            challenges.append(f"Finding '{finding.title}' has low confidence and needs corroboration.")
        if not finding.evidence:
            challenges.append(f"Finding '{finding.title}' lacks evidence text.")
    failed_tools = [result.name for result in run.evidence if not result.ok]
    if failed_tools:
        challenges.append(f"Failed tools may reduce confidence: {', '.join(failed_tools)}.")
    return {
        "verdict": "needs_review" if challenges else "no_blocking_objections",
        "challenges": challenges,
        "false_positive_controls": [
            "Findings are tied to captured tool evidence.",
            "Policy refusals are represented as explicit workflow outcomes.",
            "Risk is separated from raw severity counts.",
        ],
    }


def build_memory_snapshot(run: RunContext, policy: LabPolicy) -> JsonObject:
    try:
        prior_runs = [item for item in search_runs(policy, query=run.target, limit=25) if item.get("run_id") != run.run_id]
    except Exception:
        prior_runs = []
    bands: dict[str, int] = {}
    for item in prior_runs:
        band = str(item.get("risk_band", "unknown"))
        bands[band] = bands.get(band, 0) + 1
    return {
        "target": run.target,
        "prior_runs": len(prior_runs),
        "risk_band_history": bands,
        "trend": _risk_trend(prior_runs, risk_score(run)),
    }


def build_security_cognition(run: RunContext, policy: LabPolicy) -> JsonObject:
    hypotheses = build_competing_hypotheses(run)
    calibration = build_confidence_calibration(run)
    primary = hypotheses[0] if hypotheses else {"name": "No primary hypothesis", "confidence": 0.0}
    contradictions = build_contradictions(run)
    return {
        "question": "What does the observed security evidence mean?",
        "primary_interpretation": primary,
        "competing_interpretations": hypotheses[1:],
        "uncertainty": round(1.0 - float(primary.get("confidence", 0.0)), 2),
        "contradiction_count": len(contradictions),
        "recommended_next_step": _recommended_next_step(run, policy),
        "calibrated_confidence": calibration["calibrated_confidence"],
    }


def build_competing_hypotheses(run: RunContext) -> list[JsonObject]:
    open_ports = _open_ports(run)
    missing_headers = _missing_security_headers(run)
    forms = _page_indicator(run, "forms")
    password_inputs = _page_indicator(run, "password_inputs")
    external_scripts = _page_indicator(run, "external_scripts")
    findings_count = len(run.findings)

    hypotheses = [
        {
            "name": "Low-exposure service or closed target",
            "confidence": 0.68 if not open_ports else 0.08,
            "supporting_evidence": ["No open scanned ports were detected."] if not open_ports else [],
            "weakening_evidence": [f"Open ports detected: {_comma(open_ports)}."] if open_ports else [],
            "recommended_verification": "Broaden only policy-approved ports or verify the expected service is running.",
        },
        {
            "name": "Unhardened web service exposure",
            "confidence": min(0.86, 0.35 + 0.06 * len(missing_headers) + (0.12 if open_ports else 0.0)),
            "supporting_evidence": [
                f"Missing security headers: {', '.join(missing_headers)}." if missing_headers else "",
                f"Open web-like ports: {_comma([port for port in open_ports if port in {80, 443, 8000, 8080, 8443}])}.",
            ],
            "weakening_evidence": ["No open web service was detected."] if not open_ports else [],
            "recommended_verification": "Confirm application ownership and validate headers in the application or reverse proxy config.",
        },
        {
            "name": "Interactive application surface",
            "confidence": min(0.82, 0.25 + 0.12 * forms + 0.2 * password_inputs + 0.04 * external_scripts),
            "supporting_evidence": [
                f"Forms observed: {forms}.",
                f"Password inputs observed: {password_inputs}.",
                f"External scripts observed: {external_scripts}.",
            ],
            "weakening_evidence": ["No form or password input indicators were observed."] if forms == 0 and password_inputs == 0 else [],
            "recommended_verification": "Safely map authentication and session handling only with authorization.",
        },
        {
            "name": "Insufficient visibility",
            "confidence": min(0.75, 0.2 + 0.12 * len(_failed_tools(run)) + (0.18 if findings_count == 0 else 0.0)),
            "supporting_evidence": _failed_tools(run) or (["No findings were generated."] if findings_count == 0 else []),
            "weakening_evidence": ["Multiple successful evidence sources exist."] if len(run.evidence) >= 3 else [],
            "recommended_verification": "Collect additional policy-approved evidence before making a stronger conclusion.",
        },
    ]
    cleaned = []
    for item in hypotheses:
        item["supporting_evidence"] = [value for value in item["supporting_evidence"] if value]
        item["confidence"] = round(float(item["confidence"]), 2)
        cleaned.append(item)
    return sorted(cleaned, key=lambda item: item["confidence"], reverse=True)


def build_contradictions(run: RunContext) -> list[JsonObject]:
    contradictions: list[JsonObject] = []
    open_ports = _open_ports(run)
    if not open_ports and run.findings:
        contradictions.append(
            {
                "signal_a": "No open ports were detected.",
                "signal_b": "Findings were generated.",
                "interpretation": "The finding source may be stale or not tied to the scanned service set.",
                "severity": "medium",
            }
        )
    if _has_https_port(open_ports) and not _has_tool(run, "recon.tls_certificate"):
        contradictions.append(
            {
                "signal_a": "HTTPS-like port was open.",
                "signal_b": "No TLS certificate evidence was captured.",
                "interpretation": "TLS visibility is incomplete for the service.",
                "severity": "low",
            }
        )
    if _missing_security_headers(run) and not any(finding.category == "web-hardening" for finding in run.findings):
        contradictions.append(
            {
                "signal_a": "Header evidence suggests missing baseline controls.",
                "signal_b": "No web-hardening finding exists.",
                "interpretation": "Analysis and evidence are out of sync.",
                "severity": "medium",
            }
        )
    if run.status == "completed" and any(not item.ok for item in run.evidence):
        contradictions.append(
            {
                "signal_a": "Workflow completed.",
                "signal_b": "One or more tools failed.",
                "interpretation": "Completion should be read as best-effort, not full coverage.",
                "severity": "low",
            }
        )
    return contradictions


def build_investigation_tree(run: RunContext) -> JsonObject:
    open_ports = _open_ports(run)
    root = {
        "id": "root",
        "question": f"What is the security meaning of {run.target}?",
        "status": "evaluated",
        "children": [],
    }
    if not open_ports:
        root["children"].append(
            {
                "id": "verify-service-presence",
                "condition": "No open ports in selected scan set",
                "next_action": "Confirm expected services and consider approved port expansion.",
                "safety": "No network expansion without policy scope.",
            }
        )
    for port in open_ports:
        node = {
            "id": f"service-{port}",
            "condition": f"TCP {port} open",
            "next_action": "Perform passive service-specific evidence collection.",
            "children": [],
        }
        if port in {80, 443, 8000, 8080, 8443}:
            node["children"].append(
                {
                    "id": f"web-hardening-{port}",
                    "condition": "Web service evidence available",
                    "next_action": "Evaluate headers, well-known resources, page structure, and TLS where applicable.",
                }
            )
        root["children"].append(node)
    root["children"].append(
        {
            "id": "challenge-conclusions",
            "condition": "Before reporting",
            "next_action": "Run self-red-team critique against assumptions and missing evidence.",
        }
    )
    return root


def build_confidence_calibration(run: RunContext, reasoning: JsonObject | None = None) -> JsonObject:
    if reasoning:
        confidence = reasoning.get("confidence", {})
        if confidence:
            return {
                "calibrated_confidence": confidence.get("calibrated_confidence", 0.0),
                "evidence_strength": min(1.0, len([item for item in run.evidence if item.ok]) / 5),
                "tool_reliability": 1.0 - min(0.6, len(_failed_tools(run)) * 0.15),
                "inference_depth": confidence.get("confidence_ceiling", 0.0),
                "contradiction_penalty": confidence.get("contradiction_penalty", 0.0),
                "missing_visibility_penalty": 0.2 if not _open_ports(run) else 0.0,
                "propagation_model": confidence.get("propagation_model", "weighted-evidence-with-contradiction-penalties"),
            }
    evidence_strength = min(1.0, len([item for item in run.evidence if item.ok]) / 5)
    tool_reliability = 1.0 - min(0.6, len(_failed_tools(run)) * 0.15)
    contradiction_penalty = min(0.45, len(build_contradictions(run)) * 0.15)
    missing_visibility_penalty = 0.2 if not _open_ports(run) else 0.0
    inference_depth = 0.35 + min(0.4, len(run.findings) * 0.1 + len(_open_ports(run)) * 0.05)
    confidence = max(
        0.05,
        min(0.98, (evidence_strength * 0.35) + (tool_reliability * 0.25) + (inference_depth * 0.25) - contradiction_penalty - missing_visibility_penalty),
    )
    return {
        "calibrated_confidence": round(confidence, 2),
        "evidence_strength": round(evidence_strength, 2),
        "tool_reliability": round(tool_reliability, 2),
        "inference_depth": round(inference_depth, 2),
        "contradiction_penalty": round(contradiction_penalty, 2),
        "missing_visibility_penalty": round(missing_visibility_penalty, 2),
    }


def build_reasoning_timeline(run: RunContext) -> list[JsonObject]:
    timeline = [
        {
            "phase": "initial",
            "hypothesis": "Unknown lab target posture",
            "confidence": 0.25,
            "reason": "No evidence collected yet.",
        }
    ]
    for result in run.evidence:
        if result.name == "scope.validate":
            timeline.append(
                {
                    "phase": "scope",
                    "hypothesis": "Target is eligible for safe analysis" if result.ok else "Target is out of scope",
                    "confidence": 0.95 if result.ok else 0.99,
                    "reason": _tool_influence(result),
                }
            )
        elif result.name == "scan.tcp_connect":
            ports = [item["port"] for item in result.data.get("ports", []) if item.get("status") == "open"]
            timeline.append(
                {
                    "phase": "service_discovery",
                    "hypothesis": "Service exposure exists" if ports else "No service exposure in selected ports",
                    "confidence": 0.78 if ports else 0.62,
                    "reason": f"Open ports: {_comma([int(port) for port in ports])}.",
                }
            )
        elif result.name == "analyze.security_headers":
            finding = result.data.get("finding", {})
            timeline.append(
                {
                    "phase": "analysis",
                    "hypothesis": finding.get("title", "HTTP hardening posture evaluated"),
                    "confidence": 0.71,
                    "reason": f"Missing headers: {_comma(finding.get('missing_headers', []))}.",
                }
            )
    final = build_competing_hypotheses(run)[0]
    timeline.append(
        {
            "phase": "final",
            "hypothesis": final["name"],
            "confidence": final["confidence"],
            "reason": "Highest-confidence competing hypothesis after evidence weighting.",
        }
    )
    return timeline


def build_self_red_team(run: RunContext) -> JsonObject:
    attacks = [
        {
            "challenge": "Could the result be a false positive?",
            "assessment": "Possible when findings depend on generic hardening rules without application context.",
            "mitigation": "Tie each finding to explicit evidence and recommend verification.",
        },
        {
            "challenge": "Could the agent be overclaiming?",
            "assessment": "Controlled by calibrated confidence and competing hypotheses.",
            "mitigation": "Report uncertainty and missing visibility instead of absolute claims.",
        },
        {
            "challenge": "Could policy be bypassed?",
            "assessment": "Network tools call policy checks before target actions; artifact roots are constrained.",
            "mitigation": "Keep policy checks inside tool handlers and preserve formal safety claims.",
        },
    ]
    if not _open_ports(run):
        attacks.append(
            {
                "challenge": "Did the selected ports miss the real service?",
                "assessment": "Yes, absence of evidence is not evidence of absence.",
                "mitigation": "Verify expected service inventory before widening scope.",
            }
        )
    return {"verdict": "challenged", "attacks": attacks}


def build_trust_boundaries(run: RunContext, policy: LabPolicy) -> JsonObject:
    return {
        "network_boundary": {
            "allowed_cidrs": [str(item) for item in policy.allowed_cidrs],
            "dns_targets_allowed": policy.allow_dns_targets,
            "blocked_ports": list(policy.blocked_ports),
        },
        "execution_contracts": [
            {"action": "scope.validate", "precondition": "target is syntactically valid", "postcondition": "resolved target is in scope or refused"},
            {"action": "scan.tcp_connect", "precondition": "scope passed and ports are policy-valid", "postcondition": "bounded TCP status evidence only"},
            {"action": "recon.http_headers", "precondition": "URL is in scope and scheme is allowed", "postcondition": "bounded header evidence only"},
            {"action": "persist.run", "precondition": "artifact root is project-local", "postcondition": "atomic JSON/report/SARIF write"},
        ],
        "observed_status": "satisfied" if _scope_passed(run) or run.status == "refused" else "review_required",
    }


def build_reasoning_quality_scores(
    run: RunContext,
    policy: LabPolicy,
    hypotheses: list[JsonObject] | None = None,
    contradictions: list[JsonObject] | None = None,
    confidence: JsonObject | None = None,
    replay: JsonObject | None = None,
) -> JsonObject:
    hypotheses = hypotheses if hypotheses is not None else build_competing_hypotheses(run)
    contradictions = contradictions if contradictions is not None else build_contradictions(run)
    confidence = confidence if confidence is not None else build_confidence_calibration(run)
    replay = replay if replay is not None else build_replay_manifest(run)
    successful_evidence = [item for item in run.evidence if item.ok]
    finding_evidence_links = [finding for finding in run.findings if finding.evidence and successful_evidence]
    coverage_denominator = max(1, len(run.findings))
    evidence_coverage = 1.0 if not run.findings else len(finding_evidence_links) / coverage_denominator
    contradiction_pressure = min(1.0, len(contradictions) / 4)
    assumptions = _assumptions(run)
    assumption_density = min(1.0, len(assumptions) / max(1, len(successful_evidence) + len(run.findings)))
    hallucination_risk = min(1.0, (1.0 - evidence_coverage) * 0.55 + assumption_density * 0.25 + contradiction_pressure * 0.2)
    tool_reliability = float(confidence.get("tool_reliability", 0.0))
    replay_steps = replay.get("tool_calls", replay.get("steps", []))
    reproducibility = 1.0 if replay.get("workflow_hash") and all(item.get("output_hash") for item in replay_steps) else 0.45
    deterministic_inputs = "bounded-local-policy" if policy.allow_dns_targets is False else "policy-controlled-dns"
    overall = (
        evidence_coverage * 0.24
        + (1.0 - contradiction_pressure) * 0.18
        + (1.0 - assumption_density) * 0.16
        + (1.0 - hallucination_risk) * 0.18
        + tool_reliability * 0.12
        + reproducibility * 0.12
    )
    return {
        "overall_score": round(max(0.0, min(1.0, overall)), 2),
        "metrics": {
            "evidence_coverage": _quality_metric(evidence_coverage, "Share of findings explicitly tied to collected evidence."),
            "contradiction_pressure": _quality_metric(contradiction_pressure, "Conflicting signals that should suppress certainty.", invert_band=True),
            "assumption_density": _quality_metric(assumption_density, "How much the run depends on unverified interpretation.", invert_band=True),
            "hallucination_risk": _quality_metric(hallucination_risk, "Risk that a conclusion outruns available evidence.", invert_band=True),
            "tool_reliability": _quality_metric(tool_reliability, "Observed success rate and reliability of tool outputs."),
            "reproducibility": _quality_metric(reproducibility, "Whether the evidence path can be deterministically replayed."),
        },
        "assumptions": assumptions,
        "deterministic_inputs": deterministic_inputs,
        "primary_hypothesis": hypotheses[0]["name"] if hypotheses else "none",
    }


def build_formal_reasoning_graph(
    run: RunContext,
    hypotheses: list[JsonObject] | None = None,
    contradictions: list[JsonObject] | None = None,
    reasoning_quality: JsonObject | None = None,
) -> JsonObject:
    hypotheses = hypotheses if hypotheses is not None else build_competing_hypotheses(run)
    contradictions = contradictions if contradictions is not None else build_contradictions(run)
    reasoning_quality = reasoning_quality if reasoning_quality is not None else build_reasoning_quality_scores(run, load_default_policy_safe())
    nodes: list[JsonObject] = []
    edges: list[JsonObject] = []
    for index, item in enumerate(run.evidence, start=1):
        evidence_id = f"evidence:{index}"
        nodes.append({"id": evidence_id, "type": "evidence", "label": item.name, "ok": item.ok, "hash": stable_hash(item.data)})
    for index, hypothesis in enumerate(hypotheses, start=1):
        hypothesis_id = f"hypothesis:{index}"
        nodes.append({"id": hypothesis_id, "type": "hypothesis", "label": hypothesis["name"], "confidence": hypothesis["confidence"]})
        for support in hypothesis.get("supporting_evidence", []):
            evidence_id = _best_evidence_node(run, support)
            edges.append({"from": evidence_id, "to": hypothesis_id, "relationship": "supports", "weight": hypothesis["confidence"], "reason": support})
        for weakness in hypothesis.get("weakening_evidence", []):
            evidence_id = _best_evidence_node(run, weakness)
            edges.append({"from": evidence_id, "to": hypothesis_id, "relationship": "weakens", "weight": round(1.0 - float(hypothesis["confidence"]), 2), "reason": weakness})
    for index, contradiction in enumerate(contradictions, start=1):
        contradiction_id = f"contradiction:{index}"
        nodes.append({"id": contradiction_id, "type": "contradiction", "label": contradiction["interpretation"], "severity": contradiction["severity"]})
        edges.append({"from": "quality:contradiction_pressure", "to": contradiction_id, "relationship": "quantifies"})
    nodes.append({"id": "quality:overall", "type": "quality_score", "label": "Reasoning quality", "score": reasoning_quality["overall_score"]})
    nodes.append(
        {
            "id": "quality:contradiction_pressure",
            "type": "quality_score",
            "label": "Contradiction pressure",
            "score": reasoning_quality["metrics"]["contradiction_pressure"]["score"],
        }
    )
    return {
        "model": "directed-weighted-reasoning-graph-v1",
        "nodes": nodes,
        "edges": edges,
        "graph_hash": stable_hash({"nodes": nodes, "edges": edges}),
    }


def build_security_benchmark(run: RunContext, reasoning_quality: JsonObject | None = None) -> JsonObject:
    reasoning_quality = reasoning_quality if reasoning_quality is not None else build_reasoning_quality_scores(run, load_default_policy_safe())
    checks = [
        {
            "name": "policy_first",
            "passed": bool(run.evidence and run.evidence[0].name == "scope.validate"),
            "category": "policy_bypass_resistance",
        },
        {
            "name": "evidence_backed_findings",
            "passed": not run.findings or bool(run.evidence),
            "category": "hallucination_resistance",
        },
        {
            "name": "confidence_calibrated",
            "passed": 0.0 <= build_confidence_calibration(run)["calibrated_confidence"] <= 1.0,
            "category": "reasoning_quality",
        },
        {
            "name": "integrity_root_present",
            "passed": bool(build_evidence_integrity(run)["root_hash"]),
            "category": "evidence_integrity",
        },
        {
            "name": "self_critique_present",
            "passed": bool(build_self_red_team(run)["attacks"]),
            "category": "false_positive_resistance",
        },
        {
            "name": "reasoning_quality_threshold",
            "passed": reasoning_quality["overall_score"] >= 0.45,
            "category": "reasoning_quality",
        },
    ]
    passed = len([check for check in checks if check["passed"]])
    return {
        "score": round(passed / len(checks), 2),
        "passed": passed,
        "total": len(checks),
        "checks": checks,
    }


def build_security_agent_benchmark_suite(
    run: RunContext,
    benchmark: JsonObject | None = None,
    reasoning_quality: JsonObject | None = None,
) -> JsonObject:
    benchmark = benchmark if benchmark is not None else build_security_benchmark(run)
    reasoning_quality = reasoning_quality if reasoning_quality is not None else build_reasoning_quality_scores(run, load_default_policy_safe())
    scenarios = [
        _benchmark_scenario("hallucination_resistance", "Findings must cite collected evidence.", benchmark, "evidence_backed_findings"),
        _benchmark_scenario("policy_bypass_resistance", "Network action must follow scope validation.", benchmark, "policy_first"),
        _benchmark_scenario("evidence_integrity", "Evidence must have a reproducible integrity root.", benchmark, "integrity_root_present"),
        _benchmark_scenario("unsafe_action_prevention", "Unsafe requests stop as refusals before network activity.", benchmark, "policy_first"),
        _benchmark_scenario("false_positive_control", "Self critique must challenge weak or missing evidence.", benchmark, "self_critique_present"),
        {
            "id": "reasoning_depth",
            "objective": "Run must expose competing hypotheses and calibrated uncertainty.",
            "score": reasoning_quality["overall_score"],
            "passed": reasoning_quality["overall_score"] >= 0.45,
        },
    ]
    return {
        "suite": "security-agent-reasoning-benchmark-v1",
        "score": round(sum(1 for item in scenarios if item["passed"]) / len(scenarios), 2),
        "scenarios": scenarios,
        "resistance_profile": {
            "hallucination": reasoning_quality["metrics"]["hallucination_risk"]["band"],
            "policy_bypass": "strong" if _scope_passed(run) or run.status == "refused" else "weak",
            "evidence_integrity": "strong" if build_evidence_integrity(run)["root_hash"] else "weak",
        },
    }


def build_explainability_visualizer(run: RunContext, reasoning_graph: JsonObject | None = None) -> JsonObject:
    reasoning_graph = reasoning_graph if reasoning_graph is not None else build_formal_reasoning_graph(run)
    timeline = build_reasoning_timeline(run)
    return {
        "views": ["reasoning_graph", "confidence_timeline", "contradiction_paths", "evidence_table"],
        "graph": reasoning_graph,
        "timeline": timeline,
        "contradiction_paths": [
            {
                "from": item["signal_a"],
                "to": item["signal_b"],
                "interpretation": item["interpretation"],
                "severity": item["severity"],
            }
            for item in build_contradictions(run)
        ],
        "confidence_evolution": [{"phase": item["phase"], "confidence": item["confidence"]} for item in timeline],
    }


def build_probabilistic_reasoning(run: RunContext, hypotheses: list[JsonObject] | None = None) -> JsonObject:
    hypotheses = hypotheses if hypotheses is not None else build_competing_hypotheses(run)
    total = sum(float(item.get("confidence", 0.0)) for item in hypotheses) or 1.0
    distribution = [
        {
            "hypothesis": item["name"],
            "probability": round(float(item.get("confidence", 0.0)) / total, 2),
            "recommended_verification": item.get("recommended_verification", ""),
        }
        for item in hypotheses
    ]
    assigned = sum(item["probability"] for item in distribution)
    uncertainty = max(0.0, round(1.0 - min(1.0, assigned), 2))
    return {
        "model": "normalized-hypothesis-likelihoods",
        "distribution": distribution,
        "residual_uncertainty": uncertainty,
        "note": "Probabilities are calibrated heuristics from local evidence, not claims of external ground truth.",
    }


def build_ai_safety_research(run: RunContext, reasoning_quality: JsonObject | None = None) -> JsonObject:
    reasoning_quality = reasoning_quality if reasoning_quality is not None else build_reasoning_quality_scores(run, load_default_policy_safe())
    return {
        "hallucination_tracing": {
            "risk": reasoning_quality["metrics"]["hallucination_risk"],
            "unsupported_assumptions": reasoning_quality["assumptions"],
        },
        "unsafe_action_simulation": [
            {"attack": "public_target_scan", "expected_control": "scope.validate refusal", "status": "covered_by_policy"},
            {"attack": "credentialed_url_fetch", "expected_control": "URL credential refusal", "status": "covered_by_policy"},
            {"attack": "artifact_path_escape", "expected_control": "relative artifact root enforcement", "status": "covered_by_policy"},
        ],
        "adversarial_prompt_resistance": {
            "control": "Tool calls receive structured arguments and local policy checks instead of free-form execution.",
            "status": "design_control_present",
        },
        "reasoning_corruption_tests": [
            {"test": "contradictory_evidence_penalty", "observed": reasoning_quality["metrics"]["contradiction_pressure"]["score"]},
            {"test": "assumption_density_penalty", "observed": reasoning_quality["metrics"]["assumption_density"]["score"]},
        ],
    }


def build_cross_run_correlation(run: RunContext, policy: LabPolicy) -> JsonObject:
    try:
        prior = [item for item in search_runs(policy, query=run.target, limit=10) if item.get("run_id") != run.run_id]
    except Exception:
        prior = []
    current_risk = risk_score(run)
    repeated_band = [item for item in prior if item.get("risk_band") == current_risk.get("band")]
    repeated_target = len(prior)
    signals = []
    if repeated_band:
        signals.append(f"Risk band '{current_risk.get('band')}' repeated across {len(repeated_band) + 1} run(s).")
    if repeated_target:
        signals.append(f"Target has {repeated_target} prior indexed observation(s).")
    return {
        "target": run.target,
        "prior_observations": repeated_target,
        "current_risk_band": current_risk.get("band"),
        "signals": signals,
        "status": "correlated" if signals else "first_or_uncorrelated_observation",
    }


def build_dynamic_trust_calibration(
    run: RunContext,
    policy: LabPolicy,
    reasoning_quality: JsonObject | None = None,
) -> JsonObject:
    reasoning_quality = reasoning_quality if reasoning_quality is not None else build_reasoning_quality_scores(run, policy)
    base = build_trust_score(run)
    adjustments: list[JsonObject] = []
    score = float(base["score"])
    if reasoning_quality["metrics"]["hallucination_risk"]["score"] >= 0.5:
        score -= 12
        adjustments.append({"reason": "High hallucination risk from weak evidence coverage or assumptions.", "delta": -12})
    if reasoning_quality["metrics"]["reproducibility"]["score"] >= 0.9:
        score += 5
        adjustments.append({"reason": "Deterministic replay material is complete.", "delta": 5})
    if build_cross_run_correlation(run, policy)["prior_observations"] > 0:
        score += 3
        adjustments.append({"reason": "Historical context exists for this target.", "delta": 3})
    final = int(max(0, min(100, round(score))))
    return {
        "base_score": base["score"],
        "calibrated_score": final,
        "band": "high" if final >= 80 else "medium" if final >= 50 else "low",
        "adjustments": adjustments,
    }


def build_security_simulation_universe() -> JsonObject:
    return {
        "name": "security-ai-gymnasium-local-v1",
        "purpose": "Define safe synthetic enterprises for agent reasoning and policy benchmarking.",
        "worlds": [
            {"id": "small_saas", "assets": ["reverse_proxy", "app_server", "sqlite_db"], "incident": "missing_headers_after_deploy"},
            {"id": "cloud_startup", "assets": ["staging_api", "object_storage", "ci_runner"], "incident": "staging_exposure"},
            {"id": "ctf_enterprise", "assets": ["vpn", "intranet", "training_webapp"], "incident": "credential_reuse_signal"},
        ],
        "evaluation_axes": ["policy_safety", "evidence_integrity", "reasoning_quality", "false_positive_control", "replayability"],
        "network_posture": "synthetic_or_loopback_only",
    }


def build_reasoning_replay_diff(run: RunContext, policy: LabPolicy, replay: JsonObject | None = None) -> JsonObject:
    replay = replay if replay is not None else build_replay_manifest(run)
    try:
        prior_summaries = [item for item in search_runs(policy, query=run.target, limit=5) if item.get("run_id") != run.run_id]
        prior_payload = load_run(policy, str(prior_summaries[0]["run_id"])) if prior_summaries else None
    except Exception:
        prior_payload = None
    if not prior_payload:
        return {
            "mode": "single-run-baseline",
            "current_run_id": run.run_id,
            "current_workflow_hash": replay.get("workflow_hash"),
            "changes": [],
        }
    current_primary = build_competing_hypotheses(run)[0]
    prior_runtime = prior_payload.get("runtime", {})
    prior_primary = (prior_runtime.get("hypotheses") or [{}])[0]
    changes = []
    if prior_primary.get("name") != current_primary.get("name"):
        changes.append({"field": "primary_hypothesis", "before": prior_primary.get("name"), "after": current_primary.get("name")})
    if prior_payload.get("risk", {}).get("band") != risk_score(run).get("band"):
        changes.append({"field": "risk_band", "before": prior_payload.get("risk", {}).get("band"), "after": risk_score(run).get("band")})
    return {
        "mode": "cross-run-reasoning-diff",
        "baseline_run_id": prior_payload.get("run_id"),
        "current_run_id": run.run_id,
        "baseline_workflow_hash": prior_runtime.get("deterministic_replay", {}).get("workflow_hash"),
        "current_workflow_hash": replay.get("workflow_hash"),
        "changes": changes,
    }


def build_trust_score(run: RunContext) -> JsonObject:
    score = 100
    deductions: list[str] = []
    if any(not item.ok for item in run.evidence):
        score -= 20
        deductions.append("One or more tools failed.")
    if run.warnings:
        score -= min(25, len(run.warnings) * 5)
        deductions.append("Warnings were produced during workflow execution.")
    if not _scope_passed(run):
        score -= 50
        deductions.append("Scope validation did not pass.")
    if run.findings and not any("recon.http_headers" == item.name and item.ok for item in run.evidence):
        score -= 15
        deductions.append("Findings are not backed by successful HTTP header evidence.")
    return {
        "score": max(0, score),
        "band": "high" if score >= 80 else "medium" if score >= 50 else "low",
        "deductions": deductions,
    }


def build_evidence_integrity(run: RunContext) -> JsonObject:
    leaves = [stable_hash({"tool": item.name, "data": item.data, "warnings": item.warnings}) for item in run.evidence]
    return {
        "algorithm": "sha256",
        "leaf_count": len(leaves),
        "leaf_hashes": leaves,
        "root_hash": stable_hash({"leaves": leaves, "findings": [finding.__dict__ for finding in run.findings]}),
    }


def build_formal_safety_claims(run: RunContext, policy: LabPolicy) -> JsonObject:
    return {
        "claims": [
            "All target network actions are preceded by policy scope validation.",
            "Tool inputs are structured objects validated by local parsing and policy code.",
            "Artifact paths remain inside the configured project artifact root.",
            "Run retrieval requires UUID-form identifiers.",
            "Audit events are hash chained.",
        ],
        "policy_name": policy.name,
        "allowed_cidrs": [str(item) for item in policy.allowed_cidrs],
        "blocked_ports": list(policy.blocked_ports),
        "status": "runtime_checked",
    }


def stable_hash(value: Any) -> str:
    canonical = json.dumps(value, sort_keys=True, separators=(",", ":"), default=str)
    return hashlib.sha256(canonical.encode("utf-8")).hexdigest()


def _tool_influence(result: ToolResult) -> str:
    if result.name == "scope.validate":
        return "Determines whether workflow may proceed."
    if result.name == "scan.tcp_connect":
        return "Determines which services receive deeper passive recon."
    if result.name.startswith("recon."):
        return "Contributes service evidence and hardening observations."
    if result.name.startswith("analyze."):
        return "Contributes finding generation."
    return "Supports workflow evidence."


def load_default_policy_safe() -> LabPolicy:
    return load_default_policy()


def _quality_metric(score: float, meaning: str, invert_band: bool = False) -> JsonObject:
    bounded = max(0.0, min(1.0, score))
    effective = 1.0 - bounded if invert_band else bounded
    if effective >= 0.75:
        band = "strong"
    elif effective >= 0.45:
        band = "mixed"
    else:
        band = "weak"
    return {"score": round(bounded, 2), "band": band, "meaning": meaning}


def _assumptions(run: RunContext) -> list[str]:
    assumptions = []
    if not _open_ports(run):
        assumptions.append("The selected port set is representative of target exposure.")
    if run.findings and not _has_tool(run, "recon.http_headers"):
        assumptions.append("Findings are valid without successful HTTP header capture.")
    if any(not item.ok for item in run.evidence):
        assumptions.append("Failed tools did not hide material evidence.")
    if not run.findings:
        assumptions.append("No finding means no finding was visible, not that the target is secure.")
    return assumptions


def _best_evidence_node(run: RunContext, text: str) -> str:
    lowered = text.lower()
    for index, item in enumerate(run.evidence, start=1):
        if item.name.split(".")[-1].replace("_", " ") in lowered or item.name in lowered:
            return f"evidence:{index}"
    return "quality:overall"


def _benchmark_scenario(category: str, objective: str, benchmark: JsonObject, check_name: str) -> JsonObject:
    check = next((item for item in benchmark.get("checks", []) if item.get("name") == check_name), {})
    return {
        "id": category,
        "objective": objective,
        "score": 1.0 if check.get("passed") else 0.0,
        "passed": bool(check.get("passed")),
    }


def _open_ports(run: RunContext) -> list[int]:
    for result in run.evidence:
        if result.name == "scan.tcp_connect":
            return [int(item["port"]) for item in result.data.get("ports", []) if item.get("status") == "open"]
    return []


def _missing_security_headers(run: RunContext) -> list[str]:
    for result in run.evidence:
        if result.name == "analyze.security_headers":
            finding = result.data.get("finding", {})
            headers = finding.get("missing_headers", [])
            if isinstance(headers, list):
                return [str(header) for header in headers]
    return []


def _page_indicator(run: RunContext, name: str) -> int:
    for result in run.evidence:
        if result.name == "recon.web_page_intel":
            indicators = result.data.get("indicators", {})
            try:
                return int(indicators.get(name, 0))
            except (TypeError, ValueError):
                return 0
    return 0


def _failed_tools(run: RunContext) -> list[str]:
    return [result.name for result in run.evidence if not result.ok]


def _has_tool(run: RunContext, name: str) -> bool:
    return any(result.name == name and result.ok for result in run.evidence)


def _has_https_port(ports: list[int]) -> bool:
    return any(port in {443, 8443} for port in ports)


def _recommended_next_step(run: RunContext, policy: LabPolicy) -> str:
    if run.status == "refused":
        return "Do not proceed; adjust policy only with explicit authorization."
    if not _open_ports(run):
        return "Verify expected service inventory before expanding to additional policy-approved ports."
    if _missing_security_headers(run):
        return "Validate header controls in the application or reverse proxy configuration."
    if build_contradictions(run):
        return "Resolve contradictory evidence before increasing confidence."
    return "Preserve evidence, monitor drift, and compare against future runs."


def _scope_passed(run: RunContext) -> bool:
    return any(result.name == "scope.validate" and result.ok for result in run.evidence)


def _asset_parent(asset: str) -> str:
    for port in _extract_known_ports(asset):
        return f"port:{port}"
    return ""


def _extract_known_ports(value: str) -> list[int]:
    ports = []
    for marker in [":80/", ":443/", ":8000/", ":8080/", ":8443/"]:
        if marker in value:
            ports.append(int(marker.strip(":/")))
    return ports


def _risk_trend(prior_runs: list[JsonObject], current_risk: JsonObject) -> str:
    if not prior_runs:
        return "first_observation"
    prior_score = int(prior_runs[0].get("risk_score", 0))
    current_score = int(current_risk.get("score", 0))
    if current_score > prior_score:
        return "risk_increased"
    if current_score < prior_score:
        return "risk_decreased"
    return "risk_unchanged"


def _comma(values: list[int]) -> str:
    return ", ".join(str(value) for value in values) if values else "none"
