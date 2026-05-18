from __future__ import annotations

from security_lab_assistant.models import JsonObject, ToolResult
from security_lab_assistant.policy import LabPolicy, PolicyError
from security_lab_assistant.storage import load_run
from security_lab_assistant.tools.base import refused
from security_lab_assistant.validation import require_run_id


RUNTIME_SECTIONS = {
    "explain": "explainability",
    "replay": "deterministic_replay",
    "graph": "attack_graph",
    "critique": "adversarial_critique",
    "memory": "memory",
    "cognition": "security_cognition",
    "hypotheses": "hypotheses",
    "contradictions": "contradictions",
    "investigation": "investigation_tree",
    "confidence": "confidence_calibration",
    "timeline": "reasoning_timeline",
    "redteam": "self_red_team",
    "boundaries": "trust_boundaries",
    "benchmark": "benchmark",
    "trust": "trust",
    "integrity": "evidence_integrity",
    "safety": "formal_safety_claims",
    "agents": "agent_roles",
    "approvals": "approval_gates",
    "quality": "reasoning_quality",
    "reasoning-graph": "formal_reasoning_graph",
    "benchmark-suite": "benchmark_suite",
    "visualizer": "explainability_visualizer",
    "probabilistic": "probabilistic_reasoning",
    "ai-safety": "ai_safety_research",
    "correlation": "cross_run_correlation",
    "trust-calibration": "dynamic_trust_calibration",
    "simulation": "security_simulation_universe",
    "diff": "reasoning_replay_diff",
}


def runtime_section(arguments: JsonObject, policy: LabPolicy) -> ToolResult:
    name = "runtime.section"
    try:
        run_id = require_run_id(arguments)
        section = str(arguments.get("section", "")).strip()
        if section not in RUNTIME_SECTIONS:
            raise PolicyError(f"section must be one of: {', '.join(sorted(RUNTIME_SECTIONS))}.")
        run = load_run(policy, run_id)
    except (PolicyError, FileNotFoundError) as exc:
        return refused(name, PolicyError(str(exc)))

    runtime = run.get("runtime", {})
    key = RUNTIME_SECTIONS[section]
    return ToolResult(
        name=name,
        ok=True,
        data={
            "run_id": run_id,
            "section": section,
            "runtime_key": key,
            "data": runtime.get(key, {}),
        },
    )
