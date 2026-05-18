from __future__ import annotations

import hashlib
import html
import json
from dataclasses import asdict, dataclass, field
from datetime import UTC, datetime
from typing import Any

from security_lab_assistant.models import Finding, JsonObject, RunContext, ToolResult
from security_lab_assistant.product import RUNTIME_VERSION, SCHEMA_VERSIONS


RELATION_TYPES = {"supports", "contradicts", "weakens", "derived_from", "assumes"}


@dataclass(frozen=True)
class ReasoningNode:
    id: str
    type: str
    statement: str
    confidence: float
    timestamp: str
    source_tool: str = ""
    evidence_hash: str = ""
    metadata: JsonObject = field(default_factory=dict)


@dataclass(frozen=True)
class ReasoningEdge:
    source: str
    target: str
    relation_type: str
    weight: float = 1.0
    rationale: str = ""

    def __post_init__(self) -> None:
        if self.relation_type not in RELATION_TYPES:
            raise ValueError(f"Unsupported reasoning relation: {self.relation_type}")


@dataclass(frozen=True)
class ReasoningState:
    sequence: int
    phase: str
    confidence_before: float
    confidence_after: float
    delta: float
    reason: str
    active_node_ids: list[str] = field(default_factory=list)
    contradiction_ids: list[str] = field(default_factory=list)
    timestamp: str = field(default_factory=lambda: datetime.now(UTC).isoformat())


@dataclass(frozen=True)
class ReasoningGraph:
    nodes: list[ReasoningNode]
    edges: list[ReasoningEdge]
    states: list[ReasoningState]

    def to_dict(self) -> JsonObject:
        payload = {
            "model": "formal-security-reasoning-graph-v1",
            "schema_version": SCHEMA_VERSIONS["reasoning_graph"],
            "runtime_version": RUNTIME_VERSION,
            "policy_hash": "",
            "contract_hash": "",
            "timestamp": datetime.now(UTC).isoformat(),
            "signature": {},
            "nodes": [asdict(node) for node in self.nodes],
            "edges": [asdict(edge) for edge in self.edges],
            "states": [asdict(state) for state in self.states],
        }
        payload["graph_hash"] = stable_hash({"nodes": payload["nodes"], "edges": payload["edges"]})
        payload["state_hash"] = stable_hash(payload["states"])
        return payload


def build_reasoning_artifact(run: RunContext) -> JsonObject:
    graph = _build_graph(run)
    graph_payload = graph.to_dict()
    replay = _build_replay(run, graph_payload)
    return {
        "graph": graph_payload,
        "replay": replay,
        "timeline": _timeline_from_states(graph.states),
        "confidence": _confidence_summary(graph.states),
        "contradictions": _contradiction_payload(graph),
        "visualizer": build_visualizer_payload(graph_payload),
    }


def build_visualizer_payload(graph: JsonObject) -> JsonObject:
    return {
        "views": ["graph", "confidence_timeline", "contradictions", "replay_states"],
        "graph": graph,
        "confidence_evolution": [
            {
                "sequence": state["sequence"],
                "phase": state["phase"],
                "confidence": state["confidence_after"],
                "delta": state["delta"],
            }
            for state in graph.get("states", [])
        ],
        "contradiction_paths": [
            edge for edge in graph.get("edges", []) if edge.get("relation_type") == "contradicts"
        ],
    }


def render_reasoning_visualizer_html(graph: JsonObject) -> str:
    nodes = graph.get("nodes", [])
    edges = graph.get("edges", [])
    states = graph.get("states", [])
    node_rows = "\n".join(
        "<tr>"
        f"<td>{html.escape(str(node.get('id', '')))}</td>"
        f"<td>{html.escape(str(node.get('type', '')))}</td>"
        f"<td>{html.escape(str(node.get('statement', '')))}</td>"
        f"<td>{html.escape(str(node.get('confidence', '')))}</td>"
        "</tr>"
        for node in nodes
    )
    edge_rows = "\n".join(
        "<tr>"
        f"<td>{html.escape(str(edge.get('source', '')))}</td>"
        f"<td>{html.escape(str(edge.get('relation_type', '')))}</td>"
        f"<td>{html.escape(str(edge.get('target', '')))}</td>"
        f"<td>{html.escape(str(edge.get('weight', '')))}</td>"
        "</tr>"
        for edge in edges
    )
    state_items = "\n".join(
        "<li>"
        f"<strong>{html.escape(str(state.get('phase', '')))}</strong>: "
        f"{html.escape(str(state.get('confidence_before', '')))} -> "
        f"{html.escape(str(state.get('confidence_after', '')))} "
        f"({html.escape(str(state.get('reason', '')))})"
        "</li>"
        for state in states
    )
    return f"""<!doctype html>
<html lang="en">
<head>
  <meta charset="utf-8">
  <title>Security Reasoning Replay</title>
  <style>
    body {{ font-family: Segoe UI, Arial, sans-serif; margin: 24px; color: #17202a; }}
    table {{ border-collapse: collapse; width: 100%; margin: 16px 0 28px; }}
    th, td {{ border: 1px solid #ccd3db; padding: 8px; text-align: left; vertical-align: top; }}
    th {{ background: #eef3f8; }}
    code {{ background: #eef3f8; padding: 2px 4px; }}
  </style>
</head>
<body>
  <h1>Security Reasoning Replay</h1>
  <p>Graph hash: <code>{html.escape(str(graph.get("graph_hash", "")))}</code></p>
  <h2>Confidence Timeline</h2>
  <ol>{state_items}</ol>
  <h2>Nodes</h2>
  <table><thead><tr><th>ID</th><th>Type</th><th>Statement</th><th>Confidence</th></tr></thead><tbody>{node_rows}</tbody></table>
  <h2>Edges</h2>
  <table><thead><tr><th>Source</th><th>Relation</th><th>Target</th><th>Weight</th></tr></thead><tbody>{edge_rows}</tbody></table>
</body>
</html>
"""


def stable_hash(value: Any) -> str:
    canonical = json.dumps(value, sort_keys=True, separators=(",", ":"), default=str)
    return hashlib.sha256(canonical.encode("utf-8")).hexdigest()


def _build_graph(run: RunContext) -> ReasoningGraph:
    nodes: list[ReasoningNode] = []
    edges: list[ReasoningEdge] = []
    states: list[ReasoningState] = []
    current_confidence = 0.25
    states.append(
        ReasoningState(
            sequence=1,
            phase="initial",
            confidence_before=0.0,
            confidence_after=current_confidence,
            delta=current_confidence,
            reason="No evidence has been evaluated yet.",
        )
    )

    for index, result in enumerate(run.evidence, start=1):
        node = _evidence_node(index, result)
        nodes.append(node)
        before = current_confidence
        current_confidence = _bounded(current_confidence + _evidence_delta(result))
        states.append(
            ReasoningState(
                sequence=len(states) + 1,
                phase=f"tool:{result.name}",
                confidence_before=round(before, 2),
                confidence_after=round(current_confidence, 2),
                delta=round(current_confidence - before, 2),
                reason=_evidence_reason(result),
                active_node_ids=[node.id],
            )
        )

    finding_nodes = []
    for index, finding in enumerate(run.findings, start=1):
        node = _finding_node(index, finding, run)
        nodes.append(node)
        finding_nodes.append(node)
        source = _best_tool_node(run, finding)
        if source:
            edges.append(
                ReasoningEdge(
                    source=source,
                    target=node.id,
                    relation_type="derived_from",
                    weight=node.confidence,
                    rationale="Finding was derived from collected tool evidence.",
                )
            )

    hypothesis_nodes = _hypothesis_nodes(run, current_confidence)
    nodes.extend(hypothesis_nodes)
    for hypothesis in hypothesis_nodes:
        for finding_node in finding_nodes:
            edges.append(
                ReasoningEdge(
                    source=finding_node.id,
                    target=hypothesis.id,
                    relation_type="supports",
                    weight=min(finding_node.confidence, hypothesis.confidence),
                    rationale="Finding increases confidence in this interpretation.",
                )
            )
        if not finding_nodes:
            assumption_id = f"assumption:{hypothesis.id}"
            assumption = ReasoningNode(
                id=assumption_id,
                type="assumption",
                source_tool="",
                evidence_hash="",
                statement="No finding was visible in the selected evidence set.",
                confidence=0.35,
                timestamp=run.created_at,
            )
            nodes.append(assumption)
            edges.append(
                ReasoningEdge(
                    source=assumption.id,
                    target=hypothesis.id,
                    relation_type="assumes",
                    weight=0.35,
                    rationale="The hypothesis depends on bounded scan coverage.",
                )
            )

    contradiction_nodes = _contradiction_nodes(run)
    nodes.extend(contradiction_nodes)
    for contradiction in contradiction_nodes:
        target = hypothesis_nodes[0].id if hypothesis_nodes else "hypothesis:none"
        edges.append(
            ReasoningEdge(
                source=contradiction.id,
                target=target,
                relation_type="contradicts",
                weight=contradiction.confidence,
                rationale=str(contradiction.metadata.get("interpretation", "Contradictory evidence reduces confidence.")),
            )
        )
        before = current_confidence
        current_confidence = _bounded(current_confidence - 0.12 * contradiction.confidence)
        states.append(
            ReasoningState(
                sequence=len(states) + 1,
                phase="contradiction",
                confidence_before=round(before, 2),
                confidence_after=round(current_confidence, 2),
                delta=round(current_confidence - before, 2),
                reason=contradiction.statement,
                active_node_ids=[contradiction.id],
                contradiction_ids=[contradiction.id],
            )
        )

    for hypothesis in hypothesis_nodes:
        supported = [edge for edge in edges if edge.target == hypothesis.id and edge.relation_type == "supports"]
        contradicted = [edge for edge in edges if edge.target == hypothesis.id and edge.relation_type == "contradicts"]
        before = current_confidence
        current_confidence = _bounded(
            current_confidence
            + min(0.25, sum(edge.weight for edge in supported) * 0.08)
            - min(0.25, sum(edge.weight for edge in contradicted) * 0.12)
        )
        states.append(
            ReasoningState(
                sequence=len(states) + 1,
                phase=f"hypothesis:{hypothesis.id}",
                confidence_before=round(before, 2),
                confidence_after=round(current_confidence, 2),
                delta=round(current_confidence - before, 2),
                reason=f"Weighted propagation for '{hypothesis.statement}'.",
                active_node_ids=[hypothesis.id],
                contradiction_ids=[edge.source for edge in contradicted],
            )
        )

    return ReasoningGraph(nodes=nodes, edges=edges, states=states)


def _build_replay(run: RunContext, graph: JsonObject) -> JsonObject:
    tool_calls = [
        {
            "sequence": index,
            "tool": result.name,
            "ok": result.ok,
            "started_at": result.started_at,
            "finished_at": result.finished_at,
            "output_hash": stable_hash(result.data),
            "warnings_hash": stable_hash({"warnings": result.warnings}),
        }
        for index, result in enumerate(run.evidence, start=1)
    ]
    payload = {
        "mode": "deterministic-reasoning-replay",
        "schema_version": SCHEMA_VERSIONS["replay_state"],
        "runtime_version": RUNTIME_VERSION,
        "policy_hash": "",
        "contract_hash": "",
        "timestamp": datetime.now(UTC).isoformat(),
        "signature": {},
        "run_id": run.run_id,
        "tool_calls": tool_calls,
        "graph_hash": graph["graph_hash"],
        "state_hash": graph["state_hash"],
        "graph_states": graph["states"],
        "confidence_shifts": [
            {
                "sequence": state["sequence"],
                "phase": state["phase"],
                "before": state["confidence_before"],
                "after": state["confidence_after"],
                "delta": state["delta"],
            }
            for state in graph["states"]
        ],
        "contradictions": [
            node for node in graph["nodes"] if node.get("type") == "contradiction"
        ],
    }
    payload["workflow_hash"] = stable_hash({"target": run.target, "objective": run.objective, "tool_calls": tool_calls})
    payload["replay_hash"] = stable_hash(payload)
    return payload


def _timeline_from_states(states: list[ReasoningState]) -> list[JsonObject]:
    return [
        {
            "phase": state.phase,
            "hypothesis": state.reason,
            "confidence": state.confidence_after,
            "reason": state.reason,
            "delta": state.delta,
        }
        for state in states
    ]


def _confidence_summary(states: list[ReasoningState]) -> JsonObject:
    final = states[-1].confidence_after if states else 0.0
    penalties = [abs(state.delta) for state in states if state.delta < 0]
    return {
        "calibrated_confidence": round(final, 2),
        "confidence_floor": min((state.confidence_after for state in states), default=0.0),
        "confidence_ceiling": max((state.confidence_after for state in states), default=0.0),
        "contradiction_penalty": round(sum(penalties), 2),
        "propagation_model": "weighted-evidence-with-contradiction-penalties",
    }


def _contradiction_payload(graph: ReasoningGraph) -> list[JsonObject]:
    return [
        {
            "id": node.id,
            "signal_a": node.metadata.get("signal_a", ""),
            "signal_b": node.metadata.get("signal_b", ""),
            "interpretation": node.metadata.get("interpretation", node.statement),
            "severity": node.metadata.get("severity", "low"),
            "confidence_penalty": node.confidence,
        }
        for node in graph.nodes
        if node.type == "contradiction"
    ]


def _evidence_node(index: int, result: ToolResult) -> ReasoningNode:
    return ReasoningNode(
        id=f"evidence:{index}",
        type="evidence",
        source_tool=result.name,
        evidence_hash=stable_hash(result.data),
        statement=_evidence_statement(result),
        confidence=_tool_confidence(result),
        timestamp=result.finished_at,
        metadata={"ok": result.ok, "warnings": result.warnings},
    )


def _finding_node(index: int, finding: Finding, run: RunContext) -> ReasoningNode:
    return ReasoningNode(
        id=f"finding:{index}",
        type="finding",
        source_tool="analyze.security_headers" if finding.category == "web-hardening" else "",
        evidence_hash=stable_hash({"finding": finding.__dict__}),
        statement=finding.title,
        confidence=_finding_confidence(finding),
        timestamp=run.created_at,
        metadata={"severity": finding.severity, "category": finding.category, "asset": finding.affected_asset},
    )


def _hypothesis_nodes(run: RunContext, propagated_confidence: float) -> list[ReasoningNode]:
    open_ports = _open_ports(run)
    if run.findings:
        statement = "Observed evidence indicates a security-relevant exposure requiring verification."
    elif open_ports:
        statement = "Services are reachable, but no finding was visible in collected passive evidence."
    else:
        statement = "No exposure was visible in the selected bounded scan set."
    return [
        ReasoningNode(
            id="hypothesis:primary",
            type="hypothesis",
            statement=statement,
            confidence=round(propagated_confidence, 2),
            timestamp=datetime.now(UTC).isoformat(),
            metadata={"open_ports": open_ports, "finding_count": len(run.findings)},
        )
    ]


def _contradiction_nodes(run: RunContext) -> list[ReasoningNode]:
    contradictions: list[JsonObject] = []
    open_ports = _open_ports(run)
    if not open_ports and run.findings:
        contradictions.append(
            {
                "signal_a": "No open ports were detected.",
                "signal_b": "Findings were generated.",
                "interpretation": "The finding source may not be tied to the scanned service set.",
                "severity": "medium",
            }
        )
    if any(port in {443, 8443} for port in open_ports) and not _has_successful_tool(run, "recon.tls_certificate"):
        contradictions.append(
            {
                "signal_a": "HTTPS-like port was open.",
                "signal_b": "No TLS certificate evidence was captured.",
                "interpretation": "TLS visibility is incomplete for the service.",
                "severity": "low",
            }
        )
    if run.status == "completed" and any(not item.ok for item in run.evidence):
        contradictions.append(
            {
                "signal_a": "Workflow completed.",
                "signal_b": "One or more tools failed.",
                "interpretation": "Completion should be interpreted as best-effort coverage.",
                "severity": "low",
            }
        )
    return [
        ReasoningNode(
            id=f"contradiction:{index}",
            type="contradiction",
            statement=f"{item['signal_a']} BUT {item['signal_b']}",
            confidence=_severity_weight(str(item["severity"])),
            timestamp=datetime.now(UTC).isoformat(),
            metadata=item,
        )
        for index, item in enumerate(contradictions, start=1)
    ]


def _evidence_delta(result: ToolResult) -> float:
    if not result.ok:
        return -0.1
    if result.name == "scope.validate":
        return 0.1
    if result.name == "scan.tcp_connect":
        return 0.12 if _scan_has_open_port(result) else 0.04
    if result.name.startswith("recon."):
        return 0.08
    if result.name.startswith("analyze."):
        return 0.1
    return 0.04


def _evidence_reason(result: ToolResult) -> str:
    if result.ok:
        return f"{result.name} added structured evidence."
    return f"{result.name} failed or was refused, reducing certainty."


def _evidence_statement(result: ToolResult) -> str:
    if result.name == "scan.tcp_connect":
        ports = [item["port"] for item in result.data.get("ports", []) if item.get("status") == "open"]
        return f"TCP scan observed open ports: {', '.join(str(port) for port in ports) if ports else 'none'}."
    if result.name == "scope.validate":
        return "Policy scope validation passed." if result.ok else "Policy scope validation refused the target."
    if result.name == "analyze.security_headers":
        finding = result.data.get("finding", {})
        return str(finding.get("title", "Security header analysis completed."))
    return f"{result.name} produced {'accepted' if result.ok else 'failed'} evidence."


def _tool_confidence(result: ToolResult) -> float:
    if not result.ok:
        return 0.2
    if result.name == "scope.validate":
        return 0.95
    if result.name == "scan.tcp_connect":
        return 0.82
    if result.name.startswith("recon."):
        return 0.72
    if result.name.startswith("analyze."):
        return 0.68
    return 0.55


def _finding_confidence(finding: Finding) -> float:
    return {"high": 0.85, "medium": 0.65, "low": 0.4}.get(finding.confidence, 0.5)


def _severity_weight(severity: str) -> float:
    return {"critical": 0.95, "high": 0.8, "medium": 0.6, "low": 0.35, "informational": 0.2}.get(severity, 0.35)


def _scan_has_open_port(result: ToolResult) -> bool:
    return any(item.get("status") == "open" for item in result.data.get("ports", []))


def _best_tool_node(run: RunContext, finding: Finding) -> str:
    if finding.category == "web-hardening":
        for index, result in enumerate(run.evidence, start=1):
            if result.name in {"analyze.security_headers", "recon.http_headers"} and result.ok:
                return f"evidence:{index}"
    for index, result in enumerate(run.evidence, start=1):
        if result.ok:
            return f"evidence:{index}"
    return ""


def _open_ports(run: RunContext) -> list[int]:
    for result in run.evidence:
        if result.name == "scan.tcp_connect":
            return [int(item["port"]) for item in result.data.get("ports", []) if item.get("status") == "open"]
    return []


def _has_successful_tool(run: RunContext, name: str) -> bool:
    return any(result.name == name and result.ok for result in run.evidence)


def _bounded(value: float) -> float:
    return max(0.0, min(1.0, value))
