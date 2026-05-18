from __future__ import annotations

from urllib.parse import urlparse

from security_lab_assistant.models import Finding, JsonObject, RunContext, ToolResult
from security_lab_assistant.policy import LabPolicy
from security_lab_assistant.platform import (
    record_metric,
    record_workflow_latency,
    workflow_timer,
)
from security_lab_assistant.reasoning import stable_hash
from security_lab_assistant.reporting import render_markdown_report, severity_counts
from security_lab_assistant.risk import risk_score
from security_lab_assistant.runtimes.evidence import EvidenceRuntime
from security_lab_assistant.runtimes.governance import GovernanceRuntime
from security_lab_assistant.runtimes.reasoning import ReasoningRuntime
from security_lab_assistant.runtimes.tools import ToolRuntime
from security_lab_assistant.runtimes.workflow import WorkflowRuntime
from security_lab_assistant.sarif import render_sarif
from security_lab_assistant.storage import append_audit_event, save_run
from security_lab_assistant.tools.registry import TOOLS
from security_lab_assistant.validation import parse_ports, require_string


COMMON_WEB_PORTS = [80, 443, 8000, 8080, 8443]


def _call_tool(name: str, arguments: JsonObject, policy: LabPolicy) -> ToolResult:
    return ToolRuntime(policy).execute(name, arguments, TOOLS[name].handler)


def _record_approval(ctx: RunContext, action: str, arguments: JsonObject, policy: LabPolicy) -> None:
    ctx.runtime.setdefault("approval_gates", []).append(GovernanceRuntime(policy).approve_action(action, arguments))


def _event(ctx: RunContext, policy: LabPolicy, event_type: str, payload: JsonObject) -> None:
    WorkflowRuntime(policy).emit(ctx, event_type, payload)


def _transition(ctx: RunContext, policy: LabPolicy, state: str, **kwargs: str) -> None:
    WorkflowRuntime(policy).transition(ctx, state, **kwargs)


def _finalize_run(ctx: RunContext, policy: LabPolicy) -> tuple[str, object]:
    GovernanceRuntime(policy).enforce_run_quotas(ctx)
    EvidenceRuntime(policy).append_lineage(
        ctx,
        "evidence.collected",
        {"evidence_items": len(ctx.evidence), "findings": len(ctx.findings), "status": ctx.status},
    )
    ctx.runtime.update(ReasoningRuntime().build_profile(ctx, policy))
    EvidenceRuntime(policy).append_lineage(
        ctx,
        "reasoning.built",
        {
            "graph_hash": ctx.runtime.get("formal_reasoning_graph", {}).get("graph_hash", ""),
            "replay_hash": ctx.runtime.get("deterministic_replay", {}).get("replay_hash", ""),
        },
    )
    report = render_markdown_report(ctx)
    sarif = render_sarif(ctx)
    run_path = save_run(policy, ctx, report, sarif)
    return str(run_path), sarif


def run_autonomous_recon(arguments: JsonObject, policy: LabPolicy) -> ToolResult:
    started = workflow_timer()
    try:
        target = require_string(arguments, "target")
        objective = str(arguments.get("objective", "baseline web reconnaissance")).strip()
        ports = parse_ports(arguments.get("ports", COMMON_WEB_PORTS))
        scheme = str(arguments.get("scheme", "http")).strip() or "http"
    except Exception as exc:
        return ToolResult(
            name="workflow.autonomous_recon",
            ok=False,
            data={"error": str(exc), "phase": "input_validation"},
        )

    ctx = RunContext(target=target, objective=objective)
    ctx.runtime["policy_hash"] = stable_hash(policy.to_dict())
    append_audit_event(policy, "workflow.started", {"run_id": ctx.run_id, "target": target})
    _transition(ctx, policy, "created")
    _event(ctx, policy, "workflow.started", {"target": target, "objective": objective, "ports": ports})

    ctx.add_phase("scope")
    _transition(ctx, policy, "scope_validating", replay_cursor="scope.validate")
    _record_approval(ctx, "scope.validate", {"target": target}, policy)
    scope = ctx.add_result(_call_tool("scope.validate", {"target": target}, policy))
    _event(ctx, policy, "tool.completed", {"tool": "scope.validate", "ok": scope.ok})
    if not scope.ok:
        ctx.status = "refused"
        ctx.warnings.append("Workflow stopped before network activity because the target was out of scope.")
        _transition(ctx, policy, "failed", checkpoint_id="scope.validate", terminal_status=ctx.status)
        _event(ctx, policy, "workflow.refused", {"stopped_at": "scope.validate"})
        run_path, _sarif = _finalize_run(ctx, policy)
        record_workflow_latency(policy, started, {"workflow": "autonomous_recon", "status": ctx.status})
        return ToolResult(
            name="workflow.autonomous_recon",
            ok=False,
            data={
                "run_id": ctx.run_id,
                "status": ctx.status,
                "stopped_at": "scope.validate",
                "result": scope.data,
                "runtime": ctx.runtime,
                "run_path": run_path,
            },
        )

    ctx.add_phase("port_scan")
    _transition(ctx, policy, "running", replay_cursor="scan.tcp_connect")
    _record_approval(ctx, "scan.tcp_connect", {"target": target, "ports": ports}, policy)
    scan = ctx.add_result(_call_tool("scan.tcp_connect", {"target": target, "ports": ports}, policy))
    _event(ctx, policy, "tool.completed", {"tool": "scan.tcp_connect", "ok": scan.ok})
    if not scan.ok:
        ctx.status = "failed"
        ctx.warnings.append("Workflow stopped because the TCP scan failed policy or validation checks.")
        _transition(ctx, policy, "failed", checkpoint_id="scan.tcp_connect", terminal_status=ctx.status)
        _event(ctx, policy, "workflow.failed", {"stopped_at": "scan.tcp_connect"})
        run_path, _sarif = _finalize_run(ctx, policy)
        record_workflow_latency(policy, started, {"workflow": "autonomous_recon", "status": ctx.status})
        return ToolResult(
            name="workflow.autonomous_recon",
            ok=False,
            data={
                "run_id": ctx.run_id,
                "status": ctx.status,
                "stopped_at": "scan.tcp_connect",
                "runtime": ctx.runtime,
                "run_path": run_path,
            },
        )

    open_ports = [item["port"] for item in scan.data.get("ports", []) if item.get("status") == "open"]

    ctx.add_phase("service_recon")
    _transition(ctx, policy, "running", replay_cursor="service_recon")
    for port in open_ports:
        if port in {80, 8000, 8080}:
            url = f"http://{target}:{port}/"
        elif port in {443, 8443}:
            url = f"https://{target}:{port}/"
        else:
            url = f"{scheme}://{target}:{port}/"

        parsed = urlparse(url)
        if parsed.scheme not in {"http", "https"}:
            continue
        _record_approval(ctx, "recon.http_headers", {"url": url}, policy)
        headers = ctx.add_result(_call_tool("recon.http_headers", {"url": url}, policy))
        _event(ctx, policy, "tool.completed", {"tool": "recon.http_headers", "ok": headers.ok, "url": url})
        if parsed.scheme == "https":
            _record_approval(ctx, "recon.tls_certificate", {"target": target, "port": port}, policy)
            tls = ctx.add_result(_call_tool("recon.tls_certificate", {"target": target, "port": port}, policy))
            _event(ctx, policy, "tool.completed", {"tool": "recon.tls_certificate", "ok": tls.ok, "port": port})
        if headers.ok:
            _record_approval(ctx, "recon.well_known_security", {"base_url": url.rstrip("/")}, policy)
            well_known = ctx.add_result(_call_tool("recon.well_known_security", {"base_url": url.rstrip("/")}, policy))
            _event(ctx, policy, "tool.completed", {"tool": "recon.well_known_security", "ok": well_known.ok, "url": url})
            _record_approval(ctx, "recon.web_page_intel", {"url": url}, policy)
            page_intel = ctx.add_result(_call_tool("recon.web_page_intel", {"url": url}, policy))
            _event(ctx, policy, "tool.completed", {"tool": "recon.web_page_intel", "ok": page_intel.ok, "url": url})
            for warning in page_intel.warnings:
                ctx.warnings.append(f"{url}: {warning}")
        if headers.ok:
            _record_approval(ctx, "analyze.security_headers", {"headers": headers.data.get("headers", {})}, policy)
            analysis = ctx.add_result(
                _call_tool("analyze.security_headers", {"headers": headers.data.get("headers", {})}, policy)
            )
            _event(ctx, policy, "tool.completed", {"tool": "analyze.security_headers", "ok": analysis.ok, "url": url})
            finding_data = analysis.data.get("finding", {})
            missing_headers = finding_data.get("missing_headers", [])
            ctx.findings.append(
                Finding(
                    title=str(finding_data.get("title", "HTTP security header review")),
                    severity=str(finding_data.get("severity", "informational")),
                    evidence=f"{url} headers: {headers.data.get('headers', {})}",
                    recommendation=str(finding_data.get("recommendation", "")),
                    affected_asset=url,
                    category=str(finding_data.get("category", "web-hardening")),
                    confidence=str(finding_data.get("confidence", "medium")),
                )
            )
            if missing_headers:
                ctx.warnings.append(f"{url} is missing {len(missing_headers)} baseline security headers.")

    ctx.status = "completed"
    if not open_ports:
        ctx.warnings.append("No open ports were detected in the requested scan set.")
    _transition(ctx, policy, "completed", checkpoint_id="final", terminal_status=ctx.status)
    _event(ctx, policy, "workflow.completed", {"status": ctx.status, "open_ports": open_ports, "findings": len(ctx.findings)})
    run_path, _sarif = _finalize_run(ctx, policy)
    append_audit_event(policy, "workflow.completed", {"run_id": ctx.run_id, "status": ctx.status})
    record_metric(policy, "workflow_findings_total", len(ctx.findings), {"workflow": "autonomous_recon"})
    record_metric(policy, "workflow_open_ports_total", len(open_ports), {"workflow": "autonomous_recon"})
    record_workflow_latency(policy, started, {"workflow": "autonomous_recon", "status": ctx.status})
    return ToolResult(
        name="workflow.autonomous_recon",
        ok=True,
        data={
            "run_id": ctx.run_id,
            "target": target,
            "objective": objective,
            "status": ctx.status,
            "open_ports": open_ports,
            "severity_counts": severity_counts(ctx),
            "risk": risk_score(ctx),
            "warnings": ctx.warnings,
            "runtime": ctx.runtime,
            "steps": [
                {"tool": item.name, "ok": item.ok, "data": item.data, "warnings": item.warnings}
                for item in ctx.evidence
            ],
            "findings": [finding.__dict__ for finding in ctx.findings],
            "run_path": run_path,
            "report_path": str(policy.artifact_root() / "reports" / f"{ctx.run_id}.md"),
            "sarif_path": str(policy.artifact_root() / "exports" / f"{ctx.run_id}.sarif.json"),
            "reasoning_visualizer_path": str(policy.artifact_root() / "visualizations" / f"{ctx.run_id}.reasoning.html"),
            "benchmark_path": str(policy.artifact_root() / "benchmarks" / f"{ctx.run_id}.benchmark.json"),
        },
    )
