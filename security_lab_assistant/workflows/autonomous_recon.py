from __future__ import annotations

from urllib.parse import urlparse

from security_lab_assistant.models import Finding, JsonObject, RunContext, ToolResult
from security_lab_assistant.policy import LabPolicy
from security_lab_assistant.reporting import render_markdown_report, severity_counts
from security_lab_assistant.risk import risk_score
from security_lab_assistant.sarif import render_sarif
from security_lab_assistant.storage import append_audit_event, save_run
from security_lab_assistant.tools.registry import TOOLS
from security_lab_assistant.validation import parse_ports, require_string


COMMON_WEB_PORTS = [80, 443, 8000, 8080, 8443]


def _call_tool(name: str, arguments: JsonObject, policy: LabPolicy) -> ToolResult:
    return TOOLS[name].handler(arguments, policy)


def run_autonomous_recon(arguments: JsonObject, policy: LabPolicy) -> ToolResult:
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
    append_audit_event(policy, "workflow.started", {"run_id": ctx.run_id, "target": target})

    ctx.add_phase("scope")
    scope = ctx.add_result(_call_tool("scope.validate", {"target": target}, policy))
    if not scope.ok:
        ctx.status = "refused"
        ctx.warnings.append("Workflow stopped before network activity because the target was out of scope.")
        report = render_markdown_report(ctx)
        sarif = render_sarif(ctx)
        run_path = save_run(policy, ctx, report, sarif)
        return ToolResult(
            name="workflow.autonomous_recon",
            ok=False,
            data={
                "run_id": ctx.run_id,
                "status": ctx.status,
                "stopped_at": "scope.validate",
                "result": scope.data,
                "run_path": str(run_path),
            },
        )

    ctx.add_phase("port_scan")
    scan = ctx.add_result(_call_tool("scan.tcp_connect", {"target": target, "ports": ports}, policy))
    if not scan.ok:
        ctx.status = "failed"
        ctx.warnings.append("Workflow stopped because the TCP scan failed policy or validation checks.")
        report = render_markdown_report(ctx)
        sarif = render_sarif(ctx)
        run_path = save_run(policy, ctx, report, sarif)
        return ToolResult(
            name="workflow.autonomous_recon",
            ok=False,
            data={"run_id": ctx.run_id, "status": ctx.status, "stopped_at": "scan.tcp_connect", "run_path": str(run_path)},
        )

    open_ports = [item["port"] for item in scan.data.get("ports", []) if item.get("status") == "open"]

    ctx.add_phase("service_recon")
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
        headers = ctx.add_result(_call_tool("recon.http_headers", {"url": url}, policy))
        if parsed.scheme == "https":
            ctx.add_result(_call_tool("recon.tls_certificate", {"target": target, "port": port}, policy))
        if headers.ok:
            ctx.add_result(_call_tool("recon.well_known_security", {"base_url": url.rstrip("/")}, policy))
            page_intel = ctx.add_result(_call_tool("recon.web_page_intel", {"url": url}, policy))
            for warning in page_intel.warnings:
                ctx.warnings.append(f"{url}: {warning}")
        if headers.ok:
            analysis = ctx.add_result(
                _call_tool("analyze.security_headers", {"headers": headers.data.get("headers", {})}, policy)
            )
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
    report = render_markdown_report(ctx)
    sarif = render_sarif(ctx)
    run_path = save_run(policy, ctx, report, sarif)
    append_audit_event(policy, "workflow.completed", {"run_id": ctx.run_id, "status": ctx.status})
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
            "steps": [
                {"tool": item.name, "ok": item.ok, "data": item.data, "warnings": item.warnings}
                for item in ctx.evidence
            ],
            "findings": [finding.__dict__ for finding in ctx.findings],
            "run_path": str(run_path),
            "report_path": str(policy.artifact_root() / "reports" / f"{ctx.run_id}.md"),
            "sarif_path": str(policy.artifact_root() / "exports" / f"{ctx.run_id}.sarif.json"),
        },
    )
