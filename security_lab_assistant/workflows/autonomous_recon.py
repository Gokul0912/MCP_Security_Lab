from __future__ import annotations

from urllib.parse import urlparse

from security_lab_assistant.models import Finding, JsonObject, RunContext, ToolResult
from security_lab_assistant.policy import LabPolicy
from security_lab_assistant.tools.registry import TOOLS


COMMON_WEB_PORTS = [80, 443, 8000, 8080, 8443]


def _call_tool(name: str, arguments: JsonObject, policy: LabPolicy) -> ToolResult:
    return TOOLS[name].handler(arguments, policy)


def run_autonomous_recon(arguments: JsonObject, policy: LabPolicy) -> ToolResult:
    target = str(arguments.get("target", "")).strip()
    objective = str(arguments.get("objective", "baseline web reconnaissance")).strip()
    ports = [int(port) for port in arguments.get("ports", COMMON_WEB_PORTS)]
    scheme = str(arguments.get("scheme", "http")).strip() or "http"

    ctx = RunContext(target=target, objective=objective)
    scope = ctx.add_result(_call_tool("scope.validate", {"target": target}, policy))
    if not scope.ok:
        return ToolResult(
            name="workflow.autonomous_recon",
            ok=False,
            data={"run_id": ctx.run_id, "stopped_at": "scope.validate", "result": scope.data},
        )

    scan = ctx.add_result(_call_tool("scan.tcp_connect", {"target": target, "ports": ports}, policy))
    open_ports = [item["port"] for item in scan.data.get("ports", []) if item.get("status") == "open"]

    header_results = []
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
        header_results.append(headers)
        if headers.ok:
            analysis = ctx.add_result(
                _call_tool("analyze.security_headers", {"headers": headers.data.get("headers", {})}, policy)
            )
            finding_data = analysis.data.get("finding", {})
            ctx.findings.append(
                Finding(
                    title=str(finding_data.get("title", "HTTP security header review")),
                    severity=str(finding_data.get("severity", "informational")),
                    evidence=f"{url} headers: {headers.data.get('headers', {})}",
                    recommendation=str(finding_data.get("recommendation", "")),
                )
            )

    return ToolResult(
        name="workflow.autonomous_recon",
        ok=True,
        data={
            "run_id": ctx.run_id,
            "target": target,
            "objective": objective,
            "open_ports": open_ports,
            "steps": [
                {"tool": item.name, "ok": item.ok, "data": item.data, "warnings": item.warnings}
                for item in ctx.evidence
            ],
            "findings": [finding.__dict__ for finding in ctx.findings],
        },
    )
