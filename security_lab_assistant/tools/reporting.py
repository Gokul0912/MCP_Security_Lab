from __future__ import annotations

from security_lab_assistant.models import JsonObject, ToolResult
from security_lab_assistant.policy import LabPolicy


def summarize_security_headers(arguments: JsonObject, policy: LabPolicy) -> ToolResult:
    name = "analyze.security_headers"
    headers = arguments.get("headers", {})
    if not isinstance(headers, dict):
        return ToolResult(name=name, ok=False, data={"error": "headers must be an object"})

    missing = [
        header
        for header in [
            "Content-Security-Policy",
            "Strict-Transport-Security",
            "X-Frame-Options",
            "X-Content-Type-Options",
        ]
        if not headers.get(header)
    ]
    severity = "low" if missing else "informational"
    return ToolResult(
        name=name,
        ok=True,
        data={
            "finding": {
                "title": "HTTP security header review",
                "severity": severity,
                "missing_headers": missing,
                "recommendation": "Add missing defensive headers where appropriate for the service.",
            }
        },
    )
