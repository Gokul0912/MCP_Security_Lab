from __future__ import annotations

from security_lab_assistant.models import JsonObject, ToolResult
from security_lab_assistant.policy import LabPolicy


RECOMMENDED_HEADERS = {
    "Content-Security-Policy": "Define an application-specific Content-Security-Policy.",
    "Strict-Transport-Security": "Enable HSTS on HTTPS origins after validating preload readiness.",
    "X-Frame-Options": "Set DENY or SAMEORIGIN unless framing is intentionally required.",
    "X-Content-Type-Options": "Set nosniff to reduce MIME confusion risk.",
    "Referrer-Policy": "Set a referrer policy such as no-referrer or strict-origin-when-cross-origin.",
    "Permissions-Policy": "Disable browser capabilities that the application does not require.",
}


def summarize_security_headers(arguments: JsonObject, policy: LabPolicy) -> ToolResult:
    name = "analyze.security_headers"
    headers = arguments.get("headers", {})
    if not isinstance(headers, dict):
        return ToolResult(name=name, ok=False, data={"error": "headers must be an object"})

    normalized = {str(key).lower(): value for key, value in headers.items()}
    missing = [header for header in RECOMMENDED_HEADERS if not normalized.get(header.lower())]
    high_value_missing = {"Content-Security-Policy", "Strict-Transport-Security"} & set(missing)
    severity = "medium" if len(high_value_missing) == 2 else "low" if missing else "informational"
    recommendations = [RECOMMENDED_HEADERS[header] for header in missing]
    return ToolResult(
        name=name,
        ok=True,
        data={
            "finding": {
                "title": "HTTP security header review",
                "severity": severity,
                "missing_headers": missing,
                "category": "web-hardening",
                "confidence": "medium",
                "recommendation": " ".join(recommendations)
                if recommendations
                else "No missing baseline security headers were detected.",
            }
        },
    )
