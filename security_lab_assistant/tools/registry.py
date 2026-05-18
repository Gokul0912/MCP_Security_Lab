from __future__ import annotations

from security_lab_assistant.models import JsonObject
from security_lab_assistant.tools.base import ToolSpec
from security_lab_assistant.tools.network import fetch_text, http_headers, tcp_connect_scan
from security_lab_assistant.tools.reporting import summarize_security_headers
from security_lab_assistant.tools.scope import validate_scope


def _schema(properties: JsonObject, required: list[str]) -> JsonObject:
    return {"type": "object", "properties": properties, "required": required}


TOOLS: dict[str, ToolSpec] = {
    "scope.validate": ToolSpec(
        name="scope.validate",
        description="Validate that a hostname or IP address is inside the configured lab scope.",
        input_schema=_schema({"target": {"type": "string"}}, ["target"]),
        handler=validate_scope,
    ),
    "scan.tcp_connect": ToolSpec(
        name="scan.tcp_connect",
        description="Perform a constrained TCP connect scan against an in-scope lab target.",
        input_schema=_schema(
            {
                "target": {"type": "string"},
                "ports": {"type": "array", "items": {"type": "integer"}},
                "timeout_seconds": {"type": "number"},
            },
            ["target", "ports"],
        ),
        handler=tcp_connect_scan,
    ),
    "recon.http_headers": ToolSpec(
        name="recon.http_headers",
        description="Fetch selected HTTP response headers from an in-scope lab URL.",
        input_schema=_schema(
            {"url": {"type": "string"}, "timeout_seconds": {"type": "number"}},
            ["url"],
        ),
        handler=http_headers,
    ),
    "web.fetch_text": ToolSpec(
        name="web.fetch_text",
        description="Fetch bounded text content from an in-scope lab URL.",
        input_schema=_schema(
            {"url": {"type": "string"}, "timeout_seconds": {"type": "number"}},
            ["url"],
        ),
        handler=fetch_text,
    ),
    "analyze.security_headers": ToolSpec(
        name="analyze.security_headers",
        description="Generate a basic finding from captured HTTP security headers.",
        input_schema=_schema({"headers": {"type": "object"}}, ["headers"]),
        handler=summarize_security_headers,
    ),
}


def list_tools() -> list[JsonObject]:
    return [
        {
            "name": tool.name,
            "description": tool.description,
            "inputSchema": tool.input_schema,
        }
        for tool in TOOLS.values()
    ]
