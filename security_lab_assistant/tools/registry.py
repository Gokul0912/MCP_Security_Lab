from __future__ import annotations

from security_lab_assistant.models import JsonObject
from security_lab_assistant.tools.base import ToolSpec
from security_lab_assistant.tools.network import (
    fetch_text,
    http_headers,
    tcp_connect_scan,
    tls_certificate,
    web_page_intel,
    well_known_security,
)
from security_lab_assistant.tools.reporting import summarize_security_headers
from security_lab_assistant.tools.runs import run_get, run_list, run_search, run_verify_audit
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
    "recon.tls_certificate": ToolSpec(
        name="recon.tls_certificate",
        description="Inspect the TLS certificate presented by an in-scope lab endpoint.",
        input_schema=_schema(
            {
                "target": {"type": "string"},
                "port": {"type": "integer"},
                "timeout_seconds": {"type": "number"},
            },
            ["target"],
        ),
        handler=tls_certificate,
    ),
    "recon.well_known_security": ToolSpec(
        name="recon.well_known_security",
        description="Check robots.txt and security.txt locations on an in-scope lab web origin.",
        input_schema=_schema(
            {"base_url": {"type": "string"}},
            ["base_url"],
        ),
        handler=well_known_security,
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
    "recon.web_page_intel": ToolSpec(
        name="recon.web_page_intel",
        description="Extract safe structural intelligence from an in-scope HTML page.",
        input_schema=_schema(
            {"url": {"type": "string"}, "timeout_seconds": {"type": "number"}},
            ["url"],
        ),
        handler=web_page_intel,
    ),
    "analyze.security_headers": ToolSpec(
        name="analyze.security_headers",
        description="Generate a basic finding from captured HTTP security headers.",
        input_schema=_schema({"headers": {"type": "object"}}, ["headers"]),
        handler=summarize_security_headers,
    ),
    "run.list": ToolSpec(
        name="run.list",
        description="List persisted assistant run summaries.",
        input_schema=_schema({"limit": {"type": "integer"}}, []),
        handler=run_list,
    ),
    "run.get": ToolSpec(
        name="run.get",
        description="Load a persisted assistant run by run_id.",
        input_schema=_schema({"run_id": {"type": "string"}}, ["run_id"]),
        handler=run_get,
    ),
    "run.search": ToolSpec(
        name="run.search",
        description="Search persisted runs by target/objective text and optional status.",
        input_schema=_schema(
            {"query": {"type": "string"}, "status": {"type": "string"}, "limit": {"type": "integer"}},
            [],
        ),
        handler=run_search,
    ),
    "run.verify_audit": ToolSpec(
        name="run.verify_audit",
        description="Verify the tamper-evident hash chain for local audit events.",
        input_schema=_schema({}, []),
        handler=run_verify_audit,
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
