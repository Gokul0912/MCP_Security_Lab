from __future__ import annotations

from security_lab_assistant.models import JsonObject
from security_lab_assistant.tools.base import ToolSpec
from security_lab_assistant.tools.intelligence import runtime_section
from security_lab_assistant.tools.network import (
    fetch_text,
    http_headers,
    tcp_connect_scan,
    tls_certificate,
    web_page_intel,
    well_known_security,
)
from security_lab_assistant.tools.orchestration import workflow_batch_recon
from security_lab_assistant.tools.operations import (
    ops_events,
    ops_failure_taxonomy,
    ops_metrics,
    ops_platform,
    ops_queue,
    ops_runtime_contracts,
    ops_workflows,
)
from security_lab_assistant.tools.reporting import summarize_security_headers
from security_lab_assistant.tools.runs import (
    run_get,
    run_list,
    run_search,
    run_verify_artifacts,
    run_verify_audit,
    run_verify_deep,
    run_verify_lineage,
    run_verify_replay,
)
from security_lab_assistant.tools.scope import validate_scope


def _schema(properties: JsonObject, required: list[str]) -> JsonObject:
    return {"type": "object", "properties": properties, "required": required}


TOOLS: dict[str, ToolSpec] = {
    "scope.validate": ToolSpec(
        name="scope.validate",
        description="Validate that a hostname or IP address is inside the configured lab scope.",
        input_schema=_schema({"target": {"type": "string"}}, ["target"]),
        handler=validate_scope,
        required_permission="workflow.run",
        risk_class="governance",
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
        approval_level="policy",
        risk_class="medium",
    ),
    "recon.http_headers": ToolSpec(
        name="recon.http_headers",
        description="Fetch selected HTTP response headers from an in-scope lab URL.",
        input_schema=_schema(
            {"url": {"type": "string"}, "timeout_seconds": {"type": "number"}},
            ["url"],
        ),
        handler=http_headers,
        approval_level="policy",
        risk_class="medium",
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
        approval_level="policy",
        risk_class="medium",
    ),
    "recon.well_known_security": ToolSpec(
        name="recon.well_known_security",
        description="Check robots.txt and security.txt locations on an in-scope lab web origin.",
        input_schema=_schema(
            {"base_url": {"type": "string"}},
            ["base_url"],
        ),
        handler=well_known_security,
        approval_level="policy",
        risk_class="medium",
    ),
    "web.fetch_text": ToolSpec(
        name="web.fetch_text",
        description="Fetch bounded text content from an in-scope lab URL.",
        input_schema=_schema(
            {"url": {"type": "string"}, "timeout_seconds": {"type": "number"}},
            ["url"],
        ),
        handler=fetch_text,
        approval_level="policy",
        risk_class="medium",
    ),
    "recon.web_page_intel": ToolSpec(
        name="recon.web_page_intel",
        description="Extract safe structural intelligence from an in-scope HTML page.",
        input_schema=_schema(
            {"url": {"type": "string"}, "timeout_seconds": {"type": "number"}},
            ["url"],
        ),
        handler=web_page_intel,
        approval_level="policy",
        risk_class="medium",
    ),
    "analyze.security_headers": ToolSpec(
        name="analyze.security_headers",
        description="Generate a basic finding from captured HTTP security headers.",
        input_schema=_schema({"headers": {"type": "object"}}, ["headers"]),
        handler=summarize_security_headers,
        risk_class="analysis",
    ),
    "run.list": ToolSpec(
        name="run.list",
        description="List persisted assistant run summaries.",
        input_schema=_schema({"limit": {"type": "integer"}}, []),
        handler=run_list,
        required_role="readonly",
        required_permission="run.read",
        risk_class="read",
    ),
    "run.get": ToolSpec(
        name="run.get",
        description="Load a persisted assistant run by run_id.",
        input_schema=_schema({"run_id": {"type": "string"}}, ["run_id"]),
        handler=run_get,
        required_role="readonly",
        required_permission="run.read",
        risk_class="read",
    ),
    "run.search": ToolSpec(
        name="run.search",
        description="Search persisted runs by target/objective text and optional status.",
        input_schema=_schema(
            {"query": {"type": "string"}, "status": {"type": "string"}, "limit": {"type": "integer"}},
            [],
        ),
        handler=run_search,
        required_role="readonly",
        required_permission="run.read",
        risk_class="read",
    ),
    "run.verify_audit": ToolSpec(
        name="run.verify_audit",
        description="Verify the tamper-evident hash chain for local audit events.",
        input_schema=_schema({"role": {"type": "string"}}, []),
        handler=run_verify_audit,
        required_role="auditor",
        required_permission="audit.verify",
        risk_class="governance",
    ),
    "run.verify_artifacts": ToolSpec(
        name="run.verify_artifacts",
        description="Verify detached HMAC signatures for persisted local artifacts.",
        input_schema=_schema({"role": {"type": "string"}}, []),
        handler=run_verify_artifacts,
        required_role="auditor",
        required_permission="audit.verify",
        risk_class="governance",
    ),
    "run.verify_lineage": ToolSpec(
        name="run.verify_lineage",
        description="Verify append-only hash-chained evidence lineage for a saved run.",
        input_schema=_schema({"run_id": {"type": "string"}, "role": {"type": "string"}}, ["run_id"]),
        handler=run_verify_lineage,
        required_role="auditor",
        required_permission="audit.verify",
        risk_class="governance",
    ),
    "run.verify_replay": ToolSpec(
        name="run.verify_replay",
        description="Validate deterministic replay material for a saved run.",
        input_schema=_schema({"run_id": {"type": "string"}, "role": {"type": "string"}}, ["run_id"]),
        handler=run_verify_replay,
        required_role="auditor",
        required_permission="audit.verify",
        risk_class="governance",
    ),
    "run.verify_deep": ToolSpec(
        name="run.verify_deep",
        description="Run forensic runtime verification across signatures, lineage, manifests, replay, policy, and benchmarks.",
        input_schema=_schema({"role": {"type": "string"}, "quarantine": {"type": "boolean"}}, []),
        handler=run_verify_deep,
        required_role="auditor",
        required_permission="audit.verify",
        approval_level="forensic",
        risk_class="governance",
    ),
    "runtime.section": ToolSpec(
        name="runtime.section",
        description="Read explainability, replay, graph, critique, memory, reasoning quality, benchmark, trust, integrity, safety, agent, or approval metadata for a run.",
        input_schema=_schema(
            {"run_id": {"type": "string"}, "section": {"type": "string"}},
            ["run_id", "section"],
        ),
        handler=runtime_section,
    ),
    "workflow.batch_recon": ToolSpec(
        name="workflow.batch_recon",
        description="Run approved bounded reconnaissance across multiple in-scope targets with a persisted batch record.",
        input_schema=_schema(
            {
                "targets": {"type": "array", "items": {"type": "string"}},
                "ports": {"type": "array", "items": {"type": "integer"}},
                "objective": {"type": "string"},
                "role": {"type": "string"},
                "approved": {"type": "boolean"},
            },
            ["targets"],
        ),
        handler=workflow_batch_recon,
        required_role="reviewer",
        required_permission="workflow.approve",
        approval_level="human",
        risk_class="medium",
    ),
    "ops.metrics": ToolSpec(
        name="ops.metrics",
        description="Read local workflow metrics for observability and latency monitoring.",
        input_schema=_schema({"role": {"type": "string"}}, []),
        handler=ops_metrics,
        required_role="auditor",
        required_permission="audit.verify",
        risk_class="read",
    ),
    "ops.events": ToolSpec(
        name="ops.events",
        description="Read the local workflow event stream for operational debugging.",
        input_schema=_schema({"role": {"type": "string"}}, []),
        handler=ops_events,
        required_role="auditor",
        required_permission="audit.verify",
        risk_class="read",
    ),
    "ops.runtime_contracts": ToolSpec(
        name="ops.runtime_contracts",
        description="Inspect explicit trust-boundary contracts for governance, reasoning, tool, evidence, and workflow runtimes.",
        input_schema=_schema({"role": {"type": "string"}}, []),
        handler=ops_runtime_contracts,
        required_role="auditor",
        required_permission="audit.verify",
        risk_class="read",
    ),
    "ops.workflows": ToolSpec(
        name="ops.workflows",
        description="Inspect durable workflow state records and recovery cursors.",
        input_schema=_schema({"role": {"type": "string"}, "limit": {"type": "integer"}}, []),
        handler=ops_workflows,
        required_role="operator",
        required_permission="audit.verify",
        risk_class="ops",
    ),
    "ops.queue": ToolSpec(
        name="ops.queue",
        description="Inspect local durable queue tasks, workflow leases, and expired lease recovery records.",
        input_schema=_schema({"role": {"type": "string"}, "limit": {"type": "integer"}, "status": {"type": "string"}}, []),
        handler=ops_queue,
        required_role="operator",
        required_permission="audit.verify",
        risk_class="ops",
    ),
    "ops.failure_taxonomy": ToolSpec(
        name="ops.failure_taxonomy",
        description="Inspect structured runtime failure classes and required fields.",
        input_schema=_schema({"role": {"type": "string"}}, []),
        handler=ops_failure_taxonomy,
        required_role="auditor",
        required_permission="audit.verify",
        risk_class="read",
    ),
    "ops.platform": ToolSpec(
        name="ops.platform",
        description="Inspect product identity, runtime version, and schema versions.",
        input_schema=_schema({"role": {"type": "string"}}, []),
        handler=ops_platform,
        required_role="readonly",
        required_permission="runtime.read",
        risk_class="read",
    ),
}


def list_tools() -> list[JsonObject]:
    return [
        {
            "name": tool.name,
            "description": tool.description,
            "inputSchema": tool.input_schema,
            "requiredRole": tool.required_role,
            "requiredPermission": tool.required_permission,
            "approvalLevel": tool.approval_level,
            "riskClass": tool.risk_class,
        }
        for tool in TOOLS.values()
    ]
