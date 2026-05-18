from __future__ import annotations

import json
from dataclasses import asdict
from typing import Any

from security_lab_assistant.models import JsonObject, ToolResult
from security_lab_assistant.policy import LabPolicy
from security_lab_assistant.tools.registry import TOOLS, list_tools
from security_lab_assistant.workflows.autonomous_recon import run_autonomous_recon


SERVER_INFO = {"name": "autonomous-security-lab-assistant", "version": "0.4.0"}


def _result_payload(result: ToolResult) -> JsonObject:
    return {
        "content": [
            {
                "type": "text",
                "text": json.dumps(result.data, indent=2),
            }
        ],
        "isError": not result.ok,
        "structuredContent": asdict(result),
    }


def _jsonrpc_result(request_id: Any, result: JsonObject) -> JsonObject:
    return {"jsonrpc": "2.0", "id": request_id, "result": result}


def _jsonrpc_error(request_id: Any, code: int, message: str) -> JsonObject:
    return {"jsonrpc": "2.0", "id": request_id, "error": {"code": code, "message": message}}


def handle_request(message: JsonObject, policy: LabPolicy) -> JsonObject | None:
    if not isinstance(message, dict):
        return _jsonrpc_error(None, -32600, "Invalid Request: message must be a JSON object.")
    method = message.get("method")
    request_id = message.get("id")
    params = message.get("params") or {}
    if not isinstance(method, str):
        return _jsonrpc_error(request_id, -32600, "Invalid Request: method must be a string.")
    if not isinstance(params, dict):
        return _jsonrpc_error(request_id, -32602, "Invalid params: params must be an object.")

    if method == "notifications/initialized":
        return None

    if method == "initialize":
        return _jsonrpc_result(
            request_id,
            {
                "protocolVersion": "2024-11-05",
                "capabilities": {"tools": {}, "logging": {}},
                "serverInfo": SERVER_INFO,
            },
        )

    if method == "tools/list":
        workflow_tool = {
            "name": "workflow.autonomous_recon",
            "description": "Run a safe autonomous recon loop against an in-scope lab target.",
            "inputSchema": {
                "type": "object",
                "properties": {
                    "target": {"type": "string"},
                    "objective": {"type": "string"},
                    "ports": {"type": "array", "items": {"type": "integer"}},
                    "scheme": {"type": "string"},
                },
                "required": ["target"],
            },
        }
        return _jsonrpc_result(request_id, {"tools": list_tools() + [workflow_tool]})

    if method == "tools/call":
        name = params.get("name")
        arguments = params.get("arguments") or {}
        if not isinstance(name, str):
            return _jsonrpc_error(request_id, -32602, "Invalid params: tool name must be a string.")
        if not isinstance(arguments, dict):
            return _jsonrpc_error(request_id, -32602, "Invalid params: arguments must be an object.")
        if name == "workflow.autonomous_recon":
            return _jsonrpc_result(request_id, _result_payload(run_autonomous_recon(arguments, policy)))
        if name not in TOOLS:
            return _jsonrpc_error(request_id, -32602, f"Unknown tool: {name}")
        return _jsonrpc_result(request_id, _result_payload(TOOLS[name].handler(arguments, policy)))

    return _jsonrpc_error(request_id, -32601, f"Unsupported method: {method}")
