from __future__ import annotations

import socket
from time import perf_counter
from urllib.error import URLError
from urllib.request import Request, urlopen

from security_lab_assistant.models import JsonObject, ToolResult
from security_lab_assistant.policy import LabPolicy, PolicyError
from security_lab_assistant.tools.base import refused


def tcp_connect_scan(arguments: JsonObject, policy: LabPolicy) -> ToolResult:
    name = "scan.tcp_connect"
    target = str(arguments.get("target", "")).strip()
    ports = [int(port) for port in arguments.get("ports", [])]
    timeout = min(float(arguments.get("timeout_seconds", 0.35)), 3.0)

    try:
        policy.assert_target_allowed(target)
        policy.assert_port_scan_allowed(ports)
    except PolicyError as exc:
        return refused(name, exc)

    observations = []
    for port in ports:
        started = perf_counter()
        status = "closed"
        error = None
        try:
            with socket.create_connection((target, port), timeout=timeout):
                status = "open"
        except OSError as exc:
            error = exc.__class__.__name__
        elapsed_ms = round((perf_counter() - started) * 1000, 2)
        observations.append(
            {"port": port, "transport": "tcp", "status": status, "elapsed_ms": elapsed_ms, "error": error}
        )

    return ToolResult(name=name, ok=True, data={"target": target, "ports": observations})


def http_headers(arguments: JsonObject, policy: LabPolicy) -> ToolResult:
    name = "recon.http_headers"
    url = str(arguments.get("url", "")).strip()
    timeout = min(float(arguments.get("timeout_seconds", 2.0)), 5.0)
    try:
        policy.assert_url_allowed(url)
    except PolicyError as exc:
        return refused(name, exc)

    request = Request(url, headers={"User-Agent": "security-lab-assistant/0.1"})
    try:
        with urlopen(request, timeout=timeout) as response:
            headers = dict(response.headers.items())
            status = response.status
            final_url = response.geturl()
    except URLError as exc:
        return ToolResult(name=name, ok=False, data={"url": url, "error": str(exc)})

    interesting = {
        header: headers.get(header)
        for header in [
            "Server",
            "X-Powered-By",
            "Content-Security-Policy",
            "Strict-Transport-Security",
            "X-Frame-Options",
            "X-Content-Type-Options",
        ]
        if header in headers
    }
    return ToolResult(
        name=name,
        ok=True,
        data={"url": url, "final_url": final_url, "status": status, "headers": interesting},
    )


def fetch_text(arguments: JsonObject, policy: LabPolicy) -> ToolResult:
    name = "web.fetch_text"
    url = str(arguments.get("url", "")).strip()
    timeout = min(float(arguments.get("timeout_seconds", 2.0)), 5.0)
    try:
        policy.assert_url_allowed(url)
    except PolicyError as exc:
        return refused(name, exc)

    request = Request(url, headers={"User-Agent": "security-lab-assistant/0.1"})
    try:
        with urlopen(request, timeout=timeout) as response:
            body = response.read(policy.max_http_bytes + 1)
            truncated = len(body) > policy.max_http_bytes
            text = body[: policy.max_http_bytes].decode("utf-8", errors="replace")
    except URLError as exc:
        return ToolResult(name=name, ok=False, data={"url": url, "error": str(exc)})

    return ToolResult(
        name=name,
        ok=True,
        data={"url": url, "text": text, "truncated": truncated, "bytes_read": len(body)},
    )
