from __future__ import annotations

from concurrent.futures import ThreadPoolExecutor, as_completed
from html.parser import HTMLParser
import socket
import ssl
from time import perf_counter
from urllib.error import HTTPError, URLError
from urllib.parse import urljoin
from urllib.request import HTTPRedirectHandler, Request, build_opener, urlopen

from security_lab_assistant.models import JsonObject, ToolResult
from security_lab_assistant.policy import LabPolicy, PolicyError
from security_lab_assistant.tools.base import refused
from security_lab_assistant.validation import parse_ports, parse_timeout, require_string


class NoRedirectHandler(HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):  # type: ignore[no-untyped-def]
        return None


def _open_no_redirect(request: Request, timeout: float):
    opener = build_opener(NoRedirectHandler)
    return opener.open(request, timeout=timeout)


def tcp_connect_scan(arguments: JsonObject, policy: LabPolicy) -> ToolResult:
    name = "scan.tcp_connect"
    try:
        target = require_string(arguments, "target")
        ports = parse_ports(arguments.get("ports", []))
        timeout = parse_timeout(
            arguments.get("timeout_seconds"),
            default=policy.connect_timeout_seconds,
            maximum=3.0,
        )
        policy.assert_target_allowed(target)
        policy.assert_port_scan_allowed(ports)
    except PolicyError as exc:
        return refused(name, exc)

    scan_started = perf_counter()
    workers = min(max(1, policy.max_scan_workers), len(ports))
    observations = []
    with ThreadPoolExecutor(max_workers=workers) as executor:
        futures = [executor.submit(_probe_tcp_port, target, port, timeout) for port in ports]
        for future in as_completed(futures):
            observations.append(future.result())
    observations.sort(key=lambda item: item["port"])
    elapsed_ms_total = round((perf_counter() - scan_started) * 1000, 2)

    return ToolResult(
        name=name,
        ok=True,
        data={"target": target, "ports": observations, "elapsed_ms": elapsed_ms_total, "workers": workers},
    )


def _probe_tcp_port(target: str, port: int, timeout: float) -> JsonObject:
    started = perf_counter()
    status = "closed"
    error = None
    try:
        with socket.create_connection((target, port), timeout=timeout):
            status = "open"
    except OSError as exc:
        error = exc.__class__.__name__
    elapsed_ms = round((perf_counter() - started) * 1000, 2)
    return {"port": port, "transport": "tcp", "status": status, "elapsed_ms": elapsed_ms, "error": error}


def http_headers(arguments: JsonObject, policy: LabPolicy) -> ToolResult:
    name = "recon.http_headers"
    try:
        url = require_string(arguments, "url")
        timeout = parse_timeout(
            arguments.get("timeout_seconds"),
            default=policy.http_timeout_seconds,
            maximum=5.0,
        )
        policy.assert_url_allowed(url)
    except PolicyError as exc:
        return refused(name, exc)

    request = Request(url, headers={"User-Agent": "security-lab-assistant/0.1"})
    try:
        with _open_no_redirect(request, timeout=timeout) as response:
            headers = dict(response.headers.items())
            status = response.status
            final_url = response.geturl()
    except HTTPError as exc:
        headers = dict(exc.headers.items())
        if 300 <= exc.code < 400 and headers.get("Location"):
            redirect_url = urljoin(url, headers["Location"])
            try:
                policy.assert_url_allowed(redirect_url)
            except PolicyError as policy_exc:
                return refused(name, policy_exc)
            return ToolResult(
                name=name,
                ok=True,
                data={
                    "url": url,
                    "status": exc.code,
                    "headers": _interesting_headers(headers),
                    "redirect_blocked": True,
                    "redirect_location": redirect_url,
                },
                warnings=["Redirects are reported but not followed by default."],
            )
        return ToolResult(name=name, ok=False, data={"url": url, "status": exc.code, "error": str(exc)})
    except URLError as exc:
        return ToolResult(name=name, ok=False, data={"url": url, "error": str(exc)})

    return ToolResult(
        name=name,
        ok=True,
        data={"url": url, "final_url": final_url, "status": status, "headers": _interesting_headers(headers)},
    )


def _interesting_headers(headers: dict[str, str]) -> dict[str, str]:
    return {
        header: headers.get(header)
        for header in [
            "Server",
            "X-Powered-By",
            "Content-Security-Policy",
            "Strict-Transport-Security",
            "X-Frame-Options",
            "X-Content-Type-Options",
            "Referrer-Policy",
            "Permissions-Policy",
            "Location",
        ]
        if header in headers
    }


def fetch_text(arguments: JsonObject, policy: LabPolicy) -> ToolResult:
    name = "web.fetch_text"
    try:
        url = require_string(arguments, "url")
        timeout = parse_timeout(
            arguments.get("timeout_seconds"),
            default=policy.http_timeout_seconds,
            maximum=5.0,
        )
        policy.assert_url_allowed(url)
    except PolicyError as exc:
        return refused(name, exc)

    request = Request(url, headers={"User-Agent": "security-lab-assistant/0.1"})
    try:
        with _open_no_redirect(request, timeout=timeout) as response:
            body = response.read(policy.max_http_bytes + 1)
            truncated = len(body) > policy.max_http_bytes
            text = body[: policy.max_http_bytes].decode("utf-8", errors="replace")
    except HTTPError as exc:
        if 300 <= exc.code < 400 and exc.headers.get("Location"):
            redirect_url = urljoin(url, exc.headers["Location"])
            try:
                policy.assert_url_allowed(redirect_url)
            except PolicyError as policy_exc:
                return refused(name, policy_exc)
            return ToolResult(
                name=name,
                ok=False,
                data={"url": url, "status": exc.code, "redirect_location": redirect_url},
                warnings=["Redirects are not followed by default."],
            )
        return ToolResult(name=name, ok=False, data={"url": url, "status": exc.code, "error": str(exc)})
    except URLError as exc:
        return ToolResult(name=name, ok=False, data={"url": url, "error": str(exc)})

    return ToolResult(
        name=name,
        ok=True,
        data={
            "url": url,
            "text": text,
            "truncated": truncated,
            "bytes_read": len(body),
            "content_type": response.headers.get("Content-Type"),
        },
    )


def well_known_security(arguments: JsonObject, policy: LabPolicy) -> ToolResult:
    name = "recon.well_known_security"
    try:
        base_url = require_string(arguments, "base_url").rstrip("/")
        policy.assert_url_allowed(base_url)
    except PolicyError as exc:
        return refused(name, exc)

    observations = []
    for path in ["/robots.txt", "/security.txt", "/.well-known/security.txt"]:
        url = f"{base_url}{path}"
        result = fetch_text({"url": url, "timeout_seconds": policy.http_timeout_seconds}, policy)
        observations.append(
            {
                "path": path,
                "ok": result.ok,
                "status": result.data.get("status"),
                "bytes_read": result.data.get("bytes_read", 0),
                "present": result.ok and bool(result.data.get("text", "").strip()),
            }
        )
    return ToolResult(name=name, ok=True, data={"base_url": base_url, "resources": observations})


def tls_certificate(arguments: JsonObject, policy: LabPolicy) -> ToolResult:
    name = "recon.tls_certificate"
    try:
        target = require_string(arguments, "target")
        port = int(arguments.get("port", 443))
        timeout = parse_timeout(
            arguments.get("timeout_seconds"),
            default=policy.connect_timeout_seconds,
            maximum=5.0,
        )
        policy.assert_target_allowed(target)
        policy.assert_port_allowed(port)
    except (PolicyError, ValueError) as exc:
        return refused(name, PolicyError(str(exc)))

    context = ssl.create_default_context()
    try:
        with socket.create_connection((target, port), timeout=timeout) as sock:
            with context.wrap_socket(sock, server_hostname=target) as tls_sock:
                cert = tls_sock.getpeercert()
                cipher = tls_sock.cipher()
                version = tls_sock.version()
    except (OSError, ssl.SSLError) as exc:
        return ToolResult(name=name, ok=False, data={"target": target, "port": port, "error": str(exc)})

    subject = dict(item[0] for item in cert.get("subject", []) if item)
    issuer = dict(item[0] for item in cert.get("issuer", []) if item)
    return ToolResult(
        name=name,
        ok=True,
        data={
            "target": target,
            "port": port,
            "subject": subject,
            "issuer": issuer,
            "not_before": cert.get("notBefore"),
            "not_after": cert.get("notAfter"),
            "subject_alt_names": cert.get("subjectAltName", []),
            "tls_version": version,
            "cipher": cipher,
        },
    )


class PageIntelligenceParser(HTMLParser):
    def __init__(self) -> None:
        super().__init__()
        self.forms = 0
        self.password_inputs = 0
        self.external_scripts = 0
        self.inline_scripts = 0
        self.script_sources: list[str] = []
        self.links: set[str] = set()
        self.meta_generator = ""

    def handle_starttag(self, tag: str, attrs: list[tuple[str, str | None]]) -> None:
        attr_map = {key.lower(): value or "" for key, value in attrs}
        if tag == "form":
            self.forms += 1
        elif tag == "input" and attr_map.get("type", "").lower() == "password":
            self.password_inputs += 1
        elif tag == "script":
            src = attr_map.get("src")
            if src:
                self.external_scripts += 1
                self.script_sources.append(src)
            else:
                self.inline_scripts += 1
        elif tag == "a" and attr_map.get("href"):
            self.links.add(attr_map["href"])
        elif tag == "meta" and attr_map.get("name", "").lower() == "generator":
            self.meta_generator = attr_map.get("content", "")


def web_page_intel(arguments: JsonObject, policy: LabPolicy) -> ToolResult:
    name = "recon.web_page_intel"
    fetch = fetch_text(arguments, policy)
    if not fetch.ok:
        return ToolResult(name=name, ok=False, data=fetch.data, warnings=fetch.warnings)

    text = str(fetch.data.get("text", ""))
    parser = PageIntelligenceParser()
    parser.feed(text)
    indicators = {
        "forms": parser.forms,
        "password_inputs": parser.password_inputs,
        "external_scripts": parser.external_scripts,
        "inline_scripts": parser.inline_scripts,
        "unique_links": len(parser.links),
        "meta_generator": parser.meta_generator,
        "script_sources_sample": parser.script_sources[:10],
    }
    warnings = []
    if parser.password_inputs:
        warnings.append("Password input detected; verify HTTPS and form handling in the lab target.")
    if parser.inline_scripts:
        warnings.append("Inline scripts detected; review CSP compatibility and injection exposure.")
    return ToolResult(
        name=name,
        ok=True,
        data={"url": fetch.data.get("url"), "indicators": indicators},
        warnings=warnings,
    )
