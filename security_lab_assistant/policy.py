from __future__ import annotations

import ipaddress
import json
import re
import socket
from dataclasses import dataclass
from pathlib import Path
from urllib.parse import urlparse


class PolicyError(ValueError):
    """Raised when a requested action violates lab policy."""


@dataclass(frozen=True)
class LabPolicy:
    name: str
    allowed_cidrs: tuple[ipaddress._BaseNetwork, ...]
    allowed_hostnames: tuple[str, ...]
    allow_dns_targets: bool
    blocked_ports: tuple[int, ...]
    allowed_schemes: tuple[str, ...]
    max_redirects: int
    connect_timeout_seconds: float
    http_timeout_seconds: float
    max_tcp_ports_per_scan: int
    max_scan_workers: int
    max_http_bytes: int
    artifacts_dir: str

    @classmethod
    def from_file(cls, path: str | Path) -> "LabPolicy":
        raw = json.loads(Path(path).read_text(encoding="utf-8"))
        return cls(
            name=raw["name"],
            allowed_cidrs=tuple(ipaddress.ip_network(cidr) for cidr in raw["allowed_cidrs"]),
            allowed_hostnames=tuple(normalize_target(hostname) for hostname in raw.get("allowed_hostnames", [])),
            allow_dns_targets=bool(raw.get("allow_dns_targets", False)),
            blocked_ports=tuple(int(port) for port in raw.get("blocked_ports", [])),
            allowed_schemes=tuple(raw.get("allowed_schemes", ["http", "https"])),
            max_redirects=int(raw.get("max_redirects", 0)),
            connect_timeout_seconds=float(raw.get("connect_timeout_seconds", 1.0)),
            http_timeout_seconds=float(raw.get("http_timeout_seconds", 3.0)),
            max_tcp_ports_per_scan=int(raw.get("max_tcp_ports_per_scan", 32)),
            max_scan_workers=int(raw.get("max_scan_workers", 16)),
            max_http_bytes=int(raw.get("max_http_bytes", 262144)),
            artifacts_dir=str(raw.get("artifacts_dir", ".security_lab_assistant")),
        )

    def resolve_target(self, target: str) -> list[ipaddress._BaseAddress]:
        target = normalize_target(target)
        if target in self.allowed_hostnames:
            return [ipaddress.ip_address("127.0.0.1")]
        try:
            return [ipaddress.ip_address(target)]
        except ValueError:
            pass
        if not self.allow_dns_targets:
            raise PolicyError(
                f"Hostname '{target}' is not explicitly allowlisted and DNS targets are disabled."
            )

        try:
            infos = socket.getaddrinfo(target, None, type=socket.SOCK_STREAM)
        except socket.gaierror as exc:
            raise PolicyError(f"Unable to resolve target '{target}'.") from exc

        addresses = sorted({info[4][0] for info in infos})
        return [ipaddress.ip_address(address) for address in addresses]

    def assert_target_allowed(self, target: str) -> list[str]:
        target = normalize_target(target)
        addresses = self.resolve_target(target)
        denied = [
            str(address)
            for address in addresses
            if not any(address in network for network in self.allowed_cidrs)
        ]
        if denied:
            raise PolicyError(
                f"Target '{target}' resolves outside the lab scope: {', '.join(denied)}."
            )
        return [str(address) for address in addresses]

    def assert_port_allowed(self, port: int) -> None:
        if not 1 <= port <= 65535:
            raise PolicyError(f"Port {port} is outside the valid TCP range.")
        if port in self.blocked_ports:
            raise PolicyError(f"Port {port} is blocked by lab policy.")

    def assert_port_scan_allowed(self, ports: list[int]) -> None:
        if not ports:
            raise PolicyError("At least one TCP port is required.")
        if len(ports) > self.max_tcp_ports_per_scan:
            raise PolicyError(
                f"Requested {len(ports)} ports; policy allows at most "
                f"{self.max_tcp_ports_per_scan} per scan."
            )
        for port in ports:
            self.assert_port_allowed(port)

    def assert_url_allowed(self, url: str) -> tuple[str, int | None]:
        if any(ord(character) < 32 for character in url):
            raise PolicyError("URL must not contain control characters.")
        parsed = urlparse(url)
        if parsed.params:
            raise PolicyError("URL parameters are not allowed for lab tooling.")
        if parsed.username or parsed.password:
            raise PolicyError("URLs with embedded credentials are not allowed.")
        if parsed.scheme not in self.allowed_schemes:
            raise PolicyError(f"Only these URL schemes are allowed: {', '.join(self.allowed_schemes)}.")
        if not parsed.hostname:
            raise PolicyError("URL must include a hostname.")
        if parsed.fragment:
            raise PolicyError("URL fragments are not allowed for lab tooling.")
        self.assert_target_allowed(parsed.hostname)
        try:
            port = parsed.port
        except ValueError as exc:
            raise PolicyError("URL port is invalid.") from exc
        if port is not None:
            self.assert_port_allowed(port)
        return parsed.hostname, port

    def artifact_root(self) -> Path:
        project_root = Path(__file__).resolve().parent.parent
        configured = Path(self.artifacts_dir)
        if configured.is_absolute():
            raise PolicyError("artifacts_dir must be relative to the project root.")
        root = (project_root / configured).resolve()
        if project_root not in root.parents and root != project_root:
            raise PolicyError("artifacts_dir must stay inside the project root.")
        return root


def normalize_target(target: str) -> str:
    normalized = target.strip().lower().rstrip(".")
    if not normalized:
        raise PolicyError("target must be a non-empty hostname or IP address.")
    if any(character.isspace() for character in normalized):
        raise PolicyError("target must not contain whitespace.")
    if any(ord(character) < 32 for character in normalized):
        raise PolicyError("target must not contain control characters.")
    if "/" in normalized or "\\" in normalized or "@" in normalized:
        raise PolicyError("target must be a hostname or IP address, not a URL or path.")
    if ":" in normalized and not _looks_like_ipv6(normalized):
        raise PolicyError("target must not include a port.")
    if "%" in normalized:
        raise PolicyError("IPv6 zone identifiers are not allowed.")
    try:
        ipaddress.ip_address(normalized)
        return normalized
    except ValueError:
        pass
    if len(normalized) > 253:
        raise PolicyError("hostname is too long.")
    hostname_re = re.compile(r"^(?=.{1,253}$)(?!-)[a-z0-9-]{1,63}(?<!-)(\.(?!-)[a-z0-9-]{1,63}(?<!-))*$")
    if not hostname_re.match(normalized):
        raise PolicyError("target must be a valid hostname or IP address.")
    return normalized


def _looks_like_ipv6(value: str) -> bool:
    try:
        ipaddress.IPv6Address(value)
        return True
    except ValueError:
        return False


def default_policy_path() -> Path:
    return Path(__file__).resolve().parent.parent / "configs" / "lab_policy.json"


def load_default_policy() -> LabPolicy:
    return LabPolicy.from_file(default_policy_path())
