from __future__ import annotations

import ipaddress
import json
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
    blocked_ports: tuple[int, ...]
    max_tcp_ports_per_scan: int
    max_http_bytes: int

    @classmethod
    def from_file(cls, path: str | Path) -> "LabPolicy":
        raw = json.loads(Path(path).read_text(encoding="utf-8"))
        return cls(
            name=raw["name"],
            allowed_cidrs=tuple(ipaddress.ip_network(cidr) for cidr in raw["allowed_cidrs"]),
            allowed_hostnames=tuple(raw.get("allowed_hostnames", [])),
            blocked_ports=tuple(int(port) for port in raw.get("blocked_ports", [])),
            max_tcp_ports_per_scan=int(raw.get("max_tcp_ports_per_scan", 32)),
            max_http_bytes=int(raw.get("max_http_bytes", 262144)),
        )

    def resolve_target(self, target: str) -> list[ipaddress._BaseAddress]:
        if target in self.allowed_hostnames:
            return [ipaddress.ip_address("127.0.0.1")]
        try:
            return [ipaddress.ip_address(target)]
        except ValueError:
            pass

        try:
            infos = socket.getaddrinfo(target, None, type=socket.SOCK_STREAM)
        except socket.gaierror as exc:
            raise PolicyError(f"Unable to resolve target '{target}'.") from exc

        addresses = sorted({info[4][0] for info in infos})
        return [ipaddress.ip_address(address) for address in addresses]

    def assert_target_allowed(self, target: str) -> list[str]:
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
        if len(ports) > self.max_tcp_ports_per_scan:
            raise PolicyError(
                f"Requested {len(ports)} ports; policy allows at most "
                f"{self.max_tcp_ports_per_scan} per scan."
            )
        for port in ports:
            self.assert_port_allowed(port)

    def assert_url_allowed(self, url: str) -> tuple[str, int | None]:
        parsed = urlparse(url)
        if parsed.scheme not in {"http", "https"}:
            raise PolicyError("Only http and https URLs are allowed.")
        if not parsed.hostname:
            raise PolicyError("URL must include a hostname.")
        self.assert_target_allowed(parsed.hostname)
        port = parsed.port
        if port is not None:
            self.assert_port_allowed(port)
        return parsed.hostname, port


def default_policy_path() -> Path:
    return Path(__file__).resolve().parent.parent / "configs" / "lab_policy.json"


def load_default_policy() -> LabPolicy:
    return LabPolicy.from_file(default_policy_path())
