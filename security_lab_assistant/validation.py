from __future__ import annotations

import re
from typing import Any
from uuid import UUID

from security_lab_assistant.policy import PolicyError


MAX_STRING_LENGTH = 4096
RUN_ID_RE = re.compile(r"^[0-9a-fA-F-]{36}$")
SAFE_STATUS_VALUES = {"", "running", "completed", "failed", "refused"}


def require_string(arguments: dict[str, Any], key: str) -> str:
    value = arguments.get(key)
    if not isinstance(value, str) or not value.strip():
        raise PolicyError(f"{key} must be a non-empty string.")
    stripped = value.strip()
    if len(stripped) > MAX_STRING_LENGTH:
        raise PolicyError(f"{key} is too long.")
    if any(ord(character) < 32 for character in stripped):
        raise PolicyError(f"{key} must not contain control characters.")
    return stripped


def require_run_id(arguments: dict[str, Any], key: str = "run_id") -> str:
    value = require_string(arguments, key)
    if not RUN_ID_RE.match(value):
        raise PolicyError(f"{key} must be a UUID.")
    try:
        parsed = UUID(value)
    except ValueError as exc:
        raise PolicyError(f"{key} must be a valid UUID.") from exc
    return str(parsed)


def bounded_optional_string(value: Any, name: str, maximum: int = 256) -> str:
    if value is None:
        return ""
    if not isinstance(value, str):
        raise PolicyError(f"{name} must be a string.")
    stripped = value.strip()
    if len(stripped) > maximum:
        raise PolicyError(f"{name} is too long.")
    if any(ord(character) < 32 for character in stripped):
        raise PolicyError(f"{name} must not contain control characters.")
    return stripped


def parse_limit(value: Any, default: int = 20, maximum: int = 100) -> int:
    if value is None:
        return default
    if isinstance(value, bool):
        raise PolicyError("limit must be an integer.")
    try:
        limit = int(value)
    except (TypeError, ValueError) as exc:
        raise PolicyError("limit must be an integer.") from exc
    if limit < 0:
        raise PolicyError("limit must not be negative.")
    return min(limit, maximum)


def parse_status(value: Any) -> str:
    status = bounded_optional_string(value, "status", maximum=32)
    if status not in SAFE_STATUS_VALUES:
        raise PolicyError("status is not a recognized run status.")
    return status


def parse_timeout(value: Any, default: float, maximum: float) -> float:
    if value is None:
        return default
    try:
        timeout = float(value)
    except (TypeError, ValueError) as exc:
        raise PolicyError("timeout_seconds must be numeric.") from exc
    if timeout <= 0:
        raise PolicyError("timeout_seconds must be greater than zero.")
    return min(timeout, maximum)


def parse_ports(value: Any) -> list[int]:
    if value is None:
        return []
    if not isinstance(value, list):
        raise PolicyError("ports must be an array of integers.")

    ports: list[int] = []
    for item in value:
        if isinstance(item, bool):
            raise PolicyError("ports must contain integers, not booleans.")
        try:
            port = int(item)
        except (TypeError, ValueError) as exc:
            raise PolicyError(f"Invalid TCP port value: {item!r}.") from exc
        ports.append(port)
    return sorted(set(ports))
