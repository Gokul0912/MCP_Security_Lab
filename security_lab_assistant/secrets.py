from __future__ import annotations

import base64
import hashlib
import json
import os
from datetime import UTC, datetime
from uuid import uuid4

from security_lab_assistant.models import JsonObject
from security_lab_assistant.policy import LabPolicy
from security_lab_assistant.storage import append_audit_event, ensure_artifact_dirs


SECRET_REF_PREFIX = "secretref:"


def store_local_secret(policy: LabPolicy, name: str, value: str, *, actor: str = "admin") -> JsonObject:
    root = ensure_artifact_dirs(policy)
    secret_id = f"{SECRET_REF_PREFIX}{uuid4()}"
    payload = {
        "secret_id": secret_id,
        "name": name,
        "created_at": datetime.now(UTC).isoformat(),
        "ciphertext": _encrypt(policy, value),
        "provider": "encrypted-local-file",
    }
    path = root / "private" / "secrets.jsonl"
    with path.open("a", encoding="utf-8") as handle:
        handle.write(json.dumps(payload, sort_keys=True) + "\n")
    append_audit_event(policy, "secret.stored", {"secret_id": secret_id, "name": name, "actor": actor})
    return {"secret_id": secret_id, "name": name, "provider": payload["provider"]}


def resolve_secret(policy: LabPolicy, secret_ref: str, *, actor: str = "worker") -> str:
    if not secret_ref.startswith(SECRET_REF_PREFIX):
        raise ValueError("secret_ref must be a secret reference, not a raw secret.")
    path = ensure_artifact_dirs(policy) / "private" / "secrets.jsonl"
    if not path.exists():
        raise KeyError("No local secrets are stored.")
    with path.open("r", encoding="utf-8") as handle:
        for line in handle:
            if not line.strip():
                continue
            payload = json.loads(line)
            if payload.get("secret_id") == secret_ref:
                append_audit_event(policy, "secret.accessed", {"secret_id": secret_ref, "actor": actor})
                return _decrypt(policy, str(payload["ciphertext"]))
    raise KeyError(f"Unknown secret reference: {secret_ref}")


def redact_secrets(value: JsonObject) -> JsonObject:
    def redact(item: object) -> object:
        if isinstance(item, str) and item.startswith(SECRET_REF_PREFIX):
            return f"{SECRET_REF_PREFIX}REDACTED"
        if isinstance(item, dict):
            return {str(key): redact(val) for key, val in item.items()}
        if isinstance(item, list):
            return [redact(entry) for entry in item]
        return item

    return redact(value)  # type: ignore[return-value]


def _encrypt(policy: LabPolicy, value: str) -> str:
    data = value.encode("utf-8")
    stream = _keystream(policy, len(data))
    encrypted = bytes(byte ^ stream[index] for index, byte in enumerate(data))
    return base64.b64encode(encrypted).decode("ascii")


def _decrypt(policy: LabPolicy, ciphertext: str) -> str:
    data = base64.b64decode(ciphertext.encode("ascii"))
    stream = _keystream(policy, len(data))
    decrypted = bytes(byte ^ stream[index] for index, byte in enumerate(data))
    return decrypted.decode("utf-8")


def _keystream(policy: LabPolicy, size: int) -> bytes:
    root = ensure_artifact_dirs(policy)
    key_path = root / "private" / "local_secret.key"
    if not key_path.exists():
        key_path.write_bytes(os.urandom(32))
    key = key_path.read_bytes()
    output = b""
    counter = 0
    while len(output) < size:
        output += hashlib.sha256(key + counter.to_bytes(8, "big")).digest()
        counter += 1
    return output[:size]
