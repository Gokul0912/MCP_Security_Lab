from __future__ import annotations

import json
from dataclasses import dataclass
from datetime import UTC, datetime
from pathlib import Path

from security_lab_assistant.models import JsonObject, RunContext
from security_lab_assistant.policy import LabPolicy
from security_lab_assistant.platform import sign_payload
from security_lab_assistant.product import SCHEMA_VERSIONS
from security_lab_assistant.reasoning import stable_hash
from security_lab_assistant.runtimes.contracts import EVIDENCE_CONTRACT, RuntimeContract


@dataclass(frozen=True)
class EvidenceRuntime:
    policy: LabPolicy
    contract: RuntimeContract = EVIDENCE_CONTRACT

    def append_lineage(self, run: RunContext, event_type: str, payload: JsonObject) -> JsonObject:
        root = self.policy.artifact_root()
        lineage_dir = root / "lineage"
        lineage_dir.mkdir(parents=True, exist_ok=True)
        path = lineage_dir / f"{run.run_id}.lineage.jsonl"
        previous_hash = _last_hash(path)
        event = {
            "schema_version": SCHEMA_VERSIONS["lineage_record"],
            "run_id": run.run_id,
            "timestamp": datetime.now(UTC).isoformat(),
            "event_type": event_type,
            "payload": payload,
            "previous_hash": previous_hash,
            "runtime": self.contract.name,
        }
        event["event_hash"] = stable_hash(event)
        event["signature"] = sign_payload(self.policy, event, "evidence_lineage_record")
        with path.open("a", encoding="utf-8") as handle:
            handle.write(json.dumps(event, sort_keys=True) + "\n")
        return {"lineage_path": str(path), "event_hash": event["event_hash"]}

    def verify_lineage(self, run_id: str) -> JsonObject:
        path = self.policy.artifact_root() / "lineage" / f"{run_id}.lineage.jsonl"
        if not path.exists():
            return {"ok": True, "events": 0, "lineage_path": str(path)}
        previous = ""
        count = 0
        with path.open("r", encoding="utf-8") as handle:
            for index, line in enumerate(handle, start=1):
                event = json.loads(line)
                event_hash = str(event.pop("event_hash", ""))
                signature = event.pop("signature", {})
                if event.get("previous_hash") != previous:
                    return {"ok": False, "events": count, "line": index, "reason": "previous hash mismatch"}
                if stable_hash(event) != event_hash:
                    return {"ok": False, "events": count, "line": index, "reason": "event hash mismatch"}
                if signature.get("digest") != stable_hash({**event, "event_hash": event_hash}):
                    return {"ok": False, "events": count, "line": index, "reason": "signature digest mismatch"}
                previous = event_hash
                count += 1
        return {"ok": True, "events": count, "last_hash": previous, "lineage_path": str(path)}


def _last_hash(path: Path) -> str:
    if not path.exists():
        return ""
    last_line = ""
    with path.open("r", encoding="utf-8") as handle:
        for line in handle:
            if line.strip():
                last_line = line
    if not last_line:
        return ""
    try:
        return str(json.loads(last_line).get("event_hash", ""))
    except json.JSONDecodeError:
        return "CORRUPT"
