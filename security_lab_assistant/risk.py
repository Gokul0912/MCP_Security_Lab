from __future__ import annotations

from security_lab_assistant.models import JsonObject, RunContext


SEVERITY_WEIGHTS = {
    "critical": 100,
    "high": 70,
    "medium": 40,
    "low": 15,
    "informational": 2,
}


def risk_score(run: RunContext) -> JsonObject:
    raw = sum(SEVERITY_WEIGHTS.get(finding.severity, 10) for finding in run.findings)
    exposed_service_bonus = 5 * len(_open_ports(run))
    warning_bonus = min(20, 2 * len(run.warnings))
    score = min(100, raw + exposed_service_bonus + warning_bonus)
    if score >= 80:
        band = "critical"
    elif score >= 60:
        band = "high"
    elif score >= 35:
        band = "medium"
    elif score > 0:
        band = "low"
    else:
        band = "informational"
    return {
        "score": score,
        "band": band,
        "drivers": {
            "finding_weight": raw,
            "open_service_bonus": exposed_service_bonus,
            "warning_bonus": warning_bonus,
        },
    }


def _open_ports(run: RunContext) -> list[int]:
    ports: list[int] = []
    for result in run.evidence:
        if result.name != "scan.tcp_connect":
            continue
        for item in result.data.get("ports", []):
            if item.get("status") == "open":
                ports.append(int(item["port"]))
    return ports
