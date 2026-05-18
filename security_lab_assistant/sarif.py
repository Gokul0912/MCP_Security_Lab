from __future__ import annotations

from dataclasses import asdict

from security_lab_assistant.models import JsonObject, RunContext


SEVERITY_TO_LEVEL = {
    "critical": "error",
    "high": "error",
    "medium": "warning",
    "low": "note",
    "informational": "none",
}


def render_sarif(run: RunContext) -> JsonObject:
    rules: dict[str, JsonObject] = {}
    results: list[JsonObject] = []

    for finding in run.findings:
        rule_id = _rule_id(finding.category, finding.title)
        rules.setdefault(
            rule_id,
            {
                "id": rule_id,
                "name": finding.title,
                "shortDescription": {"text": finding.title},
                "fullDescription": {"text": finding.recommendation},
                "properties": {
                    "category": finding.category,
                    "confidence": finding.confidence,
                    "severity": finding.severity,
                },
            },
        )
        results.append(
            {
                "ruleId": rule_id,
                "level": SEVERITY_TO_LEVEL.get(finding.severity, "warning"),
                "message": {"text": finding.evidence},
                "locations": [
                    {
                        "physicalLocation": {
                            "artifactLocation": {"uri": finding.affected_asset or run.target}
                        }
                    }
                ],
                "properties": asdict(finding),
            }
        )

    return {
        "$schema": "https://json.schemastore.org/sarif-2.1.0.json",
        "version": "2.1.0",
        "runs": [
            {
                "tool": {
                    "driver": {
                        "name": "Autonomous Security Lab Assistant",
                        "informationUri": "https://modelcontextprotocol.io/",
                        "rules": list(rules.values()),
                    }
                },
                "invocations": [
                    {
                        "executionSuccessful": run.status == "completed",
                        "properties": {
                            "run_id": run.run_id,
                            "target": run.target,
                            "objective": run.objective,
                            "status": run.status,
                        },
                    }
                ],
                "results": results,
            }
        ],
    }


def _rule_id(category: str, title: str) -> str:
    slug = "".join(character.lower() if character.isalnum() else "-" for character in title).strip("-")
    while "--" in slug:
        slug = slug.replace("--", "-")
    return f"asla.{category}.{slug or 'finding'}"
