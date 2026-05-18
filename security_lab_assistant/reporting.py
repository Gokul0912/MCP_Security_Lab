from __future__ import annotations

from security_lab_assistant.models import JsonObject, RunContext
from security_lab_assistant.risk import risk_score


SEVERITY_ORDER = {"critical": 0, "high": 1, "medium": 2, "low": 3, "informational": 4}


def severity_counts(run: RunContext) -> JsonObject:
    counts: JsonObject = {"critical": 0, "high": 0, "medium": 0, "low": 0, "informational": 0}
    for finding in run.findings:
        counts[finding.severity] = int(counts.get(finding.severity, 0)) + 1
    return counts


def render_markdown_report(run: RunContext) -> str:
    counts = severity_counts(run)
    risk = risk_score(run)
    lines = [
        f"# Security Lab Run Report: {run.target}",
        "",
        f"- Run ID: `{run.run_id}`",
        f"- Objective: {run.objective}",
        f"- Status: {run.status}",
        f"- Risk: {risk['score']}/100 ({risk['band']})",
        f"- Created: {run.created_at}",
        f"- Phases: {', '.join(run.phases) if run.phases else 'none'}",
        "",
        "## Severity Summary",
        "",
        "| Severity | Count |",
        "| --- | ---: |",
    ]
    for severity in ["critical", "high", "medium", "low", "informational"]:
        lines.append(f"| {severity.title()} | {counts.get(severity, 0)} |")

    lines.extend(["", "## Findings", ""])
    if not run.findings:
        lines.append("No findings were generated for this run.")
    else:
        ordered = sorted(run.findings, key=lambda finding: SEVERITY_ORDER.get(finding.severity, 99))
        for index, finding in enumerate(ordered, start=1):
            lines.extend(
                [
                    f"### {index}. {finding.title}",
                    "",
                    f"- Severity: {finding.severity}",
                    f"- Affected asset: {finding.affected_asset or run.target}",
                    f"- Category: {finding.category}",
                    f"- Confidence: {finding.confidence}",
                    f"- Evidence: {finding.evidence}",
                    f"- Recommendation: {finding.recommendation}",
                    "",
                ]
            )

    lines.extend(["## Evidence", ""])
    for item in run.evidence:
        lines.extend(
            [
                f"### {item.name}",
                "",
                f"- OK: `{item.ok}`",
                f"- Warnings: {', '.join(item.warnings) if item.warnings else 'none'}",
                "",
                "```json",
                _compact_json(item.data),
                "```",
                "",
            ]
        )
    return "\n".join(lines).rstrip() + "\n"


def _compact_json(value: JsonObject) -> str:
    import json

    return json.dumps(value, indent=2, sort_keys=True)
