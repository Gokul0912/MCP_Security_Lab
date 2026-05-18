from __future__ import annotations

import json
from typing import Any


JsonObject = dict[str, Any]


def format_recon_result(payload: JsonObject) -> str:
    data = payload.get("data", payload)
    lines = [_header("Recon Run Summary")]
    lines.extend(
        [
            f"Status      : {data.get('status', 'unknown')}",
            f"Run ID      : {data.get('run_id', 'n/a')}",
            f"Target      : {data.get('target', 'n/a')}",
            f"Objective   : {data.get('objective', 'n/a')}",
        ]
    )
    risk = data.get("risk", {})
    if risk:
        lines.append(f"Risk        : {risk.get('score', 0)}/100 ({risk.get('band', 'unknown')})")
        drivers = risk.get("drivers", {})
        if drivers:
            lines.append(
                "Risk drivers: "
                + ", ".join(f"{name.replace('_', ' ')}={value}" for name, value in drivers.items())
            )

    open_ports = data.get("open_ports", [])
    lines.extend(["", _header("Network")])
    lines.append(f"Open ports  : {_comma_or_none(open_ports)}")

    counts = data.get("severity_counts", {})
    if counts:
        lines.extend(["", _header("Severity Counts")])
        for severity in ["critical", "high", "medium", "low", "informational"]:
            lines.append(f"{severity.title():13}: {counts.get(severity, 0)}")

    warnings = data.get("warnings", [])
    lines.extend(["", _header("Warnings")])
    if warnings:
        lines.extend(f"- {warning}" for warning in warnings)
    else:
        lines.append("No warnings.")

    findings = data.get("findings", [])
    lines.extend(["", _header("Findings")])
    if findings:
        for index, finding in enumerate(findings, start=1):
            lines.extend(
                [
                    f"{index}. {finding.get('title', 'Finding')}",
                    f"   Severity      : {finding.get('severity', 'unknown')}",
                    f"   Asset         : {finding.get('affected_asset', 'n/a')}",
                    f"   Category      : {finding.get('category', 'n/a')}",
                    f"   Confidence    : {finding.get('confidence', 'n/a')}",
                    f"   Evidence      : {finding.get('evidence', 'n/a')}",
                    f"   Recommendation: {finding.get('recommendation', 'n/a')}",
                ]
            )
    else:
        lines.append("No findings were generated.")

    steps = data.get("steps", [])
    if steps:
        lines.extend(["", _header("Workflow Steps")])
        for step in steps:
            status = "ok" if step.get("ok") else "failed"
            lines.append(f"- {step.get('tool', 'unknown')}: {status}")

    runtime = data.get("runtime", {})
    if runtime:
        trust = runtime.get("trust", {})
        cognition = runtime.get("security_cognition", {})
        confidence = runtime.get("confidence_calibration", {})
        integrity = runtime.get("evidence_integrity", {})
        replay = runtime.get("deterministic_replay", {})
        graph = runtime.get("attack_graph", {})
        critique = runtime.get("adversarial_critique", {})
        quality = runtime.get("reasoning_quality", {})
        benchmark = runtime.get("benchmark_suite", {})
        calibration = runtime.get("dynamic_trust_calibration", {})
        lines.extend(["", _header("Advanced Runtime")])
        if trust:
            lines.append(f"Trust score : {trust.get('score', 0)}/100 ({trust.get('band', 'unknown')})")
        if calibration:
            lines.append(
                f"Calibrated trust: {calibration.get('calibrated_score', 0)}/100 "
                f"({calibration.get('band', 'unknown')})"
            )
        if quality:
            lines.append(f"Reasoning quality: {quality.get('overall_score', 0)}")
        if benchmark:
            lines.append(f"Benchmark suite: {benchmark.get('score', 0)}")
        if cognition:
            primary = cognition.get("primary_interpretation", {})
            lines.append(
                f"Meaning     : {primary.get('name', 'n/a')} "
                f"({primary.get('confidence', cognition.get('calibrated_confidence', 0))})"
            )
        if confidence:
            lines.append(f"Confidence : {confidence.get('calibrated_confidence', 0)}")
        if integrity:
            lines.append(f"Evidence root hash: {integrity.get('root_hash', 'n/a')}")
        if replay:
            lines.append(f"Replay hash : {replay.get('workflow_hash', 'n/a')}")
        if graph:
            lines.append(f"Attack graph: {graph.get('summary', 'n/a')}")
        if critique:
            lines.append(f"Critique    : {critique.get('verdict', 'n/a')}")

    artifacts = [
        ("Run JSON", data.get("run_path")),
        ("Markdown report", data.get("report_path")),
        ("SARIF export", data.get("sarif_path")),
        ("Reasoning HTML", data.get("reasoning_visualizer_path")),
    ]
    present_artifacts = [(label, path) for label, path in artifacts if path]
    if present_artifacts:
        lines.extend(["", _header("Artifacts")])
        for label, path in present_artifacts:
            lines.append(f"{label:15}: {path}")

    return "\n".join(lines).rstrip() + "\n"


def format_runs_list(runs: list[JsonObject]) -> str:
    lines = [_header("Saved Runs")]
    if not runs:
        return "\n".join([*lines, "No saved runs yet."]) + "\n"

    for run in runs:
        lines.extend(
            [
                "",
                f"Run ID   : {run.get('run_id', 'n/a')}",
                f"Target   : {run.get('target', 'n/a')}",
                f"Status   : {run.get('status', 'n/a')}",
                f"Risk     : {run.get('risk_score', 0)}/100 ({run.get('risk_band', 'unknown')})",
                f"Findings : {run.get('findings_count', 0)}",
                f"Created  : {run.get('created_at', 'n/a')}",
            ]
        )
    return "\n".join(lines).rstrip() + "\n"


def format_run_details(payload: JsonObject) -> str:
    if "data" in payload:
        return format_recon_result(payload)
    return format_recon_result({"data": payload})


def format_runtime_section(payload: JsonObject) -> str:
    section = payload.get("section", "runtime")
    data = payload.get("data", {})
    lines = [_header(f"Runtime: {section}")]
    if isinstance(data, list):
        for index, item in enumerate(data, start=1):
            lines.append("")
            lines.append(f"{index}. {_compact_item(item)}")
    elif isinstance(data, dict):
        lines.extend(_format_mapping(data))
    else:
        lines.append(str(data))
    return "\n".join(lines).rstrip() + "\n"


def format_json(payload: JsonObject) -> str:
    return json.dumps(payload, indent=2, sort_keys=True)


def _header(value: str) -> str:
    return f"== {value} =="


def _comma_or_none(values: Any) -> str:
    if not values:
        return "none"
    return ", ".join(str(value) for value in values)


def _format_mapping(value: JsonObject, indent: int = 0) -> list[str]:
    lines: list[str] = []
    prefix = " " * indent
    for key, item in value.items():
        label = str(key).replace("_", " ").title()
        if isinstance(item, dict):
            lines.append(f"{prefix}{label}:")
            lines.extend(_format_mapping(item, indent + 2))
        elif isinstance(item, list):
            lines.append(f"{prefix}{label}:")
            if not item:
                lines.append(f"{prefix}  none")
            for entry in item:
                lines.append(f"{prefix}  - {_compact_item(entry)}")
        else:
            lines.append(f"{prefix}{label}: {item}")
    return lines


def _compact_item(value: Any) -> str:
    if isinstance(value, dict):
        return ", ".join(f"{key}={item}" for key, item in value.items())
    return str(value)
