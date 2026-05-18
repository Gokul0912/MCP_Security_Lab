from __future__ import annotations

import argparse

from security_lab_assistant.output import (
    format_json,
    format_recon_result,
    format_run_details,
    format_runs_list,
    format_runtime_section,
)
from security_lab_assistant.policy import load_default_policy
from security_lab_assistant.storage import list_runs, load_run, search_runs
from security_lab_assistant.tools.intelligence import RUNTIME_SECTIONS
from security_lab_assistant.tools.registry import TOOLS
from security_lab_assistant.workflows.autonomous_recon import run_autonomous_recon


def main() -> None:
    parser = argparse.ArgumentParser(description="Run safe lab workflows without an MCP client.")
    subparsers = parser.add_subparsers(dest="command", required=True)

    recon = subparsers.add_parser("recon", help="Run autonomous recon against an in-scope lab target.")
    recon.add_argument("target")
    recon.add_argument("--ports", default="80,443,8000,8080,8443")
    recon.add_argument("--objective", default="baseline web reconnaissance")
    recon.add_argument("--json", action="store_true", help="Print raw JSON instead of a readable report.")

    runs = subparsers.add_parser("runs", help="List persisted workflow runs.")
    runs.add_argument("--limit", type=int, default=20)
    runs.add_argument("--json", action="store_true", help="Print raw JSON instead of a readable report.")

    search = subparsers.add_parser("search", help="Search persisted workflow runs.")
    search.add_argument("--query", default="")
    search.add_argument("--status", default="")
    search.add_argument("--limit", type=int, default=20)
    search.add_argument("--json", action="store_true", help="Print raw JSON instead of a readable report.")

    show = subparsers.add_parser("show", help="Show a persisted workflow run.")
    show.add_argument("run_id")
    show.add_argument("--json", action="store_true", help="Print raw JSON instead of a readable report.")

    runtime = subparsers.add_parser("runtime", help="Inspect advanced runtime metadata for a run.")
    runtime.add_argument("run_id")
    runtime.add_argument(
        "section",
        choices=sorted(RUNTIME_SECTIONS),
        help="Runtime section to inspect.",
    )
    runtime.add_argument("--json", action="store_true", help="Print raw JSON instead of a readable report.")

    batch = subparsers.add_parser("batch", help="Run approved recon across multiple in-scope targets.")
    batch.add_argument("targets", help="Comma-separated target list.")
    batch.add_argument("--ports", default="80,443,8000,8080,8443")
    batch.add_argument("--objective", default="batch baseline web reconnaissance")
    batch.add_argument("--role", default="reviewer")
    batch.add_argument("--approved", action="store_true")
    batch.add_argument("--json", action="store_true", help="Print raw JSON instead of a readable report.")

    verify = subparsers.add_parser("verify", help="Verify audit chain and artifact signatures.")
    verify.add_argument("--role", default="auditor")
    verify.add_argument("--deep", action="store_true", help="Run forensic verification across replay, lineage, manifests, policy, and benchmarks.")
    verify.add_argument("--no-quarantine", action="store_true", help="Do not quarantine compromised runs during deep verification.")
    verify.add_argument("--json", action="store_true", help="Print raw JSON instead of a readable report.")

    ops = subparsers.add_parser("ops", help="Inspect local events or metrics.")
    ops.add_argument("section", choices=["events", "metrics", "contracts", "workflows", "queue", "failures", "platform"])
    ops.add_argument("--role", default="auditor")
    ops.add_argument("--json", action="store_true", help="Print raw JSON instead of a readable report.")

    subparsers.add_parser("gui", help="Launch the desktop GUI.")

    args = parser.parse_args()
    policy = load_default_policy()

    if args.command == "recon":
        ports = [int(port.strip()) for port in args.ports.split(",") if port.strip()]
        result = run_autonomous_recon(
            {"target": args.target, "ports": ports, "objective": args.objective},
            policy,
        )
        payload = {"ok": result.ok, "data": result.data}
        print(format_json(payload) if args.json else format_recon_result(payload))
    elif args.command == "runs":
        runs_payload = list_runs(policy, limit=args.limit)
        payload = {"runs": runs_payload}
        print(format_json(payload) if args.json else format_runs_list(runs_payload))
    elif args.command == "search":
        runs_payload = search_runs(policy, query=args.query, status=args.status, limit=args.limit)
        payload = {"runs": runs_payload}
        print(format_json(payload) if args.json else format_runs_list(runs_payload))
    elif args.command == "show":
        payload = load_run(policy, args.run_id)
        print(format_json(payload) if args.json else format_run_details(payload))
    elif args.command == "runtime":
        payload = load_run(policy, args.run_id)
        runtime_data = payload.get("runtime", {})
        runtime_key = RUNTIME_SECTIONS[args.section]
        section_payload = {
            "run_id": args.run_id,
            "section": args.section,
            "runtime_key": runtime_key,
            "data": runtime_data.get(runtime_key, {}),
        }
        print(format_json(section_payload) if args.json else format_runtime_section(section_payload))
    elif args.command == "batch":
        targets = [target.strip() for target in args.targets.split(",") if target.strip()]
        ports = [int(port.strip()) for port in args.ports.split(",") if port.strip()]
        result = TOOLS["workflow.batch_recon"].handler(
            {
                "targets": targets,
                "ports": ports,
                "objective": args.objective,
                "role": args.role,
                "approved": args.approved,
            },
            policy,
        )
        payload = {"ok": result.ok, "data": result.data}
        print(format_json(payload) if args.json else format_runtime_section({"section": "batch", "data": payload}))
    elif args.command == "verify":
        if args.deep:
            result = TOOLS["run.verify_deep"].handler(
                {"role": args.role, "quarantine": not args.no_quarantine},
                policy,
            )
            payload = {"ok": result.ok and result.data.get("ok", False), "data": result.data}
        else:
            audit = TOOLS["run.verify_audit"].handler({"role": args.role}, policy)
            artifacts = TOOLS["run.verify_artifacts"].handler({"role": args.role}, policy)
            payload = {"audit": audit.data, "artifacts": artifacts.data, "ok": audit.ok and artifacts.ok}
        print(format_json(payload) if args.json else format_runtime_section({"section": "verify", "data": payload}))
    elif args.command == "ops":
        tool_name = {
            "events": "ops.events",
            "metrics": "ops.metrics",
            "contracts": "ops.runtime_contracts",
            "workflows": "ops.workflows",
            "queue": "ops.queue",
            "failures": "ops.failure_taxonomy",
            "platform": "ops.platform",
        }[args.section]
        result = TOOLS[tool_name].handler({"role": args.role}, policy)
        payload = {"ok": result.ok, "data": result.data}
        print(format_json(payload) if args.json else format_runtime_section({"section": args.section, "data": payload}))
    elif args.command == "gui":
        from security_lab_assistant.gui import SecurityLabGui

        app = SecurityLabGui(policy)
        app.mainloop()


if __name__ == "__main__":
    main()
