from __future__ import annotations

import argparse
import json

from security_lab_assistant.policy import load_default_policy
from security_lab_assistant.storage import list_runs, load_run, search_runs
from security_lab_assistant.workflows.autonomous_recon import run_autonomous_recon


def main() -> None:
    parser = argparse.ArgumentParser(description="Run safe lab workflows without an MCP client.")
    subparsers = parser.add_subparsers(dest="command", required=True)

    recon = subparsers.add_parser("recon", help="Run autonomous recon against an in-scope lab target.")
    recon.add_argument("target")
    recon.add_argument("--ports", default="80,443,8000,8080,8443")
    recon.add_argument("--objective", default="baseline web reconnaissance")

    runs = subparsers.add_parser("runs", help="List persisted workflow runs.")
    runs.add_argument("--limit", type=int, default=20)

    search = subparsers.add_parser("search", help="Search persisted workflow runs.")
    search.add_argument("--query", default="")
    search.add_argument("--status", default="")
    search.add_argument("--limit", type=int, default=20)

    show = subparsers.add_parser("show", help="Show a persisted workflow run.")
    show.add_argument("run_id")

    subparsers.add_parser("gui", help="Launch the desktop GUI.")

    args = parser.parse_args()
    policy = load_default_policy()

    if args.command == "recon":
        ports = [int(port.strip()) for port in args.ports.split(",") if port.strip()]
        result = run_autonomous_recon(
            {"target": args.target, "ports": ports, "objective": args.objective},
            policy,
        )
        print(json.dumps({"ok": result.ok, "data": result.data}, indent=2))
    elif args.command == "runs":
        print(json.dumps({"runs": list_runs(policy, limit=args.limit)}, indent=2))
    elif args.command == "search":
        print(
            json.dumps(
                {"runs": search_runs(policy, query=args.query, status=args.status, limit=args.limit)},
                indent=2,
            )
        )
    elif args.command == "show":
        print(json.dumps(load_run(policy, args.run_id), indent=2))
    elif args.command == "gui":
        from security_lab_assistant.gui import SecurityLabGui

        app = SecurityLabGui(policy)
        app.mainloop()


if __name__ == "__main__":
    main()
