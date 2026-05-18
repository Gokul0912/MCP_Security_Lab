from __future__ import annotations

import argparse
import json

from security_lab_assistant.policy import load_default_policy
from security_lab_assistant.workflows.autonomous_recon import run_autonomous_recon


def main() -> None:
    parser = argparse.ArgumentParser(description="Run safe lab workflows without an MCP client.")
    subparsers = parser.add_subparsers(dest="command", required=True)

    recon = subparsers.add_parser("recon", help="Run autonomous recon against an in-scope lab target.")
    recon.add_argument("target")
    recon.add_argument("--ports", default="80,443,8000,8080,8443")
    recon.add_argument("--objective", default="baseline web reconnaissance")

    args = parser.parse_args()
    policy = load_default_policy()

    if args.command == "recon":
        ports = [int(port.strip()) for port in args.ports.split(",") if port.strip()]
        result = run_autonomous_recon(
            {"target": args.target, "ports": ports, "objective": args.objective},
            policy,
        )
        print(json.dumps({"ok": result.ok, "data": result.data}, indent=2))


if __name__ == "__main__":
    main()
