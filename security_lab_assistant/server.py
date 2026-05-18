from __future__ import annotations

import argparse
import json
import sys

from security_lab_assistant.mcp_protocol import handle_request
from security_lab_assistant.policy import LabPolicy, load_default_policy


def serve(policy: LabPolicy) -> None:
    for line in sys.stdin:
        line = line.strip()
        if not line:
            continue
        try:
            message = json.loads(line)
            response = handle_request(message, policy)
        except Exception as exc:
            response = {
                "jsonrpc": "2.0",
                "id": None,
                "error": {"code": -32603, "message": f"Internal error: {exc}"},
            }
        if response is not None:
            sys.stdout.write(json.dumps(response, separators=(",", ":")) + "\n")
            sys.stdout.flush()


def main() -> None:
    parser = argparse.ArgumentParser(description="Run the Autonomous Security Lab Assistant MCP server.")
    parser.add_argument("--policy", help="Path to lab policy JSON.")
    args = parser.parse_args()
    policy = LabPolicy.from_file(args.policy) if args.policy else load_default_policy()
    serve(policy)


if __name__ == "__main__":
    main()
