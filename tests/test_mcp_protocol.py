from __future__ import annotations

import unittest

from security_lab_assistant.mcp_protocol import handle_request
from security_lab_assistant.policy import load_default_policy


class McpProtocolTests(unittest.TestCase):
    def test_initialize_response_advertises_tools(self) -> None:
        response = handle_request({"jsonrpc": "2.0", "id": 1, "method": "initialize"}, load_default_policy())
        self.assertIsNotNone(response)
        assert response is not None
        self.assertEqual(response["result"]["capabilities"]["tools"], {})

    def test_tools_list_includes_workflow(self) -> None:
        response = handle_request({"jsonrpc": "2.0", "id": 2, "method": "tools/list"}, load_default_policy())
        self.assertIsNotNone(response)
        assert response is not None
        names = {tool["name"] for tool in response["result"]["tools"]}
        self.assertIn("workflow.autonomous_recon", names)
        self.assertIn("scope.validate", names)

    def test_tools_call_returns_structured_refusal(self) -> None:
        response = handle_request(
            {
                "jsonrpc": "2.0",
                "id": 3,
                "method": "tools/call",
                "params": {"name": "scope.validate", "arguments": {"target": "8.8.8.8"}},
            },
            load_default_policy(),
        )
        self.assertIsNotNone(response)
        assert response is not None
        self.assertTrue(response["result"]["isError"])
        self.assertIn(
            "outside the lab scope",
            response["result"]["structuredContent"]["data"]["refusal"],
        )


if __name__ == "__main__":
    unittest.main()
