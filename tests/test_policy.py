from __future__ import annotations

import unittest

from security_lab_assistant.policy import PolicyError, load_default_policy


class PolicyTests(unittest.TestCase):
    def test_default_policy_allows_localhost(self) -> None:
        policy = load_default_policy()
        self.assertIn("127.0.0.1", policy.assert_target_allowed("localhost"))

    def test_default_policy_blocks_public_ip(self) -> None:
        policy = load_default_policy()
        with self.assertRaises(PolicyError):
            policy.assert_target_allowed("8.8.8.8")

    def test_policy_blocks_mail_ports(self) -> None:
        policy = load_default_policy()
        with self.assertRaises(PolicyError):
            policy.assert_port_allowed(25)

    def test_policy_limits_scan_size(self) -> None:
        policy = load_default_policy()
        with self.assertRaises(PolicyError):
            policy.assert_port_scan_allowed(list(range(1, 40)))


if __name__ == "__main__":
    unittest.main()
