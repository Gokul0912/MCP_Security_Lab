from __future__ import annotations

from dataclasses import dataclass

from security_lab_assistant.models.base import SchemaRecord


@dataclass(frozen=True)
class OperationDeclaration:
    name: str
    required_permission: str
    required_role: str
    approval_level: str
    risk_class: str


@dataclass(frozen=True)
class ApprovalRecord(SchemaRecord):
    schema_version: str = "approval-record-v1"
    action: str = ""
    approver: str = ""
    role: str = ""
    reason: str = ""
    approval_level: str = ""


@dataclass(frozen=True)
class PolicyChangeRecord(SchemaRecord):
    schema_version: str = "policy-change-record-v1"
    policy_version: str = ""
    previous_policy_hash: str = ""
    new_policy_hash: str = ""
    author: str = ""
    reason: str = ""
