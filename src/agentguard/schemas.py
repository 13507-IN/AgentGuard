"""Pydantic schemas for AgentGuard.

All data models used across the security layer: actions, decisions,
approvals, audit entries, and policy results.
"""

from __future__ import annotations

import hashlib
import json
import re
import uuid
from datetime import datetime, timezone
from enum import Enum
from typing import Any

from pydantic import BaseModel, Field


# ---------------------------------------------------------------------------
# Enums
# ---------------------------------------------------------------------------


class ActionType(str, Enum):
    """Types of actions an AI agent can propose."""

    SHELL_COMMAND = "shell_command"
    FILE_READ = "file_read"
    FILE_WRITE = "file_write"
    FILE_DELETE = "file_delete"
    DIRECTORY_LIST = "directory_list"
    NETWORK_REQUEST = "network_request"


class Decision(str, Enum):
    """Security decision outcomes."""

    ALLOW = "ALLOW"
    REQUIRE_APPROVAL = "REQUIRE_APPROVAL"
    BLOCK = "BLOCK"


class RiskCategory(str, Enum):
    """Risk severity levels."""

    NONE = "none"
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"


class ApprovalStatus(str, Enum):
    """Approval workflow states."""

    PENDING = "pending"
    APPROVED = "approved"
    REJECTED = "rejected"
    EXPIRED = "expired"


# ---------------------------------------------------------------------------
# Action Request
# ---------------------------------------------------------------------------


class ActionRequest(BaseModel):
    """A proposed action from an AI agent."""

    action_type: ActionType
    command: str | None = None
    resource: str | None = None
    arguments: dict[str, Any] = Field(default_factory=dict)
    working_directory: str | None = None
    task_context: str | None = None
    requested_by: str = "ai_agent"

    def compute_hash(self) -> str:
        """Compute a deterministic SHA-256 hash of this action.

        The hash binds approvals to the exact action. Any change
        in action_type, command, resource, arguments, or working_directory
        produces a different hash — invalidating previous approvals.
        """
        canonical = json.dumps(
            {
                "action_type": self.action_type.value,
                "command": self.command,
                "resource": self.resource,
                "arguments": self.arguments,
                "working_directory": self.working_directory,
            },
            sort_keys=True,
            separators=(",", ":"),
        )
        return hashlib.sha256(canonical.encode("utf-8")).hexdigest()

    def summary(self) -> str:
        """Return a human-readable one-line summary of the action."""
        if self.command:
            return f"{self.action_type.value}: {self.command}"
        if self.resource:
            return f"{self.action_type.value}: {self.resource}"
        return self.action_type.value


# ---------------------------------------------------------------------------
# Policy Result (returned by individual policy checks)
# ---------------------------------------------------------------------------


class PolicyResult(BaseModel):
    """Result from a single policy evaluation."""

    policy_id: str
    policy_name: str
    decision: Decision
    risk_category: RiskCategory
    explanation: str
    safer_alternative: str | None = None


# ---------------------------------------------------------------------------
# Security Decision (aggregated result from the policy engine)
# ---------------------------------------------------------------------------


class SecurityDecision(BaseModel):
    """Aggregated security decision from the policy engine."""

    decision: Decision
    risk_category: RiskCategory
    matched_policies: list[str] = Field(default_factory=list)
    explanation: str
    safer_alternative: str | None = None
    requires_approval: bool = False
    action_hash: str
    timestamp: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))


# ---------------------------------------------------------------------------
# Risk Explanation (from AI model)
# ---------------------------------------------------------------------------


class RiskExplanation(BaseModel):
    """AI-generated risk explanation for a security decision."""

    explanation: str
    consequences: str | None = None
    safer_alternative: str | None = None
    model_used: str | None = None
    generated: bool = True  # False if model was unavailable


# ---------------------------------------------------------------------------
# Approval Record
# ---------------------------------------------------------------------------


class ApprovalRecord(BaseModel):
    """An action-bound approval request."""

    approval_id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    action_hash: str
    action_summary: str
    action_details: dict[str, Any] = Field(default_factory=dict)
    risk_category: RiskCategory = RiskCategory.MEDIUM
    requested_at: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))
    expires_at: datetime
    status: ApprovalStatus = ApprovalStatus.PENDING
    decided_by: str | None = None
    decided_at: datetime | None = None


# ---------------------------------------------------------------------------
# Audit Entry
# ---------------------------------------------------------------------------


# Patterns for redacting secrets in output
_SECRET_PATTERNS = [
    re.compile(r"(?i)(api[_-]?key|token|secret|password|passwd|credential)\s*[=:]\s*\S+"),
    re.compile(r"(?i)(bearer\s+)\S+"),
    re.compile(r"(?i)(aws_access_key_id|aws_secret_access_key)\s*=\s*\S+"),
    re.compile(r"ghp_[A-Za-z0-9_]{36,}"),
    re.compile(r"sk-[A-Za-z0-9]{20,}"),
]


def redact_secrets(text: str | None) -> str | None:
    """Remove potential secrets from text for audit storage."""
    if text is None:
        return None
    result = text
    for pattern in _SECRET_PATTERNS:
        result = pattern.sub("[REDACTED]", result)
    return result


class AuditEntry(BaseModel):
    """A single audit log record."""

    entry_id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    action_type: str
    action_summary: str
    action_hash: str
    decision: Decision
    risk_category: RiskCategory
    matched_policies: list[str] = Field(default_factory=list)
    explanation: str = ""
    ai_explanation: str | None = None
    approval_status: ApprovalStatus | None = None
    approval_id: str | None = None
    execution_status: str | None = None  # "success", "failed", "timeout", "not_executed", "blocked"
    execution_output: str | None = None  # Truncated, redacted
    was_simulated: bool = False
    timestamp: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))
    duration_ms: int | None = None

    def redact(self) -> AuditEntry:
        """Return a copy with secrets redacted from output fields."""
        return self.model_copy(
            update={
                "execution_output": redact_secrets(self.execution_output),
                "action_summary": redact_secrets(self.action_summary) or self.action_summary,
            }
        )
