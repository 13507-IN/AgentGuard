"""Approval workflow manager for AgentGuard.

Approvals are bound to exact actions via hash to prevent tampering or replay attacks.
Only authorized human operators are permitted to grant approvals; AI agents and
automated identifiers are strictly rejected.
"""

from __future__ import annotations

import json
from datetime import datetime, timedelta, timezone
from typing import Any

from agentguard.config import AgentGuardConfig
from agentguard.db import Database
from agentguard.schemas import (
    ActionRequest,
    ApprovalRecord,
    ApprovalStatus,
    Decision,
    RiskCategory,
    SecurityDecision,
)

# Identifiers and substring patterns representing AI agents
_BLOCKED_IDENTIFIER_SUBSTRINGS: tuple[str, ...] = ("agent", "ai")
_EXPLICIT_AI_BLOCKLIST: frozenset[str] = frozenset(
    {
        "ai_agent",
        "agent",
        "ai",
        "bot",
        "llm",
        "assistant",
        "copilot",
        "autonomous",
        "model",
    }
)


def _validate_human_approver(decided_by: str) -> None:
    """Validate that the decision maker is not an AI agent.

    Raises:
        ValueError: If decided_by is empty, on the blocklist, or contains
            forbidden AI identifier substrings (case-insensitive).
    """
    if not decided_by or not decided_by.strip():
        raise ValueError("decided_by must be a non-empty string representing a human operator")

    cleaned = decided_by.strip().lower()

    for forbidden in _EXPLICIT_AI_BLOCKLIST | set(_BLOCKED_IDENTIFIER_SUBSTRINGS):
        if forbidden in cleaned:
            raise ValueError(
                f"Invalid approver '{decided_by}': AI agents cannot approve actions. "
                "Approvals must be made by authorized human reviewers."
            )


class ApprovalManager:
    """The approval workflow manager.

    Approvals are bound to exact actions via hash (tamper protection).
    """

    def __init__(self, db: Database, config: AgentGuardConfig) -> None:
        """Initialize ApprovalManager with database and configuration settings."""
        self.db = db
        self.timeout = config.approval_timeout_seconds

    async def create_request(
        self, action: ActionRequest, decision: SecurityDecision
    ) -> ApprovalRecord:
        """Create a pending approval request bound to the action's hash.

        Only creates if decision is REQUIRE_APPROVAL.

        Args:
            action: The proposed ActionRequest to be approved.
            decision: The SecurityDecision requiring approval.

        Returns:
            The created pending ApprovalRecord.

        Raises:
            ValueError: If the decision is not REQUIRE_APPROVAL.
        """
        if decision.decision != Decision.REQUIRE_APPROVAL:
            raise ValueError(
                f"Cannot create approval request: decision is {decision.decision.value}, "
                "only REQUIRE_APPROVAL decisions can be queued for approval."
            )

        now = datetime.now(timezone.utc)
        expires_at = now + timedelta(seconds=self.timeout)
        action_hash = action.compute_hash()

        if decision.action_hash and decision.action_hash != action_hash:
            raise ValueError(
                f"Action hash mismatch: action computes to {action_hash}, "
                f"but decision specifies {decision.action_hash}."
            )

        record = ApprovalRecord(
            action_hash=action_hash,
            action_summary=action.summary(),
            action_details=action.model_dump(mode="json"),
            risk_category=decision.risk_category,
            requested_at=now,
            expires_at=expires_at,
            status=ApprovalStatus.PENDING,
            decided_by=None,
            decided_at=None,
        )

        record_dict = {
            "approval_id": record.approval_id,
            "action_hash": record.action_hash,
            "action_summary": record.action_summary,
            "action_details": record.action_details,
            "risk_category": (
                record.risk_category.value
                if isinstance(record.risk_category, RiskCategory)
                else str(record.risk_category)
            ),
            "requested_at": record.requested_at.isoformat(),
            "expires_at": record.expires_at.isoformat(),
            "status": (
                record.status.value
                if isinstance(record.status, ApprovalStatus)
                else str(record.status)
            ),
            "decided_by": record.decided_by,
            "decided_at": None,
        }
        await self.db.insert_approval(record_dict)
        return record

    async def approve(self, approval_id: str, decided_by: str) -> ApprovalRecord:
        """Approve a pending request.

        CRITICAL RULES:
        - decided_by must NOT be 'ai_agent' or contain 'agent' or 'ai' (case-insensitive)
        - Must not be expired
        - Must be in PENDING status

        Args:
            approval_id: Unique ID of the approval request.
            decided_by: Identifier of the human approver.

        Returns:
            The updated ApprovalRecord with APPROVED status.

        Raises:
            ValueError: If any validation rule is violated or approval not found.
        """
        _validate_human_approver(decided_by)

        raw = await self.db.get_approval(approval_id)
        if raw is None:
            raise ValueError(f"Approval record '{approval_id}' not found.")

        record = self._to_record(raw)

        if record.status != ApprovalStatus.PENDING:
            raise ValueError(
                f"Approval request '{approval_id}' is not pending (current status: {record.status.value})."
            )

        now = datetime.now(timezone.utc)
        if record.expires_at <= now:
            await self.db.update_approval_status(
                approval_id, ApprovalStatus.EXPIRED.value
            )
            raise ValueError(f"Approval request '{approval_id}' has expired.")

        record.status = ApprovalStatus.APPROVED
        record.decided_by = decided_by
        record.decided_at = now

        await self.db.update_approval_status(
            approval_id,
            ApprovalStatus.APPROVED.value,
            decided_by=decided_by,
            decided_at=now.isoformat(),
        )

        return record

    async def reject(self, approval_id: str, decided_by: str) -> ApprovalRecord:
        """Reject a pending request.

        Args:
            approval_id: Unique ID of the approval request.
            decided_by: Identifier of the operator rejecting the request.

        Returns:
            The updated ApprovalRecord with REJECTED status.

        Raises:
            ValueError: If approval not found, not pending, or expired.
        """
        if not decided_by or not decided_by.strip():
            raise ValueError("decided_by must be a non-empty string.")

        raw = await self.db.get_approval(approval_id)
        if raw is None:
            raise ValueError(f"Approval record '{approval_id}' not found.")

        record = self._to_record(raw)

        if record.status != ApprovalStatus.PENDING:
            raise ValueError(
                f"Approval request '{approval_id}' is not pending (current status: {record.status.value})."
            )

        now = datetime.now(timezone.utc)
        if record.expires_at <= now:
            await self.db.update_approval_status(
                approval_id, ApprovalStatus.EXPIRED.value
            )
            raise ValueError(f"Approval request '{approval_id}' has expired.")

        record.status = ApprovalStatus.REJECTED
        record.decided_by = decided_by
        record.decided_at = now

        await self.db.update_approval_status(
            approval_id,
            ApprovalStatus.REJECTED.value,
            decided_by=decided_by,
            decided_at=now.isoformat(),
        )

        return record

    async def verify(self, approval_id: str, action_hash: str) -> bool:
        """Verify an approval is valid for execution.

        Rules:
        - Must be APPROVED status
        - Must not be expired
        - action_hash must EXACTLY match the stored hash (tamper protection)

        Args:
            approval_id: Unique ID of the approval request.
            action_hash: SHA-256 hash of the action attempting execution.

        Returns:
            True if valid and approved; False otherwise.
        """
        if not approval_id or not action_hash:
            return False

        raw = await self.db.get_approval(approval_id)
        if raw is None:
            return False

        record = self._to_record(raw)

        if record.status != ApprovalStatus.APPROVED:
            return False

        now = datetime.now(timezone.utc)
        if record.expires_at <= now:
            return False

        if record.action_hash != action_hash:
            return False

        return True

    async def get_pending(self) -> list[ApprovalRecord]:
        """Get all pending approval requests after expiring stale ones.

        Returns:
            List of pending ApprovalRecord instances.
        """
        await self.expire_stale()
        rows = await self.db.get_pending_approvals()
        return [self._to_record(row) for row in rows]

    async def get_record(self, approval_id: str) -> ApprovalRecord | None:
        """Get a specific approval record by its ID.

        Args:
            approval_id: Unique ID of the approval record.

        Returns:
            The ApprovalRecord if found, or None.
        """
        raw = await self.db.get_approval(approval_id)
        if raw is None:
            return None
        return self._to_record(raw)

    async def expire_stale(self) -> int:
        """Expire all pending approvals past their timeout.

        Returns:
            Count of expired approval requests.
        """
        return await self.db.expire_stale_approvals()

    @staticmethod
    def _to_record(data: dict[str, Any]) -> ApprovalRecord:
        """Convert a database row dictionary to an ApprovalRecord instance."""
        payload = dict(data)
        if isinstance(payload.get("action_details"), str):
            try:
                payload["action_details"] = json.loads(payload["action_details"])
            except Exception:
                payload["action_details"] = {}

        record = ApprovalRecord.model_validate(payload)
        if record.requested_at and record.requested_at.tzinfo is None:
            record.requested_at = record.requested_at.replace(tzinfo=timezone.utc)
        if record.expires_at and record.expires_at.tzinfo is None:
            record.expires_at = record.expires_at.replace(tzinfo=timezone.utc)
        if record.decided_at and record.decided_at.tzinfo is None:
            record.decided_at = record.decided_at.replace(tzinfo=timezone.utc)
        return record
