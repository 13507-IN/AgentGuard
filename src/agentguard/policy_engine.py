"""AgentGuard Policy Engine.

Central orchestrator for evaluating AI agent actions against security policies.
Aggregates policy results, resolves conflicting decisions using strict priority rules
(BLOCK > REQUIRE_APPROVAL > ALLOW), and enforces fail-closed defaults.
"""

from __future__ import annotations

import asyncio
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from agentguard.config import AgentGuardConfig
from agentguard.policies.base import Policy
from agentguard.policies.filesystem_policies import (
    DirectoryListPolicy,
    FileDeletionPolicy,
    FileReadPolicy,
    FileWritePolicy,
    PathTraversalPolicy,
    ProtectedDirectoryPolicy,
    SecretFilePolicy,
    WorkspaceBoundaryPolicy,
)
from agentguard.policies.shell_policies import (
    CommandChainingPolicy,
    DangerousCommandPolicy,
    DestructiveCommandPolicy,
    NetworkExfilPolicy,
    PrivilegeEscalationPolicy,
    SafeReadOnlyPolicy,
)
from agentguard.schemas import (
    ActionRequest,
    Decision,
    PolicyResult,
    RiskCategory,
    SecurityDecision,
)

# Priority order for risk severity
_RISK_ORDER: dict[RiskCategory, int] = {
    RiskCategory.NONE: 0,
    RiskCategory.LOW: 1,
    RiskCategory.MEDIUM: 2,
    RiskCategory.HIGH: 3,
    RiskCategory.CRITICAL: 4,
}


def _highest_risk(risks: list[RiskCategory]) -> RiskCategory:
    """Return the highest severity risk category from a list."""
    if not risks:
        return RiskCategory.NONE
    return max(risks, key=lambda r: _RISK_ORDER.get(r, 0))


class PolicyEngine:
    """Central policy evaluation engine for AgentGuard.

    Coordinates all loaded security policies, evaluates proposed agent actions,
    and returns authoritative security decisions.
    """

    def __init__(self, config: AgentGuardConfig) -> None:
        """Initialize PolicyEngine with configuration and default policies.

        Args:
            config: AgentGuard configuration instance.
        """
        self.config = config
        self.policies: list[Policy] = []
        self._load_default_policies()

    def _load_default_policies(self) -> None:
        """Register all built-in policies from shell and filesystem policy modules."""
        self.policies = [
            # Shell policies
            DestructiveCommandPolicy(),
            DangerousCommandPolicy(),
            CommandChainingPolicy(),
            PrivilegeEscalationPolicy(),
            SafeReadOnlyPolicy(),
            NetworkExfilPolicy(),
            # Filesystem policies
            WorkspaceBoundaryPolicy(),
            PathTraversalPolicy(),
            SecretFilePolicy(),
            ProtectedDirectoryPolicy(),
            FileDeletionPolicy(),
            FileReadPolicy(),
            FileWritePolicy(),
            DirectoryListPolicy(),
        ]

    async def evaluate(self, action: ActionRequest) -> SecurityDecision:
        """Evaluate an action against ALL enabled policies.

        Decision resolution rules:
        1. Run all enabled policies concurrently.
        2. BLOCK wins over everything (CRITICAL/HIGH risk).
        3. REQUIRE_APPROVAL wins over ALLOW.
        4. If no policies match -> default to REQUIRE_APPROVAL (fail-closed).

        Args:
            action: The proposed ActionRequest from an agent.

        Returns:
            The authoritative SecurityDecision.
        """
        action_hash = action.compute_hash()
        workspace = self.config.resolved_workspace

        enabled_policies = [p for p in self.policies if p.enabled]

        # Evaluate all enabled policies concurrently
        raw_results: list[PolicyResult | None] = await asyncio.gather(
            *(p.evaluate(action, workspace) for p in enabled_policies),
            return_exceptions=False,
        )

        # Collect non-None matching policy results
        matched: list[PolicyResult] = [r for r in raw_results if r is not None]

        # 4. If no policies match -> default to REQUIRE_APPROVAL (fail-closed)
        if not matched:
            return SecurityDecision(
                decision=Decision.REQUIRE_APPROVAL,
                risk_category=RiskCategory.MEDIUM,
                matched_policies=[],
                explanation="No matching security policy found. Requiring human approval by default (fail-closed).",
                safer_alternative=None,
                requires_approval=True,
                action_hash=action_hash,
                timestamp=datetime.now(timezone.utc),
            )

        matched_policy_ids = [r.policy_id for r in matched]

        # 2. BLOCK wins over everything
        blocks = [r for r in matched if r.decision == Decision.BLOCK]
        if blocks:
            max_risk = _highest_risk([r.risk_category for r in blocks])
            explanation = "\n".join(r.explanation for r in blocks)
            safer_alt = next((r.safer_alternative for r in blocks if r.safer_alternative), None)
            return SecurityDecision(
                decision=Decision.BLOCK,
                risk_category=max_risk,
                matched_policies=matched_policy_ids,
                explanation=explanation,
                safer_alternative=safer_alt,
                requires_approval=False,
                action_hash=action_hash,
                timestamp=datetime.now(timezone.utc),
            )

        # 3. REQUIRE_APPROVAL wins over ALLOW
        approvals = [r for r in matched if r.decision == Decision.REQUIRE_APPROVAL]
        if approvals:
            max_risk = _highest_risk([r.risk_category for r in approvals])
            explanation = "\n".join(r.explanation for r in approvals)
            safer_alt = next((r.safer_alternative for r in approvals if r.safer_alternative), None)
            return SecurityDecision(
                decision=Decision.REQUIRE_APPROVAL,
                risk_category=max_risk,
                matched_policies=matched_policy_ids,
                explanation=explanation,
                safer_alternative=safer_alt,
                requires_approval=True,
                action_hash=action_hash,
                timestamp=datetime.now(timezone.utc),
            )

        # All matched are ALLOW
        allows = [r for r in matched if r.decision == Decision.ALLOW]
        max_risk = _highest_risk([r.risk_category for r in allows])
        explanation = "; ".join(r.explanation for r in allows)
        safer_alt = next((r.safer_alternative for r in allows if r.safer_alternative), None)
        return SecurityDecision(
            decision=Decision.ALLOW,
            risk_category=max_risk,
            matched_policies=matched_policy_ids,
            explanation=explanation,
            safer_alternative=safer_alt,
            requires_approval=False,
            action_hash=action_hash,
            timestamp=datetime.now(timezone.utc),
        )

    def get_policies(self) -> list[dict[str, Any]]:
        """Return list of all registered policies with their configuration status."""
        return [
            {
                "policy_id": p.policy_id,
                "name": p.name,
                "description": p.description,
                "enabled": p.enabled,
                "is_mandatory": p.is_mandatory,
            }
            for p in self.policies
        ]

    def get_policy(self, policy_id: str) -> Policy | None:
        """Find and return a registered policy by its ID.

        Args:
            policy_id: The unique identifier of the policy.

        Returns:
            The Policy instance if found, or None.
        """
        for p in self.policies:
            if p.policy_id == policy_id:
                return p
        return None

    def set_policy_enabled(self, policy_id: str, enabled: bool) -> bool:
        """Enable or disable a policy by ID. Mandatory policies cannot be disabled.

        Args:
            policy_id: The unique identifier of the policy.
            enabled: Desired enabled status.

        Returns:
            True if the status was successfully updated, False otherwise.
        """
        for p in self.policies:
            if p.policy_id == policy_id:
                if p.is_mandatory and not enabled:
                    return False
                p.enabled = enabled
                return True
        return False

    def add_policy(self, policy: Policy) -> None:
        """Add a custom policy to the engine.

        Args:
            policy: Policy instance to add.
        """
        self.policies.append(policy)

    def remove_policy(self, policy_id: str) -> bool:
        """Remove a non-mandatory policy by its ID.

        Args:
            policy_id: The unique identifier of the policy to remove.

        Returns:
            True if removed, False if not found or mandatory.
        """
        for i, p in enumerate(self.policies):
            if p.policy_id == policy_id:
                if p.is_mandatory:
                    return False
                del self.policies[i]
                return True
        return False
