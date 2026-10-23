"""Abstract base class for AgentGuard security policies."""

from __future__ import annotations

from abc import ABC, abstractmethod
from pathlib import Path

from agentguard.schemas import ActionRequest, PolicyResult


class Policy(ABC):
    """Abstract base class for all AgentGuard security policies.
    
    Subclasses represent specific inspection rules for actions proposed by AI agents.
    Policies can be mandatory (cannot be disabled by users) or configurable.
    """

    policy_id: str
    name: str
    description: str
    enabled: bool = True
    is_mandatory: bool = False  # If True, cannot be disabled via UI

    def __init__(
        self,
        enabled: bool | None = None,
        is_mandatory: bool | None = None,
    ) -> None:
        if enabled is not None:
            self.enabled = enabled
        if is_mandatory is not None:
            self.is_mandatory = is_mandatory

    @abstractmethod
    async def evaluate(self, action: ActionRequest, workspace: Path) -> PolicyResult | None:
        """Evaluate action. Return PolicyResult if policy applies, None if not."""
