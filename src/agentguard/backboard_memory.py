"""Backboard.io long-term persistent memory integration for AgentGuard.

Provides cross-session memory, incident retention, and autonomous agent governance
using the official backboard-sdk.
"""

from __future__ import annotations

import asyncio
import logging
import uuid
from typing import Any

from backboard import BackboardClient
from backboard.exceptions import BackboardError

from agentguard.config import AgentGuardConfig
from agentguard.schemas import ActionRequest, ActionType, Decision, SecurityDecision

logger = logging.getLogger("agentguard.memory")

ASSISTANT_NAME = "AgentGuard-Governor"
ASSISTANT_DESCRIPTION = "Autonomous security-governed developer agent with persistent Backboard memory"
ASSISTANT_SYSTEM_PROMPT = (
    "You are an AI software developer operating under strict AgentGuard Runtime Security Governance. "
    "All shell commands, file modifications, and package installations are checked against security policies. "
    "You have persistent long-term memory powered by Backboard to remember previous approvals, blocked actions, "
    "and user workspace preferences."
)


class BackboardMemoryManager:
    """Manages persistent memory and autonomous agent runs via Backboard.io."""

    def __init__(self, config: AgentGuardConfig | None = None) -> None:
        self.config = config or AgentGuardConfig.from_env()
        self.api_key = self.config.backboard_api_key
        self._client: BackboardClient | None = None
        self._assistant_id: str | None = None
        self._assistant_lock = asyncio.Lock()

        if self.api_key:
            try:
                self._client = BackboardClient(api_key=self.api_key)
                logger.info("BackboardClient initialized with provided API key")
            except Exception as exc:
                logger.warning("Failed to initialize BackboardClient: %s", exc)

    def is_available(self) -> bool:
        """Check if Backboard memory service is configured and available."""
        return self._client is not None and bool(self.api_key)

    async def get_or_create_assistant(self) -> str:
        """Get or lazily create the persistent AgentGuard Assistant in Backboard."""
        if not self.is_available():
            raise RuntimeError("Backboard API key is not configured")

        if self._assistant_id:
            return self._assistant_id

        async with self._assistant_lock:
            if self._assistant_id:
                return self._assistant_id

            assert self._client is not None
            assistants = await self._client.list_assistants()
            for a in assistants:
                if a.name == ASSISTANT_NAME:
                    self._assistant_id = str(a.assistant_id)
                    logger.info("Found existing Backboard assistant: %s", self._assistant_id)
                    return self._assistant_id

            # Create new assistant in Backboard
            new_assistant = await self._client.create_assistant(
                name=ASSISTANT_NAME,
                description=ASSISTANT_DESCRIPTION,
                system_prompt=ASSISTANT_SYSTEM_PROMPT,
            )
            self._assistant_id = str(new_assistant.assistant_id)
            logger.info("Created new Backboard assistant: %s", self._assistant_id)
            return self._assistant_id

    async def add_memory(self, content: str, metadata: dict[str, Any] | None = None) -> dict[str, Any]:
        """Store a new long-term memory in Backboard."""
        if not self.is_available():
            return {"error": "Backboard not configured"}

        try:
            assistant_id = await self.get_or_create_assistant()
            assert self._client is not None
            res = await self._client.add_memory(
                assistant_id=assistant_id,
                content=content,
                metadata=metadata or {},
            )
            logger.info("Stored Backboard memory: %s", content[:60])
            return res if isinstance(res, dict) else {"status": "success", "result": str(res)}
        except Exception as exc:
            logger.error("Failed to add Backboard memory: %s", exc)
            return {"error": str(exc)}

    async def get_memories(self, limit: int = 50) -> list[dict[str, Any]]:
        """Retrieve all long-term memories stored in Backboard."""
        if not self.is_available():
            return []

        try:
            assistant_id = await self.get_or_create_assistant()
            assert self._client is not None
            resp = await self._client.get_memories(assistant_id=assistant_id, page_size=limit)
            mems = getattr(resp, "memories", [])
            output = []
            for m in mems:
                output.append({
                    "id": getattr(m, "id", str(uuid.uuid4())),
                    "content": getattr(m, "content", ""),
                    "created_at": getattr(m, "created_at", None),
                    "score": getattr(m, "score", None),
                    "metadata": getattr(m, "metadata", {}),
                })
            return output
        except Exception as exc:
            logger.error("Failed to fetch Backboard memories: %s", exc)
            return []

    async def record_security_decision(
        self,
        action: ActionRequest,
        decision: SecurityDecision,
        was_approved: bool | None = None,
    ) -> None:
        """Record a security decision to Backboard memory for future context."""
        if not self.is_available():
            return

        summary = action.summary()
        dec_val = decision.decision.value if hasattr(decision.decision, "value") else str(decision.decision)
        policies = ", ".join(decision.matched_policies) if decision.matched_policies else "default"

        if dec_val == Decision.BLOCK.value:
            mem_text = f"Security Policy Block: Action '{summary}' was BLOCKED under policy [{policies}]. Reason: {decision.explanation}"
        elif dec_val == Decision.REQUIRE_APPROVAL.value:
            if was_approved is True:
                mem_text = f"Human Approval Granted: Action '{summary}' was approved by human operator and executed."
            elif was_approved is False:
                mem_text = f"Human Approval Rejected: Action '{summary}' was rejected by human operator."
            else:
                mem_text = f"Security Authorization Required: Action '{summary}' requires human approval under [{policies}]."
        else:
            mem_text = f"Security Policy Permitted: Action '{summary}' was verified safe and permitted under [{policies}]."

        await self.add_memory(
            content=mem_text,
            metadata={
                "action_type": str(action.action_type),
                "decision": dec_val,
                "action_hash": decision.action_hash,
            },
        )
