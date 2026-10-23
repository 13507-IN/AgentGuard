"""AI Risk Explainer using Ollama for AgentGuard.

Provides natural language security explanations and safer alternative recommendations
for proposed AI agent actions evaluated by the policy engine.
"""

from __future__ import annotations

import httpx

from agentguard.config import AgentGuardConfig
from agentguard.schemas import (
    ActionRequest,
    ActionType,
    Decision,
    RiskExplanation,
    SecurityDecision,
)


class RiskExplainer:
    """AI risk explainer that interfaces with Ollama.

    Generates human-readable context and alternatives for flagged actions
    without ever overriding policy decisions.
    """

    def __init__(self, config: AgentGuardConfig) -> None:
        """Initialize RiskExplainer with configuration settings."""
        self.base_url = config.ollama_base_url
        self.model = config.ollama_model
        self.timeout = config.ai_timeout_seconds
        self.enabled = config.ai_enabled

    async def explain(
        self, action: ActionRequest, decision: SecurityDecision
    ) -> RiskExplanation | None:
        """Generate AI risk explanation. Returns None if unavailable.

        MUST:
        - Return None (not raise) if Ollama is unreachable
        - Return None if response times out
        - Never override the policy decision
        - Use httpx for async HTTP requests to Ollama API

        Args:
            action: The proposed ActionRequest.
            decision: The SecurityDecision produced by the policy engine.

        Returns:
            A RiskExplanation instance if generation succeeds, or None.
        """
        if not self.enabled:
            return None

        try:
            command_or_resource = (
                action.command
                if action.command is not None
                else (action.resource if action.resource is not None else action.summary())
            )
            action_type = (
                action.action_type.value
                if isinstance(action.action_type, ActionType)
                else str(action.action_type)
            )
            decision_val = (
                decision.decision.value
                if isinstance(decision.decision, Decision)
                else str(decision.decision)
            )
            matched_policies_str = (
                ", ".join(decision.matched_policies) if decision.matched_policies else "None"
            )

            prompt = (
                "You are a security analyst reviewing an AI agent's proposed action.\n\n"
                f"Action: {action_type} — {command_or_resource}\n"
                f"Policy Decision: {decision_val}\n"
                f"Matched Rules: {matched_policies_str}\n\n"
                "In 2-3 sentences:\n"
                f"1. Explain why this action was {decision_val}.\n"
                "2. Describe the potential consequences if executed unsafely.\n"
                "3. If blocked or requiring approval, suggest a safer alternative.\n\n"
                "Be concise and technical. Do not override the policy decision."
            )

            url = f"{self.base_url.rstrip('/')}/api/generate"
            payload = {
                "model": self.model,
                "prompt": prompt,
                "stream": False,
                "options": {
                    "temperature": 0.2,
                    "num_predict": 120,
                },
            }

            async with httpx.AsyncClient(timeout=float(self.timeout)) as client:
                response = await client.post(url, json=payload)
                if response.status_code != 200:
                    return None

                data = response.json()
                raw_text = data.get("response", "").strip()
                if not raw_text:
                    return None

                consequences: str | None = None
                safer_alt: str | None = decision.safer_alternative

                for line in raw_text.splitlines():
                    stripped = line.strip()
                    lower = stripped.lower()
                    if lower.startswith(("2.", "2)", "consequences:", "consequence:")):
                        parts = stripped.split(":", 1) if ":" in stripped else stripped.split(".", 1)
                        if len(parts) > 1 and parts[1].strip():
                            consequences = parts[1].strip()
                    elif lower.startswith(("3.", "3)", "safer alternative:", "alternative:")):
                        parts = stripped.split(":", 1) if ":" in stripped else stripped.split(".", 1)
                        if len(parts) > 1 and parts[1].strip():
                            safer_alt = parts[1].strip()

                return RiskExplanation(
                    explanation=raw_text,
                    consequences=consequences,
                    safer_alternative=safer_alt,
                    model_used=self.model,
                    generated=True,
                )
        except Exception:
            return None

    async def is_available(self) -> bool:
        """Check if Ollama is reachable.

        Returns:
            True if Ollama responded with 200 status; False otherwise.
        """
        if not self.enabled:
            return False

        try:
            url = f"{self.base_url.rstrip('/')}/api/tags"
            async with httpx.AsyncClient(timeout=min(float(self.timeout), 3.0)) as client:
                response = await client.get(url)
                return response.status_code == 200
        except Exception:
            return False
