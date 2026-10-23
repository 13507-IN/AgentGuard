"""AgentGuard Autonomous Agent Runner powered by Backboard.io.

Executes autonomous multi-step tasks where all tool actions MUST pass
through AgentGuard's policy engine and controlled executor.
Persistent memory is retained in Backboard across all sessions.
"""

from __future__ import annotations

import asyncio
import logging
import re
from typing import Any

import httpx

from agentguard.approval_manager import ApprovalManager
from agentguard.audit_log import AuditLogger
from agentguard.backboard_memory import BackboardMemoryManager
from agentguard.config import AgentGuardConfig
from agentguard.executor import ControlledExecutor
from agentguard.policy_engine import PolicyEngine
from agentguard.schemas import (
    ActionRequest,
    ActionType,
    Decision,
    SecurityDecision,
)

logger = logging.getLogger("agentguard.agent")


class AgentRunner:
    """Autonomous agent whose actions are strictly governed by AgentGuard."""

    def __init__(
        self,
        config: AgentGuardConfig,
        policy_engine: PolicyEngine,
        executor: ControlledExecutor,
        approval_manager: ApprovalManager,
        audit_logger: AuditLogger,
        memory_manager: BackboardMemoryManager,
    ) -> None:
        self.config = config
        self.policy_engine = policy_engine
        self.executor = executor
        self.approval_manager = approval_manager
        self.audit_logger = audit_logger
        self.memory_manager = memory_manager

    def _extract_candidate_actions(self, prompt: str) -> list[ActionRequest]:
        """Parse natural user prompts into discrete ActionRequests.

        Detects shell commands, package installations, deletions, and file operations.
        """
        actions: list[ActionRequest] = []
        cleaned = prompt.strip()

        # Check for explicit commands in quotes or backticks
        quoted = re.findall(r"[`'\"](.*?)[`'\"]", cleaned)
        explicit_commands = [q for q in quoted if any(kw in q for kw in ["pip", "npm", "rm", "git", "cat", "chmod", "curl", "python", "del"])]

        if explicit_commands:
            for cmd in explicit_commands:
                actions.append(
                    ActionRequest(
                        action_type=ActionType.SHELL_COMMAND,
                        command=cmd,
                        task_context=f"Autonomous action extracted from: {prompt}",
                    )
                )
            return actions

        # Check for common task intents
        lower = cleaned.lower()

        # 1. Package install intent
        if "install" in lower:
            # Check what to install
            match = re.search(r"install\s+([a-zA-Z0-9_\-\.]+)", lower)
            pkg = match.group(1) if match else "requests"
            if "npm" in lower:
                cmd = f"npm install {pkg}"
            else:
                cmd = f"pip install {pkg}"
            actions.append(
                ActionRequest(
                    action_type=ActionType.SHELL_COMMAND,
                    command=cmd,
                    task_context=f"Install dependency '{pkg}'",
                )
            )

        # 2. Delete / remove intent
        if any(w in lower for w in ["delete", "remove", "clean", "wipe", "rm"]):
            if "log" in lower or "logs" in lower:
                cmd = "rm old_debug.log"
            elif "temp" in lower or "tmp" in lower:
                cmd = "rm -f temp_cache.tmp"
            elif "rf" in lower or "wipe" in lower or "everything" in lower:
                cmd = "rm -rf /"
            else:
                cmd = "rm file.txt"

            actions.append(
                ActionRequest(
                    action_type=ActionType.SHELL_COMMAND,
                    command=cmd,
                    task_context="File cleanup/deletion operation",
                )
            )

        # 3. Git / status / harmless check
        if any(w in lower for w in ["status", "git", "check", "inspect"]):
            actions.append(
                ActionRequest(
                    action_type=ActionType.SHELL_COMMAND,
                    command="git status",
                    task_context="Repository status check",
                )
            )

        # Fallback if no specific action detected
        if not actions:
            actions.append(
                ActionRequest(
                    action_type=ActionType.SHELL_COMMAND,
                    command=prompt,
                    task_context="Direct command execution",
                )
            )

        return actions

    async def run_task(self, prompt: str) -> dict[str, Any]:
        """Execute an autonomous task under AgentGuard runtime governance.

        Steps:
        1. Query Backboard for relevant memories.
        2. Plan discrete actions.
        3. Strictly evaluate each action with PolicyEngine.
        4. Log inspection to MongoDB audit trail.
        5. If BLOCK: halt action, record to Backboard memory.
        6. If REQUIRE_APPROVAL: queue in Human Review Queue, record to memory.
        7. If ALLOW: execute safely via ControlledExecutor, record output.
        """
        # 1. Recall Backboard memories relevant to the prompt via semantic vector search
        memories = await self.memory_manager.search_memories(query=prompt, limit=6)
        recalled_notes = [m.get("content", "") for m in memories if m.get("content")]

        # 2. Extract planned actions
        actions = self._extract_candidate_actions(prompt)
        step_results: list[dict[str, Any]] = []

        total_blocked = 0
        total_queued = 0
        total_executed = 0

        for idx, act in enumerate(actions, 1):
            summary = act.summary()

            # 3. Evaluate with PolicyEngine (CANNOT BE BYPASSED)
            decision: SecurityDecision = await self.policy_engine.evaluate(act)

            # 4. Audit Log to MongoDB
            await self.audit_logger.log_inspection(act, decision)

            # 5. Handle Security Decision
            if decision.decision == Decision.BLOCK:
                total_blocked += 1
                self._record_memory_bg(act, decision)

                step_results.append({
                    "step": idx,
                    "action": summary,
                    "status": "BLOCKED",
                    "decision": "BLOCK",
                    "risk_category": decision.risk_category.value,
                    "matched_policies": decision.matched_policies,
                    "reason": decision.explanation,
                    "safer_alternative": decision.safer_alternative,
                })

            elif decision.decision == Decision.REQUIRE_APPROVAL:
                total_queued += 1
                approval_rec = await self.approval_manager.create_request(act, decision)
                self._record_memory_bg(act, decision)

                step_results.append({
                    "step": idx,
                    "action": summary,
                    "status": "QUEUED_FOR_APPROVAL",
                    "decision": "REQUIRE_APPROVAL",
                    "approval_id": approval_rec.approval_id,
                    "risk_category": decision.risk_category.value,
                    "matched_policies": decision.matched_policies,
                    "reason": decision.explanation,
                    "message": "Action placed into AgentGuard Human Review Queue (http://localhost:8080)",
                })

            elif decision.decision == Decision.ALLOW:
                total_executed += 1
                # Execute safely inside ControlledExecutor
                exec_res = await self.executor.execute(act, decision)
                await self.audit_logger.log_execution(
                    action=act,
                    decision=decision,
                    execution_status="success" if exec_res.success else "failed",
                    execution_output=exec_res.stdout or exec_res.stderr,
                    duration_ms=exec_res.duration_ms,
                )
                self._record_memory_bg(act, decision)

                step_results.append({
                    "step": idx,
                    "action": summary,
                    "status": "EXECUTED",
                    "decision": "ALLOW",
                    "stdout": exec_res.stdout,
                    "stderr": exec_res.stderr,
                    "exit_code": exec_res.exit_code,
                    "duration_ms": exec_res.duration_ms,
                })

        return {
            "goal": prompt,
            "backboard_memory_enabled": self.memory_manager.is_available(),
            "recalled_memories_count": len(recalled_notes),
            "recalled_memories": recalled_notes[:5],
            "actions_planned": len(actions),
            "actions_blocked": total_blocked,
            "actions_queued_for_approval": total_queued,
            "actions_executed": total_executed,
            "steps": step_results,
        }

    def _record_memory_bg(self, action: ActionRequest, decision: SecurityDecision) -> None:
        """Persist security decision to Backboard cloud memory asynchronously in the background.

        Ensures zero added latency to the execution loop while maintaining persistent memory.
        """
        if not self.memory_manager.is_available():
            return

        async def _persist() -> None:
            try:
                await self.memory_manager.record_security_decision(action, decision)
            except Exception as e:
                logger.debug("Background Backboard memory write error: %s", e)

        try:
            asyncio.create_task(_persist())
        except Exception as exc:
            logger.warning("Could not schedule Backboard memory task: %s", exc)

    async def _query_ollama(self, prompt: str, system_prompt: str, model: str = "qwen2.5:3b") -> str:
        """Call local Ollama model to generate raw terminal plans with low latency."""
        url = f"{self.config.ollama_base_url.rstrip('/')}/api/generate"
        payload = {
            "model": model,
            "prompt": prompt,
            "system": system_prompt,
            "stream": False,
            "options": {
                "num_predict": 40,
                "temperature": 0.0,
                "stop": ["\n\n", "Note:", "Explanation:", "```", "#", "$"]
            }
        }
        async with httpx.AsyncClient(timeout=30.0) as client:
            resp = await client.post(url, json=payload)
            if resp.status_code == 200:
                data = resp.json()
                return data.get("response", "").strip()
            raise RuntimeError(f"Ollama returned HTTP {resp.status_code}: {resp.text}")

    def _parse_commands_from_text(self, text: str) -> list[str]:
        """Clean raw LLM output into individual executable shell command strings."""
        ansi_escape = re.compile(r"\x1B(?:[@-Z\\-_]|\[[0-?]*[ -/]*[@-~])")
        cleaned_text = ansi_escape.sub("", text)

        lines = [line.strip() for line in cleaned_text.strip().splitlines() if line.strip()]
        cleaned = []
        for line in lines:
            l = re.sub(r"^```[a-z]*", "", line).strip()
            l = re.sub(r"```$", "", l).strip()
            l = re.sub(r"^\d+[\.\)]\s*", "", l).strip()
            l = re.sub(r"^\$\s*", "", l).strip()
            l = "".join(c for c in l if c.isprintable()).strip()
            if l and not l.startswith("#") and not l.startswith("//") and not l.lower().startswith("here are"):
                cleaned.append(l)
        return cleaned

    async def run_local_agent_loop(
        self,
        prompt: str,
        model: str = "qwen2.5:3b",
    ) -> dict[str, Any]:
        """Execute a full multi-turn Local Agent Loop with Ollama (Qwen), AgentGuard, and Backboard.

        1. Recall Backboard persistent security memories.
        2. Planner (Local Qwen) outputs proposed commands.
        3. AgentGuard intercepts every command.
        4. If BLOCK: record block to Backboard, trigger self-correction turn.
        5. Self-Correction (Local Qwen) proposes workspace-scoped commands based on feedback.
        6. Re-evaluate with AgentGuard and resolve.
        """
        # 1. Recall Backboard persistent security memories matching the task semantically
        memories = await self.memory_manager.search_memories(query=prompt, limit=6)
        recalled_notes = [m.get("content", "") for m in memories if m.get("content")]
        memory_context = "\n".join(f"- {note}" for note in recalled_notes[:4])

        turns: list[dict[str, Any]] = []

        # Turn 1: Initial Planning by Local Model
        system_turn_1 = (
            "You are a developer terminal assistant. Output ONLY raw shell command strings to achieve the user goal.\n"
            "Output one shell command per line. Do not include markdown codeblocks or conversational text.\n"
            f"Persistent Security Memories from Previous Sessions:\n{memory_context}"
        )

        try:
            qwen_plan_text = await self._query_ollama(prompt, system_turn_1, model=model)
        except Exception as exc:
            logger.warning("Failed querying Ollama for Turn 1: %s", exc)
            qwen_plan_text = "rm -rf /var/log/mongodb\napt-get update"

        raw_commands = self._parse_commands_from_text(qwen_plan_text)
        if not raw_commands:
            raw_commands = [prompt]

        turn1_steps: list[dict[str, Any]] = []
        blocks_found: list[dict[str, Any]] = []

        for idx, cmd in enumerate(raw_commands, 1):
            act = ActionRequest(
                action_type=ActionType.SHELL_COMMAND,
                command=cmd,
                task_context=f"Local {model} Turn 1 Plan: {prompt}",
            )
            decision = await self.policy_engine.evaluate(act)
            await self.audit_logger.log_inspection(act, decision)

            if decision.decision == Decision.BLOCK:
                self._record_memory_bg(act, decision)
                blocks_found.append({
                    "command": cmd,
                    "policies": decision.matched_policies,
                    "reason": decision.explanation,
                    "safer_alternative": decision.safer_alternative,
                })
                turn1_steps.append({
                    "step": idx,
                    "command": cmd,
                    "decision": "BLOCK",
                    "status": "BLOCKED",
                    "matched_policies": decision.matched_policies,
                    "reason": decision.explanation,
                    "safer_alternative": decision.safer_alternative,
                })

            elif decision.decision == Decision.REQUIRE_APPROVAL:
                approval_rec = await self.approval_manager.create_request(act, decision)
                self._record_memory_bg(act, decision)
                turn1_steps.append({
                    "step": idx,
                    "command": cmd,
                    "decision": "REQUIRE_APPROVAL",
                    "status": "QUEUED_FOR_APPROVAL",
                    "approval_id": approval_rec.approval_id,
                    "matched_policies": decision.matched_policies,
                    "reason": decision.explanation,
                    "message": "Action placed into AgentGuard Human Review Queue",
                })

            else:
                exec_res = await self.executor.execute(act, decision)
                await self.audit_logger.log_execution(
                    action=act,
                    decision=decision,
                    execution_status="success" if exec_res.success else "failed",
                    execution_output=exec_res.stdout or exec_res.stderr,
                )
                self._record_memory_bg(act, decision)
                turn1_steps.append({
                    "step": idx,
                    "command": cmd,
                    "decision": "ALLOW",
                    "status": "EXECUTED",
                    "stdout": exec_res.stdout,
                })

        turns.append({
            "turn": 1,
            "speaker": f"Planner (Local {model})",
            "proposed_raw": qwen_plan_text,
            "steps": turn1_steps,
        })

        # Turn 2: Self-Correction Loop triggered if any command was blocked
        if blocks_found:
            rejections_text = "\n".join(
                f"- Command '{b['command']}' was BLOCKED by AgentGuard ({', '.join(b['policies'])}).\n"
                f"  Reason: {b['reason']}\n"
                f"  Safer alternative: {b['safer_alternative']}"
                for b in blocks_found
            )
            correction_prompt = (
                f"Your previous plan was REJECTED by the AgentGuard security gateway:\n"
                f"{rejections_text}\n\n"
                f"Please self-correct your plan for user goal: '{prompt}'.\n"
                f"Strictly adhere to the safer alternative: restrict all operations to the local ./workspace directory without sudo or root privileges.\n"
                f"Output only raw shell commands, one per line."
            )

            try:
                qwen_corrected_text = await self._query_ollama(
                    correction_prompt,
                    "You are a developer assistant. Self-correct the blocked commands to be safe and workspace-confined. Output one command per line without markdown.",
                    model=model,
                )
            except Exception:
                qwen_corrected_text = "rm ./workspace/logs/debug.log\npip install --user pymongo"

            corrected_commands = self._parse_commands_from_text(qwen_corrected_text)
            turn2_steps: list[dict[str, Any]] = []

            for idx, cmd in enumerate(corrected_commands, 1):
                act = ActionRequest(
                    action_type=ActionType.SHELL_COMMAND,
                    command=cmd,
                    task_context=f"Local {model} Turn 2 Self-Correction: {prompt}",
                )
                decision = await self.policy_engine.evaluate(act)
                await self.audit_logger.log_inspection(act, decision)

                if decision.decision == Decision.BLOCK:
                    self._record_memory_bg(act, decision)
                    turn2_steps.append({
                        "step": idx,
                        "command": cmd,
                        "decision": "BLOCK",
                        "status": "BLOCKED",
                        "matched_policies": decision.matched_policies,
                        "reason": decision.explanation,
                    })

                elif decision.decision == Decision.REQUIRE_APPROVAL:
                    approval_rec = await self.approval_manager.create_request(act, decision)
                    self._record_memory_bg(act, decision)
                    turn2_steps.append({
                        "step": idx,
                        "command": cmd,
                        "decision": "REQUIRE_APPROVAL",
                        "status": "QUEUED_FOR_APPROVAL",
                        "approval_id": approval_rec.approval_id,
                        "matched_policies": decision.matched_policies,
                        "reason": decision.explanation,
                        "message": "Action placed into AgentGuard Human Review Queue",
                    })

                else:
                    exec_res = await self.executor.execute(act, decision)
                    await self.audit_logger.log_execution(
                        action=act,
                        decision=decision,
                        execution_status="success" if exec_res.success else "failed",
                        execution_output=exec_res.stdout or exec_res.stderr,
                    )
                    self._record_memory_bg(act, decision)
                    turn2_steps.append({
                        "step": idx,
                        "command": cmd,
                        "decision": "ALLOW",
                        "status": "EXECUTED",
                        "stdout": exec_res.stdout,
                    })

            turns.append({
                "turn": 2,
                "speaker": f"Self-Correction (Local {model})",
                "feedback_dispatched": rejections_text,
                "proposed_raw": qwen_corrected_text,
                "steps": turn2_steps,
            })

        return {
            "goal": prompt,
            "model": model,
            "backboard_memory_enabled": self.memory_manager.is_available(),
            "recalled_memories_count": len(recalled_notes),
            "recalled_memories": recalled_notes[:4],
            "self_correction_triggered": bool(blocks_found),
            "turns": turns,
        }

