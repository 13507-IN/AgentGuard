"""FastMCP server implementation for AgentGuard.

Exposes 4 core security tools to AI clients via the Model Context Protocol:
1. inspect_action — Comprehensive action evaluation with policy checking and risk analysis.
2. check_policy — Lightweight policy compliance check without audit logging or AI.
3. request_approval — Submit an action requiring human approval to the approval queue.
4. get_audit_log — Retrieve historical audit records of inspected and executed actions.
"""

from __future__ import annotations

import asyncio
import json
import logging
from enum import Enum
from typing import Any

try:
    from mcp.server.mcpserver import MCPServer
except ImportError:
    try:
        from mcp.server import MCPServer
    except ImportError:
        from mcp.server.fastmcp import FastMCP as MCPServer

from agentguard.approval_manager import ApprovalManager
from agentguard.audit_log import AuditLogger
from agentguard.config import AgentGuardConfig
from agentguard.db import Database
from agentguard.executor import ControlledExecutor
from agentguard.policy_engine import PolicyEngine
from agentguard.risk_explainer import RiskExplainer
from agentguard.schemas import (
    ActionRequest,
    ActionType,
    Decision,
    RiskCategory,
    RiskExplanation,
    SecurityDecision,
)

logger = logging.getLogger("agentguard.server")

# ---------------------------------------------------------------------------
# MCP Server Instance
# ---------------------------------------------------------------------------

mcp = MCPServer(
    "AgentGuard",
    description="AI Agent Security Layer — inspect, restrict, approve, execute, and audit agent actions",
)

# ---------------------------------------------------------------------------
# Module-level State Holder
# ---------------------------------------------------------------------------

_config: AgentGuardConfig | None = None
_db: Database | None = None
_policy_engine: PolicyEngine | None = None
_approval_manager: ApprovalManager | None = None
_audit_logger: AuditLogger | None = None
_risk_explainer: RiskExplainer | None = None
_executor: ControlledExecutor | None = None
_initialized_loop: Any = None
_init_lock: asyncio.Lock | None = None


def _get_init_lock() -> asyncio.Lock:
    global _init_lock
    if _init_lock is None:
        _init_lock = asyncio.Lock()
    return _init_lock


async def setup(
    config: AgentGuardConfig | None = None,
    db: Database | None = None,
    policy_engine: PolicyEngine | None = None,
    approval_manager: ApprovalManager | None = None,
    audit_logger: AuditLogger | None = None,
    risk_explainer: RiskExplainer | None = None,
    executor: ControlledExecutor | None = None,
) -> None:
    """Initialize or inject shared dependencies for the MCP server.

    Args:
        config: Optional pre-configured AgentGuardConfig.
        db: Optional pre-initialized Database instance.
        policy_engine: Optional PolicyEngine instance.
        approval_manager: Optional ApprovalManager instance.
        audit_logger: Optional AuditLogger instance.
        risk_explainer: Optional RiskExplainer instance.
        executor: Optional ControlledExecutor instance.
    """
    global _config, _db, _policy_engine, _approval_manager, _audit_logger, _risk_explainer, _executor, _initialized_loop

    try:
        _initialized_loop = asyncio.get_running_loop()
    except RuntimeError:
        _initialized_loop = None

    _config = config or AgentGuardConfig.from_env()
    _config.ensure_workspace()

    if db is not None:
        _db = db
    else:
        _db = Database(_config)
    await _db.initialize()

    _policy_engine = policy_engine or PolicyEngine(_config)
    _approval_manager = approval_manager or ApprovalManager(_db, _config)
    _audit_logger = audit_logger or AuditLogger(_db)
    _risk_explainer = risk_explainer or RiskExplainer(_config)
    _executor = executor or ControlledExecutor(_config, _policy_engine, _approval_manager)
    logger.info("AgentGuard MCP server components successfully initialized")


async def _ensure_initialized() -> None:
    """Ensure that the module-level state has been initialized on the current running event loop."""
    global _initialized_loop
    try:
        current_loop = asyncio.get_running_loop()
    except RuntimeError:
        current_loop = None

    if (
        _config is not None
        and _db is not None
        and _initialized_loop is not None
        and _initialized_loop == current_loop
    ):
        return

    async with _get_init_lock():
        if (
            _config is None
            or _db is None
            or _initialized_loop is None
            or _initialized_loop != current_loop
        ):
            await setup()
            _initialized_loop = current_loop


def _parse_arguments(arguments: str | dict[str, Any] | None) -> dict[str, Any]:
    """Safely parse arguments into a dictionary.

    Args:
        arguments: JSON string, dict, or None.

    Returns:
        Dictionary of parsed arguments.
    """
    if arguments is None or arguments == "":
        return {}
    if isinstance(arguments, dict):
        return arguments
    if isinstance(arguments, str):
        parsed = json.loads(arguments)
        if isinstance(parsed, dict):
            return parsed
        return {"value": parsed}
    return {}


def _parse_action_type(action_type: str) -> ActionType:
    """Convert string to ActionType enum, raising ValueError on failure.

    Args:
        action_type: Action type string (e.g. 'shell_command', 'file_read').

    Returns:
        ActionType enum member.
    """
    cleaned = action_type.strip().lower()
    return ActionType(cleaned)


# ---------------------------------------------------------------------------
# MCP Tools
# ---------------------------------------------------------------------------


@mcp.tool()
async def inspect_action(
    action_type: str,
    command: str | None = None,
    resource: str | None = None,
    arguments: str | None = None,
    working_directory: str | None = None,
    task_context: str | None = None,
) -> str:
    """Evaluate a proposed action without executing it. Returns security decision with risk analysis.

    Args:
        action_type: Type of action (shell_command, file_read, file_write, file_delete, directory_list)
        command: The shell command to evaluate (for shell_command type)
        resource: File path or URL (for file operations)
        arguments: JSON string of additional parameters
        working_directory: Working directory for the action
        task_context: Why the agent wants to perform this action

    Returns:
        JSON string containing decision, risk_category, matched_policies, explanation,
        safer_alternative, action_hash, requires_approval, and ai_explanation (if available).
    """
    await _ensure_initialized()
    try:
        # 1. Parse arguments JSON string to dict
        try:
            args_dict = _parse_arguments(arguments)
        except (json.JSONDecodeError, TypeError) as err:
            return json.dumps(
                {
                    "error": f"Invalid JSON in arguments: {err}",
                    "decision": Decision.BLOCK.value,
                    "risk_category": RiskCategory.HIGH.value,
                    "matched_policies": ["arguments_validation"],
                    "explanation": "Arguments could not be parsed as valid JSON.",
                    "safer_alternative": None,
                    "action_hash": "",
                    "requires_approval": False,
                    "ai_explanation": None,
                },
                indent=2,
            )

        # 2. Validate action_type against ActionType enum
        try:
            action_enum = _parse_action_type(action_type)
        except (ValueError, KeyError, AttributeError):
            valid_types = [t.value for t in ActionType]
            return json.dumps(
                {
                    "error": f"Invalid action_type '{action_type}'. Valid options: {valid_types}",
                    "decision": Decision.BLOCK.value,
                    "risk_category": RiskCategory.HIGH.value,
                    "matched_policies": ["action_type_validation"],
                    "explanation": f"Unknown action type '{action_type}'. Defaulting to BLOCK.",
                    "safer_alternative": None,
                    "action_hash": "",
                    "requires_approval": False,
                    "ai_explanation": None,
                },
                indent=2,
            )

        # 3. Create ActionRequest
        action_req = ActionRequest(
            action_type=action_enum,
            command=command,
            resource=resource,
            arguments=args_dict,
            working_directory=working_directory,
            task_context=task_context,
        )

        # 4. Call policy_engine.evaluate(action)
        if _policy_engine is None:
            raise RuntimeError("Policy engine is not initialized")

        eval_res = _policy_engine.evaluate(action_req)
        decision: SecurityDecision = (
            await eval_res if asyncio.iscoroutine(eval_res) else eval_res
        )

        # 5. Optionally call risk_explainer.explain(action, decision) with graceful fallback
        ai_explanation_str: str | None = None
        if _risk_explainer is not None:
            try:
                is_available = True
                if hasattr(_risk_explainer, "is_available"):
                    avail_val = _risk_explainer.is_available()
                    is_available = (
                        await avail_val if asyncio.iscoroutine(avail_val) else bool(avail_val)
                    )

                if is_available:
                    explain_res = _risk_explainer.explain(action_req, decision)
                    explanation_obj = (
                        await explain_res if asyncio.iscoroutine(explain_res) else explain_res
                    )
                    if isinstance(explanation_obj, RiskExplanation):
                        ai_explanation_str = explanation_obj.explanation
                    elif isinstance(explanation_obj, dict):
                        ai_explanation_str = explanation_obj.get("explanation")
                    elif isinstance(explanation_obj, str):
                        ai_explanation_str = explanation_obj
            except Exception as exp_err:
                logger.warning("Risk explainer unavailable or failed: %s", exp_err)
                ai_explanation_str = None

        # 6. Log via audit_logger.log_inspection()
        if _audit_logger is not None:
            try:
                log_res = _audit_logger.log_inspection(
                    action_req, decision, ai_explanation=ai_explanation_str
                )
                if asyncio.iscoroutine(log_res):
                    await log_res
            except TypeError:
                try:
                    log_res = _audit_logger.log_inspection(action_req, decision)
                    if asyncio.iscoroutine(log_res):
                        await log_res
                except Exception as log_err:
                    logger.warning("Failed to log inspection: %s", log_err)
            except Exception as log_err:
                logger.warning("Failed to log inspection: %s", log_err)

        # 7. Return JSON string
        result = {
            "decision": decision.decision.value
            if isinstance(decision.decision, Enum)
            else str(decision.decision),
            "risk_category": decision.risk_category.value
            if isinstance(decision.risk_category, Enum)
            else str(decision.risk_category),
            "matched_policies": decision.matched_policies,
            "explanation": decision.explanation,
            "safer_alternative": decision.safer_alternative,
            "action_hash": decision.action_hash,
            "requires_approval": decision.requires_approval,
            "ai_explanation": ai_explanation_str,
        }
        return json.dumps(result, indent=2, default=str)

    except Exception as exc:
        logger.exception("Error in inspect_action tool")
        return json.dumps(
            {
                "error": str(exc),
                "decision": Decision.BLOCK.value,
                "risk_category": RiskCategory.CRITICAL.value,
                "matched_policies": ["internal_error_guard"],
                "explanation": f"Internal error during action inspection: {exc}. Defaulting to BLOCK.",
                "safer_alternative": None,
                "action_hash": "",
                "requires_approval": False,
                "ai_explanation": None,
            },
            indent=2,
        )


@mcp.tool()
async def check_policy(
    action_type: str,
    resource: str | None = None,
    operation: str | None = None,
    arguments: str | None = None,
) -> str:
    """Quick policy compliance check without full risk analysis or audit logging.

    Args:
        action_type: Type of action to check
        resource: Resource path or identifier
        operation: Specific operation (e.g., the command)
        arguments: JSON string of additional parameters

    Returns:
        JSON string containing decision, risk_category, matched_policies, explanation,
        safer_alternative, action_hash, and requires_approval.
    """
    await _ensure_initialized()
    try:
        try:
            args_dict = _parse_arguments(arguments)
        except (json.JSONDecodeError, TypeError) as err:
            return json.dumps(
                {
                    "error": f"Invalid JSON in arguments: {err}",
                    "decision": Decision.BLOCK.value,
                    "risk_category": RiskCategory.HIGH.value,
                    "matched_policies": ["arguments_validation"],
                    "explanation": "Arguments could not be parsed as valid JSON.",
                    "safer_alternative": None,
                    "action_hash": "",
                    "requires_approval": False,
                },
                indent=2,
            )

        try:
            action_enum = _parse_action_type(action_type)
        except (ValueError, KeyError, AttributeError):
            valid_types = [t.value for t in ActionType]
            return json.dumps(
                {
                    "error": f"Invalid action_type '{action_type}'. Valid options: {valid_types}",
                    "decision": Decision.BLOCK.value,
                    "risk_category": RiskCategory.HIGH.value,
                    "matched_policies": ["action_type_validation"],
                    "explanation": f"Unknown action type '{action_type}'. Defaulting to BLOCK.",
                    "safer_alternative": None,
                    "action_hash": "",
                    "requires_approval": False,
                },
                indent=2,
            )

        cmd = operation if action_enum == ActionType.SHELL_COMMAND else None
        if operation and action_enum != ActionType.SHELL_COMMAND and "operation" not in args_dict:
            args_dict["operation"] = operation

        action_req = ActionRequest(
            action_type=action_enum,
            command=cmd,
            resource=resource,
            arguments=args_dict,
        )

        if _policy_engine is None:
            raise RuntimeError("Policy engine is not initialized")

        eval_res = _policy_engine.evaluate(action_req)
        decision: SecurityDecision = (
            await eval_res if asyncio.iscoroutine(eval_res) else eval_res
        )

        result = {
            "allowed": decision.decision == Decision.ALLOW,
            "decision": decision.decision.value
            if isinstance(decision.decision, Enum)
            else str(decision.decision),
            "risk_category": decision.risk_category.value
            if isinstance(decision.risk_category, Enum)
            else str(decision.risk_category),
            "matched_policies": decision.matched_policies,
            "explanation": decision.explanation,
            "safer_alternative": decision.safer_alternative,
            "action_hash": decision.action_hash,
            "requires_approval": decision.requires_approval,
        }
        return json.dumps(result, indent=2, default=str)

    except Exception as exc:
        logger.exception("Error in check_policy tool")
        return json.dumps(
            {
                "error": str(exc),
                "decision": Decision.BLOCK.value,
                "risk_category": RiskCategory.CRITICAL.value,
                "matched_policies": ["internal_error_guard"],
                "explanation": f"Internal error during policy check: {exc}. Defaulting to BLOCK.",
                "safer_alternative": None,
                "action_hash": "",
                "requires_approval": False,
            },
            indent=2,
        )


@mcp.tool()
async def request_approval(
    action_type: str,
    command: str | None = None,
    resource: str | None = None,
    arguments: str | None = None,
    working_directory: str | None = None,
    reason: str | None = None,
) -> str:
    """Request human approval for an action requiring review. Returns approval status and ID.

    Args:
        action_type: Type of action requiring approval
        command: The command (for shell actions)
        resource: The resource path (for file actions)
        arguments: JSON string of additional parameters
        working_directory: Working directory
        reason: Why this action is needed

    Returns:
        JSON string containing approval_id, status, expires_at, and action details.
    """
    await _ensure_initialized()
    try:
        try:
            args_dict = _parse_arguments(arguments)
        except (json.JSONDecodeError, TypeError) as err:
            return json.dumps(
                {
                    "error": f"Invalid JSON in arguments: {err}",
                    "status": "error",
                },
                indent=2,
            )

        try:
            action_enum = _parse_action_type(action_type)
        except (ValueError, KeyError, AttributeError):
            valid_types = [t.value for t in ActionType]
            return json.dumps(
                {
                    "error": f"Invalid action_type '{action_type}'. Valid options: {valid_types}",
                    "status": "error",
                },
                indent=2,
            )

        # 1. Build ActionRequest
        action_req = ActionRequest(
            action_type=action_enum,
            command=command,
            resource=resource,
            arguments=args_dict,
            working_directory=working_directory,
            task_context=reason,
        )

        # 2. Re-evaluate policy (never trust prior check)
        if _policy_engine is None:
            raise RuntimeError("Policy engine is not initialized")

        eval_res = _policy_engine.evaluate(action_req)
        decision: SecurityDecision = (
            await eval_res if asyncio.iscoroutine(eval_res) else eval_res
        )

        # 3. If BLOCK -> return blocked, no approval possible
        if decision.decision == Decision.BLOCK:
            return json.dumps(
                {
                    "status": "blocked",
                    "decision": Decision.BLOCK.value,
                    "message": "Action is blocked by policy and cannot be submitted for approval.",
                    "explanation": decision.explanation,
                    "matched_policies": decision.matched_policies,
                    "action_hash": decision.action_hash,
                },
                indent=2,
            )

        # 4. If ALLOW -> return allowed, no approval needed
        if decision.decision == Decision.ALLOW:
            return json.dumps(
                {
                    "status": "allowed",
                    "decision": Decision.ALLOW.value,
                    "message": "Action is allowed by policy; human approval is not required.",
                    "explanation": decision.explanation,
                    "action_hash": decision.action_hash,
                },
                indent=2,
            )

        # 5. If REQUIRE_APPROVAL -> create approval via approval_manager
        if _approval_manager is None:
            raise RuntimeError("Approval manager is not initialized")

        try:
            create_res = _approval_manager.create_request(action_req, decision)
            record = (
                await create_res if asyncio.iscoroutine(create_res) else create_res
            )
        except TypeError:
            create_res = _approval_manager.create_request(action_req)
            record = (
                await create_res if asyncio.iscoroutine(create_res) else create_res
            )

        # 6. Extract record fields safely
        approval_id = getattr(record, "approval_id", None) or (
            record.get("approval_id") if isinstance(record, dict) else None
        )
        status_val = getattr(record, "status", None) or (
            record.get("status") if isinstance(record, dict) else "pending"
        )
        if isinstance(status_val, Enum):
            status_val = status_val.value

        expires_at = getattr(record, "expires_at", None) or (
            record.get("expires_at") if isinstance(record, dict) else None
        )
        if hasattr(expires_at, "isoformat"):
            expires_at_str = expires_at.isoformat()
        else:
            expires_at_str = str(expires_at) if expires_at else None

        return json.dumps(
            {
                "approval_id": approval_id,
                "status": status_val,
                "expires_at": expires_at_str,
                "action_hash": decision.action_hash,
                "action_summary": action_req.summary(),
                "explanation": decision.explanation,
                "message": "Approval request submitted successfully. Awaiting review.",
            },
            indent=2,
        )

    except Exception as exc:
        logger.exception("Error in request_approval tool")
        return json.dumps(
            {
                "error": str(exc),
                "status": "error",
            },
            indent=2,
        )


@mcp.tool()
async def get_audit_log(
    action_id: str | None = None,
    time_range_minutes: int | None = None,
    decision_filter: str | None = None,
    limit: int = 50,
) -> str:
    """Retrieve audit history of action inspections, decisions, and executions.

    Args:
        action_id: Filter by specific action/entry ID
        time_range_minutes: Show entries from the last N minutes
        decision_filter: Filter by decision type (ALLOW, BLOCK, REQUIRE_APPROVAL)
        limit: Maximum entries to return (default 50)

    Returns:
        JSON string containing the list of matching audit entries.
    """
    await _ensure_initialized()
    try:
        entries: list[Any] = []
        if _audit_logger is not None:
            try:
                res = _audit_logger.get_entries(
                    entry_id=action_id,
                    decision=decision_filter,
                    since_minutes=time_range_minutes,
                    limit=limit,
                )
                entries = await res if asyncio.iscoroutine(res) else res
            except (TypeError, AttributeError):
                if _db is not None:
                    entries = await _db.get_audit_entries(
                        entry_id=action_id,
                        decision=decision_filter,
                        since_minutes=time_range_minutes,
                        limit=limit,
                    )
        elif _db is not None:
            entries = await _db.get_audit_entries(
                entry_id=action_id,
                decision=decision_filter,
                since_minutes=time_range_minutes,
                limit=limit,
            )

        serialized: list[dict[str, Any]] = []
        for entry in entries or []:
            if hasattr(entry, "model_dump"):
                serialized.append(entry.model_dump(mode="json"))
            elif hasattr(entry, "dict"):
                serialized.append(entry.dict())
            elif isinstance(entry, dict):
                serialized.append(entry)
            else:
                serialized.append({"raw": str(entry)})

        return json.dumps(
            {
                "count": len(serialized),
                "entries": serialized,
            },
            indent=2,
            default=str,
        )

    except Exception as exc:
        logger.exception("Error in get_audit_log tool")
        return json.dumps(
            {
                "error": str(exc),
                "count": 0,
                "entries": [],
            },
            indent=2,
        )
