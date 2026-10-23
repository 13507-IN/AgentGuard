"""Unit tests for AgentGuard FastMCP tools exposed to AI clients."""

from __future__ import annotations

import json
from pathlib import Path
import pytest

from agentguard.approval_manager import ApprovalManager
from agentguard.audit_log import AuditLogger
from agentguard.config import AgentGuardConfig
from agentguard.db import Database
from agentguard.executor import ControlledExecutor
from agentguard.policy_engine import PolicyEngine
from agentguard.server import (
    check_policy,
    get_audit_log,
    inspect_action,
    request_approval,
    setup,
)


@pytest.fixture
async def mcp_server_env(tmp_path: Path):
    workspace = tmp_path / "workspace"
    workspace.mkdir(parents=True, exist_ok=True)
    (workspace / "allowed.txt").write_text("Hello MCP", encoding="utf-8")

    db_file = tmp_path / "mcp_test.db"
    db = Database(str(db_file))
    await db.initialize()

    config = AgentGuardConfig(
        workspace_path=str(workspace),
        db_path=str(db_file),
        approval_timeout_seconds=300,
        ai_enabled=False,  # Offline for tests
    )

    policy_engine = PolicyEngine(config)
    approval_manager = ApprovalManager(db, config)
    audit_logger = AuditLogger(db)
    executor = ControlledExecutor(config, policy_engine, approval_manager)

    await setup(
        config=config,
        db=db,
        policy_engine=policy_engine,
        approval_manager=approval_manager,
        audit_logger=audit_logger,
        risk_explainer=None,
        executor=executor,
    )

    yield {
        "workspace": workspace,
        "db": db,
        "config": config,
        "policy_engine": policy_engine,
    }

    await db.close()


@pytest.mark.asyncio
async def test_tool_inspect_action_allow(mcp_server_env: dict) -> None:
    workspace = mcp_server_env["workspace"]
    res_raw = await inspect_action(
        action_type="file_read",
        resource=str(workspace / "allowed.txt"),
    )
    res = json.loads(res_raw)
    assert res["decision"] == "ALLOW"
    assert "action_hash" in res
    assert len(res["action_hash"]) == 64


@pytest.mark.asyncio
async def test_tool_inspect_action_block(mcp_server_env: dict) -> None:
    res_raw = await inspect_action(
        action_type="shell_command",
        command="rm -rf /",
    )
    res = json.loads(res_raw)
    assert res["decision"] == "BLOCK"
    assert "shell.destructive_commands" in res["matched_policies"]


@pytest.mark.asyncio
async def test_tool_inspect_action_invalid_type(mcp_server_env: dict) -> None:
    res_raw = await inspect_action(
        action_type="invalid_unknown_type",
        command="some_command",
    )
    res = json.loads(res_raw)
    assert res["decision"] == "BLOCK"
    assert "error" in res


@pytest.mark.asyncio
async def test_tool_check_policy_lightweight(mcp_server_env: dict) -> None:
    res_raw = await check_policy(
        action_type="shell_command",
        operation="ls -la",
    )
    res = json.loads(res_raw)
    assert res["decision"] == "ALLOW"
    assert res["allowed"] is True


@pytest.mark.asyncio
async def test_tool_request_approval_blocks_destructive(mcp_server_env: dict) -> None:
    # A destructive action should be rejected immediately, NOT queued
    res_raw = await request_approval(
        action_type="shell_command",
        command="rm -rf /",
        reason="I want to clean up everything",
    )
    res = json.loads(res_raw)
    assert res["status"] in ("rejected", "blocked")
    assert res.get("decision") == "BLOCK"


@pytest.mark.asyncio
async def test_tool_request_approval_queues_sensitive(mcp_server_env: dict) -> None:
    workspace = mcp_server_env["workspace"]
    res_raw = await request_approval(
        action_type="file_delete",
        resource=str(workspace / "allowed.txt"),
        reason="Delete test file",
    )
    res = json.loads(res_raw)
    assert res["status"] == "pending"
    assert "approval_id" in res


@pytest.mark.asyncio
async def test_tool_get_audit_log(mcp_server_env: dict) -> None:
    # First generate an inspection to populate audit log
    await inspect_action(
        action_type="shell_command",
        command="echo testing_mcp_audit",
    )
    
    log_raw = await get_audit_log(limit=10)
    log_data = json.loads(log_raw)
    assert isinstance(log_data, dict)
    entries = log_data.get("entries", [])
    assert len(entries) >= 1
    assert any("testing_mcp_audit" in e.get("action_summary", "") for e in entries)
