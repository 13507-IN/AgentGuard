"""Unit tests for ControlledExecutor."""

from __future__ import annotations

import asyncio
from pathlib import Path
from unittest.mock import AsyncMock, MagicMock

import pytest

from agentguard.config import AgentGuardConfig
from agentguard.executor import ControlledExecutor, ExecutionResult
from agentguard.schemas import (
    ActionRequest,
    ActionType,
    Decision,
    RiskCategory,
    SecurityDecision,
)


@pytest.fixture
def temp_workspace(tmp_path: Path) -> Path:
    """Fixture providing a temporary workspace directory."""
    ws = tmp_path / "workspace"
    ws.mkdir(parents=True, exist_ok=True)
    return ws


@pytest.fixture
def config(temp_workspace: Path) -> AgentGuardConfig:
    """Fixture providing configuration with temporary workspace."""
    return AgentGuardConfig(
        workspace_path=str(temp_workspace),
        execution_timeout_seconds=5,
        max_output_bytes=256,
    )


@pytest.fixture
def mock_policy_engine() -> MagicMock:
    """Mock PolicyEngine fixture."""
    engine = MagicMock()
    # Default to ALLOW on evaluation
    engine.evaluate.return_value = SecurityDecision(
        decision=Decision.ALLOW,
        risk_category=RiskCategory.LOW,
        matched_policies=[],
        explanation="Allowed by test mock",
        action_hash="",
    )
    return engine


@pytest.fixture
def mock_approval_manager() -> MagicMock:
    """Mock ApprovalManager fixture."""
    manager = MagicMock()
    manager.verify.return_value = True
    return manager


@pytest.fixture
def executor(
    config: AgentGuardConfig,
    mock_policy_engine: MagicMock,
    mock_approval_manager: MagicMock,
) -> ControlledExecutor:
    """ControlledExecutor test instance."""
    return ControlledExecutor(
        config=config,
        policy_engine=mock_policy_engine,
        approval_manager=mock_approval_manager,
    )


def test_validate_path_allowed(executor: ControlledExecutor, temp_workspace: Path) -> None:
    """Test path validation for paths strictly inside workspace."""
    resolved = executor._validate_path("test.txt")
    assert resolved == (temp_workspace / "test.txt").resolve()

    sub_dir = temp_workspace / "sub"
    sub_dir.mkdir(parents=True, exist_ok=True)
    resolved_sub = executor._validate_path(str(sub_dir / "file.txt"))
    assert resolved_sub == (sub_dir / "file.txt").resolve()


def test_validate_path_denied(executor: ControlledExecutor, tmp_path: Path) -> None:
    """Test path validation refuses paths outside workspace."""
    outside_file = tmp_path / "outside.txt"

    with pytest.raises(PermissionError):
        executor._validate_path(str(outside_file))

    with pytest.raises(PermissionError):
        executor._validate_path("../outside.txt")

    with pytest.raises(ValueError):
        executor._validate_path("")


@pytest.mark.asyncio
async def test_file_write_read_delete(executor: ControlledExecutor) -> None:
    """Test full file write, read, and delete cycle."""
    # 1. Write file
    write_action = ActionRequest(
        action_type=ActionType.FILE_WRITE,
        resource="hello.txt",
        arguments={"content": "Hello AgentGuard!"},
    )
    write_res = await executor._execute_file_write(write_action)
    assert write_res.success is True
    assert "Successfully wrote" in (write_res.output or "")

    # 2. Read file
    read_action = ActionRequest(
        action_type=ActionType.FILE_READ,
        resource="hello.txt",
    )
    read_res = await executor._execute_file_read(read_action)
    assert read_res.success is True
    assert read_res.output == "Hello AgentGuard!"

    # 3. Delete file
    delete_action = ActionRequest(
        action_type=ActionType.FILE_DELETE,
        resource="hello.txt",
    )
    delete_res = await executor._execute_file_delete(delete_action)
    assert delete_res.success is True
    assert "Successfully deleted file" in (delete_res.output or "")

    # Verify file is gone
    assert not (executor.workspace / "hello.txt").exists()


@pytest.mark.asyncio
async def test_file_delete_directory_rejected(
    executor: ControlledExecutor, temp_workspace: Path
) -> None:
    """Test that file_delete rejects deleting directories."""
    sub_dir = temp_workspace / "subfolder"
    sub_dir.mkdir(parents=True, exist_ok=True)

    action = ActionRequest(
        action_type=ActionType.FILE_DELETE,
        resource="subfolder",
    )
    res = await executor._execute_file_delete(action)
    assert res.success is False
    assert "Cannot delete directory" in (res.error or "")


@pytest.mark.asyncio
async def test_directory_list(executor: ControlledExecutor, temp_workspace: Path) -> None:
    """Test directory listing."""
    (temp_workspace / "file1.txt").write_text("123", encoding="utf-8")
    (temp_workspace / "file2.txt").write_text("456789", encoding="utf-8")
    (temp_workspace / "subdir").mkdir(parents=True, exist_ok=True)

    action = ActionRequest(
        action_type=ActionType.DIRECTORY_LIST,
        resource=".",
    )
    res = await executor._execute_directory_list(action)
    assert res.success is True
    assert "file1.txt" in (res.output or "")
    assert "file2.txt" in (res.output or "")
    assert "subdir" in (res.output or "")


@pytest.mark.asyncio
async def test_shell_command_execution(executor: ControlledExecutor) -> None:
    """Test shell command execution."""
    action = ActionRequest(
        action_type=ActionType.SHELL_COMMAND,
        command='echo "AgentGuard execution test"',
    )
    res = await executor._execute_shell_command(action)
    assert res.success is True
    assert "AgentGuard execution test" in (res.output or "")


@pytest.mark.asyncio
async def test_shell_command_secret_redaction(executor: ControlledExecutor) -> None:
    """Test that secrets in command output are redacted."""
    action = ActionRequest(
        action_type=ActionType.SHELL_COMMAND,
        command='echo api_key=supersecret123',
    )
    res = await executor._execute_shell_command(action)
    assert res.success is True
    assert "supersecret123" not in (res.output or "")
    assert "[REDACTED]" in (res.output or "")


@pytest.mark.asyncio
async def test_execute_blocked_action_refused(executor: ControlledExecutor) -> None:
    """Test that BLOCK decisions are refused immediately."""
    action = ActionRequest(
        action_type=ActionType.SHELL_COMMAND,
        command="rm -rf /",
    )
    decision = SecurityDecision(
        decision=Decision.BLOCK,
        risk_category=RiskCategory.CRITICAL,
        matched_policies=["blocked_command"],
        explanation="Dangerous command detected",
        action_hash=action.compute_hash(),
    )
    res = await executor.execute(action, decision)
    assert res.success is False
    assert "Action blocked by policy" in (res.error or "")


@pytest.mark.asyncio
async def test_execute_require_approval_missing_approval_id(
    executor: ControlledExecutor,
) -> None:
    """Test that REQUIRE_APPROVAL without approval_id is refused."""
    action = ActionRequest(
        action_type=ActionType.SHELL_COMMAND,
        command="git push",
    )
    decision = SecurityDecision(
        decision=Decision.REQUIRE_APPROVAL,
        risk_category=RiskCategory.MEDIUM,
        matched_policies=["require_human_approval"],
        explanation="Pushing code requires approval",
        action_hash=action.compute_hash(),
    )
    res = await executor.execute(action, decision, approval_id=None)
    assert res.success is False
    assert "requires human approval" in (res.error or "")


@pytest.mark.asyncio
async def test_execute_require_approval_verification_failed(
    executor: ControlledExecutor,
    mock_approval_manager: MagicMock,
) -> None:
    """Test that invalid approval verification refuses execution."""
    mock_approval_manager.verify.return_value = False

    action = ActionRequest(
        action_type=ActionType.SHELL_COMMAND,
        command="git push",
    )
    decision = SecurityDecision(
        decision=Decision.REQUIRE_APPROVAL,
        risk_category=RiskCategory.MEDIUM,
        matched_policies=["require_human_approval"],
        explanation="Pushing code requires approval",
        action_hash=action.compute_hash(),
    )
    res = await executor.execute(action, decision, approval_id="appr-123")
    assert res.success is False
    assert "Approval verification failed" in (res.error or "")


@pytest.mark.asyncio
async def test_execute_require_approval_success(
    executor: ControlledExecutor,
    mock_approval_manager: MagicMock,
    mock_policy_engine: MagicMock,
) -> None:
    """Test successful execution of approved action."""
    mock_approval_manager.verify.return_value = True

    action = ActionRequest(
        action_type=ActionType.FILE_WRITE,
        resource="approved.txt",
        arguments={"content": "Authorized content"},
    )
    decision = SecurityDecision(
        decision=Decision.REQUIRE_APPROVAL,
        risk_category=RiskCategory.MEDIUM,
        matched_policies=["file_write_approval"],
        explanation="File writes require approval",
        action_hash=action.compute_hash(),
    )
    # Policy re-evaluation also allows or requires approval
    mock_policy_engine.evaluate.return_value = decision

    res = await executor.execute(action, decision, approval_id="appr-456")
    assert res.success is True
    assert (executor.workspace / "approved.txt").read_text(encoding="utf-8") == "Authorized content"


@pytest.mark.asyncio
async def test_execute_policy_re_evaluation_blocks(
    executor: ControlledExecutor,
    mock_policy_engine: MagicMock,
) -> None:
    """Test defense-in-depth policy re-evaluation blocking."""
    action = ActionRequest(
        action_type=ActionType.FILE_WRITE,
        resource="defense.txt",
        arguments={"content": "test"},
    )
    initial_decision = SecurityDecision(
        decision=Decision.ALLOW,
        risk_category=RiskCategory.LOW,
        matched_policies=[],
        explanation="Initially allowed",
        action_hash=action.compute_hash(),
    )
    # Re-evaluation returns BLOCK
    mock_policy_engine.evaluate.return_value = SecurityDecision(
        decision=Decision.BLOCK,
        risk_category=RiskCategory.HIGH,
        matched_policies=["late_detect"],
        explanation="Detected malware payload",
        action_hash=action.compute_hash(),
    )

    res = await executor.execute(action, initial_decision)
    assert res.success is False
    assert "blocked by policy re-evaluation" in (res.error or "")
    assert not (executor.workspace / "defense.txt").exists()
