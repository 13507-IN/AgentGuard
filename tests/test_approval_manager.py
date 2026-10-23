"""Unit tests for AgentGuard ApprovalManager."""

from __future__ import annotations

import asyncio
from datetime import datetime, timedelta, timezone
from pathlib import Path
import pytest

from agentguard.approval_manager import ApprovalManager
from agentguard.config import AgentGuardConfig
from agentguard.db import Database
from agentguard.schemas import (
    ActionRequest,
    ActionType,
    ApprovalStatus,
    Decision,
    RiskCategory,
    SecurityDecision,
)


@pytest.fixture
async def test_db(tmp_path: Path):
    db_file = tmp_path / "test_approvals.db"
    db = Database(str(db_file))
    await db.initialize()
    yield db
    await db.close()


@pytest.fixture
def config(tmp_path: Path) -> AgentGuardConfig:
    return AgentGuardConfig(
        workspace_path=str(tmp_path / "workspace"),
        approval_timeout_seconds=2,  # Short timeout for testing
    )


@pytest.fixture
def approval_manager(test_db: Database, config: AgentGuardConfig) -> ApprovalManager:
    return ApprovalManager(test_db, config)


@pytest.fixture
def sample_action() -> ActionRequest:
    return ActionRequest(
        action_type=ActionType.FILE_DELETE,
        resource="test.txt",
    )


@pytest.fixture
def sample_decision(sample_action: ActionRequest) -> SecurityDecision:
    return SecurityDecision(
        decision=Decision.REQUIRE_APPROVAL,
        risk_category=RiskCategory.MEDIUM,
        matched_policies=["fs.file_deletion"],
        explanation="Deleting files requires approval",
        action_hash=sample_action.compute_hash(),
    )


@pytest.mark.asyncio
async def test_create_approval_request(
    approval_manager: ApprovalManager,
    sample_action: ActionRequest,
    sample_decision: SecurityDecision,
) -> None:
    record = await approval_manager.create_request(sample_action, sample_decision)
    assert record.approval_id is not None
    assert record.status == ApprovalStatus.PENDING
    assert record.action_hash == sample_action.compute_hash()

    # Verify retrieval
    retrieved = await approval_manager.get_record(record.approval_id)
    assert retrieved is not None
    assert retrieved.approval_id == record.approval_id
    assert retrieved.status == ApprovalStatus.PENDING


@pytest.mark.asyncio
async def test_create_request_refuses_non_require_approval(
    approval_manager: ApprovalManager,
    sample_action: ActionRequest,
) -> None:
    allow_decision = SecurityDecision(
        decision=Decision.ALLOW,
        risk_category=RiskCategory.NONE,
        matched_policies=[],
        explanation="Allowed",
        action_hash=sample_action.compute_hash(),
    )
    with pytest.raises(ValueError, match="only REQUIRE_APPROVAL"):
        await approval_manager.create_request(sample_action, allow_decision)


@pytest.mark.asyncio
async def test_human_approval_workflow(
    approval_manager: ApprovalManager,
    sample_action: ActionRequest,
    sample_decision: SecurityDecision,
) -> None:
    record = await approval_manager.create_request(sample_action, sample_decision)
    
    # Human operator approves
    approved = await approval_manager.approve(record.approval_id, decided_by="alice_security_lead")
    assert approved.status == ApprovalStatus.APPROVED
    assert approved.decided_by == "alice_security_lead"

    # Verification passes
    is_valid = await approval_manager.verify(record.approval_id, sample_action.compute_hash())
    assert is_valid is True


@pytest.mark.asyncio
async def test_ai_agent_self_approval_strictly_forbidden(
    approval_manager: ApprovalManager,
    sample_action: ActionRequest,
    sample_decision: SecurityDecision,
) -> None:
    record = await approval_manager.create_request(sample_action, sample_decision)

    forbidden_identities = [
        "ai_agent",
        "agent",
        "my_agent",
        "autonomous_ai",
        "copilot",
        "assistant_bot",
        "ai",
    ]
    for forbidden in forbidden_identities:
        with pytest.raises(ValueError, match="AI agents cannot approve|cannot approve"):
            await approval_manager.approve(record.approval_id, decided_by=forbidden)


@pytest.mark.asyncio
async def test_tamper_protection_invalidates_modified_action(
    approval_manager: ApprovalManager,
    sample_action: ActionRequest,
    sample_decision: SecurityDecision,
) -> None:
    record = await approval_manager.create_request(sample_action, sample_decision)
    await approval_manager.approve(record.approval_id, decided_by="bob_admin")

    # Action is modified (different resource)
    modified_action = ActionRequest(
        action_type=ActionType.FILE_DELETE,
        resource="completely_different_file.txt",
    )
    # Verification with altered hash MUST fail
    is_valid = await approval_manager.verify(record.approval_id, modified_action.compute_hash())
    assert is_valid is False


@pytest.mark.asyncio
async def test_rejection_workflow(
    approval_manager: ApprovalManager,
    sample_action: ActionRequest,
    sample_decision: SecurityDecision,
) -> None:
    record = await approval_manager.create_request(sample_action, sample_decision)
    rejected = await approval_manager.reject(record.approval_id, decided_by="charlie_admin")
    assert rejected.status == ApprovalStatus.REJECTED

    # Rejected action must never verify
    is_valid = await approval_manager.verify(record.approval_id, sample_action.compute_hash())
    assert is_valid is False


@pytest.mark.asyncio
async def test_approval_expiration(
    approval_manager: ApprovalManager,
    sample_action: ActionRequest,
    sample_decision: SecurityDecision,
) -> None:
    record = await approval_manager.create_request(sample_action, sample_decision)
    record2 = await approval_manager.create_request(sample_action, sample_decision)
    
    # Wait for expiration timeout (timeout is 2 seconds in config)
    await asyncio.sleep(2.5)

    # Attempting to approve an expired request must fail
    with pytest.raises(ValueError, match="expired"):
        await approval_manager.approve(record.approval_id, decided_by="dave_admin")

    # Stale expiration cleanup handles unhandled pending records
    expired_count = await approval_manager.expire_stale()
    assert expired_count >= 1
