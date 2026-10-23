"""Integration tests covering Demonstration Scenarios A, B, C, and D.

Explicitly satisfies Section 14 and Section 15 of the AgentGuard specification:
- Scenario A: Harmless Action (ALLOW -> successful execution)
- Scenario B: Sensitive Action (REQUIRE_APPROVAL -> gated -> approved -> execution)
- Scenario C: Prohibited Action (BLOCK -> executor refuses unconditionally)
- Scenario D: Approval Tampering (Approval bound to hash -> modified action rejected)
"""

from __future__ import annotations

from pathlib import Path
import pytest

from agentguard.approval_manager import ApprovalManager
from agentguard.config import AgentGuardConfig
from agentguard.db import Database
from agentguard.executor import ControlledExecutor
from agentguard.policy_engine import PolicyEngine
from agentguard.schemas import ActionRequest, ActionType, Decision, RiskCategory


@pytest.fixture
async def integration_environment(tmp_path: Path):
    # Setup test workspace and files
    workspace = tmp_path / "sandbox_workspace"
    workspace.mkdir(parents=True, exist_ok=True)
    
    # Create test target file for deletion/reading
    test_file = workspace / "deletable_file.txt"
    test_file.write_text("Dispensable data for deletion testing", encoding="utf-8")

    db_path = tmp_path / "integration_audit.db"
    db = Database(str(db_path))
    await db.initialize()

    config = AgentGuardConfig(
        workspace_path=str(workspace),
        db_path=str(db_path),
        approval_timeout_seconds=300,
        execution_timeout_seconds=10,
    )

    policy_engine = PolicyEngine(config)
    approval_manager = ApprovalManager(db, config)
    executor = ControlledExecutor(config, policy_engine, approval_manager)

    yield {
        "workspace": workspace,
        "test_file": test_file,
        "config": config,
        "db": db,
        "policy_engine": policy_engine,
        "approval_manager": approval_manager,
        "executor": executor,
    }

    await db.close()


# ============================================================================
# Scenario A: Harmless Action
# ============================================================================


@pytest.mark.asyncio
async def test_scenario_a_harmless_action(integration_environment: dict) -> None:
    """The agent requests a permitted operation (listing files in authorized workspace).
    Expected result: ALLOW, followed by successful execution through the controlled adapter.
    """
    workspace = integration_environment["workspace"]
    policy_engine: PolicyEngine = integration_environment["policy_engine"]
    executor: ControlledExecutor = integration_environment["executor"]

    action = ActionRequest(
        action_type=ActionType.DIRECTORY_LIST,
        resource=str(workspace),
        working_directory=str(workspace),
    )

    # 1. Policy Engine evaluation
    decision = await policy_engine.evaluate(action)
    assert decision.decision == Decision.ALLOW
    assert decision.risk_category in (RiskCategory.NONE, RiskCategory.LOW)

    # 2. Execution through controlled adapter
    result = await executor.execute(action, decision)
    assert result.success is True
    assert "deletable_file.txt" in result.output


# ============================================================================
# Scenario B: Sensitive Action
# ============================================================================


@pytest.mark.asyncio
async def test_scenario_b_sensitive_action(integration_environment: dict) -> None:
    """The agent proposes deleting files within the authorized workspace.
    Expected result: REQUIRE_APPROVAL. The operation must not execute while approval is pending.
    After an authorized user approves the exact action, the adapter may execute it.
    """
    test_file: Path = integration_environment["test_file"]
    policy_engine: PolicyEngine = integration_environment["policy_engine"]
    approval_manager: ApprovalManager = integration_environment["approval_manager"]
    executor: ControlledExecutor = integration_environment["executor"]

    assert test_file.exists(), "Target file must exist prior to deletion test"

    action = ActionRequest(
        action_type=ActionType.FILE_DELETE,
        resource=str(test_file),
    )

    # 1. Policy evaluation
    decision = await policy_engine.evaluate(action)
    assert decision.decision == Decision.REQUIRE_APPROVAL
    assert decision.requires_approval is True

    # 2. Attempt execution without approval -> MUST be refused
    unapproved_exec = await executor.execute(action, decision, approval_id=None)
    assert unapproved_exec.success is False
    assert test_file.exists(), "File must NOT be deleted without approval"

    # 3. Request human approval
    approval_req = await approval_manager.create_request(action, decision)
    
    # 4. Human operator approves
    approved_record = await approval_manager.approve(
        approval_req.approval_id, decided_by="lead_security_engineer"
    )
    assert approved_record.status.value == "approved"

    # 5. Execute with verified approval -> MUST succeed
    approved_exec = await executor.execute(action, decision, approval_id=approval_req.approval_id)
    assert approved_exec.success is True
    assert not test_file.exists(), "File should be deleted after verified execution"


# ============================================================================
# Scenario C: Prohibited Action
# ============================================================================


@pytest.mark.asyncio
async def test_scenario_c_prohibited_action(integration_environment: dict) -> None:
    """The agent attempts to read a protected secret file or perform a destructive operation.
    Expected result: BLOCK. The action must not execute, even if someone attempts execution.
    """
    workspace: Path = integration_environment["workspace"]
    policy_engine: PolicyEngine = integration_environment["policy_engine"]
    executor: ControlledExecutor = integration_environment["executor"]

    # Attempting to read a secret .env file
    secret_path = workspace / ".env"
    secret_path.write_text("SECRET_KEY=supersecretkey123", encoding="utf-8")

    action = ActionRequest(
        action_type=ActionType.FILE_READ,
        resource=str(secret_path),
    )

    # 1. Policy evaluation
    decision = await policy_engine.evaluate(action)
    assert decision.decision == Decision.BLOCK

    # 2. Controlled execution layer MUST unconditionally refuse execution
    exec_result = await executor.execute(action, decision)
    assert exec_result.success is False
    assert "refused" in exec_result.error.lower() or "blocked" in exec_result.error.lower()


# ============================================================================
# Scenario D: Approval Tampering
# ============================================================================


@pytest.mark.asyncio
async def test_scenario_d_approval_tampering(integration_environment: dict) -> None:
    """Request approval for one action and then modify its arguments.
    Expected result: The previous approval is rejected as invalid for the modified action.
    """
    workspace: Path = integration_environment["workspace"]
    policy_engine: PolicyEngine = integration_environment["policy_engine"]
    approval_manager: ApprovalManager = integration_environment["approval_manager"]
    executor: ControlledExecutor = integration_environment["executor"]

    original_file = workspace / "benign.txt"
    original_file.write_text("safe to remove", encoding="utf-8")

    tampered_file = workspace / "critical_production_data.txt"
    tampered_file.write_text("CRITICAL DO NOT DELETE", encoding="utf-8")

    # 1. Propose action 1 (delete benign.txt)
    original_action = ActionRequest(
        action_type=ActionType.FILE_DELETE,
        resource=str(original_file),
    )
    decision1 = await policy_engine.evaluate(original_action)
    assert decision1.decision == Decision.REQUIRE_APPROVAL

    # 2. Get approval for original action
    approval = await approval_manager.create_request(original_action, decision1)
    await approval_manager.approve(approval.approval_id, decided_by="admin_user")

    # 3. Agent now attempts to use that approval to delete a different, critical file
    tampered_action = ActionRequest(
        action_type=ActionType.FILE_DELETE,
        resource=str(tampered_file),
    )
    tampered_decision = await policy_engine.evaluate(tampered_action)

    # 4. Executor checks hash binding -> MUST fail validation and refuse
    exec_tampered = await executor.execute(
        tampered_action, tampered_decision, approval_id=approval.approval_id
    )
    assert exec_tampered.success is False
    assert "approval" in exec_tampered.error.lower()
    assert tampered_file.exists(), "Critical file must NOT be deleted with mismatched approval"
