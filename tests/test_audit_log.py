"""Unit tests for AgentGuard AuditLogger and secret redaction."""

from __future__ import annotations

from pathlib import Path
import pytest

from agentguard.audit_log import AuditLogger
from agentguard.db import Database
from agentguard.schemas import (
    ActionRequest,
    ActionType,
    Decision,
    RiskCategory,
    SecurityDecision,
    redact_secrets,
)


@pytest.fixture
async def test_db(tmp_path: Path):
    db_file = tmp_path / "test_audit.db"
    db = Database(str(db_file))
    await db.initialize()
    yield db
    await db.close()


@pytest.fixture
def audit_logger(test_db: Database) -> AuditLogger:
    return AuditLogger(test_db)


def test_secret_redaction_patterns() -> None:
    # Test credentials and API keys
    sample_texts = [
        ("api_key=sk-1234567890abcdef1234567890", "[REDACTED]"),
        ("Authorization: Bearer mysecrettoken123", "[REDACTED]"),
        ("aws_secret_access_key=wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY", "[REDACTED]"),
        ("ghp_123456789012345678901234567890123456", "[REDACTED]"),
        ("password: supersecret123", "[REDACTED]"),
    ]
    for raw, expected in sample_texts:
        redacted = redact_secrets(raw)
        assert expected in redacted, f"Failed redaction for {raw}"


@pytest.mark.asyncio
async def test_log_inspection_stores_record(
    audit_logger: AuditLogger,
) -> None:
    action = ActionRequest(
        action_type=ActionType.SHELL_COMMAND,
        command="ls -la",
    )
    decision = SecurityDecision(
        decision=Decision.ALLOW,
        risk_category=RiskCategory.LOW,
        matched_policies=["shell.safe_readonly"],
        explanation="Safe command",
        action_hash=action.compute_hash(),
    )
    entry = await audit_logger.log_inspection(
        action, decision, ai_explanation="AI confirms safe listing"
    )
    assert entry.entry_id is not None
    assert entry.decision == Decision.ALLOW

    # Verify retrieval
    entries = await audit_logger.get_entries(decision="ALLOW")
    assert len(entries) >= 1
    assert entries[0].entry_id == entry.entry_id


@pytest.mark.asyncio
async def test_log_execution_and_statistics(
    audit_logger: AuditLogger,
) -> None:
    action = ActionRequest(
        action_type=ActionType.SHELL_COMMAND,
        command="echo password=secret1234",
    )
    decision = SecurityDecision(
        decision=Decision.ALLOW,
        risk_category=RiskCategory.LOW,
        matched_policies=[],
        explanation="Echo output",
        action_hash=action.compute_hash(),
    )
    entry = await audit_logger.log_execution(
        action=action,
        decision=decision,
        execution_status="success",
        execution_output="password=secret1234",
        duration_ms=15,
        was_simulated=False,
    )
    assert "[REDACTED]" in entry.execution_output

    # Test aggregate stats
    stats = await audit_logger.get_stats()
    assert stats["total"] >= 1
    assert stats["allowed"] >= 1
