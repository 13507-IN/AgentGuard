"""Unit tests for MongoDB backend in AgentGuard."""

from __future__ import annotations

import pytest

from agentguard.config import AgentGuardConfig
from agentguard.db import Database, MongoDatabase


@pytest.mark.asyncio
async def test_mongodb_backend_operations():
    # Connect to test database
    cfg = AgentGuardConfig.from_env()
    cfg.mongodb_database = "agentguard_test_db"
    db = Database(cfg)
    try:
        await db.initialize()
    except Exception as e:
        pytest.skip(f"MongoDB not available: {e}")

    # 1. Insert audit entry
    await db.insert_audit_entry({
        "entry_id": "mongo-test-1",
        "action_type": "file_read",
        "action_summary": "Reading test config in Mongo",
        "action_hash": "hash12345",
        "decision": "ALLOW",
        "risk_category": "low",
        "matched_policies": ["fs.file_read"],
        "explanation": "Mongo read test",
        "timestamp": "2026-10-23T12:00:00Z",
    })

    # 2. Query audit entries
    entries = await db.get_audit_entries(entry_id="mongo-test-1")
    assert len(entries) == 1
    assert entries[0]["action_summary"] == "Reading test config in Mongo"

    # 3. Stats
    stats = await db.get_audit_stats()
    assert stats["total"] >= 1
    assert stats["allowed"] >= 1

    # 4. Insert approval
    await db.insert_approval({
        "approval_id": "app-test-1",
        "action_hash": "hash12345",
        "action_summary": "Delete temp file",
        "action_details": {"resource": "temp.txt"},
        "risk_category": "high",
        "requested_at": "2026-10-23T12:00:00Z",
        "expires_at": "2026-10-23T12:30:00Z",
        "status": "pending",
    })

    # 5. Retrieve approval
    app = await db.get_approval("app-test-1")
    assert app is not None
    assert app["status"] == "pending"

    # 6. Update approval
    await db.update_approval_status("app-test-1", "approved", decided_by="admin_user")
    app_updated = await db.get_approval("app-test-1")
    assert app_updated["status"] == "approved"
    assert app_updated["decided_by"] == "admin_user"

    await db.close()
