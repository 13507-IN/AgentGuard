"""MongoDB database initialization and access for AgentGuard.

Uses Motor (async Python driver for MongoDB) to store audit logs and approval records.
"""

from __future__ import annotations

import asyncio
import json
import logging
from datetime import datetime, timedelta, timezone
from typing import Any

from motor.motor_asyncio import AsyncIOMotorClient
import pymongo

from agentguard.config import AgentGuardConfig

logger = logging.getLogger("agentguard.db")


class Database:
    """Async MongoDB database client for AgentGuard."""

    def __init__(self, target: AgentGuardConfig | str | None = None):
        if isinstance(target, AgentGuardConfig):
            self.uri = target.mongodb_uri
            self.database_name = target.mongodb_database
        elif isinstance(target, str):
            if target.startswith("mongodb://") or target.startswith("mongodb+srv://"):
                self.uri = target
                self.database_name = "agentguard"
            else:
                from pathlib import Path
                cfg = AgentGuardConfig.from_env()
                self.uri = cfg.mongodb_uri
                clean_name = "".join(c for c in Path(target).stem if c.isalnum() or c == "_") or "test_db"
                self.database_name = f"test_{clean_name}"
        else:
            cfg = AgentGuardConfig.from_env()
            self.uri = cfg.mongodb_uri
            self.database_name = cfg.mongodb_database

        self._client: AsyncIOMotorClient | None = None
        self._db: Any = None
        self._audit_col: Any = None
        self._approvals_col: Any = None
        self._loop: Any = None

    async def initialize(self) -> None:
        """Connect to MongoDB and set up required indexes."""
        try:
            self._loop = asyncio.get_running_loop()
            self._client = AsyncIOMotorClient(
                self.uri,
                serverSelectionTimeoutMS=5000,
                connectTimeoutMS=5000,
                socketTimeoutMS=5000,
            )
            # Verify server is actually alive
            await self._client.server_info()
            self._db = self._client[self.database_name]
            self._audit_col = self._db["audit_log"]
            self._approvals_col = self._db["approvals"]

            # Create performance and query indexes
            await self._audit_col.create_index([("timestamp", pymongo.DESCENDING)])
            await self._audit_col.create_index([("decision", pymongo.ASCENDING)])
            await self._audit_col.create_index([("action_type", pymongo.ASCENDING)])

            await self._approvals_col.create_index([("status", pymongo.ASCENDING)])
            await self._approvals_col.create_index([("action_hash", pymongo.ASCENDING)])
            await self._approvals_col.create_index([("expires_at", pymongo.ASCENDING)])
            logger.info("Connected to MongoDB at %s (database: %s)", self.uri, self.database_name)
        except pymongo.errors.PyMongoError as exc:
            logger.error("Failed to connect to MongoDB at %s: %s", self.uri, exc)
            raise ConnectionError(
                f"AgentGuard requires MongoDB, but could not connect to {self.uri}. "
                "Please verify that MongoDB is running locally (e.g. on port 27017) "
                "or configure MONGODB_URI in your .env file."
            ) from exc

    async def ensure_connected(self) -> None:
        """Ensure MongoDB client is connected and bound to the current running event loop."""
        try:
            current_loop = asyncio.get_running_loop()
        except RuntimeError:
            return

        if (
            self._client is not None
            and self._loop is not None
            and self._loop == current_loop
            and not current_loop.is_closed()
        ):
            return

        await self.initialize()

    async def close(self) -> None:
        """Close MongoDB connection."""
        if self._client:
            self._client.close()
            self._client = None
            self._db = None

    # ---- Audit Log ----

    async def insert_audit_entry(self, entry: dict[str, Any]) -> None:
        """Insert or replace an audit log entry in MongoDB."""
        await self.ensure_connected()
        doc = dict(entry)
        doc["_id"] = doc["entry_id"]
        if isinstance(doc.get("matched_policies"), str):
            try:
                doc["matched_policies"] = json.loads(doc["matched_policies"])
            except Exception:
                pass
        await self._audit_col.replace_one({"_id": doc["_id"]}, doc, upsert=True)

    async def get_audit_entries(
        self,
        entry_id: str | None = None,
        decision: str | None = None,
        action_type: str | None = None,
        since_minutes: int | None = None,
        limit: int = 50,
    ) -> list[dict[str, Any]]:
        """Query audit log entries with optional filters."""
        await self.ensure_connected()
        query: dict[str, Any] = {}
        if entry_id:
            query["entry_id"] = entry_id
        if decision:
            query["decision"] = decision
        if action_type:
            query["action_type"] = action_type
        if since_minutes:
            cutoff = (datetime.now(timezone.utc) - timedelta(minutes=since_minutes)).isoformat()
            query["timestamp"] = {"$gte": cutoff}

        cursor = self._audit_col.find(query, {"_id": 0}).sort("timestamp", pymongo.DESCENDING).limit(limit)
        results = []
        async for doc in cursor:
            if isinstance(doc.get("matched_policies"), str):
                try:
                    doc["matched_policies"] = json.loads(doc["matched_policies"])
                except Exception:
                    pass
            results.append(doc)
        return results

    async def get_audit_stats(self) -> dict[str, int]:
        """Get aggregate counts for the dashboard overview."""
        await self.ensure_connected()
        total = await self._audit_col.count_documents({})
        allowed = await self._audit_col.count_documents({"decision": "ALLOW"})
        blocked = await self._audit_col.count_documents({"decision": "BLOCK"})
        require_approval = await self._audit_col.count_documents({"decision": "REQUIRE_APPROVAL"})
        return {
            "total": total,
            "allowed": allowed,
            "blocked": blocked,
            "require_approval": require_approval,
        }

    # ---- Approvals ----

    async def insert_approval(self, record: dict[str, Any]) -> None:
        """Insert or update an approval record in MongoDB."""
        await self.ensure_connected()
        doc = dict(record)
        doc["_id"] = doc["approval_id"]
        if isinstance(doc.get("action_details"), str):
            try:
                doc["action_details"] = json.loads(doc["action_details"])
            except Exception:
                pass
        await self._approvals_col.replace_one({"_id": doc["_id"]}, doc, upsert=True)

    async def get_approval(self, approval_id: str) -> dict[str, Any] | None:
        """Get a single approval record by ID."""
        await self.ensure_connected()
        doc = await self._approvals_col.find_one({"approval_id": approval_id}, {"_id": 0})
        if doc and isinstance(doc.get("action_details"), str):
            try:
                doc["action_details"] = json.loads(doc["action_details"])
            except Exception:
                pass
        return doc

    async def update_approval_status(
        self,
        approval_id: str,
        status: str,
        decided_by: str | None = None,
        decided_at: str | None = None,
    ) -> None:
        """Update the status of an approval."""
        await self.ensure_connected()
        await self._approvals_col.update_one(
            {"approval_id": approval_id},
            {
                "$set": {
                    "status": status,
                    "decided_by": decided_by,
                    "decided_at": decided_at,
                }
            },
        )

    async def get_approvals(self, status: str | None = None, limit: int = 50) -> list[dict[str, Any]]:
        """Get approvals with optional status filter (e.g. pending, approved, rejected, expired, all)."""
        await self.ensure_connected()
        query: dict[str, Any] = {}
        if status and status.lower() != "all":
            query["status"] = status.lower()
        cursor = self._approvals_col.find(query, {"_id": 0}).sort(
            "requested_at", pymongo.DESCENDING
        ).limit(limit)
        results = []
        async for doc in cursor:
            if isinstance(doc.get("action_details"), str):
                try:
                    doc["action_details"] = json.loads(doc["action_details"])
                except Exception:
                    pass
            results.append(doc)
        return results

    async def get_pending_approvals(self) -> list[dict[str, Any]]:
        """Get all pending approvals."""
        return await self.get_approvals(status="pending", limit=100)

    async def expire_stale_approvals(self) -> int:
        """Expire all pending approvals that have passed their timeout."""
        await self.ensure_connected()
        now = datetime.now(timezone.utc).isoformat()
        res = await self._approvals_col.update_many(
            {"status": "pending", "expires_at": {"$lte": now}},
            {"$set": {"status": "expired"}},
        )
        return res.modified_count


# Compatibility alias
MongoDatabase = Database
