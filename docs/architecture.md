# AgentGuard Architecture

AgentGuard is an MCP-compatible security gateway designed to sit between AI coding agents and the host operating system.

```
┌────────────────────────────────────────────────────────┐
│                   AI Coding Client                     │
│               (Cursor / Claude Desktop)                │
└───────────────────────────┬────────────────────────────┘
                            │
                            │ Model Context Protocol
                            │ (JSON-RPC 2.0 over stdio or SSE)
                            ▼
┌────────────────────────────────────────────────────────┐
│                  AgentGuard MCP Server                 │
│                                                        │
│  • inspect_action(action_type, command, resource, ...) │
│  • check_policy(action_type, operation, resource)      │
│  • request_approval(action_type, command, resource)    │
│  • get_audit_log(entry_id, decision, limit)            │
└───────────┬────────────────────────────────┬───────────┘
            │                                │
            ▼                                ▼
┌───────────────────────┐        ┌───────────────────────┐
│     Policy Engine     │        │    FastAPI Gateway    │
│  (Deterministic Rules)│        │   (Port 8080 REST)    │
└───────────┬───────────┘        └───────────┬───────────┘
            │                                │
     ┌──────┴──────┐                  ┌──────┴──────┐
     ▼             ▼                  ▼             ▼
┌─────────┐   ┌─────────┐        ┌─────────┐   ┌─────────┐
│  Shell  │   │   FS    │        │Approval │   │  React  │
│Policies │   │Policies │        │ REST API│   │Dashboard│
└────┬────┘   └────┬────┘        └─────────┘   └─────────┘
     │             │
     └──────┬──────┘
            ▼
┌────────────────────────────────────────────────────────┐
│                 Security Decision Engine               │
│                                                        │
│   Resolution: BLOCK > REQUIRE_APPROVAL > ALLOW        │
│   Default-Deny for unmapped actions                    │
└───────────┬────────────────────────────────┬───────────┘
            │                                │
            ▼ (Enriched by)                  ▼ (If REQUIRE_APPROVAL)
┌───────────────────────┐        ┌───────────────────────┐
│   AI Risk Explainer   │        │   Approval Manager    │
│ (Qwen 2.5-3B, local)  │        │ • Action-bound hash   │
│ • Non-authoritative   │        │ • Time-to-live expiry │
│ • Graceful degradation│        │ • Strict human check  │
└───────────────────────┘        └───────────┬───────────┘
                                             │
                                             ▼ (If ALLOW or Valid Approval)
                                 ┌───────────────────────┐
                                 │  Controlled Executor  │
                                 │ • Defense-in-depth    │
                                 │ • Cleaned environment │
                                 │ • Timeout enforcement │
                                 │ • Output truncation   │
                                 └───────────┬───────────┘
                                             │
                                             ▼
                                 ┌───────────────────────┐
                                 │  Audit Logger (SQLite)│
                                 │ • Redacted secrets    │
                                 │ • Immutable events    │
                                 └───────────────────────┘
```

## Component Responsibilities

### 1. MCP Server (`server.py`)
- Implements MCP 2.x standard (`MCPServer`).
- Exposes tools to AI clients via JSON-RPC.
- Handles input parsing and parameter normalization.
- Serves as the first point of contact for AI clients.

### 2. Policy Engine (`policy_engine.py`)
- Manages policy catalog (mandatory and configurable rules).
- Concurrently evaluates all active rules using `asyncio.gather`.
- Computes SHA-256 canonical hash of proposed actions.
- Resolves conflicts using a strict hierarchy:
  1. `BLOCK` takes precedence over all other outcomes.
  2. `REQUIRE_APPROVAL` takes precedence over `ALLOW`.
  3. No matching policies defaults to `REQUIRE_APPROVAL` (fail-closed).

### 3. Approval Manager (`approval_manager.py`)
- Creates pending approvals strictly tied to the SHA-256 action hash.
- Enforces human-only approval checks (rejects `ai_agent`, `bot`, `copilot`, `assistant`).
- Enforces approval expiration lifetimes.
- Invalidates approval if any action attribute (command, resource, arguments, working dir) changes.

### 4. Controlled Execution Adapter (`executor.py`)
- Serves as the execution boundary.
- Conducts defense-in-depth re-evaluation immediately prior to execution.
- Verifies workspace path containment, denying directory traversal and symlink escapes.
- Strips sensitive environment variables (API keys, credentials, tokens) from child processes.
- Enforces timeout limits and output byte bounds.
- Automatically redacts sensitive patterns in stdout and stderr.

### 5. AI Risk Explainer (`risk_explainer.py`)
- Employs an open-weight local model (`qwen2.5:3b` via Ollama).
- Provides plain-language explanations and safer alternatives.
- **Strictly advisory**: The AI model has zero authority to approve or override decisions.
- Operates with strict timeouts and falls back gracefully if Ollama is unreachable.

### 6. Audit & Storage (`db.py` & `audit_log.py`)
- SQLite database configured with Write-Ahead Logging (WAL) mode for concurrent access.
- Redacts secrets from command arguments and execution output prior to disk persistence.
- Provides indexed query capabilities for dashboard inspection.
