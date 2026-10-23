# AgentGuard 🛡️

**Let AI agents act. Make every action accountable.**

AgentGuard is an open-source security layer for tool-using AI agents. Connected to compatible AI clients through the **Model Context Protocol (MCP)**, AgentGuard acts as a security gateway that inspects proposed actions, enforces deterministic safety policies, gates risky operations with action-bound human approvals, executes permitted tasks in a restricted environment, and maintains an auditable trail of all agent activities.

---

## Architecture Overview

```
                      ┌─────────────────────────────────────────┐
                      │    AI Client (Cursor, Claude Desktop)   │
                      └────────────────────┬────────────────────┘
                                           │ MCP Protocol (stdio / SSE)
                                           ▼
                      ┌─────────────────────────────────────────┐
                      │          AgentGuard MCP Server          │
                      │                                         │
                      │  [inspect_action]     [check_policy]    │
                      │  [request_approval]   [get_audit_log]   │
                      └────────────────────┬────────────────────┘
                                           │
                                           ▼
                      ┌─────────────────────────────────────────┐
                      │          Policy Engine (Core)           │
                      │  • Shell command inspection             │
                      │  • Workspace boundary enforcement       │
                      │  • Secret detection & traversal check   │
                      │  • Fail-closed decision model           │
                      └──────────────┬──────────────────┬───────┘
                                     │                  │
               ┌─────────────────────▼─────┐    ┌───────▼────────────────┐
               │    AI Risk Explainer      │    │    Approval Manager    │
               │  • Qwen 2.5 (Apache 2.0)  │    │  • Action-bound hash   │
               │  • Contextual reasoning   │    │  • Expiration control  │
               │  • Graceful degradation   │    │  • AI self-approve ban │
               └───────────────────────────┘    └───────┬────────────────┘
                                                        │
                                                        ▼
                                       ┌────────────────────────────────┐
                                       │  Controlled Execution Adapter  │
                                       │  • Defense-in-depth re-check   │
                                       │  • Workspace containment       │
                                       │  • Output & secret redaction   │
                                       │  • Execution timeout limits    │
                                       └────────────────┬───────────────┘
                                                        │
                                                        ▼
                                       ┌────────────────────────────────┐
                                       │       Audit Log & Storage      │
                                       │  • SQLite + WAL mode           │
                                       │  • Full tamper-evident history │
                                       └────────────────────────────────┘
```

> ⚠️ **Important Architectural Notice:**  
> An MCP server **does not automatically intercept** every raw system call made by an AI client. The AI client, agent framework, or execution runtime must route security-critical operations through AgentGuard's exposed MCP tools. AgentGuard provides an enforceable execution boundary for actions dispatched through it.

---

## Security Decision Model

AgentGuard classifies every proposed operation into one of three distinct outcomes:

| Outcome | Description | Behavior |
|---|---|---|
| **`ALLOW`** | Action complies with all active policies and does not pose unintended hazards. | Permitted to execute immediately through the controlled execution adapter. |
| **`REQUIRE_APPROVAL`** | Action has potentially significant side effects (e.g., deleting workspace files, command chaining). | Gated until an authorized human explicitly approves the exact action hash. |
| **`BLOCK`** | Action violates mandatory security policies (e.g., destructive commands, accessing secrets, directory traversal). | Strictly rejected. **Cannot be overridden** by the AI model or human approval. |

---

## MCP Tools Exposed

1. **`inspect_action`**: Evaluates a proposed action (shell command, file read/write/delete, directory list) against deterministic policies and returns the decision, matched rules, risk severity, and AI explanation without execution.
2. **`check_policy`**: Lightweight, fast compliance check without full risk analysis or audit persistence.
3. **`request_approval`**: Enqueues sensitive actions for human review. Returns an action-bound approval ID. Re-evaluates policy to guarantee prohibited actions cannot enter the queue.
4. **`get_audit_log`**: Retrieves timestamped history of previous decisions, approvals, and execution records with secret redaction.

---

## Installation & Setup

### Prerequisites
- Python 3.11+
- Node.js 18+ (for dashboard frontend)
- (Optional) [Ollama](https://ollama.ai) with `qwen2.5:3b` for local AI risk explanations

### 1. Clone & Set Up Python Environment
```bash
git clone https://github.com/your-username/AgentGuard.git
cd AgentGuard

# Create and activate virtual environment
python -m venv .venv

# Windows PowerShell:
.\.venv\Scripts\Activate.ps1
# Linux / macOS:
# source .venv/bin/activate

# Install dependencies and AgentGuard in editable mode
pip install -e . "pytest>=8.0" "pytest-asyncio>=0.24"
```

### 2. Configure Environment
Copy `.env.example` to `.env`:
```bash
cp .env.example .env
```
Default configuration:
- `AGENTGUARD_WORKSPACE=./workspace`: Path where filesystem actions are strictly confined.
- `AGENTGUARD_DB_PATH=./agentguard.db`: SQLite database location.
- `AGENTGUARD_APPROVAL_TIMEOUT=300`: Approval expiration in seconds (5 minutes).
- `OLLAMA_BASE_URL=http://localhost:11434`: Local Ollama server.
- `OLLAMA_MODEL=qwen2.5:3b`: Open-weight model for risk explanations.

### 3. Build Dashboard Frontend
```bash
cd frontend
npm install
npm run build
cd ..
```

---

## Running AgentGuard

### Option A: Run MCP Server (for AI Clients)
```bash
# Stdio transport (for Cursor or Claude Desktop)
python -m agentguard --mode mcp --transport stdio

# SSE / HTTP transport
python -m agentguard --mode mcp --transport sse --mcp-port 3001
```

### Option B: Run Dashboard API & Web UI
```bash
python -m agentguard --mode api --api-port 8080
```
Open [http://localhost:8080](http://localhost:8080) to access the interactive security dashboard.

### Option C: Run Both MCP Server & Dashboard API Concurrently
```bash
python -m agentguard --mode both --mcp-port 3001 --api-port 8080
```

---

## Connecting to AI Clients

### Cursor Configuration
Add to your Cursor MCP settings (`.cursor/mcp.json` or Global Settings):
```json
{
  "mcpServers": {
    "agentguard": {
      "command": "d:/My Code/AgentGuard/.venv/Scripts/python.exe",
      "args": ["-m", "agentguard", "--mode", "mcp", "--transport", "stdio"]
    }
  }
}
```

### Claude Desktop Configuration
Add to `claude_desktop_config.json`:
```json
{
  "mcpServers": {
    "agentguard": {
      "command": "d:/My Code/AgentGuard/.venv/Scripts/python.exe",
      "args": ["-m", "agentguard", "--mode", "mcp", "--transport", "stdio"]
    }
  }
}
```

---

## Running the Test Suite

AgentGuard includes a comprehensive test suite validating policy evaluations, tamper protection, execution containment, and end-to-end scenarios:

```bash
.\.venv\Scripts\pytest -v
```

---

## Demonstration Scenarios

### Scenario A: Harmless Permitted Operation
- **Action**: Read a file or list contents in the authorized workspace (`ls`, `directory_list`).
- **Result**: `ALLOW`. Executed immediately through the controlled adapter.

### Scenario B: Sensitive Workspace Mutation
- **Action**: Deleting a file inside the workspace (`FILE_DELETE` on `temp.txt`).
- **Result**: `REQUIRE_APPROVAL`. Execution is halted. A human operator reviews and approves the request in the dashboard or via API.

### Scenario C: Prohibited Destructive Operation
- **Action**: Attempting to read `.env`, access `/etc/shadow`, or execute `rm -rf /`.
- **Result**: `BLOCK`. Refused outright. The AI model cannot override this decision.

### Scenario D: Approval Tampering & Invalidation
- **Action**: Request approval for `rm file1.txt`, obtain approval, then alter arguments to `rm important.txt`.
- **Result**: Hash mismatch triggers immediate invalidation. The modified action is rejected.

---

## Model & License Details

- **AI Model**: [Qwen2.5-3B-Instruct](https://huggingface.co/Qwen/Qwen2.5-3B-Instruct)
  - **License**: Apache 2.0 (permissive open-source commercial and research use).
  - **Role**: AI Risk Explainer (summarizes policy triggers and provides safer alternatives).
  - **Graceful Fallback**: The deterministic policy engine functions identically even if the model or Ollama is offline.
- **Software License**: MIT License. See [LICENSE](LICENSE) for details.

---

## Assumptions and Known Limitations

1. **Non-Intrusive Interception**: AgentGuard does not hook OS system calls globally. The client environment must invoke AgentGuard tools.
2. **Command Parsing Bounds**: Complex nested bash expressions and multi-stage pipelines default to `REQUIRE_APPROVAL` (fail-closed).
3. **Platform Scope**: Process isolation uses sub-process sanitization with cleaned environment variables. For multi-tenant hosting, deployment inside containerized sandboxes (Docker / gVisor) is recommended.
