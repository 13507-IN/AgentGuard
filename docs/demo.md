# AgentGuard Live Demonstration Guide

This guide walks through reproducing the 4 required demonstration scenarios using AgentGuard.

---

## Prerequisites

1. Ensure the Python virtual environment is activated:
   ```powershell
   .\.venv\Scripts\Activate.ps1
   ```
2. Start the AgentGuard backend in `both` mode:
   ```powershell
   python -m agentguard --mode both --api-port 8080 --mcp-port 3001
   ```
3. Open the Dashboard in your browser:
   [http://localhost:8080](http://localhost:8080)

---

## Scenario A: Harmless Permitted Action (`ALLOW`)

### Objective
Demonstrate that standard, safe developer operations execute smoothly without unnecessary prompts.

### Action
An AI agent attempts to list files in the designated workspace.

### Inspection via MCP / Inspector Tool
- **Action Type**: `directory_list`
- **Resource**: `./workspace`

### Result
- **Decision**: `ALLOW`
- **Policy Matched**: `fs.directory_list`
- **Execution**: The controlled execution layer validates workspace containment and returns the directory listing immediately.
- **Audit**: Logged as `ALLOW` with `execution_status: success`.

---

## Scenario B: Sensitive Workspace Mutation (`REQUIRE_APPROVAL`)

### Objective
Demonstrate that risky actions are blocked from executing until explicit, human approval is granted.

### Action
An AI agent proposes deleting a file within the workspace.

### Steps
1. Create a dummy file in the workspace:
   ```powershell
   "temporary build artifact" | Out-File -FilePath ./workspace/temp_build.log
   ```
2. Agent calls `inspect_action` or `request_approval`:
   - **Action Type**: `file_delete`
   - **Resource**: `./workspace/temp_build.log`
3. **Outcome**:
   - **Decision**: `REQUIRE_APPROVAL`
   - **Status**: `pending`
   - **Approval ID**: Created and queued in the dashboard.
4. Verify the file `./workspace/temp_build.log` **still exists** on disk.
5. In the Dashboard under the **Approvals** tab:
   - Review the requested action summary and risk severity.
   - Enter your name/operator ID (e.g., `developer_john`).
   - Click **Approve**.
6. Trigger execution with the valid `approval_id`. The file is now safely unlinked.
7. Attempting to approve using an AI identity (e.g. `ai_agent`) is strictly rejected with a validation error.

---

## Scenario C: Prohibited Destructive Operation (`BLOCK`)

### Objective
Demonstrate that hard security policies cannot be bypassed by agent persuasion or approvals.

### Action
An agent attempts to read secret credentials or run a destructive system command.

### Test Commands
1. **Secret File Access**:
   - **Action Type**: `file_read`
   - **Resource**: `./workspace/.env`
   - **Result**: `BLOCK` (Matched: `fs.secret_files`)
2. **Destructive Shell Command**:
   - **Action Type**: `shell_command`
   - **Command**: `rm -rf /` (or `format C:`)
   - **Result**: `BLOCK` (Matched: `shell.destructive_commands`)
3. **Privilege Escalation**:
   - **Action Type**: `shell_command`
   - **Command**: `sudo cat /etc/shadow`
   - **Result**: `BLOCK` (Matched: `shell.privilege_escalation`)

### Enforcement
- The controlled execution layer rejects the action immediately.
- The action cannot be submitted to the approval queue.
- Even if the AI risk explainer generates a justification, the policy engine holds the `BLOCK` decision.

---

## Scenario D: Approval Tampering & Invalidation

### Objective
Demonstrate that approvals are cryptographically bound to the exact action and cannot be replayed or altered.

### Steps
1. Request approval for a benign deletion:
   - Action: `file_delete` on `./workspace/safe_file.txt`
2. An authorized human approves the request, creating an approval record bound to $\text{Hash}_1$.
3. The agent attempts to execute a different action using the same approval ID:
   - Tampered Action: `file_delete` on `./workspace/critical_database.db` (which computes to $\text{Hash}_2$).
4. The controlled execution adapter detects that:
   $$\text{Hash}_1 \neq \text{Hash}_2$$
5. Execution is refused with an authorization mismatch error. The critical database remains untouched.
