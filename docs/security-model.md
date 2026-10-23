# AgentGuard Security Model & Threat Specification

## 1. Threat Model & Design Principles

### Core Principles
1. **Never Trust the LLM for Security Decisions**: Language models can generate plausible justifications for dangerous commands. Security decisions must be deterministic, auditable, and mathematically bound.
2. **Fail-Closed by Default**: Unrecognized action types or ambiguous instructions default to `REQUIRE_APPROVAL` or `BLOCK`.
3. **Action-Bound Approvals**: An approval for operation $A$ must never authorize operation $A'$. Any change in command, arguments, or path alters the cryptographic hash and invalidates the approval.
4. **Defense-in-Depth**: Policies are verified at inspection time, verified again at approval time, and verified a third time immediately prior to subprocess invocation.

---

## 2. Decision Outcomes

### `ALLOW`
Operations explicitly permitted under active policy that carry negligible risk of persistent harm or credential compromise.
- *Examples*: Reading workspace files, listing directory contents within workspace boundaries, safe inspection commands (`pwd`, `whoami`, `date`, `ls`).

### `REQUIRE_APPROVAL`
Operations that cause mutations, state changes, or potential side-effects within the authorized boundary.
- *Examples*: Modifying files, deleting workspace files, package installation, network connections, chained shell commands (`&&`, `||`, `;`).
- *Enforcement*: Cannot be executed until an authorized human logs into the dashboard or calls the approval endpoint with a verified non-AI identity.

### `BLOCK`
Operations that violate hard security boundaries or pose unacceptable hazards.
- *Examples*: Destructive shell commands (`rm -rf /`, `mkfs`, `format`, `dd`), privilege escalation (`sudo`, `su`, `runas`), reading secret files (`.env`, `id_rsa`, `.aws/credentials`), path traversal outside the workspace, touching system paths (`/etc`, `C:\Windows`).
- *Enforcement*: Hard stop. Neither the AI model nor human approval can override a `BLOCK` decision.

---

## 3. Policy Catalog & Classification

### Shell Policies
| ID | Policy Name | Severity | Action | Mandatory |
|---|---|---|---|---|
| `shell.destructive_commands` | Destructive Command Filter | CRITICAL | BLOCK | Yes |
| `shell.privilege_escalation` | Privilege Escalation Guard | CRITICAL | BLOCK | Yes |
| `shell.command_chaining` | Command Chaining Detection | HIGH | BLOCK / APPROVE | Yes |
| `shell.dangerous_commands` | Sensitive Command Review | MEDIUM | REQUIRE_APPROVAL | No |
| `shell.network_exfil` | Network Call Guard | HIGH | REQUIRE_APPROVAL | No |
| `shell.safe_readonly` | Safe Read-Only Permitter | LOW | ALLOW | No |

### Filesystem Policies
| ID | Policy Name | Severity | Action | Mandatory |
|---|---|---|---|---|
| `fs.workspace_boundary` | Workspace Boundary Enforcer | CRITICAL | BLOCK | Yes |
| `fs.path_traversal` | Path Traversal & Symlink Check | CRITICAL | BLOCK | Yes |
| `fs.secret_files` | Secret Files Protection | CRITICAL | BLOCK | Yes |
| `fs.protected_dirs` | Protected OS Directory Enforcer | CRITICAL | BLOCK | Yes |
| `fs.file_deletion` | File Deletion Guard | HIGH | REQUIRE_APPROVAL | No |
| `fs.file_write` | Workspace File Write Permitter | LOW | ALLOW | No |
| `fs.file_read` | Workspace File Read Permitter | LOW | ALLOW | No |
| `fs.directory_list` | Workspace Directory Listing | LOW | ALLOW | No |

---

## 4. Tamper Protection Mechanics

1. **Canonical Action Hashing**:
   Before an action is evaluated or enqueued for approval, it is transformed into a canonical JSON representation:
   $$\text{Hash} = \text{SHA-256}(\text{JSON}(\text{action\_type}, \text{command}, \text{resource}, \text{sorted}(\text{arguments}), \text{working\_dir}))$$
2. **Approval Binding**:
   The approval record in the database stores this exact hash.
3. **Execution Verification**:
   The execution adapter re-computes the hash of the action submitted for execution. If:
   $$\text{Hash}_{\text{execution}} \neq \text{Hash}_{\text{approval}}$$
   Execution is refused immediately.

---

## 5. Known Gaps & Out-of-Scope Risks (MVP)

- **Kernel Exploits**: AgentGuard runs commands within subprocess boundaries with sanitized environment variables, but does not provide hardware virtualization (e.g., Firecracker microVMs).
- **In-Memory Data Exfiltration**: Allowed read operations that transmit contents through subsequent natural language prompts must be managed via client context filters.
- **Complex Shell Encodings**: Advanced obfuscation (such as base64-decoded commands piped into `eval`) are mitigated by blocking command chaining and pipes, but arbitrary eval execution should be disabled in the host shell.
