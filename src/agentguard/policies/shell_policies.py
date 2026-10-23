"""Shell command security policies for AgentGuard.

Inspects shell commands for destructive actions, dangerous patterns,
command chaining, privilege escalation, and network exfiltration.
"""

from __future__ import annotations

import re
import shlex
from pathlib import Path
from typing import Any

from agentguard.policies.base import Policy
from agentguard.schemas import (
    ActionRequest,
    ActionType,
    Decision,
    PolicyResult,
    RiskCategory,
)


# ---------------------------------------------------------------------------
# Helper Parsing Functions
# ---------------------------------------------------------------------------


def _manual_split(command: str) -> list[str]:
    """Tokenize a command string manually when shlex.split fails (e.g. unclosed quotes)."""
    tokens: list[str] = []
    current: list[str] = []
    in_single = False
    in_double = False
    escape = False

    for char in command:
        if escape:
            current.append(char)
            escape = False
            continue

        if char == "\\":
            escape = True
            continue

        if char == "'" and not in_double:
            in_single = not in_single
            continue

        if char == '"' and not in_single:
            in_double = not in_double
            continue

        if char.isspace() and not in_single and not in_double:
            if current:
                tokens.append("".join(current))
                current = []
        else:
            current.append(char)

    if current:
        tokens.append("".join(current))

    return tokens


def parse_shell_command(command: str) -> tuple[str, list[str]]:
    """Parse a shell command string into (base_command, args).

    Handles Windows paths (with backslashes), POSIX commands, quoted arguments,
    and falls back to manual parsing on syntax errors.

    Args:
        command: The raw shell command string.

    Returns:
        A tuple of (base_command, list_of_arguments).
    """
    if not command or not command.strip():
        return ("", [])

    cleaned = command.strip()
    tokens: list[str] = []

    # Try POSIX parsing first via shlex.split
    # Note: On Windows paths with backslashes, if posix=True it escapes backslashes.
    # If the command has Windows path markers (drive letter or backslash), we try
    # Windows-friendly splitting or fallback.
    try:
        if "\\" in cleaned:
            # Preserve backslashes for Windows path handling
            raw_tokens = shlex.split(cleaned, posix=False)
            tokens = [
                t[1:-1]
                if (
                    len(t) >= 2
                    and ((t[0] == '"' and t[-1] == '"') or (t[0] == "'" and t[-1] == "'"))
                )
                else t
                for t in raw_tokens
            ]
        else:
            tokens = shlex.split(cleaned, posix=True)
    except ValueError:
        tokens = _manual_split(cleaned)

    if not tokens:
        return ("", [])

    # If the command line starts with environment variable assignments (e.g., VAR=val cmd)
    # find the actual executable
    idx = 0
    while idx < len(tokens) and re.match(r"^[A-Za-z_][A-Za-z0-9_]*=.*$", tokens[idx]):
        idx += 1

    if idx >= len(tokens):
        return (tokens[0], tokens[1:])

    return (tokens[idx], tokens[idx + 1 :])


def _extract_executable_name(cmd: str) -> str:
    """Extract normalized executable name without path or file extension."""
    if not cmd:
        return ""
    # Strip quotes if present
    cleaned = cmd.strip("\"' ")
    name = Path(cleaned).name
    # Strip common executable extensions
    for ext in (".exe", ".bat", ".cmd", ".sh", ".bin"):
        if name.lower().endswith(ext):
            name = name[: -len(ext)]
            break
    return name.lower()


def has_chaining_operators(command: str) -> bool:
    """Check if command contains unquoted chaining operators or command substitutions.

    Detects:
    - &&
    - ||
    - ;
    - backticks (`)
    - $(...)

    Operators inside single quotes are ignored. In double quotes, backticks and $()
    are active (as evaluated by shells).
    """
    in_single = False
    in_double = False
    escape = False
    i = 0
    n = len(command)

    while i < n:
        c = command[i]

        if escape:
            escape = False
            i += 1
            continue

        if c == "\\":
            escape = True
            i += 1
            continue

        if c == "'" and not in_double:
            in_single = not in_single
            i += 1
            continue

        if c == '"' and not in_single:
            in_double = not in_double
            i += 1
            continue

        if not in_single:
            # Active in both unquoted and double-quoted contexts in POSIX shells
            if c == "`":
                return True
            if c == "$" and i + 1 < n and command[i + 1] == "(":
                return True

        if not in_single and not in_double:
            # Only active outside all quotes
            if c == ";":
                return True
            if c == "&" and i + 1 < n and command[i + 1] == "&":
                return True
            if c == "|" and i + 1 < n and command[i + 1] == "|":
                return True

        i += 1

    return False


def split_chained_commands(command: str) -> list[str]:
    """Split a chained command into sub-commands and extracted substitutions.

    Splits on unquoted &&, ||, and ; and extracts inner commands from $(...) and `...`.
    """
    parts: list[str] = []

    # 1. Extract command substitutions
    for m in re.finditer(r"\$\((.*?)\)", command):
        inner = m.group(1).strip()
        if inner:
            parts.append(inner)

    for m in re.finditer(r"`(.*?)`", command):
        inner = m.group(1).strip()
        if inner:
            parts.append(inner)

    # 2. Split by unquoted operators &&, ||, ;
    current: list[str] = []
    in_single = False
    in_double = False
    escape = False
    i = 0
    n = len(command)

    while i < n:
        c = command[i]

        if escape:
            escape = False
            current.append(c)
            i += 1
            continue

        if c == "\\":
            escape = True
            current.append(c)
            i += 1
            continue

        if c == "'" and not in_double:
            in_single = not in_single
            current.append(c)
            i += 1
            continue

        if c == '"' and not in_single:
            in_double = not in_double
            current.append(c)
            i += 1
            continue

        if not in_single and not in_double:
            if c == ";":
                part = "".join(current).strip()
                if part:
                    parts.append(part)
                current = []
                i += 1
                continue
            if c == "&" and i + 1 < n and command[i + 1] == "&":
                part = "".join(current).strip()
                if part:
                    parts.append(part)
                current = []
                i += 2
                continue
            if c == "|" and i + 1 < n and command[i + 1] == "|":
                part = "".join(current).strip()
                if part:
                    parts.append(part)
                current = []
                i += 2
                continue

        current.append(c)
        i += 1

    final_part = "".join(current).strip()
    if final_part:
        parts.append(final_part)

    return parts


# ---------------------------------------------------------------------------
# Command Inspection Helpers
# ---------------------------------------------------------------------------


def is_destructive_command(command: str) -> tuple[bool, str]:
    """Check if a command is destructive.

    Returns (is_destructive, explanation).
    """
    base_cmd, args = parse_shell_command(command)
    norm_cmd = _extract_executable_name(base_cmd)

    # 1. Fork bomb patterns
    if re.search(r":\s*\(\s*\)\s*\{\s*:\s*\|\s*:\s*&\s*\}\s*;\s*:", command):
        return True, "Fork bomb pattern ':(){ :|:& };:' detected"
    if re.search(r"(\w+)\s*\(\s*\)\s*\{\s*\1\s*\|\s*\1\s*&\s*\}\s*;\s*\1", command):
        return True, "Fork bomb recursion pattern detected"

    # 2. rm -rf or rm -r / (with flags interspersed)
    if norm_cmd == "rm":
        has_recursive = False
        has_force = False
        targets: list[str] = []

        for arg in args:
            if arg.startswith("--"):
                if arg == "--recursive":
                    has_recursive = True
                elif arg == "--force":
                    has_force = True
            elif arg.startswith("-"):
                # Short flags e.g. -rf, -fr, -r, -f, -rfi
                lower_arg = arg[1:].lower()
                if "r" in lower_arg:
                    has_recursive = True
                if "f" in lower_arg:
                    has_force = True
            else:
                targets.append(arg)

        # Regex fallback for interspersed flags
        if not has_recursive:
            if re.search(r"\brm\b\s+.*-[a-zA-Z]*r", command, re.IGNORECASE) or "--recursive" in command:
                has_recursive = True
        if not has_force:
            if re.search(r"\brm\b\s+.*-[a-zA-Z]*f", command, re.IGNORECASE) or "--force" in command:
                has_force = True

        if has_recursive and has_force:
            return True, "Destructive recursive force deletion 'rm -rf' detected"

        # rm -r / or root / system paths
        if has_recursive:
            root_targets = {"/", "/*", "~", "c:\\", "c:/", "..", "\\"}
            for t in targets:
                clean_t = t.rstrip("/\\").lower()
                if t in root_targets or clean_t in ("", "c:"):
                    return True, f"Destructive recursive deletion on root directory '{t}' detected"
            # Regex for rm -r /
            if re.search(r"\brm\s+.*-[a-zA-Z]*r[a-zA-Z]*\s+(?:/|/\*|~|[a-zA-Z]:[/\\])", command, re.IGNORECASE):
                return True, "Destructive recursive deletion on root directory detected"

    # 3. mkfs
    if norm_cmd == "mkfs" or norm_cmd.startswith("mkfs."):
        return True, f"Filesystem formatting command '{base_cmd}' detected"
    if re.search(r"\bmkfs(?:\.\w+)?\b", command):
        return True, "Filesystem formatting command 'mkfs' detected"

    # 4. dd if=
    if norm_cmd == "dd":
        if any(arg.startswith("if=") or "if=" in arg for arg in args):
            return True, "Low-level block copy command 'dd if=' detected"
    if re.search(r"\bdd\b\s+.*if=", command):
        return True, "Low-level block copy command 'dd if=' detected"

    # 5. format (Windows/DOS)
    if norm_cmd == "format":
        return True, "Disk formatting command 'format' detected"
    if re.search(r"\bformat\s+[a-zA-Z]:", command, re.IGNORECASE):
        return True, "Disk formatting command 'format' detected"

    # 6. System shutdown/reboot/halt/poweroff
    if norm_cmd in {"shutdown", "reboot", "halt", "poweroff", "init"}:
        return True, f"System termination command '{base_cmd}' detected"

    # 7. kill -9 1
    if norm_cmd == "kill":
        has_kill9 = any(arg in {"-9", "-KILL", "-SIGKILL"} for arg in args)
        has_target_one = any(arg == "1" for arg in args)
        if has_kill9 and has_target_one:
            return True, "Destructive command 'kill -9 1' (killing init process) detected"
    if re.search(r"\bkill\s+.*(?:-9|-KILL|-s\s+9|-SIGKILL)\s+.*(?:\b1\b)", command):
        return True, "Destructive command 'kill -9 1' (killing init process) detected"

    return False, ""


def is_dangerous_command(command: str) -> tuple[bool, str]:
    """Check if a command is dangerous and requires approval.

    Returns (is_dangerous, explanation).
    """
    base_cmd, args = parse_shell_command(command)
    norm_cmd = _extract_executable_name(base_cmd)

    # 1. rm (non-recursive)
    if norm_cmd == "rm":
        return True, f"File deletion command '{command}' requires user approval"

    # 2. chmod 777 or permissive permissions
    if norm_cmd == "chmod":
        if any("777" in arg or "a+rwx" in arg or "o+w" in arg for arg in args):
            return True, f"Overly permissive chmod command '{command}' requires approval"

    # 3. chown
    if norm_cmd == "chown":
        return True, f"File ownership change command '{command}' requires approval"

    # 4. curl | sh / wget | bash (pipes to shell interpreters)
    if re.search(
        r"\b(?:curl|wget)\b.*\|\s*(?:ba|z|da)?sh\b", command, re.IGNORECASE
    ) or re.search(r"\b(?:curl|wget)\b.*\|\s*python", command, re.IGNORECASE):
        return True, f"Piping remote web download into a shell interpreter '{command}' requires approval"

    # 5. pip install without --dry-run
    if norm_cmd in {"pip", "pip3"}:
        if "install" in args and "--dry-run" not in args:
            return True, f"Package installation '{command}' modifies the environment and requires approval"
    elif norm_cmd in {"python", "python3"} and "pip" in args and "install" in args:
        if "--dry-run" not in args:
            return True, f"Package installation '{command}' modifies the environment and requires approval"

    return False, ""


def is_privilege_escalation(command: str) -> tuple[bool, str]:
    """Check if command attempts privilege escalation.

    Returns (is_priv_esc, explanation).
    """
    base_cmd, _ = parse_shell_command(command)
    norm_cmd = _extract_executable_name(base_cmd)

    escalation_bins = {"sudo", "su", "doas", "runas", "pkexec"}
    if norm_cmd in escalation_bins:
        return True, f"Privilege escalation command '{base_cmd}' is prohibited"

    # Check for escalation commands nested within wrappers (e.g. env sudo)
    tokens = command.split()
    for token in tokens:
        clean = _extract_executable_name(token)
        if clean in escalation_bins:
            return True, f"Privilege escalation command '{token}' detected in command line"

    return False, ""


# ---------------------------------------------------------------------------
# Policy Implementations
# ---------------------------------------------------------------------------


class DestructiveCommandPolicy(Policy):
    """Blocks destructive shell commands that cause irreversible data loss or system damage.

    Rules:
    - BLOCK: rm -rf, rm -r /, mkfs, dd if=, format, shutdown, reboot, halt, kill -9 1, fork bombs.
    - Flags can be interspersed in any order.
    """

    policy_id = "shell.destructive_commands"
    name = "Destructive Shell Commands"
    description = "Blocks destructive shell commands that could cause system damage or data loss"
    is_mandatory = True
    enabled = True

    async def evaluate(self, action: ActionRequest, workspace: Path) -> PolicyResult | None:
        """Evaluate action for destructive shell commands."""
        if action.action_type != ActionType.SHELL_COMMAND or not action.command:
            return None

        destructive, reason = is_destructive_command(action.command)
        if destructive:
            return PolicyResult(
                policy_id=self.policy_id,
                policy_name=self.name,
                decision=Decision.BLOCK,
                risk_category=RiskCategory.CRITICAL,
                explanation=reason,
                safer_alternative=(
                    "Refrain from running destructive system commands. "
                    "For file modifications, target specific workspace files individually."
                ),
            )

        return None


class DangerousCommandPolicy(Policy):
    """Requires approval for potentially dangerous shell operations.

    Rules:
    - REQUIRE_APPROVAL: rm (non-recursive), chmod 777, chown, curl | sh, wget | bash,
      pip install (without --dry-run).
    """

    policy_id = "shell.dangerous_commands"
    name = "Dangerous Shell Commands"
    description = "Requires human approval for potentially dangerous shell operations"
    is_mandatory = False
    enabled = True

    async def evaluate(self, action: ActionRequest, workspace: Path) -> PolicyResult | None:
        """Evaluate action for dangerous shell commands requiring approval."""
        if action.action_type != ActionType.SHELL_COMMAND or not action.command:
            return None

        # Destructive commands are handled by DestructiveCommandPolicy
        is_destr, _ = is_destructive_command(action.command)
        if is_destr:
            return None

        dangerous, reason = is_dangerous_command(action.command)
        if dangerous:
            safer_alt = None
            if "pip install" in reason:
                safer_alt = "Use 'pip install --dry-run' to inspect dependencies without modifying the environment."
            elif "chmod" in reason:
                safer_alt = "Use restrictive permissions such as chmod 755 or 644."
            elif "rm" in reason:
                safer_alt = "Move files to a backup or temporary folder before deleting."
            elif "sh" in reason or "interpreter" in reason:
                safer_alt = "Download the script first, inspect its contents, and execute locally."

            return PolicyResult(
                policy_id=self.policy_id,
                policy_name=self.name,
                decision=Decision.REQUIRE_APPROVAL,
                risk_category=RiskCategory.HIGH,
                explanation=reason,
                safer_alternative=safer_alt,
            )

        return None


class CommandChainingPolicy(Policy):
    """Detects and restricts chained shell commands and command substitutions.

    Rules:
    - Detect unquoted &&, ||, ;, backticks, $(...) in commands.
    - If chain contains a destructive command -> BLOCK.
    - If chain contains any potentially dangerous command -> REQUIRE_APPROVAL.
    - Simple chains of safe commands -> REQUIRE_APPROVAL (can't verify all parts).
    """

    policy_id = "shell.command_chaining"
    name = "Command Chaining Detection"
    description = "Detects and restricts chained shell commands and command substitutions"
    is_mandatory = True
    enabled = True

    async def evaluate(self, action: ActionRequest, workspace: Path) -> PolicyResult | None:
        """Evaluate action for command chaining and command substitutions."""
        if action.action_type != ActionType.SHELL_COMMAND or not action.command:
            return None

        if not has_chaining_operators(action.command):
            return None

        # Extract sub-commands
        sub_commands = split_chained_commands(action.command)

        # 1. Check for destructive commands in any sub-command
        for sub in sub_commands:
            destr, reason = is_destructive_command(sub)
            if destr:
                return PolicyResult(
                    policy_id=self.policy_id,
                    policy_name=self.name,
                    decision=Decision.BLOCK,
                    risk_category=RiskCategory.CRITICAL,
                    explanation=f"Command chain contains destructive command: '{sub}' ({reason})",
                    safer_alternative="Do not combine destructive commands in shell chains.",
                )

        # 2. Check for privilege escalation
        for sub in sub_commands:
            priv, reason = is_privilege_escalation(sub)
            if priv:
                return PolicyResult(
                    policy_id=self.policy_id,
                    policy_name=self.name,
                    decision=Decision.BLOCK,
                    risk_category=RiskCategory.CRITICAL,
                    explanation=f"Command chain contains privilege escalation command: '{sub}'",
                    safer_alternative="Avoid privilege escalation commands.",
                )

        # 3. Check for dangerous commands in any sub-command
        for sub in sub_commands:
            danger, reason = is_dangerous_command(sub)
            if danger:
                return PolicyResult(
                    policy_id=self.policy_id,
                    policy_name=self.name,
                    decision=Decision.REQUIRE_APPROVAL,
                    risk_category=RiskCategory.HIGH,
                    explanation=f"Command chain contains potentially dangerous command: '{sub}' ({reason})",
                    safer_alternative="Execute commands individually with separate approval.",
                )

        # 4. Simple chain of commands -> REQUIRE_APPROVAL
        return PolicyResult(
            policy_id=self.policy_id,
            policy_name=self.name,
            decision=Decision.REQUIRE_APPROVAL,
            risk_category=RiskCategory.MEDIUM,
            explanation=(
                "Chained command detected (using &&, ||, ;, backticks, or $()). "
                "Chained commands execute multiple operations that cannot be verified independently."
            ),
            safer_alternative="Execute each command individually rather than chaining them together.",
        )


class PrivilegeEscalationPolicy(Policy):
    """Blocks commands that attempt to escalate privileges or switch user contexts.

    Rules:
    - BLOCK: sudo, su, doas, runas, pkexec.
    """

    policy_id = "shell.privilege_escalation"
    name = "Privilege Escalation Detection"
    description = "Blocks commands that attempt to escalate privileges or switch users"
    is_mandatory = True
    enabled = True

    async def evaluate(self, action: ActionRequest, workspace: Path) -> PolicyResult | None:
        """Evaluate action for privilege escalation commands."""
        if action.action_type != ActionType.SHELL_COMMAND or not action.command:
            return None

        is_esc, reason = is_privilege_escalation(action.command)
        if is_esc:
            return PolicyResult(
                policy_id=self.policy_id,
                policy_name=self.name,
                decision=Decision.BLOCK,
                risk_category=RiskCategory.CRITICAL,
                explanation=reason,
                safer_alternative="Execute commands with standard unprivileged user permissions.",
            )

        return None


class SafeReadOnlyPolicy(Policy):
    """Allows safe read-only shell commands within the workspace boundary.

    Rules:
    - ALLOW: ls, dir, cat, head, tail, echo, pwd, whoami, date, wc, find, grep, which, type, where, hostname
    - Only if no chaining operators and within workspace.
    """

    policy_id = "shell.safe_readonly"
    name = "Safe Read-Only Commands"
    description = "Allows safe read-only shell commands within the workspace"
    is_mandatory = False
    enabled = True

    SAFE_COMMANDS = {
        "ls",
        "dir",
        "cat",
        "head",
        "tail",
        "echo",
        "pwd",
        "whoami",
        "date",
        "wc",
        "find",
        "grep",
        "which",
        "type",
        "where",
        "hostname",
    }

    async def evaluate(self, action: ActionRequest, workspace: Path) -> PolicyResult | None:
        """Evaluate action for safe read-only execution."""
        if action.action_type != ActionType.SHELL_COMMAND or not action.command:
            return None

        # Chaining operators invalidate pure read-only status
        if has_chaining_operators(action.command):
            return None

        # Check for output redirection (> or >>)
        if re.search(r"(?:>|>>)", action.command):
            return None

        base_cmd, args = parse_shell_command(action.command)
        norm_cmd = _extract_executable_name(base_cmd)

        if norm_cmd not in self.SAFE_COMMANDS:
            return None

        # Working directory check
        ws_resolved = workspace.resolve()
        if action.working_directory:
            try:
                wd_resolved = Path(action.working_directory).resolve()
                if wd_resolved.drive.lower() != ws_resolved.drive.lower():
                    return None
                try:
                    wd_resolved.relative_to(ws_resolved)
                except ValueError:
                    return None
            except Exception:
                return None

        # Path arguments check
        for arg in args:
            # Skip flag options
            if arg.startswith("-") or arg.startswith("/"):
                # On Windows, /c, /w can be flags; check if it's an existing path or root
                if arg.lower() in {"/c", "/w", "/b", "/s", "/q", "/p", "/a", "/l", "/n"}:
                    continue
                if not any(sep in arg for sep in ("/", "\\")):
                    continue

            # Check if arg looks like a path
            if (
                any(sep in arg for sep in ("/", "\\"))
                or arg.startswith("..")
                or (len(arg) >= 2 and arg[1] == ":")
            ):
                try:
                    p = Path(arg)
                    resolved = (workspace / p).resolve() if not p.is_absolute() else p.resolve()
                    if resolved.drive.lower() != ws_resolved.drive.lower():
                        return None
                    try:
                        resolved.relative_to(ws_resolved)
                    except ValueError:
                        return None
                except Exception:
                    return None

        return PolicyResult(
            policy_id=self.policy_id,
            policy_name=self.name,
            decision=Decision.ALLOW,
            risk_category=RiskCategory.LOW,
            explanation=f"Safe read-only command '{norm_cmd}' permitted within workspace boundary.",
            safer_alternative=None,
        )


class NetworkExfilPolicy(Policy):
    """Requires approval for shell commands that connect to external network targets.

    Rules:
    - REQUIRE_APPROVAL: curl, wget, nc, ncat, scp, rsync, ftp with external targets.
    """

    policy_id = "shell.network_exfil"
    name = "Network Exfiltration Detection"
    description = "Requires approval for shell commands that connect to external network targets"
    is_mandatory = False
    enabled = True

    NETWORK_COMMANDS = {
        "curl",
        "wget",
        "nc",
        "ncat",
        "netcat",
        "scp",
        "rsync",
        "ftp",
        "sftp",
        "telnet",
    }

    LOCAL_TARGETS = {
        "localhost",
        "127.0.0.1",
        "::1",
        "0.0.0.0",
    }

    async def evaluate(self, action: ActionRequest, workspace: Path) -> PolicyResult | None:
        """Evaluate action for external network requests."""
        if action.action_type != ActionType.SHELL_COMMAND or not action.command:
            return None

        base_cmd, args = parse_shell_command(action.command)
        norm_cmd = _extract_executable_name(base_cmd)

        if norm_cmd not in self.NETWORK_COMMANDS:
            return None

        # Check for destination arguments
        # If any target in args is external (not localhost / 127.0.0.1) or unknown, require approval
        is_external = False
        target_found = False

        for arg in args:
            if arg.startswith("-"):
                continue

            target_found = True
            # Extract host from URL or host:port
            clean_arg = arg
            if "://" in clean_arg:
                clean_arg = clean_arg.split("://", 1)[1]
            clean_arg = clean_arg.split("/", 1)[0].split(":", 1)[0].lower()

            if clean_arg not in self.LOCAL_TARGETS:
                is_external = True
                break

        # If a network tool is called with external destination or without identifiable localhost
        if is_external or not target_found:
            return PolicyResult(
                policy_id=self.policy_id,
                policy_name=self.name,
                decision=Decision.REQUIRE_APPROVAL,
                risk_category=RiskCategory.HIGH,
                explanation=f"Network command '{norm_cmd}' connects to external targets, creating exfiltration risk.",
                safer_alternative="Use local endpoints or request human review for external transfers.",
            )

        return None
