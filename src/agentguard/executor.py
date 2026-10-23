"""Controlled execution adapter for AgentGuard.

This is the enforcement boundary — the last line of defense that actually runs
(or refuses to run) agent actions with strict workspace confinement, environment
sanitization, timeout enforcement, output limits, and secret redaction.
"""

from __future__ import annotations

import asyncio
import inspect
import os
import shlex
import time
from pathlib import Path
from typing import TYPE_CHECKING, Any

from pydantic import BaseModel, Field

from agentguard.config import AgentGuardConfig
from agentguard.schemas import (
    ActionRequest,
    ActionType,
    Decision,
    SecurityDecision,
    redact_secrets,
)

# Resilient imports for components that may be created concurrently
try:
    from agentguard.approval_manager import ApprovalManager
except ImportError:  # pragma: no cover
    ApprovalManager = Any  # type: ignore[assignment, misc]

try:
    from agentguard.policy_engine import PolicyEngine
except ImportError:  # pragma: no cover
    PolicyEngine = Any  # type: ignore[assignment, misc]


class ExecutionResult(BaseModel):
    """Result of executing an authorized action."""

    success: bool
    output: str | None = None
    error: str | None = None
    exit_code: int | None = None
    duration_ms: int = 0
    was_simulated: bool = False


class ControlledExecutor:
    """Enforcement boundary that verifies and executes agent actions safely."""

    def __init__(
        self,
        config: AgentGuardConfig,
        policy_engine: PolicyEngine,
        approval_manager: ApprovalManager,
    ) -> None:
        """Initialize the controlled executor.

        Args:
            config: AgentGuard configuration instance.
            policy_engine: Policy engine for defense-in-depth re-evaluation.
            approval_manager: Approval manager to verify approvals.
        """
        self.workspace: Path = Path(config.resolved_workspace).resolve()
        self.timeout: int = config.execution_timeout_seconds
        self.max_output: int = config.max_output_bytes
        self.policy_engine: PolicyEngine = policy_engine
        self.approval_manager: ApprovalManager = approval_manager

        # Ensure the root workspace directory exists
        self.workspace.mkdir(parents=True, exist_ok=True)

    def _truncate_and_redact(self, text: str | None) -> str | None:
        """Truncate text to max_output bytes and redact sensitive credentials.

        Args:
            text: Raw string to truncate and redact.

        Returns:
            Sanitized and truncated string, or None if input was None.
        """
        if text is None:
            return None

        raw_bytes = text.encode("utf-8")
        if len(raw_bytes) > self.max_output:
            truncated = raw_bytes[: self.max_output].decode("utf-8", errors="ignore")
            text = truncated + "\n... [OUTPUT TRUNCATED]"

        return redact_secrets(text)

    def _build_result(
        self,
        start_time: float,
        *,
        success: bool,
        output: str | None = None,
        error: str | None = None,
        exit_code: int | None = None,
    ) -> ExecutionResult:
        """Construct an ExecutionResult with duration and simulation flags set."""
        duration_ms = int((time.perf_counter() - start_time) * 1000)
        return ExecutionResult(
            success=success,
            output=output,
            error=error,
            exit_code=exit_code,
            duration_ms=duration_ms,
            was_simulated=False,
        )

    def _validate_path(self, path_str: str | Path) -> Path:
        """Validate that a path resolves strictly within the workspace.

        Args:
            path_str: Relative or absolute path to check.

        Returns:
            Resolved Path object safely within self.workspace.

        Raises:
            ValueError: If path_str is empty.
            PermissionError: If path escapes the workspace or symlink target is external.
        """
        if not path_str or not str(path_str).strip():
            raise ValueError("Path cannot be empty")

        path = Path(path_str)
        if not path.is_absolute():
            path = self.workspace / path

        resolved = path.resolve()
        base = self.workspace.resolve()

        # Check if resolved path is within base workspace
        is_safe = False
        try:
            if os.name == "nt":
                # On Windows, drive letters can differ in case; comparison must be case-insensitive
                if resolved.drive.upper() == base.drive.upper():
                    common = os.path.commonpath([str(resolved).lower(), str(base).lower()])
                    if common == str(base).lower():
                        is_safe = True
            else:
                try:
                    resolved.relative_to(base)
                    is_safe = True
                except ValueError:
                    is_safe = False
        except (ValueError, TypeError):
            is_safe = False

        if not is_safe:
            raise PermissionError(
                f"Access denied: path '{path_str}' resolves to '{resolved}' which is outside workspace '{base}'"
            )

        # Extra defense against symlinks escaping workspace
        current = path
        while True:
            if current.is_symlink():
                symlink_target = current.resolve()
                try:
                    if os.name == "nt":
                        if symlink_target.drive.upper() != base.drive.upper() or (
                            os.path.commonpath([str(symlink_target).lower(), str(base).lower()])
                            != str(base).lower()
                        ):
                            raise PermissionError(
                                f"Access denied: symlink '{current}' points outside workspace"
                            )
                    else:
                        symlink_target.relative_to(base)
                except (ValueError, PermissionError):
                    raise PermissionError(
                        f"Access denied: symlink '{current}' points outside workspace"
                    )

            if current == current.parent:
                break
            current = current.parent

        return resolved

    def _get_sanitized_env(self) -> dict[str, str]:
        """Build a sanitized environment containing only safe system variables.

        Specifically excludes host API keys, cloud tokens, passwords, and private credentials.
        """
        allowed_keys = {
            "PATH",
            "TERM",
            "HOME",
            "USERPROFILE",
            "SYSTEMROOT",
            "COMSPEC",
            "TMPDIR",
        }
        env: dict[str, str] = {}
        for key, value in os.environ.items():
            if key.upper() in allowed_keys:
                env[key] = value

        # Ensure critical Windows system variables exist to allow subprocess execution
        if os.name == "nt":
            if not any(k.upper() == "SYSTEMROOT" for k in env):
                sys_root = (
                    os.environ.get("SystemRoot")
                    or os.environ.get("SYSTEMROOT")
                    or r"C:\Windows"
                )
                env["SystemRoot"] = sys_root
            if not any(k.upper() == "COMSPEC" for k in env):
                comspec = (
                    os.environ.get("COMSPEC")
                    or os.environ.get("ComSpec")
                    or r"C:\Windows\system32\cmd.exe"
                )
                env["COMSPEC"] = comspec

        return env

    async def _execute_shell_command(self, action: ActionRequest) -> ExecutionResult:
        """Execute a shell command in a sanitized environment within the workspace."""
        cmd = action.command
        if not cmd or not cmd.strip():
            return ExecutionResult(success=False, error="No command provided for shell execution")

        # Determine working directory
        cwd = self.workspace
        if action.working_directory:
            try:
                cwd = self._validate_path(action.working_directory)
                if not cwd.is_dir():
                    return ExecutionResult(
                        success=False,
                        error=f"Working directory does not exist or is not a directory: '{action.working_directory}'",
                    )
            except PermissionError as pe:
                return ExecutionResult(success=False, error=str(pe))
            except Exception as exc:
                return ExecutionResult(
                    success=False,
                    error=f"Invalid working directory '{action.working_directory}': {exc}",
                )

        env = self._get_sanitized_env()

        try:
            if os.name == "nt":
                process = await asyncio.create_subprocess_shell(
                    cmd,
                    stdout=asyncio.subprocess.PIPE,
                    stderr=asyncio.subprocess.PIPE,
                    cwd=str(cwd),
                    env=env,
                )
            else:
                try:
                    args = shlex.split(cmd)
                except ValueError:
                    args = ["/bin/sh", "-c", cmd]

                if not args:
                    return ExecutionResult(success=False, error="Empty command arguments")

                # If shell metacharacters exist, invoke via /bin/sh to preserve expected semantics
                if any(char in cmd for char in ("|", ">", "<", "&&", "||", ";", "$", "*")):
                    process = await asyncio.create_subprocess_exec(
                        "/bin/sh",
                        "-c",
                        cmd,
                        stdout=asyncio.subprocess.PIPE,
                        stderr=asyncio.subprocess.PIPE,
                        cwd=str(cwd),
                        env=env,
                    )
                else:
                    process = await asyncio.create_subprocess_exec(
                        args[0],
                        *args[1:],
                        stdout=asyncio.subprocess.PIPE,
                        stderr=asyncio.subprocess.PIPE,
                        cwd=str(cwd),
                        env=env,
                    )
        except Exception as exc:
            return ExecutionResult(
                success=False,
                error=f"Failed to spawn process: {exc}",
                exit_code=-1,
            )

        try:
            stdout_data, stderr_data = await asyncio.wait_for(
                process.communicate(),
                timeout=float(self.timeout),
            )
        except asyncio.TimeoutError:
            try:
                process.kill()
                await process.wait()
            except Exception:
                pass
            return ExecutionResult(
                success=False,
                error=f"Command timed out after {self.timeout} seconds",
                exit_code=-1,
            )

        stdout_str = stdout_data.decode("utf-8", errors="replace") if stdout_data else ""
        stderr_str = stderr_data.decode("utf-8", errors="replace") if stderr_data else ""

        exit_code = process.returncode
        success = exit_code == 0

        # Combine output
        combined = stdout_str
        if stderr_str:
            if combined:
                combined = f"{combined}\n{stderr_str}"
            else:
                combined = stderr_str

        output = self._truncate_and_redact(combined)
        error = None
        if not success:
            redacted_err = self._truncate_and_redact(stderr_str)
            error = redacted_err if redacted_err else f"Command failed with exit code {exit_code}"

        return ExecutionResult(
            success=success,
            output=output if output else None,
            error=error,
            exit_code=exit_code,
        )

    async def _execute_file_read(self, action: ActionRequest) -> ExecutionResult:
        """Read file contents safely from within the workspace."""
        path_str = (
            action.resource
            or action.arguments.get("path")
            or action.arguments.get("file_path")
        )
        if not path_str:
            return ExecutionResult(success=False, error="No file path specified for file_read")

        try:
            target_path = self._validate_path(path_str)
        except PermissionError as pe:
            return ExecutionResult(success=False, error=str(pe))
        except Exception as exc:
            return ExecutionResult(success=False, error=f"Invalid path: {exc}")

        if not target_path.exists():
            return ExecutionResult(success=False, error=f"File not found: {path_str}")
        if not target_path.is_file():
            return ExecutionResult(success=False, error=f"Path is not a regular file: {path_str}")

        try:
            with open(target_path, "r", encoding="utf-8", errors="replace") as f:
                content = f.read()

            content = self._truncate_and_redact(content)
            return ExecutionResult(success=True, output=content)
        except Exception as exc:
            return ExecutionResult(success=False, error=f"Failed to read file: {exc}")

    async def _execute_file_write(self, action: ActionRequest) -> ExecutionResult:
        """Write content to a file within the workspace."""
        path_str = (
            action.resource
            or action.arguments.get("path")
            or action.arguments.get("file_path")
        )
        if not path_str:
            return ExecutionResult(success=False, error="No file path specified for file_write")

        if "content" not in action.arguments:
            return ExecutionResult(
                success=False,
                error="Missing required 'content' in action arguments",
            )

        content = action.arguments["content"]
        if content is None:
            content = ""
        elif not isinstance(content, str):
            content = str(content)

        try:
            target_path = self._validate_path(path_str)
        except PermissionError as pe:
            return ExecutionResult(success=False, error=str(pe))
        except Exception as exc:
            return ExecutionResult(success=False, error=f"Invalid path: {exc}")

        try:
            target_path.parent.mkdir(parents=True, exist_ok=True)
            with open(target_path, "w", encoding="utf-8") as f:
                f.write(content)

            return ExecutionResult(
                success=True,
                output=f"Successfully wrote {len(content.encode('utf-8'))} bytes to '{target_path.name}'",
            )
        except Exception as exc:
            return ExecutionResult(success=False, error=f"Failed to write file: {exc}")

    async def _execute_file_delete(self, action: ActionRequest) -> ExecutionResult:
        """Delete a file within the workspace (directories are rejected)."""
        path_str = (
            action.resource
            or action.arguments.get("path")
            or action.arguments.get("file_path")
        )
        if not path_str:
            return ExecutionResult(success=False, error="No file path specified for file_delete")

        try:
            target_path = self._validate_path(path_str)
        except PermissionError as pe:
            return ExecutionResult(success=False, error=str(pe))
        except Exception as exc:
            return ExecutionResult(success=False, error=f"Invalid path: {exc}")

        if not target_path.exists():
            return ExecutionResult(success=False, error=f"File not found: {path_str}")

        if target_path.is_dir():
            return ExecutionResult(
                success=False,
                error=f"Cannot delete directory '{path_str}' with file_delete. Only files may be deleted.",
            )

        try:
            target_path.unlink()
            return ExecutionResult(
                success=True,
                output=f"Successfully deleted file '{target_path.name}'",
            )
        except Exception as exc:
            return ExecutionResult(success=False, error=f"Failed to delete file: {exc}")

    async def _execute_directory_list(self, action: ActionRequest) -> ExecutionResult:
        """List directory contents within the workspace."""
        path_str = (
            action.resource
            or action.arguments.get("path")
            or action.arguments.get("dir_path")
        )
        if not path_str or path_str == ".":
            target_path = self.workspace
        else:
            try:
                target_path = self._validate_path(path_str)
            except PermissionError as pe:
                return ExecutionResult(success=False, error=str(pe))
            except Exception as exc:
                return ExecutionResult(success=False, error=f"Invalid path: {exc}")

        if not target_path.exists():
            return ExecutionResult(success=False, error=f"Directory not found: {path_str}")
        if not target_path.is_dir():
            return ExecutionResult(success=False, error=f"Path is not a directory: {path_str}")

        try:
            entries: list[str] = []
            for item in sorted(
                target_path.iterdir(), key=lambda p: (not p.is_dir(), p.name.lower())
            ):
                try:
                    is_dir = item.is_dir()
                    tag = "<DIR>" if is_dir else "     "
                    size = f"{item.stat().st_size:>10} B" if not is_dir else "          "
                    entries.append(f"{tag}  {size}  {item.name}")
                except (OSError, PermissionError) as item_err:
                    entries.append(f"<ERR>              {item.name} ({item_err})")

            listing_body = "\n".join(entries) if entries else "(empty directory)"
            try:
                rel_path = target_path.relative_to(self.workspace)
                display_path = str(rel_path) if str(rel_path) != "." else "./"
            except ValueError:
                display_path = target_path.name

            header = f"Directory listing for '{display_path}' ({len(entries)} items):\n"
            full_text = header + listing_body
            truncated = self._truncate_and_redact(full_text)
            return ExecutionResult(success=True, output=truncated)
        except Exception as exc:
            return ExecutionResult(success=False, error=f"Failed to list directory: {exc}")

    async def _execute_network_request(self, action: ActionRequest) -> ExecutionResult:
        """Execute an authorized network request using httpx."""
        try:
            import httpx
        except ImportError:
            return ExecutionResult(
                success=False,
                error="httpx library is required for network_request execution",
            )

        url = action.resource or action.arguments.get("url")
        if not url:
            return ExecutionResult(success=False, error="No URL specified for network_request")

        method = action.arguments.get("method", "GET").upper()
        headers = action.arguments.get("headers", {})
        body = action.arguments.get("body")

        try:
            async with httpx.AsyncClient(timeout=float(self.timeout)) as client:
                response = await client.request(
                    method=method,
                    url=url,
                    headers=headers,
                    content=body if isinstance(body, (bytes, str)) else None,
                    json=body if isinstance(body, (dict, list)) else None,
                )
                raw_output = f"HTTP {response.status_code}\n\n{response.text}"
                truncated = self._truncate_and_redact(raw_output)
                return ExecutionResult(
                    success=response.is_success,
                    output=truncated,
                    exit_code=response.status_code,
                    error=None
                    if response.is_success
                    else f"HTTP request returned status {response.status_code}",
                )
        except Exception as exc:
            return ExecutionResult(success=False, error=f"Network request failed: {exc}")

    async def execute(
        self,
        action: ActionRequest,
        decision: SecurityDecision,
        approval_id: str | None = None,
    ) -> ExecutionResult:
        """Execute an authorized action with full pre-execution verification.

        Pre-execution checks (defense in depth):
        1. If decision is BLOCK -> refuse immediately
        2. If decision is REQUIRE_APPROVAL:
           a. approval_id must be provided
           b. approval must be verified (valid, not expired, hash matches)
        3. Re-run policy evaluation as defense-in-depth
        4. Verify resource/working_directory is within workspace
        5. Execute with timeout and output limits

        Args:
            action: Action proposal from AI agent.
            decision: Initial security decision from policy engine.
            approval_id: Human approval record identifier, if applicable.

        Returns:
            ExecutionResult containing execution status, output, errors, and timing.
        """
        start_time = time.perf_counter()

        # Check 1: Refuse BLOCKED or ambiguous actions immediately
        if decision.decision == Decision.BLOCK:
            return self._build_result(
                start_time,
                success=False,
                error=f"Action blocked by policy: {decision.explanation}",
            )

        if decision.decision not in (Decision.ALLOW, Decision.REQUIRE_APPROVAL):
            return self._build_result(
                start_time,
                success=False,
                error=f"Action refused: unknown or invalid decision state '{decision.decision}'",
            )

        # Verify action hash binds strictly to the provided decision
        computed_hash = action.compute_hash()
        if decision.action_hash != computed_hash:
            return self._build_result(
                start_time,
                success=False,
                error=(
                    f"Action hash mismatch: decision hash '{decision.action_hash}' "
                    f"does not match computed action hash '{computed_hash}'"
                ),
            )

        # Check 2: If decision requires approval, verify approval ID and record validity
        if decision.decision == Decision.REQUIRE_APPROVAL:
            if not approval_id:
                return self._build_result(
                    start_time,
                    success=False,
                    error="Action requires human approval, but no approval_id was provided",
                )

            is_valid = False
            try:
                if hasattr(self.approval_manager, "verify"):
                    verify_result = self.approval_manager.verify(approval_id, computed_hash)
                    if inspect.isawaitable(verify_result):
                        is_valid = bool(await verify_result)
                    else:
                        is_valid = bool(verify_result)
            except Exception as exc:
                return self._build_result(
                    start_time,
                    success=False,
                    error=f"Approval verification failed with error: {exc}",
                )

            if not is_valid:
                return self._build_result(
                    start_time,
                    success=False,
                    error=(
                        f"Approval verification failed for approval_id '{approval_id}'. "
                        "Approval may be missing, expired, rejected, or action hash does not match."
                    ),
                )

        # Check 3: Re-run policy evaluation as defense-in-depth
        try:
            if hasattr(self.policy_engine, "evaluate"):
                re_evaluated = self.policy_engine.evaluate(action)
                if inspect.isawaitable(re_evaluated):
                    re_evaluated = await re_evaluated

                if re_evaluated.decision == Decision.BLOCK:
                    return self._build_result(
                        start_time,
                        success=False,
                        error=(
                            "Action blocked by policy re-evaluation (defense-in-depth): "
                            f"{re_evaluated.explanation}"
                        ),
                    )

                if (
                    re_evaluated.decision == Decision.REQUIRE_APPROVAL
                    and decision.decision != Decision.REQUIRE_APPROVAL
                ):
                    return self._build_result(
                        start_time,
                        success=False,
                        error=(
                            "Action requires approval according to policy re-evaluation: "
                            f"{re_evaluated.explanation}"
                        ),
                    )
        except Exception as exc:
            return self._build_result(
                start_time,
                success=False,
                error=f"Policy re-evaluation failed: {exc}",
            )

        # Check 4: Verify resource / working directory are within workspace
        try:
            if action.working_directory:
                validated_cwd = self._validate_path(action.working_directory)
                if not validated_cwd.is_dir():
                    return self._build_result(
                        start_time,
                        success=False,
                        error=(
                            "Working directory does not exist or is not a directory: "
                            f"'{action.working_directory}'"
                        ),
                    )

            if action.action_type in (
                ActionType.FILE_READ,
                ActionType.FILE_WRITE,
                ActionType.FILE_DELETE,
                ActionType.DIRECTORY_LIST,
            ):
                target = (
                    action.resource
                    or action.arguments.get("path")
                    or action.arguments.get("file_path")
                )
                if target:
                    self._validate_path(target)
                elif action.action_type != ActionType.DIRECTORY_LIST:
                    return self._build_result(
                        start_time,
                        success=False,
                        error=f"No target resource specified for {action.action_type.value}",
                    )
        except PermissionError as pe:
            return self._build_result(start_time, success=False, error=str(pe))
        except Exception as exc:
            return self._build_result(
                start_time,
                success=False,
                error=f"Path boundary check failed: {exc}",
            )

        # Check 5: Dispatch and execute with timeout and limits
        try:
            if action.action_type == ActionType.SHELL_COMMAND:
                result = await self._execute_shell_command(action)
            elif action.action_type == ActionType.FILE_READ:
                result = await self._execute_file_read(action)
            elif action.action_type == ActionType.FILE_WRITE:
                result = await self._execute_file_write(action)
            elif action.action_type == ActionType.FILE_DELETE:
                result = await self._execute_file_delete(action)
            elif action.action_type == ActionType.DIRECTORY_LIST:
                result = await self._execute_directory_list(action)
            elif action.action_type == ActionType.NETWORK_REQUEST:
                result = await self._execute_network_request(action)
            else:
                result = ExecutionResult(
                    success=False,
                    error=f"Unsupported action type: '{action.action_type}'",
                )
        except Exception as exc:
            result = ExecutionResult(
                success=False,
                error=f"Unhandled execution exception: {exc}",
            )

        # Finalize duration and simulation status
        result.duration_ms = int((time.perf_counter() - start_time) * 1000)
        result.was_simulated = False
        return result
