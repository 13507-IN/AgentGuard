"""Filesystem security policies for AgentGuard.

Restricts file and directory operations to the workspace boundary, prevents
path traversal and symlink escapes, protects secret and system files, and guards
against destructive file deletions.
"""

from __future__ import annotations

import fnmatch
import os
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

FS_ACTIONS = {
    ActionType.FILE_READ,
    ActionType.FILE_WRITE,
    ActionType.FILE_DELETE,
    ActionType.DIRECTORY_LIST,
}


# ---------------------------------------------------------------------------
# Path Resolution Helpers
# ---------------------------------------------------------------------------


def resolve_resource_path(
    resource: str,
    workspace: Path,
    working_dir: str | None = None,
) -> Path:
    """Resolve a resource path against working directory and workspace.

    Args:
        resource: Resource path (relative or absolute).
        workspace: Base workspace path.
        working_dir: Optional working directory context.

    Returns:
        Resolved absolute Path.
    """
    raw_path = Path(resource)
    if raw_path.is_absolute():
        return raw_path.resolve()

    if working_dir:
        wd = Path(working_dir)
        base = wd if wd.is_absolute() else (workspace / wd)
        return (base / raw_path).resolve()

    return (workspace / raw_path).resolve()


def is_under_workspace(target: Path, workspace: Path) -> bool:
    """Check if target path is strictly inside or equal to the workspace.

    Handles Windows drive differences, case-insensitivity on Windows,
    and symlink/traversal resolution.
    """
    resolved_target = target.resolve()
    resolved_ws = workspace.resolve()

    # Windows drive check
    if resolved_target.drive and resolved_ws.drive:
        if resolved_target.drive.lower() != resolved_ws.drive.lower():
            return False

    # Case-insensitive comparison on Windows
    if os.name == "nt":
        target_str = str(resolved_target).lower()
        ws_str = str(resolved_ws).lower()
        if target_str == ws_str:
            return True
        if not ws_str.endswith(os.sep):
            ws_str += os.sep
        return target_str.startswith(ws_str)
    else:
        try:
            resolved_target.relative_to(resolved_ws)
            return True
        except ValueError:
            return False


# ---------------------------------------------------------------------------
# Policy Implementations
# ---------------------------------------------------------------------------


class WorkspaceBoundaryPolicy(Policy):
    """Enforces that all filesystem operations remain strictly within the workspace.

    Rules:
    - Applies to FILE_READ, FILE_WRITE, FILE_DELETE, DIRECTORY_LIST.
    - Resolves resource path with Path.resolve().
    - BLOCK if resolved path is not under the workspace.
    - Handles path traversal escaping workspace.
    - On Windows, checks drive letters match.
    """

    policy_id = "fs.workspace_boundary"
    name = "Workspace Boundary Enforcer"
    description = "Restricts all filesystem operations to within the configured workspace boundary"
    is_mandatory = True
    enabled = True

    async def evaluate(self, action: ActionRequest, workspace: Path) -> PolicyResult | None:
        """Evaluate action against workspace boundary."""
        if action.action_type not in FS_ACTIONS or not action.resource:
            return None

        target = resolve_resource_path(action.resource, workspace, action.working_directory)
        if not is_under_workspace(target, workspace):
            return PolicyResult(
                policy_id=self.policy_id,
                policy_name=self.name,
                decision=Decision.BLOCK,
                risk_category=RiskCategory.CRITICAL,
                explanation=(
                    f"Resource '{action.resource}' resolves to '{target}', "
                    f"which is outside the workspace boundary '{workspace.resolve()}'."
                ),
                safer_alternative=f"Target resources strictly within the workspace: '{workspace.resolve()}'.",
            )

        return None


class PathTraversalPolicy(Policy):
    """Detects path traversal attempts using '..' or symlinks escaping the workspace.

    Rules:
    - Detect '..' path components before resolution.
    - Try to resolve symlinks and re-check workspace boundary.
    - BLOCK if path escapes workspace after symlink resolution.
    """

    policy_id = "fs.path_traversal"
    name = "Path Traversal Detection"
    description = "Detects path traversal attempts using .. or symlinks escaping the workspace"
    is_mandatory = True
    enabled = True

    async def evaluate(self, action: ActionRequest, workspace: Path) -> PolicyResult | None:
        """Evaluate action for directory traversal or escaping symlinks."""
        if action.action_type not in FS_ACTIONS or not action.resource:
            return None

        # 1. Detect '..' path components before resolution
        raw_components = [
            c.strip()
            for c in action.resource.replace("\\", "/").split("/")
            if c.strip()
        ]
        has_dotdot = any(c == ".." for c in raw_components)

        # 2. Resolve symlinks and target
        target = resolve_resource_path(action.resource, workspace, action.working_directory)
        escapes = not is_under_workspace(target, workspace)

        if has_dotdot and escapes:
            return PolicyResult(
                policy_id=self.policy_id,
                policy_name=self.name,
                decision=Decision.BLOCK,
                risk_category=RiskCategory.CRITICAL,
                explanation=(
                    f"Directory traversal detected in resource '{action.resource}'. "
                    f"Path attempts to escape workspace boundary to '{target}'."
                ),
                safer_alternative="Use canonical relative paths within the workspace without '..'.",
            )

        # 3. Check if symlink resolves outside workspace
        raw_target = (
            workspace / action.resource
            if not Path(action.resource).is_absolute()
            else Path(action.resource)
        )
        if raw_target.is_symlink() and escapes:
            return PolicyResult(
                policy_id=self.policy_id,
                policy_name=self.name,
                decision=Decision.BLOCK,
                risk_category=RiskCategory.CRITICAL,
                explanation=(
                    f"Symlink traversal detected in '{action.resource}'. "
                    f"Symlink points outside workspace boundary to '{target}'."
                ),
                safer_alternative="Avoid referencing symlinks pointing outside the workspace boundary.",
            )

        return None


class SecretFilePolicy(Policy):
    """Blocks access to sensitive files like credentials, keys, and environment variables.

    Rules:
    - BLOCK access to: .env, .env.*, *credentials*, *.pem, *.key, id_rsa*,
      *secret*, .aws/credentials, .ssh/*, *.pfx, *.p12, *password*.
    - Match against filename (basename) and known path patterns.
    """

    policy_id = "fs.secret_files"
    name = "Secret Files Protection"
    description = "Blocks access to sensitive files like credentials, keys, and environment variables"
    is_mandatory = True
    enabled = True

    FILENAME_PATTERNS = [
        ".env",
        ".env.*",
        "*credentials*",
        "*.pem",
        "*.key",
        "id_rsa*",
        "id_ed25519*",
        "id_ecdsa*",
        "id_dsa*",
        "*secret*",
        "*.pfx",
        "*.p12",
        "*password*",
    ]

    PATH_PATTERNS = [
        "*.aws/credentials*",
        ".aws/credentials*",
        "*/.aws/credentials*",
        "*/.ssh/*",
        ".ssh/*",
        "*/.ssh",
        ".ssh",
    ]

    async def evaluate(self, action: ActionRequest, workspace: Path) -> PolicyResult | None:
        """Evaluate action for secret file access."""
        if action.action_type not in FS_ACTIONS or not action.resource:
            return None

        clean_path = action.resource.replace("\\", "/").lower()
        basename = Path(action.resource).name.lower()

        # Match basename against patterns
        for pattern in self.FILENAME_PATTERNS:
            if fnmatch.fnmatch(basename, pattern.lower()):
                return PolicyResult(
                    policy_id=self.policy_id,
                    policy_name=self.name,
                    decision=Decision.BLOCK,
                    risk_category=RiskCategory.CRITICAL,
                    explanation=f"Access to sensitive file '{action.resource}' matching secret pattern '{pattern}' is blocked.",
                    safer_alternative="Store and access credentials using environment variables or a secret manager.",
                )

        # Match full path against patterns
        for pattern in self.PATH_PATTERNS:
            if fnmatch.fnmatch(clean_path, pattern.lower()) or pattern.strip("*") in clean_path:
                return PolicyResult(
                    policy_id=self.policy_id,
                    policy_name=self.name,
                    decision=Decision.BLOCK,
                    risk_category=RiskCategory.CRITICAL,
                    explanation=f"Access to sensitive path '{action.resource}' matching secret pattern '{pattern}' is blocked.",
                    safer_alternative="Do not access sensitive credential directories (.ssh, .aws) directly.",
                )

        return None


class ProtectedDirectoryPolicy(Policy):
    """Blocks access to critical operating system directories and registry paths.

    Rules:
    - BLOCK access to: /etc, /sys, /proc, /boot, /dev, C:\\Windows,
      C:\\Windows\\System32, C:\\Program Files, system registry paths.
    - Check if the resolved path starts with any protected prefix.
    """

    policy_id = "fs.protected_dirs"
    name = "Protected Directories Enforcer"
    description = "Blocks access to critical system directories and OS files"
    is_mandatory = True
    enabled = True

    PROTECTED_PREFIXES = [
        # POSIX system directories
        "/etc",
        "/sys",
        "/proc",
        "/boot",
        "/dev",
        "/root",
        "/sbin",
        "/var/run",
        # Windows system directories
        "c:\\windows",
        "c:\\windows\\system32",
        "c:\\program files",
        "c:\\program files (x86)",
        "c:\\programdata",
        "\\windows",
        "\\program files",
        # Registry prefixes
        "hklm",
        "hkcu",
        "hkey_local_machine",
        "hkey_current_user",
        "registry::",
    ]

    async def evaluate(self, action: ActionRequest, workspace: Path) -> PolicyResult | None:
        """Evaluate action for protected system directory access."""
        if action.action_type not in FS_ACTIONS or not action.resource:
            return None

        target = resolve_resource_path(action.resource, workspace, action.working_directory)
        target_str = str(target).lower()
        resource_str = action.resource.lower()

        for prefix in self.PROTECTED_PREFIXES:
            clean_prefix = prefix.lower()
            # Check resolved target or raw resource path
            if target_str.startswith(clean_prefix) or resource_str.startswith(clean_prefix):
                return PolicyResult(
                    policy_id=self.policy_id,
                    policy_name=self.name,
                    decision=Decision.BLOCK,
                    risk_category=RiskCategory.CRITICAL,
                    explanation=f"Access to protected system directory '{prefix}' is blocked for '{action.resource}'.",
                    safer_alternative="Target resources only within the designated workspace directory.",
                )

        return None


class FileDeletionPolicy(Policy):
    """Requires approval before deleting any file within the workspace.

    Rules:
    - REQUIRE_APPROVAL for any FILE_DELETE action within workspace.
    - Suggests using a trash/recycle approach as safer alternative.
    """

    policy_id = "fs.file_deletion"
    name = "File Deletion Guard"
    description = "Requires approval before deleting any file within the workspace"
    is_mandatory = False
    enabled = True

    async def evaluate(self, action: ActionRequest, workspace: Path) -> PolicyResult | None:
        """Evaluate action for file deletion."""
        if action.action_type != ActionType.FILE_DELETE or not action.resource:
            return None

        # Verify within workspace boundary before applying deletion approval rule
        target = resolve_resource_path(action.resource, workspace, action.working_directory)
        if not is_under_workspace(target, workspace):
            # Let WorkspaceBoundaryPolicy handle out-of-boundary access
            return None

        return PolicyResult(
            policy_id=self.policy_id,
            policy_name=self.name,
            decision=Decision.REQUIRE_APPROVAL,
            risk_category=RiskCategory.HIGH,
            explanation=f"Permanent file deletion of '{action.resource}' requires user approval to prevent data loss.",
            safer_alternative="Move file to a backup, temporary, or trash directory instead of deleting it permanently.",
        )


class FileWritePolicy(Policy):
    """Allows writing files within the workspace boundary.

    Rules:
    - ALLOW FILE_WRITE within workspace (already passed workspace boundary check).
    """

    policy_id = "fs.file_write"
    name = "Workspace File Write"
    description = "Allows writing files within the workspace boundary"
    is_mandatory = False
    enabled = True

    async def evaluate(self, action: ActionRequest, workspace: Path) -> PolicyResult | None:
        """Evaluate action for allowed file write."""
        if action.action_type != ActionType.FILE_WRITE or not action.resource:
            return None

        target = resolve_resource_path(action.resource, workspace, action.working_directory)
        if not is_under_workspace(target, workspace):
            return None

        return PolicyResult(
            policy_id=self.policy_id,
            policy_name=self.name,
            decision=Decision.ALLOW,
            risk_category=RiskCategory.LOW,
            explanation=f"File write to '{action.resource}' is permitted within the workspace boundary.",
            safer_alternative=None,
        )


class DirectoryListPolicy(Policy):
    """Allows listing directory contents within the workspace boundary.

    Rules:
    - ALLOW DIRECTORY_LIST within workspace.
    """

    policy_id = "fs.directory_list"
    name = "Workspace Directory Listing"
    description = "Allows listing directories within the workspace boundary"
    is_mandatory = False
    enabled = True

    async def evaluate(self, action: ActionRequest, workspace: Path) -> PolicyResult | None:
        """Evaluate action for directory listing."""
        if action.action_type != ActionType.DIRECTORY_LIST or not action.resource:
            return None

        target = resolve_resource_path(action.resource, workspace, action.working_directory)
        if not is_under_workspace(target, workspace):
            return None

        return PolicyResult(
            policy_id=self.policy_id,
            policy_name=self.name,
            decision=Decision.ALLOW,
            risk_category=RiskCategory.LOW,
            explanation=f"Directory listing of '{action.resource}' is permitted within the workspace boundary.",
            safer_alternative=None,
        )


class FileReadPolicy(Policy):
    """Allows reading files within the workspace boundary.

    Rules:
    - ALLOW FILE_READ within workspace (when not matching secret files or protected dirs).
    """

    policy_id = "fs.file_read"
    name = "Workspace File Read"
    description = "Allows reading files within the workspace boundary"
    is_mandatory = False
    enabled = True

    async def evaluate(self, action: ActionRequest, workspace: Path) -> PolicyResult | None:
        """Evaluate action for allowed file read."""
        if action.action_type != ActionType.FILE_READ or not action.resource:
            return None

        target = resolve_resource_path(action.resource, workspace, action.working_directory)
        if not is_under_workspace(target, workspace):
            return None

        return PolicyResult(
            policy_id=self.policy_id,
            policy_name=self.name,
            decision=Decision.ALLOW,
            risk_category=RiskCategory.LOW,
            explanation=f"File read of '{action.resource}' is permitted within the workspace boundary.",
            safer_alternative=None,
        )

