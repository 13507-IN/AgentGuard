"""AgentGuard security policies."""

from __future__ import annotations

from agentguard.policies.base import Policy
from agentguard.policies.filesystem_policies import (
    DirectoryListPolicy,
    FileDeletionPolicy,
    FileReadPolicy,
    FileWritePolicy,
    PathTraversalPolicy,
    ProtectedDirectoryPolicy,
    SecretFilePolicy,
    WorkspaceBoundaryPolicy,
    is_under_workspace,
    resolve_resource_path,
)
from agentguard.policies.shell_policies import (
    CommandChainingPolicy,
    DangerousCommandPolicy,
    DestructiveCommandPolicy,
    NetworkExfilPolicy,
    PrivilegeEscalationPolicy,
    SafeReadOnlyPolicy,
    has_chaining_operators,
    is_dangerous_command,
    is_destructive_command,
    is_privilege_escalation,
    parse_shell_command,
    split_chained_commands,
)

__all__ = [
    "Policy",
    # Shell policies
    "DestructiveCommandPolicy",
    "DangerousCommandPolicy",
    "CommandChainingPolicy",
    "PrivilegeEscalationPolicy",
    "SafeReadOnlyPolicy",
    "NetworkExfilPolicy",
    "parse_shell_command",
    "has_chaining_operators",
    "split_chained_commands",
    "is_destructive_command",
    "is_dangerous_command",
    "is_privilege_escalation",
    # Filesystem policies
    "WorkspaceBoundaryPolicy",
    "PathTraversalPolicy",
    "SecretFilePolicy",
    "ProtectedDirectoryPolicy",
    "FileDeletionPolicy",
    "FileReadPolicy",
    "FileWritePolicy",
    "DirectoryListPolicy",
    "resolve_resource_path",
    "is_under_workspace",
]
