"""AgentGuard configuration management.

Loads settings from environment variables with safe defaults.
"""

from __future__ import annotations

import os
from dataclasses import dataclass, field
from pathlib import Path

from dotenv import load_dotenv


PROJECT_ROOT = Path(__file__).resolve().parent.parent.parent


def _load_env() -> None:
    """Load .env file from project root or current directory if present."""
    for p in (PROJECT_ROOT / ".env", Path.cwd() / ".env"):
        if p.exists():
            load_dotenv(p)
            break


@dataclass
class AgentGuardConfig:
    """Central configuration for all AgentGuard components."""

    # Workspace boundary — all filesystem operations restricted to this path
    workspace_path: str = str(PROJECT_ROOT / "workspace")

    # Database configuration (MongoDB)
    mongodb_uri: str = "mongodb://127.0.0.1:27017"
    mongodb_database: str = "agentguard"
    db_path: str | None = None
    db_backend: str = "mongodb"

    # Approval settings
    approval_timeout_seconds: int = 300  # 5 minutes

    # Execution settings
    execution_timeout_seconds: int = 30
    max_output_bytes: int = 10240  # 10 KB

    # AI Risk Explainer
    ollama_base_url: str = "http://localhost:11434"
    ollama_model: str = "qwen2.5:3b"
    ai_enabled: bool = True
    ai_timeout_seconds: int = 10

    # Backboard.io Memory Configuration
    backboard_api_key: str | None = None

    # Server settings
    api_port: int = 8080
    mcp_transport: str = "stdio"
    mcp_port: int = 3001

    # Internal
    _resolved_workspace: Path | None = field(default=None, repr=False)

    @classmethod
    def from_env(cls) -> AgentGuardConfig:
        """Create configuration from environment variables."""
        _load_env()
        return cls(
            workspace_path=os.getenv("AGENTGUARD_WORKSPACE", str(PROJECT_ROOT / "workspace")),
            mongodb_uri=os.getenv("MONGODB_URI", "mongodb://127.0.0.1:27017"),
            mongodb_database=os.getenv("MONGODB_DATABASE", "agentguard"),
            approval_timeout_seconds=int(os.getenv("AGENTGUARD_APPROVAL_TIMEOUT", "300")),
            execution_timeout_seconds=int(os.getenv("AGENTGUARD_EXECUTION_TIMEOUT", "30")),
            max_output_bytes=int(os.getenv("AGENTGUARD_MAX_OUTPUT_BYTES", "10240")),
            ollama_base_url=os.getenv("OLLAMA_BASE_URL", "http://localhost:11434"),
            ollama_model=os.getenv("OLLAMA_MODEL", "qwen2.5:3b"),
            ai_enabled=os.getenv("AGENTGUARD_AI_ENABLED", "true").lower() == "true",
            ai_timeout_seconds=int(os.getenv("AGENTGUARD_AI_TIMEOUT", "10")),
            api_port=int(os.getenv("AGENTGUARD_API_PORT", "8080")),
            mcp_transport=os.getenv("AGENTGUARD_MCP_TRANSPORT", "stdio"),
            mcp_port=int(os.getenv("AGENTGUARD_MCP_PORT", "3001")),
            backboard_api_key=os.getenv("BACKBOARD_API_KEY", None),
        )

    @property
    def resolved_workspace(self) -> Path:
        """Return the resolved, absolute workspace path."""
        if self._resolved_workspace is None:
            self._resolved_workspace = Path(self.workspace_path).resolve()
        return self._resolved_workspace

    def ensure_workspace(self) -> Path:
        """Ensure the workspace directory exists and return its resolved path."""
        wp = self.resolved_workspace
        wp.mkdir(parents=True, exist_ok=True)
        return wp
