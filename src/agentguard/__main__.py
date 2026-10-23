"""Main entry point for running the AgentGuard security services.

Supports running:
- The MCP server only (stdio or HTTP/SSE)
- The FastAPI dashboard API only
- Both the FastAPI API and the MCP server concurrently
"""

from __future__ import annotations

import argparse
import asyncio
import logging
import sys
import threading

import uvicorn

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(name)s: %(message)s",
)
logger = logging.getLogger("agentguard")


def main() -> None:
    """Parse command-line arguments and run the selected AgentGuard service(s)."""
    parser = argparse.ArgumentParser(
        description="AgentGuard — AI Agent Security Layer",
        formatter_class=argparse.ArgumentDefaultsHelpFormatter,
    )
    parser.add_argument(
        "--mode",
        choices=["mcp", "api", "both"],
        default="mcp",
        help="Execution mode: 'mcp' for MCP server only, 'api' for dashboard API only, 'both' for concurrent API and MCP",
    )
    parser.add_argument(
        "--transport",
        choices=["stdio", "http", "sse"],
        default="stdio",
        help="MCP server communication transport",
    )
    parser.add_argument(
        "--mcp-port",
        type=int,
        default=3001,
        help="Port to bind the MCP server when using HTTP/SSE transport",
    )
    parser.add_argument(
        "--api-port",
        type=int,
        default=8080,
        help="Port to bind the FastAPI dashboard API",
    )
    parser.add_argument(
        "--host",
        type=str,
        default="127.0.0.1",
        help="Host interface to bind server listeners",
    )

    args = parser.parse_args()

    logger.info("Starting AgentGuard in '%s' mode...", args.mode)

    if args.mode == "mcp":
        from agentguard.server import mcp

        if args.transport == "stdio":
            logger.info("Running AgentGuard MCP server on stdio transport...")
            mcp.run(transport="stdio")
        else:
            logger.info("Running AgentGuard MCP server on SSE transport (http://%s:%d)...", args.host, args.mcp_port)
            mcp.run(transport="sse", host=args.host, port=args.mcp_port)

    elif args.mode == "api":
        logger.info("Running AgentGuard Dashboard API on http://%s:%d...", args.host, args.api_port)
        uvicorn.run("agentguard.api:app", host=args.host, port=args.api_port, reload=False)

    elif args.mode == "both":
        logger.info("Starting Dashboard API on http://%s:%d in background thread...", args.host, args.api_port)
        api_thread = threading.Thread(
            target=lambda: uvicorn.run("agentguard.api:app", host=args.host, port=args.api_port, reload=False),
            daemon=True,
            name="agentguard-api-thread",
        )
        api_thread.start()

        from agentguard.server import mcp

        mcp_transport = "sse" if args.transport in ("http", "stdio") else args.transport
        logger.info("Running AgentGuard MCP server on SSE transport (http://%s:%d)...", args.host, args.mcp_port)
        mcp.run(transport=mcp_transport, host=args.host, port=args.mcp_port)


if __name__ == "__main__":
    main()
