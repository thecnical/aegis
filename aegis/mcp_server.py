"""Aegis MCP Server — exposes Aegis as a Model Context Protocol tool server.

This lets AI agents (Claude, Cursor, etc.) drive Aegis autonomously.

Install the MCP SDK:
    pip install mcp

Run the server:
    python -m aegis.mcp_server

Add to your MCP config (~/.kiro/settings/mcp.json or ~/.cursor/mcp.json):
    {
      "mcpServers": {
        "aegis": {
          "command": "python",
          "args": ["-m", "aegis.mcp_server"],
          "env": {}
        }
      }
    }
"""
from __future__ import annotations

import json
import subprocess
import sys
from pathlib import Path
from typing import Any

# MCP SDK — pip install mcp
try:
    from mcp.server import Server
    from mcp.server.stdio import stdio_server
    from mcp.types import TextContent, Tool
    _MCP_AVAILABLE = True
except ImportError:
    _MCP_AVAILABLE = False

from aegis.core.config_manager import ConfigManager
from aegis.core.db_manager import DatabaseManager
from aegis.core.workspace_manager import WorkspaceManager


def _get_db() -> DatabaseManager:
    config = ConfigManager("config/config.yaml")
    config.load()
    root_db_path = str(config.get("general.db_path", "data/aegis.db"))
    root_db = DatabaseManager(root_db_path)
    root_db.init_db()
    ws = WorkspaceManager(root_db).current()
    db = DatabaseManager(ws.db_path)
    db.init_db()
    return db


def _run_aegis(*args: str) -> str:
    """Run an aegis CLI command and return its output."""
    cmd = [sys.executable, "-m", "aegis"] + list(args)
    try:
        result = subprocess.run(cmd, capture_output=True, text=True, timeout=300)
        return result.stdout + result.stderr
    except subprocess.TimeoutExpired:
        return "Command timed out after 300s"
    except OSError as exc:
        return f"Error: {exc}"


def _get_findings(limit: int = 50) -> list[dict[str, Any]]:
    db = _get_db()
    conn = db.connect()
    rows = conn.execute(
        "SELECT id, title, severity, category, source, description, created_at "
        "FROM findings ORDER BY created_at DESC LIMIT ?",
        (limit,),
    ).fetchall()
    return [dict(r) for r in rows]


def main() -> None:
    if not _MCP_AVAILABLE:
        print(
            "MCP SDK not installed. Run: pip install mcp",
            file=sys.stderr,
        )
        sys.exit(1)

    server = Server("aegis")

    @server.list_tools()
    async def list_tools() -> list[Tool]:
        return [
            Tool(
                name="aegis_recon_domain",
                description="Run passive recon on a domain: subdomain enumeration, Shodan lookup, tech detection",
                inputSchema={
                    "type": "object",
                    "properties": {
                        "domain": {"type": "string", "description": "Target domain (e.g. example.com)"},
                        "no_techdetect": {"type": "boolean", "default": False},
                    },
                    "required": ["domain"],
                },
            ),
            Tool(
                name="aegis_vuln_web",
                description="Run Nuclei web vulnerability scan against a URL",
                inputSchema={
                    "type": "object",
                    "properties": {
                        "url": {"type": "string", "description": "Target URL (e.g. https://example.com)"},
                    },
                    "required": ["url"],
                },
            ),
            Tool(
                name="aegis_ai_auto",
                description="Run fully autonomous AI-driven pentest against a target",
                inputSchema={
                    "type": "object",
                    "properties": {
                        "target": {"type": "string", "description": "Target host, IP, or domain"},
                        "full": {"type": "boolean", "default": False, "description": "Run all 5 phases"},
                        "format": {"type": "string", "enum": ["md", "html", "pdf"], "default": "md"},
                    },
                    "required": ["target"],
                },
            ),
            Tool(
                name="aegis_get_findings",
                description="Retrieve the latest findings from the active workspace database",
                inputSchema={
                    "type": "object",
                    "properties": {
                        "limit": {"type": "integer", "default": 20, "description": "Max findings to return"},
                        "severity": {"type": "string", "description": "Filter by severity (info/low/medium/high/critical)"},
                    },
                },
            ),
            Tool(
                name="aegis_generate_report",
                description="Generate a pentest report from the current workspace findings",
                inputSchema={
                    "type": "object",
                    "properties": {
                        "target": {"type": "string", "description": "Target name for the report"},
                        "format": {"type": "string", "enum": ["md", "html", "pdf"], "default": "md"},
                        "min_severity": {"type": "string", "description": "Minimum severity to include"},
                    },
                    "required": ["target"],
                },
            ),
            Tool(
                name="aegis_scope_add",
                description="Add a target to the scan scope",
                inputSchema={
                    "type": "object",
                    "properties": {
                        "target": {"type": "string"},
                        "kind": {"type": "string", "enum": ["ip", "cidr", "domain", "url"], "default": "domain"},
                    },
                    "required": ["target"],
                },
            ),
            Tool(
                name="aegis_secrets_scan",
                description="Scan a path or git repo for exposed secrets and API keys using trufflehog",
                inputSchema={
                    "type": "object",
                    "properties": {
                        "target": {"type": "string", "description": "Local path or git repo URL"},
                        "mode": {"type": "string", "enum": ["filesystem", "git"], "default": "filesystem"},
                    },
                    "required": ["target"],
                },
            ),
        ]

    @server.call_tool()
    async def call_tool(name: str, arguments: dict[str, Any]) -> list[TextContent]:
        if name == "aegis_recon_domain":
            domain = arguments["domain"]
            args = ["recon", "domain", domain]
            if arguments.get("no_techdetect"):
                args.append("--no-techdetect")
            output = _run_aegis(*args)

        elif name == "aegis_vuln_web":
            output = _run_aegis("vuln", "web", arguments["url"])

        elif name == "aegis_ai_auto":
            args = ["ai", "auto", "--target", arguments["target"]]
            if arguments.get("full"):
                args.append("--full")
            fmt = arguments.get("format", "md")
            args += ["--format", fmt]
            output = _run_aegis(*args)

        elif name == "aegis_get_findings":
            limit = int(arguments.get("limit", 20))
            findings = _get_findings(limit)
            sev_filter = arguments.get("severity", "").lower()
            if sev_filter:
                findings = [f for f in findings if str(f.get("severity", "")).lower() == sev_filter]
            output = json.dumps(findings, indent=2, default=str)

        elif name == "aegis_generate_report":
            args = ["report", "generate", arguments["target"]]
            fmt = arguments.get("format", "md")
            args += ["--format", fmt]
            if arguments.get("min_severity"):
                args += ["--min-severity", arguments["min_severity"]]
            output = _run_aegis(*args)

        elif name == "aegis_scope_add":
            kind = arguments.get("kind", "domain")
            output = _run_aegis("scope", "add", arguments["target"], "--kind", kind)

        elif name == "aegis_secrets_scan":
            mode = arguments.get("mode", "filesystem")
            output = _run_aegis("recon", "secrets", arguments["target"], "--mode", mode)

        else:
            output = f"Unknown tool: {name}"

        return [TextContent(type="text", text=output)]

    import asyncio

    async def _serve() -> None:
        async with stdio_server() as (read_stream, write_stream):
            await server.run(read_stream, write_stream, server.create_initialization_options())

    asyncio.run(_serve())


if __name__ == "__main__":
    main()
