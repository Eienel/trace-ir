"""TRACE MCP server.

Exposes ONLY the typed, read-only forensic functions in parsers.TOOLS to an MCP
client (Claude Code, Cline, Cursor, etc.). This is the architectural guardrail:
the agent connected to this server has no generic shell, no write, and no delete
capability - only the typed analytical functions defined here.

Run:
    pip install mcp        # only needed to serve over MCP
    python -m server.trace_server

If `mcp` is not installed the module still imports and exposes call_tool() for
the in-process agent loop and the benchmark, which need no dependencies at all.
"""
from __future__ import annotations

from typing import List

from .citations import Finding
from .parsers import TOOLS

# JSON-schema-style contract advertised to the MCP client. Note: read-only,
# single typed purpose each. No execute_shell. No write_file.
TOOL_CONTRACT = {
    "list_artifacts": {
        "description": "List parseable artifacts in a case directory. Read-only.",
        "args": {"case_dir": "path to the case directory"},
    },
    "get_amcache": {
        "description": "Parse AmCache execution evidence. Read-only.",
        "args": {"path": "path to the amcache artifact"},
    },
    "extract_mft_timeline": {
        "description": "Extract $MFT file-system timeline. Read-only.",
        "args": {"path": "path to the MFT artifact"},
    },
    "analyze_prefetch": {
        "description": "Analyze Windows prefetch execution evidence. Read-only.",
        "args": {"path": "path to the prefetch artifact"},
    },
    "parse_evtx_logons": {
        "description": "Parse security event-log logon activity. Read-only.",
        "args": {"path": "path to the evtx logon artifact"},
    },
}


def call_tool(name: str, **kwargs) -> List[Finding]:
    """In-process dispatch used by the agent loop and benchmark.

    Raises if the agent asks for a capability that does not exist - there is no
    fallback to a shell. That refusal IS the guardrail.
    """
    if name not in TOOLS:
        raise ValueError(
            f"Tool '{name}' is not exposed by TRACE. Available read-only tools: "
            f"{', '.join(TOOLS)}. No shell/write/delete capability exists."
        )
    return TOOLS[name](**kwargs)


def _serve_mcp() -> None:
    """Serve the typed tools over stdio MCP. Requires the `mcp` package."""
    try:
        from mcp.server.fastmcp import FastMCP
    except ImportError:
        raise SystemExit(
            "The 'mcp' package is required to serve over MCP.\n"
            "Install with:  pip install mcp\n"
            "(The agent loop and benchmark work WITHOUT it.)"
        )

    app = FastMCP("trace-ir")

    @app.tool()
    def list_artifacts(case_dir: str) -> list:
        return [f.dict() for f in call_tool("list_artifacts", case_dir=case_dir)]

    @app.tool()
    def get_amcache(path: str) -> list:
        return [f.dict() for f in call_tool("get_amcache", path=path)]

    @app.tool()
    def extract_mft_timeline(path: str) -> list:
        return [f.dict() for f in call_tool("extract_mft_timeline", path=path)]

    @app.tool()
    def analyze_prefetch(path: str) -> list:
        return [f.dict() for f in call_tool("analyze_prefetch", path=path)]

    @app.tool()
    def parse_evtx_logons(path: str) -> list:
        return [f.dict() for f in call_tool("parse_evtx_logons", path=path)]

    app.run()


if __name__ == "__main__":
    _serve_mcp()
