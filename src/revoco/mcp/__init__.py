"""MCP transport adapters.

revoco decides; this package is how it gets onto the wire. Ported from mcp-gate,
whose decision layer duplicated `revoco.gate` — the transport was the part that
did not exist here.
"""

from .proxy import Caller, McpProxy

__all__ = ["McpProxy", "Caller"]
