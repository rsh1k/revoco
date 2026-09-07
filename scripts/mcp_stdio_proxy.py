#!/usr/bin/env python3
"""Reference launcher for the stdio MCP proxy. See docs/MCP.md.

This is deliberately **not** a supported entry point and is not registered in
`[project.scripts]`. The proxy needs an actor private key, and where that key
comes from is a deployment decision. Copy this, adapt the identity wiring, and
own the result.

The key is read from a file path given on the command line rather than from an
environment variable, because `Caller`'s docstring is right: a token read from
the environment proves only that whoever launched the process could read the
environment.

    python scripts/mcp_stdio_proxy.py \
        --key /run/secrets/agent.key --actor agent-7 --delegation "$DELEGATION_ID" \
        -- npx -y @modelcontextprotocol/server-filesystem /srv/data
"""

from __future__ import annotations

import argparse
import sys
from pathlib import Path

from revoco.controlplane import ControlPlane
from revoco.core.crypto import private_key_from_b64
from revoco.mcp import Caller, McpProxy


def build_proxy(
    *,
    key_path: Path,
    actor_id: str,
    delegation_id: str,
    upstream_cmd: list[str],
    control_plane: ControlPlane | None = None,
) -> McpProxy:
    """Assemble a proxy. Split out from `main` so it is testable without stdio."""
    caller = Caller(
        actor_id=actor_id,
        actor_private_key=private_key_from_b64(
            key_path.read_text(encoding="utf-8").strip()
        ),
        delegation_id=delegation_id,
    )
    # A real deployment supplies a ControlPlane already carrying its policy,
    # inverse registry and store. The bare one here authorizes against the
    # starter policy and keeps nothing across restarts -- fine for a smoke test,
    # wrong for anything else.
    return McpProxy(
        control_plane or ControlPlane(),
        caller,
        upstream_cmd,
        # Everything is a write unless you say otherwise. Narrow this: guessing
        # from the tool name is how `invoices.approve` gets treated as a read.
        action_of=lambda tool, args: "write",
        # Policy rules keyed on risk cannot fire while this returns 0.
        risk_of=lambda tool, args: 0,
    )


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(
        description="Gate an upstream stdio MCP server through revoco.",
        epilog="Everything after -- is the upstream server command.",
    )
    ap.add_argument("--key", required=True, type=Path,
                    help="file holding the actor's base64 Ed25519 private key")
    ap.add_argument("--actor", required=True, help="actor id to authorize as")
    ap.add_argument("--delegation", required=True,
                    help="delegation id bounding this session")
    ap.add_argument("upstream", nargs=argparse.REMAINDER,
                    help="-- followed by the upstream server command")
    args = ap.parse_args(argv)

    upstream = args.upstream[1:] if args.upstream[:1] == ["--"] else args.upstream
    if not upstream:
        ap.error("no upstream command: put it after --")

    return build_proxy(
        key_path=args.key,
        actor_id=args.actor,
        delegation_id=args.delegation,
        upstream_cmd=upstream,
    ).run()


if __name__ == "__main__":
    sys.exit(main())
