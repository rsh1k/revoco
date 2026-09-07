"""The stdio proxy must have a way to be started, and the docs must not lie.

`revoco.mcp.proxy` shipped with no entry point, no `__main__` and no mention in
any document -- and a stdio proxy's only mode of use is being launched as a
subprocess named in a client's config. There was no command to name. The README
meanwhile asserted revoco had "no MCP integration at all", which was false.
See finding 13 in docs/ADAPTERS.md.
"""

from __future__ import annotations

import importlib.util
import pathlib
import re
import sys

import pytest

from revoco.core.crypto import generate_keypair, private_key_to_b64

ROOT = pathlib.Path(__file__).resolve().parent.parent
LAUNCHER = ROOT / "scripts" / "mcp_stdio_proxy.py"


def _launcher():
    spec = importlib.util.spec_from_file_location("mcp_stdio_proxy", LAUNCHER)
    assert spec and spec.loader
    mod = importlib.util.module_from_spec(spec)
    sys.modules["mcp_stdio_proxy"] = mod
    spec.loader.exec_module(mod)
    return mod


def _keyfile(tmp_path: pathlib.Path) -> pathlib.Path:
    priv, _ = generate_keypair()
    p = tmp_path / "agent.key"
    p.write_text(private_key_to_b64(priv), encoding="utf-8")
    return p


def test_the_reference_launcher_exists_and_imports() -> None:
    assert LAUNCHER.exists(), "docs/MCP.md points at this file"
    _launcher()


def test_it_builds_a_usable_proxy(tmp_path: pathlib.Path) -> None:
    proxy = _launcher().build_proxy(
        key_path=_keyfile(tmp_path),
        actor_id="agent-7",
        delegation_id="dlg-1",
        upstream_cmd=["true"],
    )
    assert proxy.upstream_cmd == ["true"]
    assert proxy.caller.actor_id == "agent-7"
    assert proxy.caller.delegation_id == "dlg-1"
    # The safe defaults the docs promise, not something narrower by accident.
    assert proxy.action_of("anything", {}) == "write"
    assert proxy.risk_of("anything", {}) == 0


def test_an_empty_upstream_is_refused(tmp_path: pathlib.Path) -> None:
    """`McpProxy` rejects it; the launcher must not reach that as a traceback."""
    mod = _launcher()
    with pytest.raises(SystemExit):
        mod.main(["--key", str(_keyfile(tmp_path)),
                  "--actor", "a", "--delegation", "d"])


def test_readme_does_not_deny_the_shipped_proxy() -> None:
    """The claim that was false. Prose drifts from the tree silently."""
    readme = (ROOT / "README.md").read_text(encoding="utf-8")
    assert "no MCP integration at all" not in readme
    assert "docs/MCP.md" in readme, "the proxy must be discoverable from the README"


def test_the_proxy_is_documented() -> None:
    doc = (ROOT / "docs" / "MCP.md").read_text(encoding="utf-8")
    # The two things a caller must override, and the reason there is no
    # `revoco mcp` subcommand. If these vanish the document stops being useful.
    assert "action_of" in doc and "risk_of" in doc


def test_every_repo_path_the_doc_points_at_exists() -> None:
    """Checking a path *string* appears is not the same as it resolving.

    An earlier version of this test asserted `"scripts/mcp_stdio_proxy.py" in
    doc`. The document names the launcher twice, so renaming one of them left
    the assertion satisfied and the link broken -- the mutation survived. What
    matters is that a reader following the path lands on a file.
    """
    doc = (ROOT / "docs" / "MCP.md").read_text(encoding="utf-8")
    refs = set(re.findall(r"(?:\.\./)?((?:scripts|src|docs|examples)/[\w./-]+)", doc))
    assert refs, "the document points at no repo file at all; it used to"
    missing = sorted(r for r in refs if not (ROOT / r).exists())
    assert not missing, f"docs/MCP.md points at files that do not exist: {missing}"
