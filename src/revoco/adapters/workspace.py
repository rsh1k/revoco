"""Snapshot the working tree, so a local shell command has an inverse.

The shell classifier can say that `rm -rf build/` only touches the working tree.
It could not say the command was reversible, because saying so requires an undo
path and there was none to name — `InverseSpec` refuses to construct with an
undoable kind and no inverse, which is the guard that stopped a groundless claim
being written. This is the mechanism that makes the claim true instead.

What a snapshot buys
--------------------
Predicting every command a coding agent might run is hopeless; taking a cheap
copy first and making the unpredicted ones recoverable is not. That is the same
move revoco already makes for tool calls, applied to a directory: capture prior
state before the action, and the undo is a restore rather than a prediction.

Git objects rather than file copies
-----------------------------------
A shell command does not say which paths it will touch, so there is nothing to
copy selectively. `git write-tree` records the whole tree as an object in a
repository that already exists, which is cheap, exact for tracked and untracked
files, and needs no storage this package has to manage or expire.

Two details that are load-bearing:

**A scratch index.** Capturing with the agent's own index would silently
`git add -A` on its behalf, and the agent's next commit would pick up files
nobody staged. Every git call here runs against a temporary `GIT_INDEX_FILE`.

**Restore removes as well as writes.** Files present now and absent from the
snapshot were created after it, so putting the tree back means deleting them.
Restoring only the recorded files would leave anything the command created, and
an undo that leaves half the change behind is the residue this project exists to
name rather than discover.

What it does not cover
----------------------
Git-ignored files are not captured, because `git add -A` does not see them —
`node_modules`, `.env`, build output under an ignore rule. A command whose only
effect is inside an ignored path is *not* recoverable from this, and the residue
on the spec says so. There is no non-git fallback here; the original had one and
it is deliberately not ported, because a mechanism this package cannot drill is
a mechanism it should not claim.
"""

from __future__ import annotations

import contextlib
import os
import subprocess
import tempfile
from collections.abc import Iterator
from pathlib import Path
from typing import Any

from ..reversal.model import InverseSpec, Reversibility

SNAPSHOT_TOOL = "workspace.restore_tree"

# A template. The classifier replaces `tool` with the one actually being called,
# so this name is what appears if anyone uses the spec directly — a placeholder
# like "" is not an option, because InverseSpec refuses an empty tool name.
WORKSPACE_SPEC = InverseSpec(
    tool="workspace.guarded_command",
    kind=Reversibility.REVERSIBLE,
    inverse_tool=SNAPSHOT_TOOL,
    arg_map=(("root", "snapshot.root"), ("tree", "snapshot.tree")),
    snapshot_fields=("root", "tree"),
    residue=(
        "Git-ignored files are not captured and do not come back: anything under "
        "an ignore rule — node_modules, .env, build output — is outside the "
        "snapshot. Nor is anything the command did beyond this directory."
    ),
    notes=(
        "Reversible only because a tree object is written before the command "
        "runs. Without the snapshot there is no inverse and the classification "
        "would be a claim with nothing behind it."
    ),
)


@contextlib.contextmanager
def _scratch_index() -> Iterator[str]:
    """A temporary git index, so the agent's staging area is left alone."""
    handle, path = tempfile.mkstemp(prefix="revoco-index-")
    os.close(handle)
    os.unlink(path)          # git wants the path free, not an empty file
    try:
        yield path
    finally:
        with contextlib.suppress(OSError):
            os.unlink(path)


def _git(root: Path, *args: str, index: str | None = None) -> subprocess.CompletedProcess[str]:
    env = dict(os.environ)
    if index is not None:
        env["GIT_INDEX_FILE"] = index
    return subprocess.run(["git", *args], cwd=root, capture_output=True,
                          text=True, env=env, check=False)


class WorkspaceSnapshotError(RuntimeError):
    pass


def take_tree(root: str | Path) -> str:
    """Record the working tree as a git object and return its id."""
    base = Path(root)
    with _scratch_index() as index:
        added = _git(base, "add", "-A", index=index)
        if added.returncode != 0:
            raise WorkspaceSnapshotError(f"git add: {added.stderr.strip()[:160]}")
        written = _git(base, "write-tree", index=index)
        if written.returncode != 0:
            raise WorkspaceSnapshotError(f"git write-tree: {written.stderr.strip()[:160]}")
        return written.stdout.strip()


def restore_tree(root: str | Path, tree: str) -> dict[str, Any]:
    """Put the working tree back to a recorded object."""
    base = Path(root)
    if _git(base, "cat-file", "-e", f"{tree}^{{tree}}").returncode != 0:
        raise WorkspaceSnapshotError(f"tree {tree[:8]} is no longer in the repository")

    listed = _git(base, "ls-tree", "-r", "--name-only", tree)
    if listed.returncode != 0:
        raise WorkspaceSnapshotError("could not list the snapshot")
    recorded = {line for line in listed.stdout.splitlines() if line}

    now = _git(base, "ls-files", "--cached", "--others", "--exclude-standard")
    present = {line for line in now.stdout.splitlines() if line} if now.returncode == 0 else set()

    with _scratch_index() as index:
        if _git(base, "read-tree", tree, index=index).returncode != 0:
            raise WorkspaceSnapshotError("could not read the snapshot into an index")
        checked = _git(base, "checkout-index", "-a", "-f", index=index)
        if checked.returncode != 0:
            raise WorkspaceSnapshotError(
                f"checkout-index: {checked.stderr.strip()[:160]}")

    # Anything present now and absent from the snapshot was created after it.
    removed = 0
    for relative in sorted(present - recorded):
        target = base / relative
        if target.is_file():
            target.unlink()
            removed += 1
    return {"restored": len(recorded), "removed": removed, "tree": tree}


def snapshot_reader(root: str | Path):
    """A ``state_reader`` that captures the tree before a guarded command."""
    def read(tool: str, args: dict[str, Any], fields: tuple[str, ...]) -> dict[str, Any]:
        available = {"root": str(root), "tree": take_tree(root)}
        return {f: available[f] for f in fields if f in available}
    return read


def snapshot_executor(inner=None):
    """Wrap an executor so it also serves ``workspace.restore_tree``."""
    def execute(tool: str, args: dict[str, Any]) -> Any:
        if tool == SNAPSHOT_TOOL:
            return restore_tree(args["root"], args["tree"])
        if inner is None:
            raise WorkspaceSnapshotError(f"no executor for {tool}")
        return inner(tool, args)
    return execute


__all__ = [
    "SNAPSHOT_TOOL",
    "WORKSPACE_SPEC",
    "WorkspaceSnapshotError",
    "restore_tree",
    "snapshot_executor",
    "snapshot_reader",
    "take_tree",
]
