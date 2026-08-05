"""
revoco.adapters.workstation
============================
Inverse-operation specs for the agent workstation: filesystem, git, and shell.

Status: **specification, not a validated integration**, though this surface is far
easier to validate than an ERP — a temp directory and a scratch repo will do.

Why this adapter matters most for coding agents
-----------------------------------------------
This is the surface an MCP-governed agent actually touches. It is also where the
documented 2025–26 losses happened: agents deleting production databases, wiping
home directories, and destroying business-critical data through single tool calls.
None of those operations has a native undo. All of the recoverable ones here are
recoverable *only* because content was captured before the write.

The three honest hard edges
---------------------------
**`git reset --hard` destroys work that was never in the object store.** Committed
history is recoverable from the reflog, so resetting back is straightforward. But
uncommitted modifications to tracked files are overwritten and were never hashed
into an object, so no reflog, no gc-survival, and no snapshot short of copying the
working tree recovers them. The spec says so rather than implying the reflog covers
everything.

**`git clean` removes untracked files, which git never had a copy of.** Same
reasoning, no ambiguity: irreversible.

**`shell.exec` cannot be classified at all.** An arbitrary command's effects are
unknowable in advance, so it classifies `UNKNOWN` — which under the
reversibility-first policy escalates every invocation to a human. That is not a gap
in this adapter; it is the correct answer, and it is the argument for giving agents
specific tools instead of a shell.
"""

from __future__ import annotations

from ..reversal.model import (
    PHASE_AUTHORIZE,
    InverseSpec,
    InverseStep,
    ReversalGate,
    Reversibility,
)
from ..reversal.registry import InverseRegistry

# ---------------------------------------------------------------------------
# Gates
# ---------------------------------------------------------------------------

GATE_CONTENT_CAPTURABLE = ReversalGate(
    name="fs_content_captured",
    description=(
        "The file's prior content must have been captured. Very large or binary files "
        "may exceed whatever cap the state reader enforces, in which case there is "
        "nothing to restore."
    ),
    remediation=(
        "Raise the snapshot size cap for paths agents may write, or keep those paths "
        "under version control so a copy exists elsewhere."
    ),
    check_at=PHASE_AUTHORIZE,
)

GATE_TREE_CAPTURED = ReversalGate(
    name="fs_tree_captured",
    description=(
        "A recursive delete is recoverable only if the entire subtree was captured "
        "first — every file's content, plus modes and layout."
    ),
    remediation=(
        "Do not let agents delete trees. This is the operation behind the "
        "wiped-home-directory incidents; deny it and require a human, rather than "
        "relying on a snapshot large enough to cover it."
    ),
    check_at=PHASE_AUTHORIZE,
)

GATE_GIT_REFLOG_PRESENT = ReversalGate(
    name="git_commit_still_reachable",
    description=(
        "The captured commit must still exist locally. It becomes unreachable after "
        "the reset and is eventually garbage collected."
    ),
    remediation="Recover promptly, or restore the branch from a remote that still has it.",
)

WORKSTATION_GATES = (
    GATE_CONTENT_CAPTURABLE,
    GATE_TREE_CAPTURED,
    GATE_GIT_REFLOG_PRESENT,
)


WORKSTATION_SPECS: list[InverseSpec] = [
    # -- filesystem ---------------------------------------------------------
    InverseSpec(
        tool="fs.read_file",
        kind=Reversibility.REVERSIBLE,
        inverse_tool="fs.noop",
        notes="A read changes nothing.",
    ),
    InverseSpec(
        tool="fs.write_file",
        kind=Reversibility.REVERSIBLE,
        inverse_tool="fs.write_file",
        arg_map=(
            ("path", "args.path"),
            ("content", "snapshot.content"),
            ("mode", "snapshot.mode"),
        ),
        snapshot_fields=("content", "mode", "existed"),
        gates=(GATE_CONTENT_CAPTURABLE,),
        degraded_kind=Reversibility.IRREVERSIBLE,
        notes=(
            "Capture `existed` too: if the file did not exist before, the correct undo "
            "is deletion, not writing empty content. Getting that wrong leaves a "
            "zero-byte file that some build systems treat very differently from an "
            "absent one."
        ),
    ),
    InverseSpec(
        tool="fs.delete_file",
        kind=Reversibility.COMPENSABLE,
        inverse_tool="fs.write_file",
        arg_map=(
            ("path", "args.path"),
            ("content", "snapshot.content"),
            ("mode", "snapshot.mode"),
        ),
        snapshot_fields=("content", "mode", "mtime", "owner"),
        gates=(GATE_CONTENT_CAPTURABLE,),
        degraded_kind=Reversibility.IRREVERSIBLE,
        residue=(
            "The content comes back but the file does not: it has a new inode, so any "
            "hard links to the original are now separate files, and mtime, ctime, and "
            "ownership are reset unless explicitly restored. Anything watching the path "
            "saw a delete event."
        ),
        notes=(
            "Compensable rather than reversible for the inode reason. It matters more "
            "than it sounds on systems where hard links carry meaning."
        ),
    ),
    InverseSpec(
        tool="fs.move",
        kind=Reversibility.REVERSIBLE,
        inverse_tool="fs.move",
        arg_map=(("src", "args.dest"), ("dest", "args.src")),
        notes=(
            "The cleanest inverse on this surface: swap the arguments. Note it is only "
            "exact if the destination did not already exist and get overwritten — "
            "capture that if the tool permits overwriting."
        ),
    ),
    InverseSpec(
        tool="fs.chmod",
        kind=Reversibility.REVERSIBLE,
        inverse_tool="fs.chmod",
        arg_map=(("path", "args.path"), ("mode", "snapshot.mode")),
        snapshot_fields=("mode",),
    ),
    InverseSpec(
        tool="fs.delete_tree",
        kind=Reversibility.COMPENSABLE,
        inverse_tool="fs.restore_tree",
        arg_map=(("path", "args.path"), ("tree", "snapshot.tree")),
        snapshot_fields=("tree",),
        gates=(GATE_TREE_CAPTURED,),
        degraded_kind=Reversibility.IRREVERSIBLE,
        residue=(
            "Even with a full capture, restoration rebuilds files with new inodes and "
            "reset timestamps, loses hard links and any special files, and cannot "
            "restore anything excluded by the snapshot's own limits."
        ),
        notes=(
            "This is the wiped-home-directory operation. The authorize gate defaults it "
            "to irreversible, which under the starter policy means a human sees every "
            "recursive delete before it happens. That is the intended behaviour, not an "
            "inconvenience to be configured away."
        ),
    ),
    # -- git ----------------------------------------------------------------
    InverseSpec(
        tool="git.commit",
        kind=Reversibility.REVERSIBLE,
        inverse_tool="git.reset",
        arg_map=(
            ("ref", "snapshot.head_sha"),
            ("mode", "const:soft"),
        ),
        snapshot_fields=("head_sha",),
        notes=(
            "A soft reset, deliberately: it moves the branch pointer back while leaving "
            "the changes staged, so the work is preserved and only the commit is undone. "
            "A hard reset here would destroy exactly what the agent was asked to produce."
        ),
    ),
    InverseSpec(
        tool="git.checkout",
        kind=Reversibility.REVERSIBLE,
        inverse_tool="git.checkout",
        arg_map=(("ref", "snapshot.head_ref"),),
        snapshot_fields=("head_ref", "head_sha"),
    ),
    InverseSpec(
        tool="git.branch.delete",
        kind=Reversibility.REVERSIBLE,
        inverse_tool="git.branch.create",
        arg_map=(("name", "args.name"), ("sha", "snapshot.tip_sha")),
        snapshot_fields=("tip_sha",),
        gates=(GATE_GIT_REFLOG_PRESENT,),
        notes="A branch is a pointer; recreating it at the captured SHA is exact.",
    ),
    InverseSpec(
        tool="git.reset_hard",
        kind=Reversibility.COMPENSABLE,
        inverse_tool="git.reset",
        arg_map=(("ref", "snapshot.head_sha"), ("mode", "const:hard")),
        snapshot_fields=("head_sha", "dirty"),
        gates=(GATE_GIT_REFLOG_PRESENT,),
        residue=(
            "The commit history is restored exactly, but any uncommitted modifications "
            "to tracked files that the reset overwrote are gone permanently. They were "
            "never hashed into a git object, so no reflog entry, no unreachable commit, "
            "and no gc setting can bring them back."
        ),
        notes=(
            "Capture `dirty` (whether the working tree had uncommitted changes) so the "
            "residue can be stated precisely rather than generically. On a clean tree "
            "this is effectively reversible; on a dirty one it destroyed work, and the "
            "evidence pack should say which."
        ),
    ),
    InverseSpec(
        tool="git.clean",
        kind=Reversibility.IRREVERSIBLE,
        notes=(
            "Removes untracked files, which git has never had a copy of. Nothing in the "
            "repository can restore them. Unambiguous, and worth registering explicitly "
            "so it escalates rather than falling into UNKNOWN by accident."
        ),
    ),
    InverseSpec(
        tool="git.stash_drop",
        kind=Reversibility.IRREVERSIBLE,
        notes=(
            "Conservative on purpose. A dropped stash commit may linger unreachable and "
            "be recoverable by hand, but that is a forensic exercise with no API, not an "
            "undo this control plane should promise."
        ),
    ),
    # -- shell --------------------------------------------------------------
    InverseSpec(
        tool="shell.exec",
        kind=Reversibility.UNKNOWN,
        notes=(
            "Left UNKNOWN deliberately, and this is the most important entry in the "
            "file. An arbitrary command's effects cannot be known in advance, so no "
            "honest inverse can be declared. Under the starter policy UNKNOWN escalates "
            "to a human on every invocation — which is the correct answer, and the "
            "argument for giving agents specific tools rather than a shell. If shell "
            "access is unavoidable, the enforcement layer's threat scanner and argument "
            "conditions are the control, not the reversal layer."
        ),
    ),
    # -- multi-step: undo a branch switch that also stashed work ------------
    InverseSpec(
        tool="git.switch_with_stash",
        kind=Reversibility.COMPENSABLE,
        steps=(
            InverseStep(
                name="return_to_branch",
                tool="git.checkout",
                arg_map=(("ref", "snapshot.head_ref"),),
                description=(
                    "Go back to the original branch FIRST. Popping the stash onto the "
                    "wrong branch applies the changes somewhere they were never meant to "
                    "be, which is harder to clean up than the original mistake."
                ),
                critical=True,
            ),
            InverseStep(
                name="restore_stash",
                tool="git.stash_pop",
                arg_map=(("ref", "result.stash_ref"),),
                description="Reapply the work that was stashed to allow the switch.",
                critical=True,
            ),
        ),
        snapshot_fields=("head_ref", "head_sha"),
        residue=(
            "Popping a stash can conflict if the branch moved in the meantime, leaving "
            "the working tree in a conflicted state that needs a human to resolve."
        ),
    ),
]


def workstation_registry() -> InverseRegistry:
    """An :class:`InverseRegistry` preloaded with the workstation specs."""
    return InverseRegistry(list(WORKSTATION_SPECS))


__all__ = ["WORKSTATION_SPECS", "WORKSTATION_GATES", "workstation_registry"]
