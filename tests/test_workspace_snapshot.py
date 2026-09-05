"""Snapshotting the working tree, against a real git repository.

Mocking git here would test the mock. Every test below runs `git init` in a
temporary directory and asserts what is on disk afterwards, because the claim
being made is that a command can actually be taken back.
"""

from __future__ import annotations

import subprocess
from pathlib import Path

import pytest

from revoco.adapters.workspace import (
    WORKSPACE_SPEC,
    WorkspaceSnapshotError,
    restore_tree,
    snapshot_executor,
    snapshot_reader,
    take_tree,
)
from revoco.reversal import InverseRegistry, Reversibility
from revoco.reversal.engine import ReversalEngine
from revoco.reversal.shell import command_classifier


def _repo(tmp_path: Path) -> Path:
    root = tmp_path / "repo"
    root.mkdir()
    for args in (("init", "-q", "-b", "main"), ("config", "user.email", "d@e.invalid"),
                 ("config", "user.name", "d")):
        subprocess.run(["git", *args], cwd=root, check=True, capture_output=True)
    (root / "src").mkdir()
    (root / "src/keep.txt").write_text("keep\n")
    (root / "build").mkdir()
    (root / "build/out.o").write_text("artifact\n")
    subprocess.run(["git", "add", "-A"], cwd=root, check=True, capture_output=True)
    subprocess.run(["git", "commit", "-qm", "base"], cwd=root, check=True,
                   capture_output=True)
    return root


# ---- capture and restore ---------------------------------------------------

def test_a_deleted_directory_comes_back(tmp_path):
    root = _repo(tmp_path)
    tree = take_tree(root)
    subprocess.run("rm -rf build/", shell=True, cwd=root, check=True)
    assert not (root / "build").exists()

    restore_tree(root, tree)
    assert (root / "build/out.o").read_text() == "artifact\n"


def test_restore_removes_what_the_command_created(tmp_path):
    """An undo that only puts files back would leave everything the command
    added. Half a restore is residue, and residue this project names rather
    than discovers."""
    root = _repo(tmp_path)
    tree = take_tree(root)
    (root / "src/created.txt").write_text("new\n")

    result = restore_tree(root, tree)
    assert not (root / "src/created.txt").exists()
    assert result["removed"] == 1
    assert (root / "src/keep.txt").exists(), "untouched files must survive"


def test_an_untracked_file_is_captured_and_restored(tmp_path):
    """`git add -A` sees untracked files, so a snapshot covers work in progress
    that was never committed."""
    root = _repo(tmp_path)
    (root / "scratch.txt").write_text("wip\n")
    tree = take_tree(root)
    (root / "scratch.txt").unlink()

    restore_tree(root, tree)
    assert (root / "scratch.txt").read_text() == "wip\n"


def test_a_git_ignored_file_is_not_covered_and_the_spec_says_so(tmp_path):
    """The honest limit. `git add -A` does not see ignored paths, so a command
    whose only effect is inside one is not recoverable from this — and the
    residue on the spec has to say that rather than leaving it to be found."""
    root = _repo(tmp_path)
    (root / ".gitignore").write_text("secrets/\n")
    (root / "secrets").mkdir()
    (root / "secrets/key.txt").write_text("shh\n")
    tree = take_tree(root)
    (root / "secrets/key.txt").unlink()

    restore_tree(root, tree)
    assert not (root / "secrets/key.txt").exists()
    assert "ignore" in WORKSPACE_SPEC.residue.lower()


def test_the_agents_staging_area_is_left_alone(tmp_path):
    """Capturing with the agent's own index would silently `git add -A` on its
    behalf, and its next commit would pick up files nobody staged."""
    root = _repo(tmp_path)
    (root / "unstaged.txt").write_text("x\n")
    before = subprocess.run(["git", "status", "--porcelain"], cwd=root,
                            capture_output=True, text=True).stdout

    take_tree(root)

    after = subprocess.run(["git", "status", "--porcelain"], cwd=root,
                           capture_output=True, text=True).stdout
    assert after == before
    assert "?? unstaged.txt" in after, "the file must still be unstaged"


def test_restoring_a_tree_that_is_gone_is_refused(tmp_path):
    root = _repo(tmp_path)
    with pytest.raises(WorkspaceSnapshotError, match="no longer in the repository"):
        restore_tree(root, "0" * 40)


def test_snapshotting_outside_a_repository_fails_loudly(tmp_path):
    """Rather than returning an empty snapshot that would look like a successful
    capture of nothing."""
    with pytest.raises(WorkspaceSnapshotError):
        take_tree(tmp_path)


# ---- through the engine ----------------------------------------------------

def test_a_local_command_becomes_reversible_only_with_a_mechanism(tmp_path):
    root = _repo(tmp_path)
    args = {"command": "rm -rf build/"}

    without = ReversalEngine(
        InverseRegistry([]), state_reader=snapshot_reader(root),
        command_classifier=command_classifier(root=str(root)))
    assert without.classify("bash", args) is Reversibility.UNKNOWN

    with_mech = ReversalEngine(
        InverseRegistry([]), state_reader=snapshot_reader(root),
        command_classifier=command_classifier(root=str(root),
                                              local_spec=WORKSPACE_SPEC))
    plan = with_mech.plan("bash", args)
    assert plan.kind is Reversibility.REVERSIBLE
    assert plan.is_executable
    assert plan.snapshot["tree"]


def test_the_whole_loop_takes_back_a_destructive_command(tmp_path):
    """Plan, run, undo, and check the disk — the claim is that the command can
    actually be taken back, so nothing short of the filesystem settles it."""
    root = _repo(tmp_path)

    def run_shell(tool, args):
        return subprocess.run(args["command"], shell=True, cwd=root,
                              capture_output=True, text=True).returncode

    eng = ReversalEngine(
        InverseRegistry([]), state_reader=snapshot_reader(root),
        command_classifier=command_classifier(root=str(root),
                                              local_spec=WORKSPACE_SPEC))
    args = {"command": "rm -rf build/ && echo new > src/created.txt"}
    entry = eng.open_journal(eng.plan("bash", args), session_id="s")
    run_shell("bash", args)
    eng.commit(entry.id, action_id="a1", result=None)

    receipt = eng.reverse(entry.id, snapshot_executor(run_shell))
    assert receipt.ok
    assert (root / "build/out.o").exists()
    assert (root / "src/keep.txt").exists()
    assert not (root / "src/created.txt").exists()


def test_an_escaping_command_gets_no_snapshot_spec_even_with_a_mechanism(tmp_path):
    """A snapshot of this directory cannot undo a push. Offering one would be
    the phantom rollback in its most tempting form: a mechanism that exists and
    does not reach."""
    root = _repo(tmp_path)
    eng = ReversalEngine(
        InverseRegistry([]), state_reader=snapshot_reader(root),
        command_classifier=command_classifier(root=str(root),
                                              local_spec=WORKSPACE_SPEC))
    plan = eng.plan("bash", {"command": "git push --force origin main"})
    assert plan.kind is Reversibility.IRREVERSIBLE
    assert plan.inverse_tool is None
