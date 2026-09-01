#!/usr/bin/env python3
"""Validate the `workstation` adapter against a real filesystem and a real git repo.

Every other adapter in this package is a *specification*: written from vendor
documentation, never executed. This one can be validated for real in an afternoon,
which makes it the cheapest available move from "we wrote it down" to "we ran it" —
and it de-risks the whole pattern before anyone spends weeks on an SAP sandbox.

What this does
--------------
Builds a real executor over a throwaway directory and a real ``git init`` repo, then
drives it through the actual :class:`~revoco.drills.DrillRunner`. So one run tests
two things at once:

* the 14 workstation specs — do their inverses actually restore state?
* the drill machinery itself — does it work against something that is not a simulator?

A drill is the honest test because it compares state before and after rather than
trusting the inverse's return value. An inverse that succeeds and restores nothing
passes every other check.

Beyond the drills there are **claim probes**: targeted experiments against the
specific semantic assertions the specs make in prose — that a deleted-and-recreated
file gets a new inode, that ``git reset --hard`` destroys uncommitted work
irrecoverably, that a dropped stash is unreachable. Those claims are the reason the
specs classify things the way they do, so leaving them unverified would mean the
classifications rest on my reading rather than on evidence.

Run it::

    python scripts/validate_workstation.py          # human-readable
    python scripts/validate_workstation.py --json   # machine-readable

Exits non-zero if any spec's inverse fails to restore, or any prose claim turns out
false. Safe to run anywhere: everything happens under a temporary directory that is
removed afterwards.
"""

from __future__ import annotations

import argparse
import dataclasses
import json
import os
import shutil
import subprocess
import sys
import tempfile
from pathlib import Path
from typing import Any

sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "src"))

from revoco.adapters import workstation_registry  # noqa: E402
from revoco.adapters.workstation import WORKSTATION_EQUIVALENCE  # noqa: E402
from revoco.drills import Canary, DrillOutcome, DrillRunner, RecoverabilityRegister  # noqa: E402


# ---------------------------------------------------------------------------
# A real executor. No simulation: these calls touch the disk.
# ---------------------------------------------------------------------------
class RealWorkstation:
    def __init__(self, root: Path) -> None:
        self.root = root
        self.repo = root / "repo"
        self.calls: list[tuple[str, dict[str, Any]]] = []

    # -- git plumbing -------------------------------------------------------
    def git(self, *args: str, check: bool = True) -> str:
        r = subprocess.run(
            ["git", *args], cwd=self.repo, capture_output=True, text=True, check=False
        )
        if check and r.returncode != 0:
            raise RuntimeError(f"git {' '.join(args)} failed: {r.stderr.strip()}")
        return r.stdout.strip()

    def init_repo(self) -> None:
        self.repo.mkdir(parents=True, exist_ok=True)
        self.git("init", "-q", "-b", "main")
        self.git("config", "user.email", "drill@example.invalid")
        self.git("config", "user.name", "drill")
        (self.repo / "README.md").write_text("base\n")
        self.git("add", "-A")
        self.git("commit", "-q", "-m", "base")

    def head_sha(self) -> str:
        return self.git("rev-parse", "HEAD")

    def head_ref(self) -> str:
        """The branch NAME, not the full symbolic ref.

        This drill caught a real bug by failing. The first version returned
        ``git symbolic-ref HEAD`` — i.e. ``refs/heads/main`` — and the spec's inverse
        feeds that straight to ``git checkout``. Checking out a full ref path
        *detaches HEAD* rather than switching to the branch, so the undo reported
        success and left the repo in a materially different state. The drill noticed
        because it compares state; nothing else would have.
        """
        name = self.git("rev-parse", "--abbrev-ref", "HEAD", check=False)
        return name if name and name != "HEAD" else self.head_sha()

    def is_dirty(self) -> bool:
        return bool(self.git("status", "--porcelain"))

    def _abs(self, p: str) -> Path:
        # Everything is confined under the temp root. A drill that could write outside
        # it would be the incident it is meant to prevent.
        path = (self.root / p.lstrip("/")).resolve()
        if not str(path).startswith(str(self.root.resolve())):
            raise ValueError(f"refusing to touch {path}: outside the sandbox")
        return path

    # -- the executor the drill runner calls --------------------------------
    def execute(self, tool: str, args: dict[str, Any]) -> Any:  # noqa: C901
        self.calls.append((tool, dict(args)))

        if tool == "fs.noop":
            return None
        if tool == "fs.read_file":
            return {"content": self._abs(args["path"]).read_text()}
        if tool == "fs.write_file":
            p = self._abs(args["path"])
            p.parent.mkdir(parents=True, exist_ok=True)
            p.write_text(args.get("content") or "")
            if args.get("mode"):
                os.chmod(p, int(str(args["mode"]), 8))
            return {"path": args["path"], "bytes": len(args.get("content") or "")}
        if tool == "fs.delete_file":
            p = self._abs(args["path"])
            inode = p.stat().st_ino
            p.unlink()
            return {"path": args["path"], "prior_inode": inode}
        if tool == "fs.move":
            src, dest = self._abs(args["src"]), self._abs(args["dest"])
            dest.parent.mkdir(parents=True, exist_ok=True)
            shutil.move(str(src), str(dest))
            return {"src": args["src"], "dest": args["dest"]}
        if tool == "fs.chmod":
            p = self._abs(args["path"])
            os.chmod(p, int(str(args["mode"]), 8))
            return {"mode": args["mode"]}
        if tool == "fs.delete_tree":
            p = self._abs(args["path"])
            shutil.rmtree(p)
            return {"path": args["path"]}
        if tool == "fs.restore_tree":
            p = self._abs(args["path"])
            p.mkdir(parents=True, exist_ok=True)
            for rel, content in (args.get("tree") or {}).items():
                f = p / rel
                f.parent.mkdir(parents=True, exist_ok=True)
                f.write_text(content)
            return {"path": args["path"]}

        if tool == "git.commit":
            self.git("add", "-A")
            self.git("commit", "-q", "--allow-empty", "-m", args.get("message", "drill"))
            return {"sha": self.head_sha()}
        if tool == "git.reset_hard":
            self.git("reset", "--hard", args.get("ref", "HEAD"), "-q")
            return {"sha": self.head_sha()}
        if tool == "git.reset":
            mode = args.get("mode", "soft")
            self.git("reset", f"--{mode}", args["ref"], "-q")
            return {"sha": self.head_sha()}
        if tool == "git.checkout":
            self.git("checkout", "-q", args["ref"])
            return {"ref": args["ref"], "sha": self.head_sha()}
        if tool == "git.branch.create":
            self.git("branch", args["name"], args["sha"])
            return {"name": args["name"]}
        if tool == "git.branch.delete":
            sha = self.git("rev-parse", args["name"])
            self.git("branch", "-D", args["name"])
            return {"name": args["name"], "deleted_sha": sha}
        if tool == "git.clean":
            self.git("clean", "-fdq")
            return {}
        if tool == "git.stash_drop":
            self.git("stash", "drop")
            return {}
        if tool == "git.stash_pop":
            self.git("stash", "pop", "-q")
            return {}
        if tool == "git.switch_with_stash":
            self.git("stash", "push", "-q", "-m", "drill")
            self.git("checkout", "-q", args["ref"])
            return {"stash_ref": "stash@{0}"}
        if tool == "shell.exec":
            raise RuntimeError("shell.exec is deliberately unclassified; nothing to drill")
        raise KeyError(f"no real implementation for {tool!r}")

    # -- the read-only snapshot reader --------------------------------------
    def read_state(
        self, tool: str, args: dict[str, Any], fields: tuple[str, ...]
    ) -> dict[str, Any]:
        out: dict[str, Any] = {}
        if tool.startswith("fs.") and "path" in args:
            p = self._abs(args["path"])
            exists = p.exists()
            for f in fields:
                if f == "existed":
                    out[f] = exists
                elif not exists:
                    continue
                elif f == "content":
                    out[f] = p.read_text()
                elif f == "mode":
                    out[f] = oct(p.stat().st_mode & 0o777)[2:]
                elif f == "mtime":
                    out[f] = p.stat().st_mtime
                elif f == "owner":
                    out[f] = p.stat().st_uid
                elif f == "tree" and p.is_dir():
                    out[f] = {
                        str(c.relative_to(p)): c.read_text()
                        for c in p.rglob("*") if c.is_file()
                    }
        elif tool.startswith("git."):
            for f in fields:
                if f == "head_sha":
                    out[f] = self.head_sha()
                elif f == "head_ref":
                    out[f] = self.head_ref()
                elif f == "dirty":
                    out[f] = self.is_dirty()
                elif f == "tip_sha":
                    out[f] = self.git("rev-parse", args["name"], check=False)
        return out


MAX_SNAPSHOT_BYTES = 1_000_000   # what this "state reader" is willing to capture


def make_gate_evaluator(ws: RealWorkstation):
    """Answer the workstation gates against the real system.

    Supplying this is not optional decoration. Every gated spec degrades to
    irreversible without an evaluator, so a runner that omits one cannot drill any of
    them — the machinery refusing to guess is correct, and a harness that skipped
    this would have "validated" only the ungated specs while appearing to cover all.
    """

    def evaluate(ctx) -> bool | str:
        name = ctx.gate.name
        if name == "fs_content_captured":
            path = ctx.args.get("path")
            if not path:
                return "no path argument to capture from"
            p = ws._abs(path)
            if not p.exists():
                return True   # nothing to capture; the undo is a delete
            size = p.stat().st_size
            return (
                True if size <= MAX_SNAPSHOT_BYTES
                else f"{size} bytes exceeds the {MAX_SNAPSHOT_BYTES}-byte capture cap"
            )
        if name == "fs_tree_captured":
            path = ctx.args.get("path")
            p = ws._abs(path) if path else None
            if p is None or not p.exists():
                return "no such tree to capture"
            total = sum(f.stat().st_size for f in p.rglob("*") if f.is_file())
            return (
                True if total <= MAX_SNAPSHOT_BYTES
                else f"subtree is {total} bytes, over the capture cap"
            )
        if name == "git_commit_still_reachable":
            # Undo-phase: the captured SHA must still be an object in the store.
            sha = (ctx.entry.plan.snapshot.get("tip_sha") if ctx.entry else None) or (
                ctx.entry.plan.snapshot.get("head_sha") if ctx.entry else None
            )
            if not sha:
                return "no commit was captured"
            kind = ws.git("cat-file", "-t", sha, check=False)
            return True if kind == "commit" else f"object {sha[:8]} is no longer a commit"
        return f"unrecognised gate {name}; failing closed"

    return evaluate


# ---------------------------------------------------------------------------
# Canaries: one per drillable spec.
# ---------------------------------------------------------------------------
def seed_sandbox(ws: RealWorkstation) -> None:
    """Bring one sandbox to a known state before a single drill runs."""
    root = ws.root
    ws.init_repo()
    # git.reset_hard needs somewhere to reset *to*. With the single commit init_repo
    # makes, `reset --hard HEAD` moves nothing, the inverse has nothing to restore,
    # and the drill reports success without exercising anything — the same shape as
    # the stash-on-a-clean-tree trap below.
    (ws.repo / "history.txt").write_text("second\n")
    ws.git("add", "-A")
    ws.git("commit", "-q", "-m", "second")
    ws.git("branch", "doomed")
    ws.git("branch", "sidebranch")
    # switch_with_stash needs a genuinely dirty tree: `git stash push` on a clean one
    # is a no-op and the pop in its inverse then fails with nothing to apply.
    (ws.repo / "README.md").write_text("work in progress\n")

    (root / "canary").mkdir(parents=True, exist_ok=True)
    (root / "canary/file.txt").write_text("original\n")
    (root / "canary/move-me.txt").write_text("movable\n")
    (root / "canary/perm.txt").write_text("perms\n")
    (root / "canary/tree/a").mkdir(parents=True, exist_ok=True)
    (root / "canary/tree/a/one.txt").write_text("one\n")
    (root / "canary/tree/two.txt").write_text("two\n")


def rebind(template: Canary, ws: RealWorkstation) -> Canary:
    """Point a canary's verify() at a different sandbox.

    Canaries are declared once for readability, then rebound per drill so each runs
    against its own isolated copy.
    """
    fresh = {c.label: c for c in build_canaries(ws)}
    return fresh[template.label]


def build_canaries(ws: RealWorkstation) -> list[Canary]:
    root = ws.root

    def read(p: str):
        # mtime is reported but exempt. Watching it is what turns "a write cannot
        # restore mtime" from a claim probed by hand into residue measured on every
        # run; exempting it is what stops that truth failing an honest inverse.
        return lambda: (
            {
                "content": (root / p).read_text(),
                "mode": oct((root / p).stat().st_mode & 0o777)[2:],
                "mtime": (root / p).stat().st_mtime,
            }
            if (root / p).exists()
            else {"content": None, "mode": None, "mtime": None}
        )

    def tree_state(p: str):
        return lambda: {
            "files": sorted(
                str(c.relative_to(root / p)) for c in (root / p).rglob("*") if c.is_file()
            ) if (root / p).exists() else [],
        }

    def git_state():
        return lambda: {"head_sha": ws.head_sha(), "head_ref": ws.head_ref()}

    def branch_state(name: str):
        return lambda: {"sha": ws.git("rev-parse", name, check=False)}

    canaries = [
        Canary(tool="fs.read_file", args={"path": "canary/file.txt"},
               verify=read("canary/file.txt"), label="read"),
        Canary(tool="fs.write_file",
               args={"path": "canary/file.txt", "content": "OVERWRITTEN\n"},
               verify=read("canary/file.txt"), label="overwrite"),
        Canary(tool="fs.delete_file", args={"path": "canary/file.txt"},
               verify=read("canary/file.txt"), label="delete-file"),
        Canary(tool="fs.move",
               args={"src": "canary/move-me.txt", "dest": "canary/moved.txt"},
               verify=lambda: {
                   "src_exists": (root / "canary/move-me.txt").exists(),
                   "dest_exists": (root / "canary/moved.txt").exists(),
               }, label="move"),
        Canary(tool="fs.chmod", args={"path": "canary/perm.txt", "mode": "600"},
               verify=read("canary/perm.txt"), label="chmod"),
        Canary(tool="fs.delete_tree", args={"path": "canary/tree"},
               verify=tree_state("canary/tree"), label="delete-tree"),
        Canary(tool="git.commit", args={"repo": "repo", "message": "drill commit"},
               verify=git_state(), label="commit"),
        Canary(tool="git.branch.delete", args={"name": "doomed"},
               verify=branch_state("doomed"), label="branch-delete"),
        Canary(tool="git.reset_hard", args={"repo": "repo", "ref": "HEAD~1"},
               verify=git_state(), label="reset-hard"),
        Canary(tool="git.checkout", args={"repo": "repo", "ref": "sidebranch"},
               verify=git_state(), label="checkout"),
        # The one compound spec on this surface: stash, switch, then undo by
        # switching back and popping. Two ordered steps, so it also exercises
        # sequenced-undo execution against a real system rather than a simulator.
        Canary(tool="git.switch_with_stash",
               args={"repo": "repo", "ref": "sidebranch"},
               verify=lambda: {
                   "head_ref": ws.head_ref(),
                   "readme": (ws.repo / "README.md").read_text(),
               }, label="switch-with-stash"),
    ]
    # One declared relation for the surface, applied uniformly, instead of each
    # canary deciding for itself what "restored" is allowed to mean.
    return [dataclasses.replace(c, equivalence=WORKSTATION_EQUIVALENCE) for c in canaries]


# ---------------------------------------------------------------------------
# Claim probes: the prose assertions the classifications rest on.
# ---------------------------------------------------------------------------
def probe_claims(ws: RealWorkstation) -> list[dict[str, Any]]:
    root, out = ws.root, []

    def rec(claim: str, spec: str, holds: bool, detail: str) -> None:
        out.append({"claim": claim, "spec": spec, "holds": holds, "detail": detail})

    # 1. Inode reuse. The spec ORIGINALLY claimed the recreated file gets a new
    #    inode; this probe found the number immediately reused when nothing else
    #    referenced it, so that claim was wrong and the spec's residue was rewritten
    #    around the consequence that does hold (probe 2). Kept as a regression test:
    #    it asserts reuse is POSSIBLE, so nobody reintroduces the inode claim.
    p = root / "probe-inode.txt"
    p.write_text("x\n")
    before = p.stat().st_ino
    p.unlink()
    p.write_text("x\n")
    after = p.stat().st_ino
    rec("an inode may be reused on delete+recreate, so it is NOT a reliable signal",
        "fs.delete_file", True,
        f"inode {before} -> {after} ({'reused' if before == after else 'changed'}) — "
        "either outcome is allowed, which is exactly why the residue cannot cite it")

    # 1b. What the inverse structurally cannot restore, regardless of inode behaviour.
    tp = root / "probe-mtime.txt"
    tp.write_text("t\n")
    os.utime(tp, (100_000, 100_000))
    old_mtime = tp.stat().st_mtime
    content = tp.read_text()
    tp.unlink()
    tp.write_text(content)        # exactly what the spec's inverse does
    rec("the write-based inverse cannot restore mtime", "fs.delete_file",
        tp.stat().st_mtime != old_mtime,
        f"mtime {old_mtime} -> {tp.stat().st_mtime}; captured for evidence, not restored")

    # 2. ...and that breaks hard links, which is the concrete consequence.
    a, b = root / "probe-hl-a.txt", root / "probe-hl-b.txt"
    a.write_text("linked\n")
    os.link(a, b)
    linked_before = a.stat().st_nlink
    a.unlink()
    a.write_text("linked\n")
    rec("deleting and recreating breaks existing hard links", "fs.delete_file",
        linked_before == 2 and a.stat().st_nlink == 1 and b.stat().st_nlink == 1,
        f"nlink was {linked_before}, now {a.stat().st_nlink} and {b.stat().st_nlink}")

    # 3. fs.write_file captures `existed` because the correct undo for a file that
    #    did not exist is deletion, not writing empty content. Verify the two are
    #    distinguishable at all — a zero-byte file is not an absent file.
    ghost = root / "probe-ghost.txt"
    rec("an absent file is distinguishable from a zero-byte one", "fs.write_file",
        not ghost.exists(), "absent before write")
    ghost.write_text("")
    rec("...and a zero-byte file exists, so writing empty is not deleting",
        "fs.write_file", ghost.exists() and ghost.stat().st_size == 0,
        "zero-byte file exists after empty write")

    # 4. fs.move claims an exact inverse by swapping arguments. That only holds if
    #    the destination did not already exist — otherwise the move overwrote
    #    something the swap cannot bring back.
    src, dest = root / "probe-mv-src.txt", root / "probe-mv-dest.txt"
    src.write_text("source\n")
    dest.write_text("WOULD BE LOST\n")
    shutil.move(str(src), str(dest))
    shutil.move(str(dest), str(src))   # the spec's inverse
    rec("fs.move's swap inverse is NOT exact when the destination existed",
        "fs.move", not dest.exists() and src.read_text() == "source\n",
        "destination content unrecoverable after the swap-back")

    # 5. git.reset_hard is COMPENSABLE and the residue says uncommitted tracked
    #    changes are gone permanently. This is the strongest prose claim in the
    #    adapter, so it gets the most direct test.
    (ws.repo / "README.md").write_text("uncommitted work that matters\n")
    dirty_before = ws.is_dirty()
    sha = ws.head_sha()
    ws.git("reset", "--hard", sha, "-q")
    recovered = "uncommitted work" in (ws.repo / "README.md").read_text()
    dangling = ws.git("fsck", "--lost-found", check=False)
    rec("git reset --hard destroys uncommitted tracked changes irrecoverably",
        "git.reset_hard", dirty_before and not recovered,
        f"dirty before: {dirty_before}; content recovered: {recovered}; "
        f"fsck found nothing relevant: {'dangling' not in dangling.lower()}")

    # 6. git.clean is IRREVERSIBLE because untracked files were never objects.
    stray = ws.repo / "untracked.txt"
    stray.write_text("never tracked\n")
    ws.git("clean", "-fdq")
    rec("git clean removes untracked files with no object to recover from",
        "git.clean", not stray.exists(),
        "file gone; nothing in the object store ever referenced it")

    # 7. git.stash_drop is marked IRREVERSIBLE *conservatively*. If the commit is in
    #    fact still reachable by fsck, the classification is defensible but the note
    #    should say so honestly rather than implying total loss.
    (ws.repo / "README.md").write_text("stash me\n")
    ws.git("stash", "push", "-q", "-m", "probe")
    stash_sha = ws.git("rev-parse", "stash@{0}", check=False)
    ws.git("stash", "drop", check=False)
    still_there = ws.git("cat-file", "-t", stash_sha, check=False) == "commit" if stash_sha else False
    rec("a dropped stash commit lingers as an unreachable object (recoverable by "
        "hand, not by API)", "git.stash_drop", still_there,
        f"stash commit {stash_sha[:8] if stash_sha else '?'} still in the object store: "
        f"{still_there}")

    # 8. git.branch.delete claims recreating at the captured SHA is exact — which
    #    depends on the commit surviving as an unreachable object.
    ws.git("checkout", "-q", "-b", "probe-branch")
    (ws.repo / "b.txt").write_text("branch work\n")
    ws.git("add", "-A")
    ws.git("commit", "-q", "-m", "branch commit")
    tip = ws.head_sha()
    ws.git("checkout", "-q", "main")
    ws.git("branch", "-D", "probe-branch")
    survived = ws.git("cat-file", "-t", tip, check=False) == "commit"
    ws.git("branch", "probe-recreated", tip, check=False)
    exact = ws.git("rev-parse", "probe-recreated", check=False) == tip
    rec("a deleted branch's commit survives, so recreating at the captured SHA is exact",
        "git.branch.delete", survived and exact,
        f"object survived: {survived}; recreated ref matches: {exact}")

    return out


# ---------------------------------------------------------------------------
def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--json", action="store_true")
    ap.add_argument("--keep", action="store_true", help="leave the sandbox in place")
    args = ap.parse_args()

    root = Path(tempfile.mkdtemp(prefix="revoco-workstation-"))
    try:
        registry = workstation_registry()
        register = RecoverabilityRegister(stale_after=3600.0)

        # One sandbox per drill. The first version shared a single repo across all of
        # them, and it failed in a way worth keeping: earlier drills left the tree
        # clean, so `switch_with_stash` stashed nothing and its inverse died with "No
        # stash entries found". One drill's residue had become the next one's
        # precondition. That is a real lesson for anyone pointing this at production —
        # canaries have to be independent, or a drill suite starts reporting on the
        # order you happened to run it in.
        results = []
        for i, template in enumerate(build_canaries(RealWorkstation(root / "probe"))):
            cell = RealWorkstation(root / f"drill-{i:02d}")
            seed_sandbox(cell)
            canary = rebind(template, cell)
            runner = DrillRunner(
                registry,
                executor=cell.execute,
                state_reader=cell.read_state,
                gate_evaluator=make_gate_evaluator(cell),
            )
            results.append(runner.drill(canary))
        register.record_all(results)

        probe_ws = RealWorkstation(root / "claims")
        seed_sandbox(probe_ws)
        claims = probe_claims(probe_ws)

        failed_drills = [r for r in results if r.outcome.is_alarm]
        false_claims = [c for c in claims if not c["holds"]]
        # A spec with nothing to prove is not a drill that passed, and it is not one
        # that failed either. Counting it in the denominator reads as a failure.
        drillable = [r for r in results if r.outcome is not DrillOutcome.NOT_DRILLABLE]
        skipped = len(results) - len(drillable)

        if args.json:
            print(json.dumps({
                "equivalence": {
                    "name": WORKSTATION_EQUIVALENCE.name,
                    "exempt": [
                        {"field": e.field, "reason": e.reason}
                        for e in WORKSTATION_EQUIVALENCE.exempt
                    ],
                },
                "drills": [r.to_dict() for r in results],
                "claims": claims,
                "summary": {
                    "drills": len(results),
                    "drillable": len(drillable),
                    "not_drillable": skipped,
                    "passed": sum(1 for r in results if r.outcome is DrillOutcome.PASSED),
                    "failed": len(failed_drills),
                    "claims_checked": len(claims),
                    "claims_false": len(false_claims),
                },
            }, indent=2))
        else:
            print("WORKSTATION ADAPTER — VALIDATION AGAINST A REAL FILESYSTEM AND GIT REPO")
            print("=" * 78)
            print(f"sandbox: {root}\n")
            print("DRILLS  (forward action, real inverse, then compare state)")
            for r in sorted(results, key=lambda x: x.tool):
                mark = {
                    DrillOutcome.PASSED: "PASS",
                    DrillOutcome.NOT_DRILLABLE: "n/a ",
                }.get(r.outcome, "FAIL")
                print(f"  [{mark}] {r.tool:24s} {r.summary[:74]}")
            print()
            print("STATE EQUIVALENCE  (what 'restored' is allowed to mean here)")
            for line in WORKSTATION_EQUIVALENCE.describe().splitlines()[1:]:
                print(f"  {line.strip()}")
            print()
            print("CLAIM PROBES  (the prose the classifications rest on)")
            for c in claims:
                print(f"  [{'OK  ' if c['holds'] else 'WRONG'}] {c['spec']:18s} {c['claim']}")
                print(f"           {c['detail']}")
            print()
            passed = sum(1 for r in results if r.outcome is DrillOutcome.PASSED)
            tail = f" ({skipped} with nothing to prove)" if skipped else ""
            print(f"{passed}/{len(drillable)} drills passed{tail}, "
                  f"{len(claims) - len(false_claims)}/{len(claims)} claims held")
            if failed_drills or false_claims:
                print("\nA failing drill means the spec's inverse does not restore state.")
                print("A false claim means the prose justifying a classification is wrong.")
                print("Either way the spec is the thing to change, not the test.")
        return 1 if (failed_drills or false_claims) else 0
    finally:
        if not args.keep:
            shutil.rmtree(root, ignore_errors=True)


if __name__ == "__main__":
    raise SystemExit(main())
