#!/usr/bin/env python3
"""Drill the GitHub inverse specs against a real repository.

The `workstation` surface proved the machinery against a local filesystem. This
is the first drill runner against a *remote* system of record, which is the
thing the assurance loop is actually for: an inverse written from vendor
documentation is a hypothesis until it has been executed against the API it
claims to reverse.

    python scripts/drill_github.py --repo owner/name --run-out run.json

Safety, because this deletes and force-updates refs
---------------------------------------------------
Every canary lives under `refs/heads/revoco-canary/<run>/...` and is created and
destroyed by this script. It refuses to touch a ref outside that namespace, so
pointing it at a repository cannot damage a branch anyone uses — but point it at
a disposable repository anyway. A drill that needs write access is a drill that
can write.

The teardown sweep runs whatever happened, and then reports anything it could
not remove rather than exiting quietly. A runner that leaks canaries into a
customer's tenancy would be the incident it exists to prevent.

What is drilled
---------------
`github.branch.delete` and `github.ref.force_update`. Both are classified
REVERSIBLE on the claim that a ref is a pointer and the commit survives, and
both are gated on that commit still being reachable. That claim is exactly what
a drill is for.

`github.pr.merge` is compensable by revert and needs a pull request per drill;
`github.repo.delete` is irreversible and has nothing to prove. Neither is here.
"""

from __future__ import annotations

import argparse
import json
import subprocess
import sys
import time
import uuid
from pathlib import Path
from typing import Any

sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "src"))

from revoco.adapters.devops import DEVOPS_EQUIVALENCE  # noqa: E402
from revoco.drills import Canary, DrillOutcome, DrillRunner  # noqa: E402
from revoco.reversal.model import GateContext  # noqa: E402
from revoco.reversal.registry import InverseRegistry  # noqa: E402
from revoco.validation import ValidationRun  # noqa: E402

CANARY_PREFIX = "revoco-canary/"


class GitHubApiError(RuntimeError):
    pass


class GitHub:
    """The API surface these specs need, over the authenticated `gh` CLI.

    Using `gh` rather than an HTTP client keeps the dependency count at zero and
    borrows an auth path the operator already trusts, which is the same reason
    the workstation runner shells out to `git`.
    """

    def __init__(self, owner: str, repo: str, run_id: str) -> None:
        self.owner, self.repo, self.run_id = owner, repo, run_id
        self.created: list[str] = []

    # -- plumbing -----------------------------------------------------------
    def _api(self, *args: str, check: bool = True) -> Any:
        proc = subprocess.run(["gh", "api", *args], capture_output=True, text=True)
        if proc.returncode != 0:
            if check:
                raise GitHubApiError(f"gh api {' '.join(args)}: {proc.stderr.strip()}")
            return None
        return json.loads(proc.stdout) if proc.stdout.strip() else None

    def _guard(self, ref: str) -> str:
        """Refuse anything outside the canary namespace.

        The specs take a ref name as an argument, so a mistake in a canary
        definition is a mistake aimed at a real branch. This is the one check
        standing between a drill and someone's main.
        """
        name = ref.removeprefix("refs/heads/")
        if not name.startswith(CANARY_PREFIX):
            raise GitHubApiError(
                f"refusing to touch {name!r}: drills only operate on refs under "
                f"{CANARY_PREFIX!r}"
            )
        return name

    # -- state --------------------------------------------------------------
    def ref_sha(self, ref: str) -> str | None:
        name = ref.removeprefix("refs/heads/")
        got = self._api(f"repos/{self.owner}/{self.repo}/git/ref/heads/{name}",
                        check=False)
        return got["object"]["sha"] if got else None

    def commit_exists(self, sha: str) -> bool:
        """Whether the object is still reachable on the remote.

        This is the `git_objects_not_collected` gate. Without an evaluator the
        classification degrades to irreversible and the drill reports that it
        could not run — correctly, but it would mean the surface was never
        actually tested.
        """
        return self._api(f"repos/{self.owner}/{self.repo}/commits/{sha}",
                         check=False) is not None

    def head_sha(self) -> str:
        return self._api(f"repos/{self.owner}/{self.repo}/git/ref/heads/"
                         + self._default_branch())["object"]["sha"]

    def _default_branch(self) -> str:
        return self._api(f"repos/{self.owner}/{self.repo}")["default_branch"]

    # -- canary lifecycle ---------------------------------------------------
    def make_canary_ref(self, label: str, sha: str) -> str:
        name = f"{CANARY_PREFIX}{self.run_id}/{label}"
        self._api("-X", "POST", f"repos/{self.owner}/{self.repo}/git/refs",
                  "-f", f"ref=refs/heads/{name}", "-f", f"sha={sha}")
        self.created.append(name)
        return name

    def sweep(self) -> list[str]:
        """Remove every canary this run created. Returns what survived."""
        stuck = []
        for name in list(self.created):
            self._api("-X", "DELETE",
                      f"repos/{self.owner}/{self.repo}/git/refs/heads/{name}",
                      check=False)
            if self.ref_sha(name) is not None:
                stuck.append(name)
        return stuck

    # -- the executor the drill runner calls --------------------------------
    def execute(self, tool: str, args: dict[str, Any]) -> Any:
        if tool == "github.branch.delete":
            name = self._guard(args["ref"])
            self._api("-X", "DELETE",
                      f"repos/{self.owner}/{self.repo}/git/refs/heads/{name}")
            return {"ref": name}
        if tool == "github.ref.create":
            name = self._guard(args["ref"])
            self._api("-X", "POST", f"repos/{self.owner}/{self.repo}/git/refs",
                      "-f", f"ref=refs/heads/{name}", "-f", f"sha={args['sha']}")
            return {"ref": name, "sha": args["sha"]}
        if tool == "github.ref.force_update":
            name = self._guard(args["ref"])
            self._api("-X", "PATCH",
                      f"repos/{self.owner}/{self.repo}/git/refs/heads/{name}",
                      "-f", f"sha={args['sha']}", "-F", "force=true")
            return {"ref": name, "sha": args["sha"]}
        raise GitHubApiError(f"no executor for {tool}")

    def read_state(self, tool: str, args: dict[str, Any],
                   fields: tuple[str, ...]) -> dict[str, Any]:
        sha = self.ref_sha(args["ref"]) if "ref" in args else None
        prior = {"tip_sha": sha, "prior_sha": sha}
        return {f: prior.get(f) for f in fields}


def gate_evaluator(gh: GitHub):
    def evaluate(ctx: GateContext) -> bool:
        if ctx.gate.name == "git_objects_not_collected":
            sha = ctx.args.get("sha")
            return bool(sha) and gh.commit_exists(str(sha))
        return False        # an unrecognised gate is unanswerable, so closed
    return evaluate


def build_canaries(gh: GitHub, base_sha: str, second_sha: str) -> list[Canary]:
    def verify(ref: str):
        # `node_id` is reported and exempt: see DEVOPS_EQUIVALENCE. The drill
        # watches it so a recreated ref is visible as residue rather than hidden.
        def read() -> dict[str, Any]:
            name = ref.removeprefix("refs/heads/")
            got = gh._api(f"repos/{gh.owner}/{gh.repo}/git/ref/heads/{name}",
                          check=False)
            if got is None:
                return {"sha": None, "node_id": None, "exists": False}
            return {"sha": got["object"]["sha"],
                    "node_id": got.get("node_id"), "exists": True}
        return read

    delete_ref = gh.make_canary_ref("delete-me", base_sha)
    force_ref = gh.make_canary_ref("force-me", base_sha)

    return [
        Canary(tool="github.branch.delete",
               args={"owner": gh.owner, "repo": gh.repo, "ref": delete_ref},
               verify=verify(delete_ref), label="branch-delete",
               equivalence=DEVOPS_EQUIVALENCE),
        Canary(tool="github.ref.force_update",
               args={"owner": gh.owner, "repo": gh.repo, "ref": force_ref,
                     "sha": second_sha, "force": True},
               verify=verify(force_ref), label="ref-force-update",
               equivalence=DEVOPS_EQUIVALENCE),
    ]


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--repo", required=True, metavar="OWNER/NAME",
                    help="a disposable repository; canaries are created in it")
    ap.add_argument("--run-out", metavar="PATH", help="write the ValidationRun here")
    ap.add_argument("--json", action="store_true")
    args = ap.parse_args()

    owner, _, repo = args.repo.partition("/")
    if not owner or not repo:
        print("--repo must be OWNER/NAME", file=sys.stderr)
        return 2

    run_id = uuid.uuid4().hex[:8]
    gh = GitHub(owner, repo, run_id)
    started = time.time()

    try:
        base_sha = gh.head_sha()
        # A second commit to force-update *to*, so the forward action genuinely
        # moves the ref. Forcing a ref to where it already points changes nothing
        # and the drill would report FORWARD_NO_OP — correctly, and uselessly.
        blob = gh._api("-X", "POST", f"repos/{owner}/{repo}/git/blobs",
                       "-f", f"content=canary {run_id}", "-f", "encoding=utf-8")
        tree = gh._api("-X", "POST", f"repos/{owner}/{repo}/git/trees",
                       "-f", f"base_tree={base_sha}",
                       "-f", "tree[][path]=revoco-canary.txt",
                       "-f", "tree[][mode]=100644", "-f", "tree[][type]=blob",
                       "-f", f"tree[][sha]={blob['sha']}")
        second = gh._api("-X", "POST", f"repos/{owner}/{repo}/git/commits",
                         "-f", f"message=revoco canary {run_id}",
                         "-f", f"tree={tree['sha']}", "-f", f"parents[]={base_sha}")

        registry = InverseRegistry(list(_github_specs()))
        runner = DrillRunner(registry, executor=gh.execute,
                             state_reader=gh.read_state,
                             gate_evaluator=gate_evaluator(gh))
        results = [runner.drill(c) for c in
                   build_canaries(gh, base_sha, second["sha"])]
    finally:
        stuck = gh.sweep()

    run = ValidationRun(id=f"gh-{run_id}", target=f"github:{owner}/{repo}",
                        started_at=started, finished_at=time.time(),
                        results=tuple(results))

    if args.run_out:
        Path(args.run_out).write_text(json.dumps(run.payload(), indent=2,
                                                 sort_keys=True))

    if args.json:
        print(json.dumps({"run": run.payload(), "leaked": stuck}, indent=2,
                         sort_keys=True))
    else:
        print(f"GITHUB DRILLS — {owner}/{repo}")
        print("=" * 66)
        for r in sorted(results, key=lambda r: r.tool):
            mark = {DrillOutcome.PASSED: "PASS",
                    DrillOutcome.NOT_DRILLABLE: "n/a "}.get(r.outcome, "FAIL")
            print(f"  [{mark}] {r.tool:34s} {r.summary[:70]}")
        print()
        print("STATE EQUIVALENCE  (what 'restored' is allowed to mean here)")
        for line in DEVOPS_EQUIVALENCE.describe().splitlines():
            print(f"  {line.strip()}")
        print()
        proven = sum(1 for r in results if r.outcome.is_proof)
        print(f"{proven}/{len(results)} drills passed — run digest {run.digest[:16]}")
        if stuck:
            print(f"\nLEAKED {len(stuck)} canary ref(s): {', '.join(stuck)}")
            print("Remove them by hand. A runner that leaks into a tenancy is the "
                  "incident it exists to prevent.")

    alarms = [r for r in results if r.outcome.is_alarm]
    return 1 if (alarms or stuck) else 0


def _github_specs():
    from revoco.adapters.devops import DEVOPS_SPECS
    return [s for s in DEVOPS_SPECS if s.tool.startswith("github.")]


if __name__ == "__main__":
    sys.exit(main())
