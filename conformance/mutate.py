#!/usr/bin/env python3
"""Mutation testing for the conformance suite: does it actually bite?

A conformance suite that passes is not evidence of anything on its own. The
first version of these fixtures passed 8,316 cases while a `<` had been changed
to `<=` in the Go evaluator, because the hand-picked risk values never landed on
the policy's only threshold. The suite was green and worthless, and nothing about
running it would have revealed that.

So the suite is itself tested. Each mutation below is a single-character change
to a comparison or a boolean in the Go evaluator — the kind of thing a careless
edit produces — and every one of them must turn the suite red. A mutation that
survives is a hole in the fixtures, not a curiosity.

    python conformance/mutate.py

Exits non-zero if any mutation survives.
"""

from __future__ import annotations

import os
import shutil
import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
TARGET = ROOT / "internal" / "decision" / "decision.go"
# CI has go on PATH; this machine has it under ~/.local. Neither should be
# hardcoded in a way that makes the other silently skip the check.
GO = Path(os.environ.get("GO_BIN") or Path.home() / ".local" / "go" / "bin" / "go")

# (label, exact text to find, replacement). Each must be a genuine behaviour
# change, and each must be caught.
MUTATIONS = [
    ("min_risk boundary",
     "if r.MinRisk != nil && c.Risk < *r.MinRisk {",
     "if r.MinRisk != nil && c.Risk <= *r.MinRisk {"),
    ("max_risk boundary",
     "if r.MaxRisk != nil && c.Risk > *r.MaxRisk {",
     "if r.MaxRisk != nil && c.Risk >= *r.MaxRisk {"),
    ("threat boundary",
     "if r.MinThreatScore != nil && c.ThreatScore < *r.MinThreatScore {",
     "if r.MinThreatScore != nil && c.ThreatScore <= *r.MinThreatScore {"),
    ("reversibility filter inverted",
     "if len(r.Reversibility) > 0 && !contains(r.Reversibility, rev) {",
     "if len(r.Reversibility) > 0 && contains(r.Reversibility, rev) {"),
    ("required roles ignored",
     "\t\tif !hasRole(c.Roles, want) {",
     "\t\tif false && !hasRole(c.Roles, want) {"),
    ("agent glob ignored",
     "if !matchAny(c.AgentID, r.Agents) {",
     "if false && !matchAny(c.AgentID, r.Agents) {"),
    ("action glob ignored",
     "if !matchAny(c.Action, r.Actions) {",
     "if false && !matchAny(c.Action, r.Actions) {"),
    ("tool glob ignored",
     "if !matchAny(c.Tool, r.Tools) {",
     "if false && !matchAny(c.Tool, r.Tools) {"),
    ("glob crosses to path.Match semantics",
     '\t\t\tout.WriteString(".*")',
     '\t\t\tout.WriteString("[^/]*")'),
]


def run_suite() -> bool:
    """True when the conformance suite passes. `-count=1` defeats the cache."""
    proc = subprocess.run(
        [str(GO), "test", "-count=1", "./internal/decision/"],
        cwd=ROOT, capture_output=True, text=True,
        env={**os.environ, "PATH": f"{GO.parent}:{os.environ.get('PATH', '')}"},
    )
    return proc.returncode == 0


def main() -> int:
    if not GO.exists() and shutil.which(str(GO)) is None:
        print(f"go toolchain not found at {GO}", file=sys.stderr)
        return 2

    if not run_suite():
        print("the suite is already failing; fix that before mutating", file=sys.stderr)
        return 2

    files = {TARGET, ROOT / "internal" / "decision" / "fnmatch.go"}
    backups = {f: f.read_text(encoding="utf-8") for f in files}
    survivors = []

    try:
        for label, find, replace in MUTATIONS:
            target = next((f for f in files if find in backups[f]), None)
            if target is None:
                # A mutation that no longer applies is a silent loss of coverage:
                # the code moved and nobody updated the mutation.
                survivors.append(f"{label} (anchor text not found — mutation is stale)")
                print(f"  {'STALE':<9} {label}")
                continue

            target.write_text(backups[target].replace(find, replace, 1), encoding="utf-8")
            caught = not run_suite()
            target.write_text(backups[target], encoding="utf-8")

            print(f"  {'caught' if caught else 'SURVIVED':<9} {label}")
            if not caught:
                survivors.append(label)
    finally:
        for f, text in backups.items():
            f.write_text(text, encoding="utf-8")

    print()
    if survivors:
        print(f"{len(survivors)} mutation(s) survived. The fixtures do not cover:")
        for s in survivors:
            print(f"  - {s}")
        print("\nA green suite with these holes in it is worse than no suite, "
              "because it is believed.")
        return 1

    print(f"all {len(MUTATIONS)} mutations caught")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
