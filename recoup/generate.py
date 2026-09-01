"""Regenerate the conformance fixtures. Run deliberately, never automatically.

    python -m recoup.generate

The fixtures are the oracle that stops the Go enforcer and the Python control
plane drifting apart. An oracle that regenerates itself whenever the code
changes is not an oracle — it just records whatever the code currently does, and
a behaviour change would rewrite its own expectations and pass. So this is a
target someone runs on purpose, and the diff it produces is the thing to review.

The policies below are not a customer's. They exist to exercise the decision
surface: rule ordering, glob matching on three fields, role requirements,
reversibility filtering, and every numeric threshold the matcher supports.
"""

from __future__ import annotations

import sys
from pathlib import Path

from .fixtures import generate, write

# A policy in the shape retie ships: consequence decides, and reversibility is
# the axis that routes to a human.
REVERSIBILITY_FIRST = {
    "name": "reversibility-first",
    "default_effect": "deny",
    "rules": [
        {"id": "reads", "effect": "allow", "actions": ["read"]},
        {"id": "risky-needs-human", "effect": "require_approval",
         "actions": ["write"], "min_risk": 25},
        {"id": "no-undo", "effect": "require_approval",
         "reversibility": ["irreversible", "unknown"]},
        # A floor rather than a set, so the fixtures exercise rank comparison and
        # not just membership. Naming the postures here is what let `idempotent`
        # fall through to the default effect when it was added.
        {"id": "undoable", "effect": "allow",
         "min_reversibility": "compensable"},
    ],
}

# Deliberately awkward: overlapping globs, a role requirement, a threat floor and
# a risk ceiling, so rule *ordering* is observable rather than incidental.
ROLES_AND_GLOBS = {
    "name": "roles-and-globs",
    "default_effect": "deny",
    "rules": [
        {"id": "clerk-invoices", "effect": "allow", "tools": ["invoices.*"],
         "require_roles": ["ap-clerk"], "max_risk": 40},
        {"id": "threat-block", "effect": "deny", "min_threat_score": 5},
        {"id": "named-agent", "effect": "allow", "agents": ["ap-*"],
         "actions": ["read"]},
    ],
}

# A floor with nothing ahead of it. In REVERSIBILITY_FIRST the `no-undo` rule
# intercepts irreversible and unknown before they ever reach the floor rule, so
# an enforcer that ignored `min_reversibility` altogether still produced every
# expected verdict and the mutation for it survived. Coverage of a comparison
# means a case where getting it wrong changes the answer; here the floor is the
# only thing between a one-way call and an allow.
FLOOR_ONLY = {
    "name": "floor-only",
    "default_effect": "deny",
    "rules": [
        {"id": "safe-enough", "effect": "allow", "min_reversibility": "compensable",
         "reason": "recoverable enough to proceed without a human"},
    ],
}

SUITES = (REVERSIBILITY_FIRST, ROLES_AND_GLOBS, FLOOR_ONLY)


def _registry():
    """The AP starter registry, plus one tool per posture it does not carry.

    The starter registry declares reversible, compensable and irreversible tools
    and no idempotent one, so 3,960 fixtures covered four postures out of five
    and the newest — the one most likely to be handled differently by two
    runtimes — was never put through the enforcer at all. A conformance suite
    that cannot exercise a posture cannot detect a disagreement about it.
    """
    from revoco.reversal import InverseSpec, Reversibility, ap_starter_registry

    reg = ap_starter_registry()
    reg.register(InverseSpec(
        tool="invoices.read",
        kind=Reversibility.IDEMPOTENT,
        notes="A read changes nothing. Present so the fixtures cover the posture.",
    ))
    return reg


def main() -> int:
    from revoco.gate import load_policy

    out_dir = Path(__file__).resolve().parent.parent / "conformance" / "fixtures"
    built = []
    for spec in SUITES:
        built.append(generate(load_policy(spec), _registry(), spec["name"]))

    for path, suite in zip(write(out_dir, built), built):
        print(f"  {path.name:<26} {len(suite['cases']):>5} cases")

    total = sum(len(s["cases"]) for s in built)
    print(f"\n{total} verdicts frozen from revoco's own engine.")
    print("Review the diff: a change here is a change to what a policy means.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
