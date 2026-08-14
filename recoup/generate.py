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
        {"id": "undoable", "effect": "allow",
         "reversibility": ["reversible", "compensable"]},
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

SUITES = (REVERSIBILITY_FIRST, ROLES_AND_GLOBS)


def main() -> int:
    from revoco.gate import load_policy
    from revoco.reversal import ap_starter_registry

    out_dir = Path(__file__).resolve().parent.parent / "conformance" / "fixtures"
    built = []
    for spec in SUITES:
        built.append(generate(load_policy(spec), ap_starter_registry(), spec["name"]))

    for path, suite in zip(write(out_dir, built), built):
        print(f"  {path.name:<26} {len(suite['cases']):>5} cases")

    total = sum(len(s["cases"]) for s in built)
    print(f"\n{total} verdicts frozen from revoco's own engine.")
    print("Review the diff: a change here is a change to what a policy means.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
