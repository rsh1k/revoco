"""
A containment benchmark for agent control planes.

The closest public comparison is Uber's ADR-Bench, which scores *detection*: of 42
malicious tasks among 302, how many were flagged and at what false-positive cost.
That is the right question for a detection-and-response system.

It is the wrong ceiling for anything claiming actions can be undone. A system that
detects every attack and reverses nothing scores 100% on detection and has prevented
no loss. So the headline here is **containment**::

    containment = prevented + verifiably recovered

with ``recovered`` established by comparing world state against a pre-attack
baseline — never by reading a reversal receipt. That is the whole point: a phantom
rollback produces a receipt indistinguishable from a real one, so a benchmark built
on receipts would certify the exact failure mode this package exists to prevent.

Honest about scale: this corpus is far smaller than ADR-Bench and its cases are
authored from public incident reporting rather than observed enterprise telemetry.
Detection coverage is their strength; verified recoverability is this one's. They
measure different things.

Usage::

    revoco bench                  # run it
    revoco bench --verbose        # per-step detail
    revoco bench --json           # machine-readable

    from revoco.bench import Harness, all_scenarios, render
    print(render(Harness().run_all(all_scenarios())))
"""

from .corpus import TECHNIQUES, all_scenarios, benign, by_technique, malicious
from .external import available as external_available
from .external import provenance as external_provenance
from .external import ras_eval_scenarios
from .harness import DEFAULT_POLICY, Harness, default_policy
from .report import Metrics, render, score, to_dict
from .scenario import (
    GrantSpec,
    Intent,
    Outcome,
    Scenario,
    ScenarioResult,
    Step,
    StepResult,
)
from .world import Mutation, ToolBinding, World, WorldError

__all__ = [
    # running
    "Harness",
    "DEFAULT_POLICY",
    "default_policy",
    # corpus
    "TECHNIQUES",
    "all_scenarios",
    "malicious",
    "benign",
    "by_technique",
    # external corpora (opt-in, nothing vendored)
    "ras_eval_scenarios",
    "external_available",
    "external_provenance",
    # model
    "Scenario",
    "Step",
    "GrantSpec",
    "Intent",
    "Outcome",
    "ScenarioResult",
    "StepResult",
    # world
    "World",
    "ToolBinding",
    "Mutation",
    "WorldError",
    # reporting
    "Metrics",
    "score",
    "render",
    "to_dict",
]
