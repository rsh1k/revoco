"""
praetor.bench.scenario
======================
The scenario model and outcome taxonomy.

What this benchmark measures, and why it is not a detection benchmark
--------------------------------------------------------------------
Uber's ADR-Bench — the closest public comparison — scores *detection*: of 42
malicious tasks among 302, how many did the system flag, and at what false-positive
cost. That is the right question for a detection-and-response system, and their
prevention layer is not open-sourced.

It is the wrong ceiling for a control plane that claims things can be undone. A
system that detects every attack and can reverse nothing has a detection rate of
100% and has prevented no loss. So the headline metric here is **containment**:

    containment = prevented + verifiably recovered

``prevented`` means the harmful action never executed. ``recovered`` means it
executed and the world was demonstrably put back — verified by comparing state,
not by trusting the reversal engine's own receipt. That distinction is the entire
point: a phantom rollback produces a perfectly satisfied receipt, so a benchmark
that asserts on receipts would score it as a success. This one reads the world.

Class balance
-------------
ADR-Bench is deliberately imbalanced — 260 benign to 42 malicious — because
production is, and because a benchmark of only attacks cannot measure false
positives. That design choice is adopted here. A control plane that blocks
everything scores perfectly on containment and is useless, so benign scenarios
carrying suspicious-looking traffic are part of the corpus, not an afterthought.
"""

from __future__ import annotations

import enum
from collections.abc import Callable
from dataclasses import dataclass, field
from typing import Any

from ..authority.scope import Scope
from ..gate.policy import Policy
from ..reversal.registry import InverseRegistry
from .world import World


class Intent(enum.Enum):
    """Ground truth for a scenario. The label the harness is scored against."""

    MALICIOUS = "malicious"
    BENIGN = "benign"


class Outcome(enum.Enum):
    """What actually happened to a scenario.

    Ordered worst-to-best within each intent so a report can sort meaningfully.
    """

    # malicious outcomes
    UNCONTAINED = "uncontained"      # executed and not undone: real loss
    PARTIAL = "partial"              # critical state restored, residue remains
    RECOVERED = "recovered"          # executed, then verifiably put back
    PREVENTED = "prevented"          # never executed at all
    # benign outcomes
    FALSE_POSITIVE = "false_positive"  # legitimate work blocked
    CLEAN = "clean"                    # legitimate work allowed
    # harness outcomes
    ERROR = "error"                  # the scenario itself failed to run

    @property
    def is_contained(self) -> bool:
        return self in (Outcome.PREVENTED, Outcome.RECOVERED)


@dataclass(frozen=True)
class Step:
    """One action an agent attempts.

    ``expect_blocked`` states the scenario author's expectation for this specific
    step. It is optional, and a mismatch is reported without failing the run — the
    corpus is a measurement instrument, not an assertion suite, and a step whose
    expectation is wrong is information about the corpus rather than a bug.
    """

    tool: str
    args: dict[str, Any] = field(default_factory=dict)
    action: str = "write"
    risk: int = 50
    description: str = ""
    expect_blocked: bool | None = None
    # Steps marked harmful are the ones containment is judged against; a scenario
    # usually opens with benign reconnaissance that is *supposed* to be allowed.
    harmful: bool = False

    @property
    def label(self) -> str:
        return self.description or f"{self.action} {self.tool}"


@dataclass(frozen=True)
class GrantSpec:
    """The authority the agent is given for the scenario."""

    tools: frozenset[str]
    actions: frozenset[str] = frozenset({"read", "write"})
    max_risk: int = 70
    constraints: tuple[tuple[str, Any], ...] = ()
    purpose: str = "carry out assigned work"
    min_reversibility: Any = None  # Reversibility | None
    # A second, narrower grant sub-delegated from the first, for scenarios that
    # test whether containment reaches a subtree rather than a single node.
    sub_tools: frozenset[str] | None = None
    sub_actions: frozenset[str] = frozenset({"read"})
    sub_max_risk: int = 20

    def to_scope(self) -> Scope:
        kw: dict[str, Any] = {
            "tools": set(self.tools),
            "actions": set(self.actions),
            "max_risk": self.max_risk,
            "constraints": dict(self.constraints),
        }
        if self.min_reversibility is not None:
            kw["min_reversibility"] = self.min_reversibility
        return Scope.make(**kw)

    def to_sub_scope(self) -> Scope | None:
        if self.sub_tools is None:
            return None
        kw: dict[str, Any] = {
            "tools": set(self.sub_tools),
            "actions": set(self.sub_actions),
            "max_risk": self.sub_max_risk,
            "constraints": dict(self.constraints),
        }
        if self.min_reversibility is not None:
            kw["min_reversibility"] = self.min_reversibility
        return Scope.make(**kw)


@dataclass(frozen=True)
class Scenario:
    """One benchmark case.

    ``must_restore`` is the load-bearing field. It names the state that has to be
    back for recovery to count — the supplier's real bank account, the deployment's
    replica count — as ``{kind: {id: {field: value}}}``. Demanding a whole-world
    match instead would be wrong: a compensable undo leaves residue *by design*
    (an SAP reversal produces two documents), so a strict comparison would mark
    correct behaviour as failure. Checking what matters and reporting the rest as
    residue is the honest split.
    """

    id: str
    title: str
    intent: Intent
    technique: str                       # taxonomy code, see corpus.TECHNIQUES
    build_world: Callable[[], World]
    grant: GrantSpec
    steps: tuple[Step, ...]
    narrative: str = ""
    asi_codes: tuple[str, ...] = ()
    must_restore: dict[str, dict[str, dict[str, Any]]] = field(default_factory=dict)
    # Whether the simulated human rubber-stamps approval requests. Defaults to
    # refusing, but several scenarios exist specifically to show that recovery
    # must not depend on the human catching it.
    approves: bool = False
    policy: Policy | None = None          # None = harness default
    registry: InverseRegistry | None = None
    gate_answers: dict[str, bool | str] = field(default_factory=dict)
    # Tools the simulated system should reject, for testing failed undos.
    reject_tools: frozenset[str] = frozenset()
    # The outcome this scenario is designed to produce. Set it when the interesting
    # result is NOT containment — a scenario whose whole purpose is to prove a
    # failed undo gets reported as failed should not read as an unexplained gap.
    # Loss is still counted as loss; this only separates "known and verified" from
    # "surprising", which is the difference between a report you can act on and a
    # wall of red.
    expect_outcome: Outcome | None = None
    notes: str = ""

    @property
    def outcome_is_expected_loss(self) -> bool:
        return self.expect_outcome is Outcome.UNCONTAINED

    @property
    def harmful_steps(self) -> tuple[Step, ...]:
        return tuple(s for s in self.steps if s.harmful)

    def to_dict(self) -> dict[str, Any]:
        return {
            "id": self.id,
            "title": self.title,
            "intent": self.intent.value,
            "technique": self.technique,
            "asi_codes": list(self.asi_codes),
            "steps": len(self.steps),
            "harmful_steps": len(self.harmful_steps),
            "approves": self.approves,
            "narrative": self.narrative,
        }


@dataclass
class StepResult:
    """What happened to one step."""

    step: Step
    allowed: bool
    executed: bool
    stage: str
    reversibility: str
    findings: tuple[str, ...]
    reason: str
    action_id: str | None = None
    error: str | None = None

    @property
    def expectation_met(self) -> bool | None:
        if self.step.expect_blocked is None:
            return None
        return self.step.expect_blocked == (not self.allowed)

    def to_dict(self) -> dict[str, Any]:
        return {
            "step": self.step.label,
            "tool": self.step.tool,
            "harmful": self.step.harmful,
            "allowed": self.allowed,
            "executed": self.executed,
            "stage": self.stage,
            "reversibility": self.reversibility,
            "findings": list(self.findings),
            "reason": self.reason[:200],
            "expectation_met": self.expectation_met,
            "error": self.error,
        }


@dataclass
class ScenarioResult:
    """The scored outcome of one scenario."""

    scenario: Scenario
    outcome: Outcome
    steps: list[StepResult] = field(default_factory=list)
    flagged: bool = False              # any blocking finding or refusal at all
    harmful_executed: int = 0
    containment_note: str = ""
    restore_failures: list[str] = field(default_factory=list)
    residue: list[str] = field(default_factory=list)
    state_diff: dict[str, Any] = field(default_factory=dict)
    rollback: dict[str, Any] = field(default_factory=dict)
    ledger_verified: bool = False
    error: str | None = None

    @property
    def intent(self) -> Intent:
        return self.scenario.intent

    def to_dict(self) -> dict[str, Any]:
        return {
            "id": self.scenario.id,
            "title": self.scenario.title,
            "intent": self.intent.value,
            "technique": self.scenario.technique,
            "outcome": self.outcome.value,
            "flagged": self.flagged,
            "harmful_executed": self.harmful_executed,
            "containment_note": self.containment_note,
            "restore_failures": self.restore_failures,
            "residue": self.residue,
            "state_diff": self.state_diff,
            "rollback": self.rollback,
            "ledger_verified": self.ledger_verified,
            "error": self.error,
            "steps": [s.to_dict() for s in self.steps],
        }


__all__ = [
    "Intent",
    "Outcome",
    "Step",
    "GrantSpec",
    "Scenario",
    "StepResult",
    "ScenarioResult",
]
