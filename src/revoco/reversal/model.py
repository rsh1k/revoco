"""
revoco.reversal.model
======================
The reversal data model — the part of this control plane that did not exist in
any of the merged tools, and the part that turns an audit trail into a recovery
capability.

The premise
-----------
Governance tooling for agents is overwhelmingly about *detection*: was this call
allowed, was it logged, was it anomalous. That leaves the expensive half of an
incident untouched. When an agent has already modified two hundred vendor
records, knowing precisely which two hundred is necessary but not sufficient —
somebody still has to put them back, by hand, under time pressure, while the
auditors watch.

So reversibility is modeled here as a *property of the action, declared before
the action runs*, not as a recovery procedure invented afterwards.

Three things real systems forced into this model
-----------------------------------------------
The first version of this file assumed an undo was one call, valid for a fixed
number of seconds. Specifying the SAP and Workday adapters showed all three
assumptions were wrong:

* **Undos are often ordered sequences.** Reversing a cleared SAP payment means
  voiding the payment medium, then resetting the clearing (``FBRA``), then
  posting the reversal (``FB08``) — in that order, because a reversal cannot be
  posted against cleared items, and resetting clearing before voiding the cheque
  leaves the ledger and the bank statement disagreeing. Hence
  :class:`InverseStep`.
* **Undo windows are bounded by events, not clocks.** A Workday business process
  can be rescinded until payroll runs; an SAP document can be reversed while its
  accounting period is open. Neither is a duration. Hence :class:`ReversalGate`.
* **Some undos are themselves one-shot.** An SAP reversal document cannot be
  reversed; a Workday rescind cannot be un-rescinded. The undo is a single
  cartridge, and firing it wrongly is unrecoverable. Hence
  :attr:`InverseSpec.one_shot`.

The honest part
---------------
Compensating actions are not inverses. You can void a payment; you cannot
un-send the remittance advice that told the supplier it was coming. You can
delete a created record; you cannot un-ring the webhook that fired on create.
:class:`Reversibility` therefore distinguishes an exact inverse from an
approximate compensation, and :attr:`InverseSpec.residue` names in plain words
what survives the undo. A system that pretended otherwise would be worse than no
system, because it would license riskier delegation on a false promise.
"""

from __future__ import annotations

import enum
import time
from dataclasses import dataclass, field
from typing import Any, Protocol

from ..core import crypto, ids
from ..core.errors import ValidationError


class Reversibility(enum.Enum):
    """How completely an action can be undone.

    Ordered by rank so scopes and policies can state a floor. ``UNKNOWN`` ranks
    *below* ``IRREVERSIBLE`` on purpose: an unclassified tool is worse than a
    tool known to be one-way, because with the latter you at least know to
    require approval. Fail-safe means unclassified fails every stated floor.

    ``IDEMPOTENT`` ranks *above* ``REVERSIBLE`` for the mirror reason: an action
    that never changed anything is safer than one that changed something and can
    change it back. It exists as its own class because folding reads into
    ``REVERSIBLE`` inflates every count of how much of an estate can be undone
    with actions that never needed undoing. Here it means specifically **the
    action does not modify state** — a read, a query, a dry run. A write that is
    merely safe to repeat is ``REVERSIBLE``: it moved something, and putting it
    back is a real operation.

    These values are serialized — into specs, journals, evidence packs, and any
    policy bundle a downstream enforcer loads. A consumer that enumerates the set
    rather than reading it must learn ``idempotent`` before it sees one, or it
    will reject a spec it should simply have priced at zero.
    """

    UNKNOWN = "unknown"
    IRREVERSIBLE = "irreversible"
    COMPENSABLE = "compensable"
    REVERSIBLE = "reversible"
    IDEMPOTENT = "idempotent"

    @property
    def rank(self) -> int:
        return _RANKS[self]

    @property
    def is_undoable(self) -> bool:
        """Whether an undo path exists at all (exact or approximate).

        False for ``IDEMPOTENT``, which has no undo path because it has nothing to
        undo. Callers asking "is this dangerous" want :attr:`is_one_way` instead —
        the two questions used to share this property and they are not the same.
        """
        return self in (Reversibility.REVERSIBLE, Reversibility.COMPENSABLE)

    @property
    def is_one_way(self) -> bool:
        """Whether the action changed something that nothing can take back.

        The risk question, as opposed to the structural one. ``IDEMPOTENT`` is not
        one-way despite having no inverse: nothing happened, so nothing is standing
        exposure. Counting reads as irreversible fan-out would make the alarm
        useless on any agent that reads more than it writes — which is all of them.
        """
        return self in (Reversibility.IRREVERSIBLE, Reversibility.UNKNOWN)


_RANKS = {
    Reversibility.UNKNOWN: 0,
    Reversibility.IRREVERSIBLE: 1,
    Reversibility.COMPENSABLE: 2,
    Reversibility.REVERSIBLE: 3,
    Reversibility.IDEMPOTENT: 4,
}


class JournalState(enum.Enum):
    """Lifecycle of one journal entry.

    PLANNED    -> an undo path was computed; the forward action has not run
    COMMITTED  -> the forward action ran and the undo path is live
    ABANDONED  -> the forward action was blocked or never ran; plan discarded
    REVERSED   -> the undo ran successfully
    FAILED     -> the undo was attempted and failed (needs human recovery)
    EXPIRED    -> the undo window closed before anyone used it
    """

    PLANNED = "planned"
    COMMITTED = "committed"
    ABANDONED = "abandoned"
    REVERSED = "reversed"
    FAILED = "reversal_failed"
    EXPIRED = "expired"

    @property
    def is_terminal(self) -> bool:
        return self in (
            JournalState.ABANDONED,
            JournalState.REVERSED,
            JournalState.FAILED,
            JournalState.EXPIRED,
        )


# ---------------------------------------------------------------------------
# Argument mapping
# ---------------------------------------------------------------------------
# An inverse call's arguments are assembled from five sources. Keeping this a
# declarative mapping (rather than a Python callable) means an inverse spec is
# data: it can be shipped in YAML, reviewed in a pull request by someone who does
# not write Python, and — critically — recorded verbatim in the ledger so an
# auditor sees exactly what the undo would have done.
#
#   args.<path>          the forward call's arguments
#   snapshot.<path>      prior state captured BEFORE the forward action ran
#   result.<path>        the forward call's return value (bound on commit)
#   step.<name>.<path>   an earlier undo step's return value (bound at undo time)
#   const:<value>        a literal

ARG_SOURCES = ("args", "result", "snapshot", "step", "const")


def _resolve_path(path: str, root: Any) -> tuple[bool, Any]:
    """Resolve a dotted path against a nested mapping."""
    cur = root
    for part in path.split("."):
        if isinstance(cur, dict) and part in cur:
            cur = cur[part]
        else:
            return False, None
    return True, cur


def _validate_source(expr: str) -> None:
    if expr.startswith("const:"):
        return
    head = expr.split(".", 1)[0]
    if head not in ARG_SOURCES:
        raise ValidationError(
            f"inverse arg source must be one of {ARG_SOURCES} or 'const:', got {expr!r}"
        )
    if head == "step":
        if expr.count(".") < 2:
            raise ValidationError(
                f"step source {expr!r} needs the form step.<step_name>.<path>"
            )
        return
    if "." not in expr:
        raise ValidationError(f"inverse arg source {expr!r} needs a dotted path")


def _source_head(expr: str) -> str:
    return "const" if expr.startswith("const:") else expr.split(".", 1)[0]


# ---------------------------------------------------------------------------
# Steps and gates
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class InverseStep:
    """One call in an ordered undo sequence.

    Sequences exist because real reversals have prerequisites that are separate
    operations with their own failure modes. Modeling them as one opaque "undo"
    would hide exactly the step most likely to fail, and hide it at the moment
    someone most needs to know which one it was.

    ``critical`` marks a step whose failure makes continuing unsafe. Voiding a
    cheque before resetting a payment's clearing is critical: if the void fails
    and the reset proceeds, the ledger says the money was never paid while the
    bank says it was. A non-critical step (a courtesy notification) may fail and
    be reported without aborting the rest.
    """

    name: str
    tool: str
    arg_map: tuple[tuple[str, str], ...] = ()
    static_args: tuple[tuple[str, Any], ...] = ()
    description: str = ""
    critical: bool = True

    def __post_init__(self) -> None:
        object.__setattr__(self, "arg_map", tuple(sorted(self.arg_map)))
        object.__setattr__(self, "static_args", tuple(sorted(self.static_args)))
        if not isinstance(self.name, str) or not self.name:
            raise ValidationError("InverseStep.name must be a non-empty string")
        if not isinstance(self.tool, str) or not self.tool:
            raise ValidationError(f"step {self.name!r}: tool must be a non-empty string")
        for _n, expr in self.arg_map:
            _validate_source(expr)

    @property
    def needs_result(self) -> tuple[str, ...]:
        return tuple(n for n, e in self.arg_map if _source_head(e) == "result")

    @property
    def needs_prior_step(self) -> tuple[str, ...]:
        return tuple(n for n, e in self.arg_map if _source_head(e) == "step")

    def to_dict(self) -> dict[str, Any]:
        return {
            "name": self.name,
            "tool": self.tool,
            "arg_map": dict(self.arg_map),
            "static_args": dict(self.static_args),
            "description": self.description,
            "critical": self.critical,
        }

    @classmethod
    def from_dict(cls, d: dict[str, Any]) -> InverseStep:
        return cls(
            name=d["name"],
            tool=d["tool"],
            arg_map=tuple(sorted((d.get("arg_map") or {}).items())),
            static_args=tuple(sorted((d.get("static_args") or {}).items())),
            description=d.get("description", ""),
            critical=bool(d.get("critical", True)),
        )

    def resolve(
        self,
        *,
        forward_args: dict[str, Any],
        snapshot: dict[str, Any],
        result: Any = None,
        step_results: dict[str, Any] | None = None,
        include_result: bool = False,
        include_steps: bool = False,
    ) -> tuple[dict[str, Any], tuple[str, ...], tuple[str, ...], tuple[str, ...]]:
        """Assemble this step's arguments.

        Returns ``(resolved, unresolved, deferred, from_prior_step)``.
        """
        out: dict[str, Any] = dict(self.static_args)
        unresolved: list[str] = []
        deferred: list[str] = []
        from_step: list[str] = []
        roots: dict[str, Any] = {
            "args": forward_args,
            "snapshot": snapshot,
            "result": result if isinstance(result, dict) else {"value": result},
            "step": step_results or {},
        }
        for name, expr in self.arg_map:
            if expr.startswith("const:"):
                out[name] = expr[len("const:") :]
                continue
            head, _, path = expr.partition(".")
            if head == "result" and not include_result:
                deferred.append(name)
                continue
            if head == "step" and not include_steps:
                # Resolvable only while the undo is running, which is normal and
                # not a defect in the plan.
                from_step.append(name)
                continue
            found, value = _resolve_path(path, roots[head])
            if not found:
                if head == "step":
                    from_step.append(name)
                else:
                    unresolved.append(name)
                continue
            out[name] = value
        return out, tuple(unresolved), tuple(deferred), tuple(from_step)


PHASE_AUTHORIZE = "authorize"
PHASE_UNDO = "undo"
PHASE_BOTH = "both"
_VALID_PHASES = (PHASE_AUTHORIZE, PHASE_UNDO, PHASE_BOTH)


@dataclass(frozen=True)
class ReversalGate:
    """A precondition checked by the integration, at one or both phases.

    Time-based windows (:attr:`InverseSpec.window_seconds`) cover settlement
    cutoffs. They cannot express the conditions that actually bound most
    enterprise reversals, which are *events*: an SAP document is reversible while
    its accounting period is open, a Workday business process is rescindable until
    payroll runs. Neither is a duration known in advance.

    ``check_at`` decides when the question is asked, and the distinction is
    load-bearing:

    ``undo`` (default)
        Asked immediately before the undo runs. "Is the period still open?"

    ``authorize``
        Asked *before the forward action is allowed*, because the answer changes
        whether the action is undoable at all. An S3 delete is recoverable only if
        the bucket has versioning enabled; an Entra delete only if that object type
        supports soft delete. Reversibility is a property of the target, not just
        the tool, and a control plane that classified per-tool would tell policy
        "undoable" about something that is not. When an authorize-phase gate is
        closed, the spec's kind degrades to
        :attr:`InverseSpec.degraded_kind` — so the reversibility-first policy
        escalates to a human *before* the irreversible thing happens, which is the
        only moment the escalation is worth anything.

    ``both``
        Asked at both points. Versioning could be switched off between the write
        and the recovery attempt.

    Unanswerable is treated as closed. Refusing an undo you cannot confirm is safe
    is the correct failure direction, because a half-applied reversal is worse than
    a refused one — and at authorize time, treating an unverifiable precondition as
    "assume the worst" is what makes the escalation trustworthy.
    """

    name: str
    description: str
    remediation: str = ""
    check_at: str = PHASE_UNDO

    def __post_init__(self) -> None:
        if not isinstance(self.name, str) or not self.name:
            raise ValidationError("ReversalGate.name must be a non-empty string")
        if not self.description:
            raise ValidationError(
                f"gate {self.name!r} needs a description — an unexplained blocked "
                "rollback is an unactionable alert"
            )
        if self.check_at not in _VALID_PHASES:
            raise ValidationError(
                f"gate {self.name!r}: check_at must be one of {_VALID_PHASES}"
            )

    @property
    def checked_at_authorize(self) -> bool:
        return self.check_at in (PHASE_AUTHORIZE, PHASE_BOTH)

    @property
    def checked_at_undo(self) -> bool:
        return self.check_at in (PHASE_UNDO, PHASE_BOTH)

    def to_dict(self) -> dict[str, Any]:
        return {
            "name": self.name,
            "description": self.description,
            "remediation": self.remediation,
            "check_at": self.check_at,
        }

    @classmethod
    def from_dict(cls, d: dict[str, Any]) -> ReversalGate:
        return cls(
            name=d["name"],
            description=d.get("description", ""),
            remediation=d.get("remediation", ""),
            check_at=d.get("check_at", PHASE_UNDO),
        )


@dataclass(frozen=True)
class GateContext:
    """What an evaluator is given when asked about a gate.

    One context type covers both phases. ``entry`` is None at authorize time
    because the journal entry does not exist yet — that absence is the reliable
    way to tell which question is being asked, and ``phase`` states it outright.
    """

    gate: ReversalGate
    tool: str
    phase: str
    args: dict[str, Any] = field(default_factory=dict)
    entry: JournalEntry | None = None

    @property
    def is_authorize(self) -> bool:
        return self.phase == PHASE_AUTHORIZE


@dataclass(frozen=True)
class Exemption:
    """One difference a drill agrees not to hold against an inverse, and why.

    The reason is required for the same purpose ``residue`` is required on a
    COMPENSABLE spec: an exemption nobody has to justify is where a failing drill
    quietly becomes a passing one.
    """

    field: str
    reason: str

    def __post_init__(self) -> None:
        if not self.field:
            raise ValidationError("Exemption.field must be a non-empty string")
        if not self.reason:
            raise ValidationError(
                f"exemption for {self.field!r} needs a reason — an unexplained "
                "exclusion is how a comparison is tuned until it passes"
            )


@dataclass(frozen=True)
class StateEquivalence:
    """What counts as "state returned" on one surface, written down in advance.

    A drill compares state before and after, which sounds exact and is not. Real
    systems move a timestamp, bump a version counter, append an audit row and
    change an etag on every write, so requiring byte equality fails every honest
    inverse. Something has to be excluded.

    That exclusion is the most dangerous knob in the whole method — generous
    enough and no drill can ever fail — so it is a declared object with a reason
    per field rather than a tuple assembled at the call site. Publish it with the
    results and the comparison can be argued with, which is the only defence
    against having tuned it.

    Exempt fields are not ignored. A drill still watches them and reports the ones
    that did not come back as :attr:`DrillResult.observed_residue`, which is how a
    residue gets named from evidence instead of from a vendor document.
    """

    name: str
    exempt: tuple[Exemption, ...] = ()

    def __post_init__(self) -> None:
        if not self.name:
            raise ValidationError("StateEquivalence.name must be a non-empty string")
        seen = [e.field for e in self.exempt]
        if len(seen) != len(set(seen)):
            raise ValidationError(f"{self.name}: duplicate exempt field in {seen}")

    @property
    def fields(self) -> frozenset[str]:
        return frozenset(e.field for e in self.exempt)

    def describe(self) -> str:
        """The relation as publishable text, one exemption per line."""
        if not self.exempt:
            return f"{self.name}: every reported field must return exactly"
        lines = [f"{self.name}: every reported field must return exactly, except"]
        lines += [f"  - {e.field}: {e.reason}" for e in sorted(self.exempt,
                                                               key=lambda e: e.field)]
        return "\n".join(lines)


@dataclass(frozen=True)
class InverseSpec:
    """How to undo one tool.

    ``tool``            the forward tool this describes, e.g. "invoices.pay"
    ``kind``            how completely the undo restores prior state
    ``inverse_tool``    single-step shorthand: the tool that performs the undo
    ``arg_map``         single-step shorthand: arg name -> source expression
    ``steps``           an ordered sequence, for undos with prerequisites
    ``gates``           preconditions checked at undo time (period open, payroll
                        not yet run) — see :class:`ReversalGate`
    ``snapshot_fields`` prior-state fields to capture BEFORE the forward action
    ``window_seconds``  a time-based cutoff, where one genuinely applies
    ``one_shot``        the undo cannot itself be undone (an SAP reversal document
                        cannot be reversed; a Workday rescind cannot be
                        un-rescinded)
    ``residue``         what remains even after a successful undo — required for
                        COMPENSABLE, because an unnamed side effect is an unowned
                        risk
    """

    tool: str
    kind: Reversibility
    inverse_tool: str | None = None
    arg_map: tuple[tuple[str, str], ...] = ()
    static_args: tuple[tuple[str, Any], ...] = ()
    steps: tuple[InverseStep, ...] = ()
    gates: tuple[ReversalGate, ...] = ()
    snapshot_fields: tuple[str, ...] = ()
    window_seconds: float | None = None
    one_shot: bool = False
    degraded_kind: Reversibility = Reversibility.IRREVERSIBLE
    residue: str = ""
    notes: str = ""

    def __post_init__(self) -> None:
        # Canonicalize the mappings. Argument order carries no meaning, so fixing
        # it here means two specs describing the same undo compare equal and
        # produce the same plan digest regardless of how they were written.
        object.__setattr__(self, "arg_map", tuple(sorted(self.arg_map)))
        object.__setattr__(self, "static_args", tuple(sorted(self.static_args)))

        if not isinstance(self.tool, str) or not self.tool:
            raise ValidationError("InverseSpec.tool must be a non-empty string")
        if not isinstance(self.kind, Reversibility):
            raise ValidationError("InverseSpec.kind must be a Reversibility")

        has_single = bool(self.inverse_tool)
        has_steps = bool(self.steps)
        if has_single and has_steps:
            raise ValidationError(
                f"{self.tool}: give either inverse_tool (single step) or steps "
                "(a sequence), not both"
            )
        if self.kind.is_undoable and not (has_single or has_steps):
            raise ValidationError(
                f"{self.tool}: kind={self.kind.value} requires an inverse_tool or steps"
            )
        if not self.kind.is_undoable and (has_single or has_steps):
            raise ValidationError(
                f"{self.tool}: kind={self.kind.value} must not name an undo path"
            )
        if self.kind is Reversibility.COMPENSABLE and not self.residue:
            raise ValidationError(
                f"{self.tool}: COMPENSABLE requires 'residue' naming what the undo "
                "cannot restore — an unnamed side effect is an unowned risk"
            )
        if self.kind is Reversibility.IDEMPOTENT and self.snapshot_fields:
            raise ValidationError(
                f"{self.tool}: an IDEMPOTENT action does not modify state, so there "
                "is no prior state worth capturing"
            )
        if self.window_seconds is not None and self.window_seconds <= 0:
            raise ValidationError(f"{self.tool}: window_seconds must be positive")
        for _name, expr in self.arg_map:
            _validate_source(expr)

        names = [s.name for s in self.steps]
        if len(names) != len(set(names)):
            raise ValidationError(f"{self.tool}: duplicate step names {names}")
        # A step may only reference steps that ran before it. Forward references
        # would deadlock at undo time, which is the worst moment to discover it.
        seen: set[str] = set()
        for s in self.steps:
            for _n, expr in s.arg_map:
                if _source_head(expr) == "step":
                    ref = expr.split(".")[1]
                    if ref not in seen:
                        raise ValidationError(
                            f"{self.tool}: step {s.name!r} references step {ref!r}, "
                            "which does not run before it"
                        )
            seen.add(s.name)

        gate_names = [g.name for g in self.gates]
        if len(gate_names) != len(set(gate_names)):
            raise ValidationError(f"{self.tool}: duplicate gate names {gate_names}")
        if not isinstance(self.degraded_kind, Reversibility):
            raise ValidationError(f"{self.tool}: degraded_kind must be a Reversibility")
        # A spec that claims no undo path has nothing to degrade *from*, so the
        # field is pinned to the declared kind rather than left at its default.
        # This matters for UNKNOWN, which ranks below IRREVERSIBLE on purpose: an
        # unclassified tool is worse than a known one-way door, so the default
        # would otherwise read as an upgrade.
        if not self.kind.is_undoable:
            object.__setattr__(self, "degraded_kind", self.kind)
        if self.degraded_kind.rank > self.kind.rank:
            raise ValidationError(
                f"{self.tool}: degraded_kind ({self.degraded_kind.value}) cannot be "
                f"more recoverable than kind ({self.kind.value}) — degradation only "
                "ever loses recoverability"
            )
        if self.authorize_gates and not self.kind.is_undoable:
            raise ValidationError(
                f"{self.tool}: authorize-phase gates only make sense on a spec that "
                "claims to be undoable; there is nothing to degrade from"
            )

    @property
    def authorize_gates(self) -> tuple[ReversalGate, ...]:
        """Gates whose answer changes whether this action is undoable at all."""
        return tuple(g for g in self.gates if g.checked_at_authorize)

    @property
    def undo_gates(self) -> tuple[ReversalGate, ...]:
        """Gates checked immediately before the undo runs."""
        return tuple(g for g in self.gates if g.checked_at_undo)

    @property
    def effective_steps(self) -> tuple[InverseStep, ...]:
        """The undo sequence, normalizing the single-step shorthand."""
        if self.steps:
            return self.steps
        if not self.inverse_tool:
            return ()
        return (
            InverseStep(
                name="undo",
                tool=self.inverse_tool,
                arg_map=self.arg_map,
                static_args=self.static_args,
            ),
        )

    @property
    def needs_result(self) -> tuple[str, ...]:
        """Args across all steps that cannot resolve until the forward call returns."""
        out: list[str] = []
        for s in self.effective_steps:
            out.extend(s.needs_result)
        return tuple(dict.fromkeys(out))

    def to_dict(self) -> dict[str, Any]:
        return {
            "tool": self.tool,
            "kind": self.kind.value,
            "inverse_tool": self.inverse_tool,
            "arg_map": dict(self.arg_map),
            "static_args": dict(self.static_args),
            "steps": [s.to_dict() for s in self.steps],
            "gates": [g.to_dict() for g in self.gates],
            "snapshot_fields": list(self.snapshot_fields),
            "window_seconds": self.window_seconds,
            "one_shot": self.one_shot,
            "degraded_kind": self.degraded_kind.value,
            "residue": self.residue,
            "notes": self.notes,
        }

    @classmethod
    def from_dict(cls, d: dict[str, Any]) -> InverseSpec:
        try:
            return cls(
                tool=d["tool"],
                kind=Reversibility(d["kind"]),
                inverse_tool=d.get("inverse_tool"),
                arg_map=tuple(sorted((d.get("arg_map") or {}).items())),
                static_args=tuple(sorted((d.get("static_args") or {}).items())),
                steps=tuple(InverseStep.from_dict(s) for s in (d.get("steps") or ())),
                gates=tuple(ReversalGate.from_dict(g) for g in (d.get("gates") or ())),
                snapshot_fields=tuple(d.get("snapshot_fields") or ()),
                window_seconds=(
                    float(d["window_seconds"]) if d.get("window_seconds") is not None else None
                ),
                one_shot=bool(d.get("one_shot", False)),
                degraded_kind=Reversibility(
                    d.get("degraded_kind", Reversibility.IRREVERSIBLE.value)
                ),
                residue=d.get("residue", ""),
                notes=d.get("notes", ""),
            )
        except (KeyError, TypeError, ValueError) as exc:
            raise ValidationError(f"malformed InverseSpec: {exc}") from None

    def resolve_args(
        self,
        *,
        forward_args: dict[str, Any],
        snapshot: dict[str, Any],
        result: Any = None,
        include_result: bool = False,
    ) -> tuple[dict[str, Any], tuple[str, ...], tuple[str, ...]]:
        """Resolve the FIRST step's arguments.

        Retained for the single-step case and for callers that only need the head
        of the sequence. Multi-step planning goes through
        :meth:`plan_steps`.
        """
        steps = self.effective_steps
        if not steps:
            return {}, (), ()
        resolved, unresolved, deferred, _from_step = steps[0].resolve(
            forward_args=forward_args,
            snapshot=snapshot,
            result=result,
            include_result=include_result,
        )
        return resolved, unresolved, deferred


# ---------------------------------------------------------------------------
# Plans, journal entries, receipts
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class PlannedStep:
    """One resolved step of an undo plan."""

    name: str
    tool: str
    args: dict[str, Any]
    unresolved: tuple[str, ...] = ()
    deferred: tuple[str, ...] = ()
    from_prior_step: tuple[str, ...] = ()
    description: str = ""
    critical: bool = True

    def to_dict(self) -> dict[str, Any]:
        return {
            "name": self.name,
            "tool": self.tool,
            "args": self.args,
            "unresolved": list(self.unresolved),
            "deferred": list(self.deferred),
            "from_prior_step": list(self.from_prior_step),
            "description": self.description,
            "critical": self.critical,
        }


@dataclass(frozen=True)
class StepResult:
    """What happened when one undo step ran."""

    name: str
    tool: str
    args: dict[str, Any]
    ok: bool
    result: Any = None
    error: str | None = None
    skipped: bool = False

    def to_dict(self) -> dict[str, Any]:
        return {
            "name": self.name,
            "tool": self.tool,
            "args": self.args,
            "ok": self.ok,
            "result": self.result,
            "error": self.error,
            "skipped": self.skipped,
        }


@dataclass(frozen=True)
class ReversalPlan:
    """A computed undo path for one pending action.

    Built *before* the forward action executes. That ordering is the whole
    design: a plan built afterwards can only read state the action already
    changed, so it cannot know what to restore.
    """

    id: str
    tool: str
    kind: Reversibility
    inverse_tool: str | None
    inverse_args: dict[str, Any]
    unresolved_args: tuple[str, ...]
    snapshot: dict[str, Any]
    window_seconds: float | None
    residue: str
    created_at: float
    snapshot_error: str | None = None
    deferred_args: tuple[str, ...] = ()
    steps: tuple[PlannedStep, ...] = ()
    gates: tuple[ReversalGate, ...] = ()
    one_shot: bool = False

    @property
    def is_executable(self) -> bool:
        """Whether this plan could actually be run once outstanding args bind."""
        return self.kind.is_undoable and bool(self.steps)

    @property
    def is_complete(self) -> bool:
        """Whether the plan can be executed *right now* with nothing outstanding.

        Step-derived arguments do not count against completeness: they resolve
        while the sequence runs, from the results of steps that precede them.
        """
        return self.is_executable and not self.unresolved_args and not self.deferred_args

    @property
    def is_broken(self) -> bool:
        """An undo path that claims to exist but has a real hole in it.

        Deferred (result-bound) and step-derived arguments are excluded: those are
        expected to be outstanding until the relevant call returns.
        """
        return self.kind.is_undoable and bool(self.unresolved_args or self.snapshot_error)

    @property
    def step_count(self) -> int:
        return len(self.steps)

    def expires_at(self, *, committed_at: float | None = None) -> float | None:
        if self.window_seconds is None:
            return None
        return (committed_at if committed_at is not None else self.created_at) + self.window_seconds

    def digest(self) -> str:
        """Stable digest of the plan, for binding into signed records."""
        return crypto.digest_of(self.to_dict())

    def to_dict(self) -> dict[str, Any]:
        return {
            "id": self.id,
            "tool": self.tool,
            "kind": self.kind.value,
            "inverse_tool": self.inverse_tool,
            "inverse_args": self.inverse_args,
            "unresolved_args": list(self.unresolved_args),
            "deferred_args": list(self.deferred_args),
            "snapshot": self.snapshot,
            "window_seconds": self.window_seconds,
            "residue": self.residue,
            "created_at": self.created_at,
            "snapshot_error": self.snapshot_error,
            "steps": [s.to_dict() for s in self.steps],
            "gates": [g.to_dict() for g in self.gates],
            "one_shot": self.one_shot,
        }


@dataclass
class JournalEntry:
    """Mutable lifecycle record for one planned/committed reversal.

    The journal is the working index; every transition is *also* appended to the
    hash-chained ledger, which is the evidence of record. Keeping both means
    lookups stay cheap without weakening the tamper-evidence guarantee.
    """

    id: str
    plan: ReversalPlan
    state: JournalState
    action_id: str | None = None
    delegation_id: str | None = None
    session_id: str = ""
    actor_id: str | None = None
    committed_at: float | None = None
    resolved_at: float | None = None
    reversal_result: Any = None
    error: str | None = None
    note: str = ""
    history: list[dict[str, Any]] = field(default_factory=list)

    def transition(
        self, new_state: JournalState, *, note: str = "", now: float | None = None
    ) -> None:
        when = now if now is not None else time.time()
        self.history.append(
            {"from": self.state.value, "to": new_state.value, "at": when, "note": note}
        )
        self.state = new_state
        if new_state is JournalState.COMMITTED:
            self.committed_at = when
        elif new_state.is_terminal:
            self.resolved_at = when
        if note:
            self.note = note

    @property
    def expires_at(self) -> float | None:
        return self.plan.expires_at(committed_at=self.committed_at)

    def is_expired(self, *, now: float | None = None) -> bool:
        exp = self.expires_at
        if exp is None:
            return False
        return (now if now is not None else time.time()) >= exp

    def to_dict(self) -> dict[str, Any]:
        return {
            "id": self.id,
            "state": self.state.value,
            "action_id": self.action_id,
            "delegation_id": self.delegation_id,
            "session_id": self.session_id,
            "actor_id": self.actor_id,
            "committed_at": self.committed_at,
            "resolved_at": self.resolved_at,
            "expires_at": self.expires_at,
            "error": self.error,
            "note": self.note,
            "plan": self.plan.to_dict(),
            "history": list(self.history),
        }


@dataclass(frozen=True)
class ReversalReceipt:
    """The outcome of attempting one undo."""

    id: str
    journal_id: str
    action_id: str | None
    tool: str
    inverse_tool: str | None
    kind: Reversibility
    ok: bool
    state: JournalState
    residue: str
    error: str | None
    executed_args: dict[str, Any]
    result: Any
    at: float
    steps: tuple[StepResult, ...] = ()
    one_shot: bool = False

    def to_dict(self) -> dict[str, Any]:
        return {
            "id": self.id,
            "journal_id": self.journal_id,
            "action_id": self.action_id,
            "tool": self.tool,
            "inverse_tool": self.inverse_tool,
            "kind": self.kind.value,
            "ok": self.ok,
            "state": self.state.value,
            "residue": self.residue,
            "error": self.error,
            "executed_args": self.executed_args,
            "result": self.result,
            "at": self.at,
            "one_shot": self.one_shot,
            "steps": [s.to_dict() for s in self.steps],
        }


@dataclass(frozen=True)
class CascadeReport:
    """The outcome of undoing a set of actions as one unit."""

    scope_kind: str          # "session" | "delegation" | "explicit"
    scope_id: str
    attempted: int
    reversed_ok: int
    failed: int
    skipped: int
    receipts: tuple[ReversalReceipt, ...]
    residues: tuple[str, ...]
    stopped_early: bool = False
    blocked_by_gates: tuple[str, ...] = ()

    @property
    def ok(self) -> bool:
        return self.failed == 0 and not self.stopped_early

    def to_dict(self) -> dict[str, Any]:
        return {
            "scope_kind": self.scope_kind,
            "scope_id": self.scope_id,
            "attempted": self.attempted,
            "reversed_ok": self.reversed_ok,
            "failed": self.failed,
            "skipped": self.skipped,
            "stopped_early": self.stopped_early,
            "ok": self.ok,
            "residues": list(self.residues),
            "blocked_by_gates": list(self.blocked_by_gates),
            "receipts": [r.to_dict() for r in self.receipts],
        }


# ---------------------------------------------------------------------------
# Integration protocols
# ---------------------------------------------------------------------------


class StateReader(Protocol):
    """Reads prior state before an action runs.

    Implement this against whatever holds the record — an ERP client, a database
    cursor, an HTTP API. Returning a partial dict is fine and better than
    raising; a missing field degrades the plan to a named gap rather than
    blocking the action silently.
    """

    def __call__(
        self, tool: str, args: dict[str, Any], fields: tuple[str, ...]
    ) -> dict[str, Any]: ...


class InverseExecutor(Protocol):
    """Executes an inverse call. Raise to signal failure."""

    def __call__(self, tool: str, args: dict[str, Any]) -> Any: ...


class GateEvaluator(Protocol):
    """Answers whether a named reversal precondition currently holds.

    Return True to open the gate, False to close it, or a string to close it with
    an explanation. Raising is treated as closed: if the control plane cannot
    confirm the precondition, refusing is the correct direction to fail.

    One evaluator serves both phases. Read ``ctx.phase`` to tell which question is
    being asked — at ``authorize`` the forward action has not happened yet and
    ``ctx.entry`` is None, so answer from ``ctx.args`` and the live system; at
    ``undo`` you also have the journal entry with its captured snapshot.
    """

    def __call__(self, ctx: GateContext) -> bool | str: ...


def new_plan_id() -> str:
    return ids.new_id(ids.PLAN)


def new_journal_id() -> str:
    return ids.new_id(ids.JOURNAL)


def new_reversal_id() -> str:
    return ids.new_id(ids.REVERSAL)
