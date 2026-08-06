"""
revoco.drills
==============
Recovery drills: prove each inverse still works, against the real system, on a
schedule — and treat a reversibility claim as **expired** until it has been proven.

The idea, borrowed from a discipline that already learned this the hard way
--------------------------------------------------------------------------
Backup teams settled this argument decades ago. A backup that has never been
restored is not a backup; it is a hypothesis, and a restore drill is the
experiment. Nobody serious ships a backup programme without periodic restore
verification, because the failure mode is silent: everything looks healthy right
up to the moment you need it.

Agent rollback has exactly that failure mode and none of that discipline. The
agent-rollback literature that exists is about redeploying agent *versions* —
canary rollouts, model rollback, burn-rate SLOs. That is a different thing
entirely from proving that the inverse of ``sap.supplier.bank.update`` still
restores a supplier's bank account after last week's ERP upgrade.

This module is that missing discipline.

Why it matters more here than anywhere else
------------------------------------------
This package ships ninety-odd inverse specs written from vendor documentation, and
its own docs concede the sharpest limitation: *"re-validate after every ERP
upgrade — a changed API contract turns a correct spec into a confident, wrong
rollback and nothing in this package can detect that for you."*

A drill can detect it. That sentence is the reason this file exists.

The claim that makes this different from a health check
------------------------------------------------------
A drill does not ping an endpoint or validate a schema. It performs the real
forward action against a disposable canary resource, runs the real inverse, and
then **compares state** — the same discipline the containment benchmark uses, for
the same reason. An inverse that returns 200 and restores nothing passes every
check except this one.

Proof-gated classification
--------------------------
:class:`RecoverabilityRegister` can be wired into a control plane so that a spec
claiming ``REVERSIBLE`` whose drill has been failing, or has not run inside its
freshness window, **stops being treated as reversible**. Reversibility becomes a
perishable, verified property rather than a permanent declaration.

That inversion is the point. Every other system in this space treats
recoverability as a static fact asserted at design time. Here it decays, and the
only thing that renews it is evidence.
"""

from __future__ import annotations

import dataclasses
import enum
import threading
import time
from collections.abc import Callable, Iterable
from dataclasses import dataclass, field
from typing import Any

from .core import crypto, ids
from .core.errors import ValidationError
from .reversal.engine import ReversalEngine
from .reversal.model import (
    InverseExecutor,
    Reversibility,
    StateReader,
)
from .reversal.registry import InverseRegistry

DEFAULT_STALE_AFTER = 24 * 3600.0  # a day; tighten for surfaces that change often


class DrillOutcome(enum.Enum):
    PASSED = "passed"                  # inverse ran and state verifiably returned
    FAILED = "failed"                  # inverse ran and state did NOT return
    ERRORED = "errored"                # the inverse call itself raised
    FORWARD_FAILED = "forward_failed"  # could not even set up the drill
    NOT_DRILLABLE = "not_drillable"    # irreversible by design: nothing to prove

    @property
    def is_proof(self) -> bool:
        """Whether this outcome constitutes evidence the undo works."""
        return self is DrillOutcome.PASSED

    @property
    def is_alarm(self) -> bool:
        """Whether this outcome should page someone.

        ``NOT_DRILLABLE`` is not an alarm — an irreversible tool has no inverse to
        prove and saying so is correct, not a fault.
        """
        return self in (DrillOutcome.FAILED, DrillOutcome.ERRORED, DrillOutcome.FORWARD_FAILED)


@dataclass(frozen=True)
class Canary:
    """A disposable target a drill may safely mutate and restore.

    The canary is the safety boundary and it is the integrator's responsibility.
    Point one of these at production data and the drill becomes the incident.

    ``verify`` returns the state a drill compares before and after. It must read
    from the system of record rather than from any cache the control plane
    populated, otherwise the drill would be checking its own homework — the exact
    circularity that lets phantom rollbacks survive.
    """

    tool: str
    args: dict[str, Any]
    verify: Callable[[], dict[str, Any]]
    label: str = ""
    # Fields that must match before and after. Empty means compare everything
    # `verify` returns.
    compare_fields: tuple[str, ...] = ()

    def __post_init__(self) -> None:
        if not self.tool:
            raise ValidationError("Canary.tool is required")
        if not callable(self.verify):
            raise ValidationError(f"Canary for {self.tool} needs a callable verify()")

    @property
    def name(self) -> str:
        return self.label or self.tool


@dataclass(frozen=True)
class DrillResult:
    """One drill, and what it proves."""

    id: str
    tool: str
    outcome: DrillOutcome
    declared_kind: Reversibility
    at: float
    duration_ms: float
    canary: str = ""
    error: str | None = None
    mismatches: tuple[str, ...] = ()
    residue: str = ""

    @property
    def proves_recoverable(self) -> bool:
        return self.outcome.is_proof

    def to_dict(self) -> dict[str, Any]:
        return {
            "id": self.id,
            "tool": self.tool,
            "outcome": self.outcome.value,
            "declared_kind": self.declared_kind.value,
            "at": self.at,
            "duration_ms": round(self.duration_ms, 2),
            "canary": self.canary,
            "error": self.error,
            "mismatches": list(self.mismatches),
            "residue": self.residue,
        }

    @property
    def summary(self) -> str:
        if self.outcome is DrillOutcome.PASSED:
            return f"{self.tool}: inverse proven, state returned ({self.duration_ms:.0f}ms)"
        if self.outcome is DrillOutcome.FAILED:
            return (
                f"{self.tool}: inverse RAN BUT DID NOT RESTORE — "
                f"{len(self.mismatches)} field(s) still wrong: {', '.join(self.mismatches[:3])}"
            )
        if self.outcome is DrillOutcome.NOT_DRILLABLE:
            return f"{self.tool}: irreversible by design; nothing to prove"
        return f"{self.tool}: {self.outcome.value} — {self.error}"


class DrillRunner:
    """Exercises inverses against canary resources.

    Uses a real :class:`ReversalEngine` so the drill goes through the same planning,
    gating, argument resolution and step sequencing a production undo would. A drill
    that took a shortcut would prove the shortcut works.
    """

    def __init__(
        self,
        registry: InverseRegistry,
        *,
        executor: InverseExecutor,
        state_reader: StateReader | None = None,
        gate_evaluator: Any | None = None,
    ) -> None:
        self.registry = registry
        self.executor = executor
        self.state_reader = state_reader
        self.gate_evaluator = gate_evaluator

    def drill(self, canary: Canary, *, now: float | None = None) -> DrillResult:
        started = now if now is not None else time.time()
        clock = time.perf_counter()
        spec = self.registry.get(canary.tool)
        declared = spec.kind if spec else Reversibility.UNKNOWN

        def done(outcome: DrillOutcome, **kw: Any) -> DrillResult:
            return DrillResult(
                id=ids.new_id("drl"),
                tool=canary.tool,
                outcome=outcome,
                declared_kind=declared,
                at=started,
                duration_ms=(time.perf_counter() - clock) * 1000.0,
                canary=canary.name,
                residue=spec.residue if spec else "",
                **kw,
            )

        if spec is None or not spec.kind.is_undoable:
            return done(DrillOutcome.NOT_DRILLABLE)

        # A fresh engine per drill: journal state from one drill must not leak into
        # the next, and it must never touch the production journal.
        engine = ReversalEngine(
            self.registry,
            state_reader=self.state_reader,
            gate_evaluator=self.gate_evaluator,
        )

        try:
            before = dict(canary.verify() or {})
        except Exception as exc:
            return done(DrillOutcome.FORWARD_FAILED,
                        error=f"verify() failed before the drill: {exc!r}")

        plan = engine.plan(canary.tool, canary.args, now=started)
        entry = engine.open_journal(plan, session_id=f"drill-{canary.name}")

        try:
            result = self.executor(canary.tool, dict(canary.args))
        except Exception as exc:
            engine.abandon(entry.id, "forward action failed during drill")
            return done(DrillOutcome.FORWARD_FAILED,
                        error=f"forward action failed: {type(exc).__name__}: {exc}")

        engine.commit(entry.id, action_id=f"drill-{entry.id}", result=result, now=started)

        try:
            receipt = engine.reverse(entry.id, self.executor, now=started)
        except Exception as exc:
            return done(DrillOutcome.ERRORED,
                        error=f"{type(exc).__name__}: {exc}")

        if not receipt.ok:
            return done(DrillOutcome.ERRORED, error=receipt.error or "inverse reported failure")

        # The part that makes this a drill and not a health check.
        try:
            after = dict(canary.verify() or {})
        except Exception as exc:
            return done(DrillOutcome.ERRORED,
                        error=f"verify() failed after the drill: {exc!r}")

        fields = canary.compare_fields or tuple(sorted(set(before) | set(after)))
        mismatches = tuple(f for f in fields if before.get(f) != after.get(f))
        if mismatches:
            return done(DrillOutcome.FAILED, mismatches=mismatches)
        return done(DrillOutcome.PASSED)

    def drill_all(
        self, canaries: Iterable[Canary], *, now: float | None = None
    ) -> list[DrillResult]:
        return [self.drill(c, now=now) for c in canaries]

    def drill_due(
        self,
        register: RecoverabilityRegister,
        canaries: Iterable[Canary],
        *,
        now: float | None = None,
        refresh_at: float = 0.8,
        max_batch: int | None = None,
    ) -> list[DrillResult]:
        """Drill only what needs it, record the results, return them.

        The scheduler entry point: point a cron at this with a canary per tool and
        proof stays fresh without anyone remembering to check. Results are recorded
        into the register as they run, so a batch that is cut short by ``max_batch``
        still improves the picture rather than being wasted.
        """
        by_tool: dict[str, Canary] = {}
        for c in canaries:
            by_tool.setdefault(c.tool, c)
        due = register.due(
            by_tool.keys(), now=now, refresh_at=refresh_at, max_batch=max_batch
        )
        results: list[DrillResult] = []
        for item in due:
            canary = by_tool.get(item.tool)
            if canary is None:
                continue
            result = self.drill(canary, now=now)
            register.record(result)
            results.append(result)
        return results


@dataclass
class ProvenRecoverability:
    """What is currently known about one tool's undo path."""

    tool: str
    stale_after: float
    last: DrillResult | None = None
    last_pass: DrillResult | None = None
    history: list[DrillResult] = field(default_factory=list)

    def age(self, *, now: float | None = None) -> float | None:
        if self.last_pass is None:
            return None
        return (now if now is not None else time.time()) - self.last_pass.at

    def is_proven(self, *, now: float | None = None) -> bool:
        """Proven means: the most recent drill passed, and it passed recently.

        Both halves are required. A tool whose last drill failed is not proven even
        if an older one passed, and a tool whose last pass is a month old is not
        proven either — the API may have changed the day after.
        """
        if self.last is None or not self.last.outcome.is_proof:
            return False
        a = self.age(now=now)
        return a is not None and a <= self.stale_after

    def status(self, *, now: float | None = None) -> str:
        if self.last is None:
            return "never drilled"
        if self.last.outcome is DrillOutcome.NOT_DRILLABLE:
            return "not drillable (irreversible by design)"
        if not self.last.outcome.is_proof:
            return f"last drill {self.last.outcome.value}"
        a = self.age(now=now) or 0.0
        if a > self.stale_after:
            return f"stale (last proven {a / 3600:.1f}h ago, window {self.stale_after / 3600:.0f}h)"
        return f"proven {a / 3600:.1f}h ago"

    def to_dict(self, *, now: float | None = None) -> dict[str, Any]:
        return {
            "tool": self.tool,
            "is_proven": self.is_proven(now=now),
            "status": self.status(now=now),
            "age_seconds": self.age(now=now),
            "stale_after": self.stale_after,
            "drills": len(self.history),
            "last": self.last.to_dict() if self.last else None,
            "last_pass_at": self.last_pass.at if self.last_pass else None,
        }


class RecoverabilityRegister:
    """Freshest drill evidence per tool, and the proof-gated classifier.

    Wire :meth:`classify_hook` into a control plane and a spec's declared
    reversibility only survives while there is fresh evidence behind it. That is the
    inversion this module is for: recoverability stops being a design-time assertion
    and becomes a claim with an expiry date.
    """

    def __init__(
        self, *, stale_after: float = DEFAULT_STALE_AFTER, store: Any | None = None
    ) -> None:
        self.stale_after = stale_after
        self.store = store
        self._by_tool: dict[str, ProvenRecoverability] = {}
        self._lock = threading.Lock()
        if store is not None:
            # Reload drill history, so the freshness window means something across
            # deploys. Downtime deliberately still counts against it — see
            # SqliteStore.startup_report for why not counting it would be worse.
            for data in store.load_drills():
                self._ingest(DrillResult(
                    id=data["id"], tool=data["tool"],
                    outcome=DrillOutcome(data["outcome"]),
                    declared_kind=Reversibility(data["declared_kind"]),
                    at=float(data["at"]), duration_ms=float(data.get("duration_ms") or 0.0),
                    canary=data.get("canary", ""), error=data.get("error"),
                    mismatches=tuple(data.get("mismatches") or ()),
                    residue=data.get("residue", ""),
                ))

    def record(self, result: DrillResult) -> ProvenRecoverability:
        if self.store is not None:
            self.store.record_drill(result.to_dict())
        return self._ingest(result)

    def _ingest(self, result: DrillResult) -> ProvenRecoverability:
        with self._lock:
            entry = self._by_tool.setdefault(
                result.tool, ProvenRecoverability(tool=result.tool, stale_after=self.stale_after)
            )
            entry.history.append(result)
            entry.last = result
            if result.outcome.is_proof:
                entry.last_pass = result
            return entry

    def record_all(self, results: Iterable[DrillResult]) -> None:
        for r in results:
            self.record(r)

    def get(self, tool: str) -> ProvenRecoverability | None:
        return self._by_tool.get(tool)

    def is_proven(self, tool: str, *, now: float | None = None) -> bool:
        entry = self._by_tool.get(tool)
        return bool(entry and entry.is_proven(now=now))

    def classify_hook(
        self, tool: str, declared: Reversibility, *, now: float | None = None
    ) -> Reversibility:
        """Degrade a declared posture that has no fresh proof behind it.

        Only ever downgrades, and only for specs that *claim* to be undoable —
        there is nothing to demote an irreversible tool to. An undrilled tool keeps
        its declared kind, because demoting everything on day one would make the
        feature unadoptable; the register's job is to surface undrilled coverage,
        not to punish it.
        """
        if not declared.is_undoable:
            return declared
        entry = self._by_tool.get(tool)
        if entry is None or entry.last is None:
            return declared
        if entry.is_proven(now=now):
            return declared
        # Evidence exists and it is bad or stale. Trusting the declaration over the
        # evidence is how a phantom rollback stays believed.
        return Reversibility.IRREVERSIBLE

    # ---- scheduling -------------------------------------------------------
    def due(
        self,
        tools: Iterable[str],
        *,
        now: float | None = None,
        refresh_at: float = 0.8,
        max_batch: int | None = None,
    ) -> list[DrillDue]:
        """Which tools need drilling now, most urgent first.

        ``refresh_at`` re-drills before the proof actually lapses — at 0.8, a tool
        whose freshness window is a day gets re-drilled after about 19 hours. Waiting
        for expiry would mean every tool spends part of its life classified
        irreversible by the proof gate purely because the scheduler had not got to it
        yet, which would make the gate feel like a bug rather than a control. Renew
        before expiry, like a certificate.

        ``max_batch`` bounds the run. Drilling ninety tools at once means ninety real
        writes and ninety real undos against production systems of record, so the
        scheduler needs a throttle more than it needs completeness — and the ordering
        guarantees the throttle drops the least urgent work.
        """
        when = now if now is not None else time.time()
        out: list[DrillDue] = []

        for tool in tools:
            entry = self._by_tool.get(tool)
            if entry is None:
                out.append(DrillDue(
                    tool=tool, urgency="never_drilled", priority=_URGENCY["never_drilled"],
                    age_seconds=None,
                    reason="no drill has ever run; the undo path is an untested hypothesis",
                ))
                continue
            if entry.last is not None and entry.last.outcome is DrillOutcome.NOT_DRILLABLE:
                continue   # irreversible by design: nothing to prove, ever
            if entry.last is not None and entry.last.outcome.is_alarm:
                out.append(DrillDue(
                    tool=tool, urgency="failing", priority=_URGENCY["failing"],
                    age_seconds=entry.age(now=when),
                    reason=f"last drill {entry.last.outcome.value}: {entry.last.summary[:80]}",
                ))
                continue

            age = entry.age(now=when)
            if age is None:
                out.append(DrillDue(
                    tool=tool, urgency="never_drilled", priority=_URGENCY["never_drilled"],
                    age_seconds=None, reason="has drill history but no passing drill",
                ))
            elif age > entry.stale_after:
                out.append(DrillDue(
                    tool=tool, urgency="stale", priority=_URGENCY["stale"], age_seconds=age,
                    reason=(
                        f"proof expired {(age - entry.stale_after) / 3600:.1f}h ago; the "
                        "proof gate is already treating this as irreversible"
                    ),
                ))
            elif age >= entry.stale_after * refresh_at:
                out.append(DrillDue(
                    tool=tool, urgency="ageing", priority=_URGENCY["ageing"], age_seconds=age,
                    reason=f"proof is {age / 3600:.1f}h old; refresh before it lapses",
                ))

        out.sort(key=lambda d: (d.priority, -(d.age_seconds or 0.0)))
        return out[:max_batch] if max_batch else out

    # ---- reporting --------------------------------------------------------
    def report(self, *, now: float | None = None) -> dict[str, Any]:
        with self._lock:
            entries = list(self._by_tool.values())
        proven = [e for e in entries if e.is_proven(now=now)]
        alarming = [e for e in entries if e.last and e.last.outcome.is_alarm]
        stale = [
            e for e in entries
            if e.last and e.last.outcome.is_proof and not e.is_proven(now=now)
        ]
        return {
            "stale_after_seconds": self.stale_after,
            "tools_tracked": len(entries),
            "proven": len(proven),
            "stale": len(stale),
            "alarming": len(alarming),
            "proven_fraction": round(len(proven) / len(entries), 4) if entries else 0.0,
            "needs_attention": [e.to_dict(now=now) for e in alarming + stale],
            "tools": {e.tool: e.to_dict(now=now) for e in entries},
        }

    def coverage(self, tools: Iterable[str], *, now: float | None = None) -> dict[str, Any]:
        """Proven-recoverability coverage over a tool surface.

        The number to put in front of an auditor, and the one no competing system
        can produce: not "we have rollback for 39 of 91 operations" but "we have
        rollback proven working within the last day for N of them".
        """
        wanted = list(tools)
        proven = [t for t in wanted if self.is_proven(t, now=now)]
        undrilled = [t for t in wanted if self.get(t) is None]
        failing = [
            t for t in wanted
            if (e := self.get(t)) and e.last and e.last.outcome.is_alarm
        ]
        return {
            "tools": len(wanted),
            "proven": sorted(proven),
            "proven_pct": round(100.0 * len(proven) / len(wanted), 2) if wanted else 0.0,
            "undrilled": sorted(undrilled),
            "failing": sorted(failing),
        }


# ---------------------------------------------------------------------------
# Proof-of-recoverability attestation
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class RecoverabilityAttestation:
    """A signed statement that an action *could be undone* when it was taken.

    Every comparable system signs what happened. This signs that it was reversible,
    and names the evidence: which tool, what posture, when the inverse was last
    proven working, and the digest of the specific undo plan that was in place.

    That is the artifact a model-risk or AI-Act auditor actually wants and currently
    cannot get anywhere — "show me that the rollback you claim existed, existed at
    the time of the decision" — and it is unforgeable after the fact, because the
    plan digest is bound into a hash-chained ledger entry written before the action
    ran.
    """

    id: str
    action_id: str
    tool: str
    reversibility: Reversibility
    plan_digest: str
    plan_complete: bool
    proven: bool
    proof_age_seconds: float | None
    last_proven_at: float | None
    drill_outcome: str | None
    attested_at: float
    attestor_id: str
    residue: str = ""
    signature: str = ""

    def _payload(self) -> dict[str, Any]:
        return {
            "id": self.id,
            "action_id": self.action_id,
            "tool": self.tool,
            "reversibility": self.reversibility.value,
            "plan_digest": self.plan_digest,
            "plan_complete": self.plan_complete,
            "proven": self.proven,
            "proof_age_seconds": self.proof_age_seconds,
            "last_proven_at": self.last_proven_at,
            "drill_outcome": self.drill_outcome,
            "attested_at": self.attested_at,
            "attestor_id": self.attestor_id,
            "residue": self.residue,
        }

    def signing_bytes(self) -> bytes:
        return crypto.canonical_bytes(self._payload())

    def verify_signature(self, public_key: crypto.Ed25519PublicKey) -> bool:
        return crypto.verify(public_key, self.signing_bytes(), self.signature)

    def to_dict(self) -> dict[str, Any]:
        d = self._payload()
        d["signature"] = self.signature
        return d

    @property
    def statement(self) -> str:
        """Plain-language rendering, for an evidence pack a human will read."""
        if not self.reversibility.is_undoable:
            return (
                f"Action {self.action_id} on {self.tool} was {self.reversibility.value}: "
                "no rollback path existed, and this was known before it ran."
            )
        base = (
            f"Action {self.action_id} on {self.tool} was {self.reversibility.value} "
            f"with a {'complete' if self.plan_complete else 'INCOMPLETE'} undo plan "
            f"(digest {self.plan_digest[:12]})."
        )
        if self.proven and self.proof_age_seconds is not None:
            return (
                f"{base} The inverse was independently proven working against a canary "
                f"{self.proof_age_seconds / 3600:.1f}h before this action."
            )
        return f"{base} The inverse had NOT been proven working within its freshness window."


def attest(
    *,
    action_id: str,
    tool: str,
    reversibility: Reversibility,
    plan_digest: str,
    plan_complete: bool,
    register: RecoverabilityRegister | None,
    attestor_private_key: crypto.Ed25519PrivateKey,
    attestor_id: str,
    residue: str = "",
    now: float | None = None,
) -> RecoverabilityAttestation:
    """Mint and sign a proof-of-recoverability attestation."""
    when = now if now is not None else time.time()
    entry = register.get(tool) if register else None
    att = RecoverabilityAttestation(
        id=ids.new_id("att"),
        action_id=action_id,
        tool=tool,
        reversibility=reversibility,
        plan_digest=plan_digest,
        plan_complete=plan_complete,
        proven=bool(entry and entry.is_proven(now=when)),
        proof_age_seconds=entry.age(now=when) if entry else None,
        last_proven_at=entry.last_pass.at if (entry and entry.last_pass) else None,
        drill_outcome=entry.last.outcome.value if (entry and entry.last) else None,
        attested_at=when,
        attestor_id=attestor_id,
        residue=residue,
    )
    sig = crypto.sign(attestor_private_key, att.signing_bytes())
    # dataclasses.replace, not a rebuild from _payload(): that payload serialises
    # `reversibility` to its string value, so reconstructing from it produced an
    # attestation whose enum field held a str and whose signing_bytes() then raised.
    return dataclasses.replace(att, signature=sig)



# ---------------------------------------------------------------------------
# Scheduling
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class DrillDue:
    """One tool that needs drilling, and why."""

    tool: str
    urgency: str          # never_drilled | failing | stale | ageing
    priority: int         # lower runs sooner
    age_seconds: float | None
    reason: str

    def to_dict(self) -> dict[str, Any]:
        return {
            "tool": self.tool,
            "urgency": self.urgency,
            "priority": self.priority,
            "age_seconds": round(self.age_seconds, 2) if self.age_seconds is not None else None,
            "reason": self.reason,
        }


# Lower sorts first. `failing` outranks `never_drilled` because a tool that was
# proven and then broke is a live regression against something the organization is
# actively relying on, whereas an undrilled tool is a known unknown.
_URGENCY = {"failing": 0, "never_drilled": 1, "stale": 2, "ageing": 3}


def render_report(register: RecoverabilityRegister, *, now: float | None = None) -> str:
    """Human-readable drill status."""
    rep = register.report(now=now)
    lines = ["PROVEN RECOVERABILITY", "=" * 60]
    lines.append(
        f"{rep['proven']}/{rep['tools_tracked']} tools have a rollback proven working "
        f"within {rep['stale_after_seconds'] / 3600:.0f}h"
    )
    if rep["alarming"]:
        lines.append(f"!! {rep['alarming']} tool(s) failing their drill")
    if rep["stale"]:
        lines.append(f" * {rep['stale']} tool(s) proven once but now stale")
    lines.append("")
    for tool, info in sorted(rep["tools"].items()):
        mark = "ok " if info["is_proven"] else (
            "-  " if "not drillable" in info["status"] else "!! "
        )
        lines.append(f"  [{mark}] {tool:44s} {info['status']}")
    lines.append("")
    lines.append(
        "A rollback that has never been exercised is a hypothesis. These are the "
        "experiments."
    )
    return "\n".join(lines)


__all__ = [
    "Canary",
    "DrillDue",
    "DrillOutcome",
    "DrillResult",
    "DrillRunner",
    "ProvenRecoverability",
    "RecoverabilityRegister",
    "RecoverabilityAttestation",
    "attest",
    "render_report",
    "DEFAULT_STALE_AFTER",
]
