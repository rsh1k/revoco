"""Validation runs: what changed since the last time the controls were tested.

A drill proves one inverse works right now. That is the unit; it is not the
product. What an operator needs, and what an auditor asks for, is the sentence a
single drill cannot say:

    `sap.supplier.bank.update` was proven working on 12 August and stopped
    working on 3 September.

Getting there needs two runs and a comparison, which is what this module is.

Why a run is a first-class thing
--------------------------------
Backup teams learned that a restore drill is only evidence if someone recorded
it. The same is true here, and one step further: a *single* run says whether the
estate is healthy today, and only a sequence says whether it is getting worse.
Regression is the finding with an owner and a date. "Currently failing" is a
status; "was working last month" is an incident.

The absence that reads as green
-------------------------------
The subtle failure is not a control that fails. It is a control that quietly
stops being tested. Drop a drill from the suite and every number improves: the
proven count holds, the failure count falls, and the report looks better than
the week before. So a control present in the previous run and missing from this
one is reported as :attr:`Change.DISAPPEARED` rather than omitted, for the same
reason a drill whose forward action changed nothing is an alarm rather than a
pass. Coverage shrinking must never look like coverage improving.

What this module does not do
----------------------------
It does not schedule anything and it does not hold credentials. It takes drill
results someone else obtained and turns them into a comparable, signable record.
Scheduling belongs to a cron and credentials belong to the integrator, and
neither is improved by being buried in here.
"""

from __future__ import annotations

import dataclasses
import enum
import time
from dataclasses import dataclass
from typing import Any

from .core import crypto, ids
from .core.errors import ValidationError
from .drills import DrillOutcome, DrillResult


class Change(enum.Enum):
    """How one control's standing moved between two runs."""

    REGRESSED = "regressed"        # proven before, not now — the headline
    RECOVERED = "recovered"        # failing before, proven now
    STILL_FAILING = "still_failing"  # failing in both: a known issue, not news
    STILL_PROVEN = "still_proven"
    NEWLY_COVERED = "newly_covered"  # not in the previous run at all
    DISAPPEARED = "disappeared"      # in the previous run, absent from this one
    NOT_DRILLABLE = "not_drillable"  # nothing to prove, by design

    @property
    def is_alarm(self) -> bool:
        """Whether a person should look.

        ``DISAPPEARED`` is an alarm even though nothing failed. A control that
        left the suite is untested, and untested is the state this whole package
        exists to stop being mistaken for safe.
        """
        return self in (Change.REGRESSED, Change.STILL_FAILING, Change.DISAPPEARED)

    @property
    def is_new_bad_news(self) -> bool:
        """Alarms that were not already true last time, i.e. what changed."""
        return self in (Change.REGRESSED, Change.DISAPPEARED)


@dataclass(frozen=True)
class ValidationRun:
    """One pass of a drill suite over a target, as a comparable record."""

    id: str
    target: str
    started_at: float
    finished_at: float
    results: tuple[DrillResult, ...]

    def __post_init__(self) -> None:
        # Coerce the timestamps. `started_at=1` and `started_at=1.0` are the same
        # instant and canonicalise differently, so a run built with ints digests
        # differently after a round trip through JSON — and a signed report whose
        # digest changes when it is stored cannot be verified by the auditor it
        # was produced for. The digest must be a function of the value, not of
        # how the caller happened to type it.
        object.__setattr__(self, "started_at", float(self.started_at))
        object.__setattr__(self, "finished_at", float(self.finished_at))
        if not self.target:
            raise ValidationError(
                "a run needs a target: two runs against different tenants are not "
                "comparable, and silently comparing them would invent regressions"
            )
        tools = [r.tool for r in self.results]
        if len(tools) != len(set(tools)):
            raise ValidationError(f"{self.target}: a tool appears twice in one run")

    # -- standing -----------------------------------------------------------
    @property
    def by_tool(self) -> dict[str, DrillResult]:
        return {r.tool: r for r in self.results}

    @property
    def proven(self) -> tuple[str, ...]:
        return tuple(sorted(r.tool for r in self.results if r.outcome.is_proof))

    @property
    def failing(self) -> tuple[str, ...]:
        return tuple(sorted(r.tool for r in self.results if r.outcome.is_alarm))

    @property
    def not_drillable(self) -> tuple[str, ...]:
        return tuple(sorted(
            r.tool for r in self.results if r.outcome is DrillOutcome.NOT_DRILLABLE
        ))

    @property
    def coverage(self) -> int:
        """Controls this run actually put a question to."""
        return len(self.results) - len(self.not_drillable)

    def payload(self) -> dict[str, Any]:
        return {
            "id": self.id,
            "target": self.target,
            "started_at": self.started_at,
            "finished_at": self.finished_at,
            "results": [r.to_dict() for r in sorted(self.results, key=lambda r: r.tool)],
        }

    @classmethod
    def from_dict(cls, d: dict[str, Any]) -> ValidationRun:
        try:
            return cls(
                id=d["id"], target=d["target"],
                started_at=float(d["started_at"]), finished_at=float(d["finished_at"]),
                results=tuple(DrillResult.from_dict(r) for r in d.get("results") or ()),
            )
        except (KeyError, TypeError, ValueError) as exc:
            raise ValidationError(f"malformed ValidationRun: {exc}") from None

    @property
    def digest(self) -> str:
        return crypto.digest_of(self.payload())


@dataclass(frozen=True)
class ControlChange:
    """One control, and what moved."""

    tool: str
    change: Change
    now: str | None            # outcome value in this run, None if absent
    before: str | None         # outcome value in the previous run
    detail: str = ""

    def to_dict(self) -> dict[str, Any]:
        return {"tool": self.tool, "change": self.change.value,
                "now": self.now, "before": self.before, "detail": self.detail}


def compare(current: ValidationRun,
            previous: ValidationRun | None = None) -> list[ControlChange]:
    """What moved between two runs, one entry per control seen in either.

    With no previous run every drillable control is ``NEWLY_COVERED``: a first
    run establishes a baseline and cannot, by construction, show a regression.
    Reporting one would be claiming knowledge of a past that was never measured.
    """
    if previous is not None and previous.target != current.target:
        raise ValidationError(
            f"cannot compare a run against {current.target!r} with one against "
            f"{previous.target!r}; the difference would be the targets, not the controls"
        )

    now_by, before_by = current.by_tool, (previous.by_tool if previous else {})
    out: list[ControlChange] = []

    for tool in sorted(set(now_by) | set(before_by)):
        cur, prev = now_by.get(tool), before_by.get(tool)

        if cur is None:
            out.append(ControlChange(
                tool, Change.DISAPPEARED, None, prev.outcome.value if prev else None,
                "present in the previous run and absent from this one; it is now "
                "untested, which is not the same as passing",
            ))
            continue

        if cur.outcome is DrillOutcome.NOT_DRILLABLE:
            out.append(ControlChange(tool, Change.NOT_DRILLABLE, cur.outcome.value,
                                     prev.outcome.value if prev else None))
            continue

        if prev is None or prev.outcome is DrillOutcome.NOT_DRILLABLE:
            out.append(ControlChange(tool, Change.NEWLY_COVERED, cur.outcome.value,
                                     prev.outcome.value if prev else None))
            continue

        was, is_ = prev.outcome.is_proof, cur.outcome.is_proof
        if was and not is_:
            out.append(ControlChange(
                tool, Change.REGRESSED, cur.outcome.value, prev.outcome.value,
                cur.summary,
            ))
        elif is_ and not was:
            out.append(ControlChange(tool, Change.RECOVERED, cur.outcome.value,
                                     prev.outcome.value))
        elif is_:
            out.append(ControlChange(tool, Change.STILL_PROVEN, cur.outcome.value,
                                     prev.outcome.value))
        else:
            out.append(ControlChange(
                tool, Change.STILL_FAILING, cur.outcome.value, prev.outcome.value,
                cur.summary,
            ))
    return out


@dataclass(frozen=True)
class ValidationReport:
    """A run, what changed, and a signature over both.

    Signed because the point of the artifact is that someone who distrusts the
    operator can check it. The signature covers the run's digest rather than the
    rendered text, so reformatting the report does not invalidate it and editing
    a single drill result does.
    """

    id: str
    run: ValidationRun
    previous_id: str | None
    previous_digest: str | None
    changes: tuple[ControlChange, ...]
    signer_id: str
    signed_at: float
    signature: str = ""

    def _payload(self) -> dict[str, Any]:
        return {
            "id": self.id,
            "run_digest": self.run.digest,
            "run_id": self.run.id,
            "target": self.run.target,
            "previous_id": self.previous_id,
            "previous_digest": self.previous_digest,
            "changes": [c.to_dict() for c in self.changes],
            "signer_id": self.signer_id,
            "signed_at": self.signed_at,
        }

    def signing_bytes(self) -> bytes:
        return crypto.canonical_bytes(self._payload())

    def verify_signature(self, public_key: crypto.Ed25519PublicKey) -> bool:
        return crypto.verify(public_key, self.signing_bytes(), self.signature)

    def to_dict(self) -> dict[str, Any]:
        d = self._payload()
        d["signature"] = self.signature
        d["run"] = self.run.payload()
        return d

    # -- what a person reads first -----------------------------------------
    @property
    def regressions(self) -> tuple[ControlChange, ...]:
        return tuple(c for c in self.changes if c.change is Change.REGRESSED)

    @property
    def disappeared(self) -> tuple[ControlChange, ...]:
        return tuple(c for c in self.changes if c.change is Change.DISAPPEARED)

    @property
    def new_bad_news(self) -> tuple[ControlChange, ...]:
        return tuple(c for c in self.changes if c.change.is_new_bad_news)

    @property
    def clean(self) -> bool:
        """No control got worse and none stopped being tested.

        Deliberately not "nothing is failing". A suite with a known failure that
        has not moved is not a new incident, and treating it as one is how a
        report becomes noise nobody reads.
        """
        return not self.new_bad_news

    @property
    def headline(self) -> str:
        run = self.run
        if self.previous_id is None:
            return (f"{run.target}: baseline over {run.coverage} control(s) — "
                    f"{len(run.proven)} proven, {len(run.failing)} failing. "
                    "No comparison: nothing was measured before this.")
        bits = []
        if self.regressions:
            bits.append(f"{len(self.regressions)} REGRESSED")
        if self.disappeared:
            bits.append(f"{len(self.disappeared)} stopped being tested")
        if not bits:
            return (f"{run.target}: no control got worse. "
                    f"{len(run.proven)}/{run.coverage} proven.")
        return f"{run.target}: {', '.join(bits)}. {len(run.proven)}/{run.coverage} proven."


def report(
    current: ValidationRun,
    *,
    signer_private_key: crypto.Ed25519PrivateKey,
    signer_id: str,
    previous: ValidationRun | None = None,
    now: float | None = None,
) -> ValidationReport:
    """Compare, then sign. The signature is over the comparison, not the prose."""
    rep = ValidationReport(
        id=ids.new_id("vr"),
        run=current,
        previous_id=previous.id if previous else None,
        previous_digest=previous.digest if previous else None,
        changes=tuple(compare(current, previous)),
        signer_id=signer_id,
        signed_at=now if now is not None else time.time(),
    )
    return dataclasses.replace(
        rep, signature=crypto.sign(signer_private_key, rep.signing_bytes())
    )


def render(rep: ValidationReport) -> str:
    """Human-readable, ordered by what needs attention rather than by name."""
    lines = [f"CONTROL VALIDATION — {rep.run.target}", "=" * 66, rep.headline, ""]
    order = [Change.REGRESSED, Change.DISAPPEARED, Change.STILL_FAILING,
             Change.RECOVERED, Change.NEWLY_COVERED, Change.STILL_PROVEN,
             Change.NOT_DRILLABLE]
    marks = {Change.REGRESSED: "!!", Change.DISAPPEARED: "??", Change.STILL_FAILING: " x",
             Change.RECOVERED: " +", Change.NEWLY_COVERED: " *",
             Change.STILL_PROVEN: "ok", Change.NOT_DRILLABLE: " -"}
    for kind in order:
        rows = [c for c in rep.changes if c.change is kind]
        if not rows:
            continue
        lines.append(f"{kind.value.replace('_', ' ').upper()} ({len(rows)})")
        for c in rows:
            lines.append(f"  [{marks[kind]}] {c.tool:38s} {c.before or '—'} -> {c.now or 'absent'}")
            if c.detail:
                lines.append(f"        {c.detail[:76]}")
        lines.append("")
    lines.append(f"report {rep.id} signed by {rep.signer_id}")
    lines.append(f"run digest {rep.run.digest[:16]} — verify offline against the signature")
    return "\n".join(lines)


__all__ = ["Change", "ControlChange", "ValidationRun", "ValidationReport",
           "compare", "report", "render"]
