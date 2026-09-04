"""
revoco.reversal.horizon
=======================
The reversibility horizon: which undo options are still open, and when each one
closes.

The gap this fills
------------------
Every number this package produced before now was retrospective. Containment rate,
detection recall, drill results, evidence packs — all of them describe what already
happened. Incident response in general has the same bias: MTTD and MTTR are
industry standards and both are measured after the fact.

Nothing measures **how long you still can recover**. That is the only number in the
set that lets someone act before the loss is locked in, because undo windows expire
quietly. An SAP document's period closes, a Workday rescind dies the moment payroll
runs, a KMS key's waiting period elapses, an Entra soft-delete hits thirty days. In
every case the organization believes it has a rollback right up to the moment it
reaches for one.

So the headline here is **time to first close**: how long until the soonest undo
option disappears. MTTR asks how fast you recover. This asks how long you still
have the choice.

Standing exposure
-----------------
The horizon also reports committed actions that were *never* undoable — irreversible
work that has landed. That is not a window closing, it is a window that never
existed, and conflating the two would hide the more important number. An
organization with twelve open windows and forty irreversible actions behind it does
not have a recovery capability; it has a recovery capability for the wrong things.
"""

from __future__ import annotations

import time
from dataclasses import dataclass, field
from typing import Any

from ..core.errors import ValidationError
from .model import JournalEntry, JournalState, Reversibility

DEFAULT_WARN_WITHIN = 3600.0  # an hour: enough to page someone and act


@dataclass(frozen=True)
class HorizonEntry:
    """One committed action, and the state of its undo option."""

    journal_id: str
    action_id: str | None
    tool: str
    kind: Reversibility
    session_id: str
    delegation_id: str | None
    committed_at: float | None
    expires_at: float | None
    seconds_remaining: float | None
    one_shot: bool
    residue: str
    gates: tuple[str, ...] = ()
    reason: str = ""

    @property
    def has_deadline(self) -> bool:
        return self.expires_at is not None

    @classmethod
    def from_dict(cls, d: dict[str, Any]) -> HorizonEntry:
        try:
            return cls(
                journal_id=d["journal_id"], action_id=d.get("action_id"),
                tool=d["tool"], kind=Reversibility(d["kind"]),
                session_id=d.get("session_id", ""),
                delegation_id=d.get("delegation_id"),
                committed_at=d.get("committed_at"),
                expires_at=d.get("expires_at"),
                seconds_remaining=d.get("seconds_remaining"),
                one_shot=bool(d.get("one_shot", False)),
                residue=d.get("residue", ""),
                gates=tuple(d.get("gates") or ()),
                reason=d.get("reason", ""),
            )
        except (KeyError, TypeError, ValueError) as exc:
            raise ValidationError(f"malformed HorizonEntry: {exc}") from None

    def to_dict(self) -> dict[str, Any]:
        return {
            "journal_id": self.journal_id,
            "action_id": self.action_id,
            "tool": self.tool,
            "kind": self.kind.value,
            "session_id": self.session_id,
            "delegation_id": self.delegation_id,
            "committed_at": self.committed_at,
            "expires_at": self.expires_at,
            "seconds_remaining": (
                round(self.seconds_remaining, 2) if self.seconds_remaining is not None else None
            ),
            "one_shot": self.one_shot,
            "gates": list(self.gates),
            "residue": self.residue,
            "reason": self.reason,
        }


@dataclass
class Horizon:
    """A point-in-time view of remaining recovery options."""

    at: float
    warn_within: float
    # Undoable now, with a deadline. Sorted soonest-first.
    closing: tuple[HorizonEntry, ...] = ()
    # Undoable now, no time limit. Still not permanent — a gate can close, and a
    # drill can go stale — but nothing is counting down.
    open_indefinitely: tuple[HorizonEntry, ...] = ()
    # Had a window; it closed. The undo is gone.
    expired: tuple[HorizonEntry, ...] = ()
    # Committed and never undoable. Not a closing window, a window that never was.
    standing_exposure: tuple[HorizonEntry, ...] = ()
    # Committed, claims an undo path, but has a hole in it (unresolved arguments or
    # a failed snapshot). Reported apart from both: it looks recoverable and is not.
    broken: tuple[HorizonEntry, ...] = ()
    notes: list[str] = field(default_factory=list)

    # ---- the metric ------------------------------------------------------
    @property
    def time_to_first_close(self) -> float | None:
        """Seconds until the soonest undo option disappears.

        ``None`` means nothing is counting down — either there is nothing to undo,
        or everything undoable has no deadline. It does *not* mean safe; check
        :attr:`standing_exposure` for what was never recoverable in the first place.
        """
        if not self.closing:
            return None
        return self.closing[0].seconds_remaining

    @property
    def next_to_close(self) -> HorizonEntry | None:
        return self.closing[0] if self.closing else None

    @property
    def closing_soon(self) -> tuple[HorizonEntry, ...]:
        return tuple(
            e for e in self.closing
            if e.seconds_remaining is not None and e.seconds_remaining <= self.warn_within
        )

    @property
    def undoable_count(self) -> int:
        return len(self.closing) + len(self.open_indefinitely)

    @property
    def unrecoverable_count(self) -> int:
        """Everything that cannot be undone right now, for any reason."""
        return len(self.expired) + len(self.standing_exposure) + len(self.broken)

    @property
    def recoverable_fraction(self) -> float:
        total = self.undoable_count + self.unrecoverable_count
        return self.undoable_count / total if total else 1.0

    @classmethod
    def from_dict(cls, d: dict[str, Any]) -> Horizon:
        """Read a horizon back.

        The reason to serialize one is to look at it somewhere other than where
        it was taken — a console, an evidence pack, an incident review a week
        later. ``at`` is preserved rather than recomputed, because a snapshot
        that silently re-dates itself on being opened is not a snapshot.
        """
        try:
            def bucket(name: str) -> tuple[HorizonEntry, ...]:
                return tuple(HorizonEntry.from_dict(e) for e in d.get(name) or ())

            return cls(
                at=float(d["at"]),
                warn_within=float(d.get("warn_within", DEFAULT_WARN_WITHIN)),
                closing=bucket("closing"),
                open_indefinitely=bucket("open_indefinitely"),
                expired=bucket("expired"),
                standing_exposure=bucket("standing_exposure"),
                broken=bucket("broken"),
                notes=list(d.get("notes") or ()),
            )
        except (KeyError, TypeError, ValueError) as exc:
            raise ValidationError(f"malformed Horizon: {exc}") from None

    def to_dict(self) -> dict[str, Any]:
        return {
            "at": self.at,
            "warn_within": self.warn_within,
            "time_to_first_close": (
                round(self.time_to_first_close, 2)
                if self.time_to_first_close is not None else None
            ),
            "undoable": self.undoable_count,
            "unrecoverable": self.unrecoverable_count,
            "recoverable_fraction": round(self.recoverable_fraction, 4),
            "counts": {
                "closing": len(self.closing),
                "closing_soon": len(self.closing_soon),
                "open_indefinitely": len(self.open_indefinitely),
                "expired": len(self.expired),
                "standing_exposure": len(self.standing_exposure),
                "broken": len(self.broken),
            },
            "closing": [e.to_dict() for e in self.closing],
            "closing_soon": [e.to_dict() for e in self.closing_soon],
            "open_indefinitely": [e.to_dict() for e in self.open_indefinitely],
            "expired": [e.to_dict() for e in self.expired],
            "standing_exposure": [e.to_dict() for e in self.standing_exposure],
            "broken": [e.to_dict() for e in self.broken],
            "notes": list(self.notes),
        }


def _entry(e: JournalEntry, *, now: float, reason: str = "") -> HorizonEntry:
    exp = e.expires_at
    return HorizonEntry(
        journal_id=e.id,
        action_id=e.action_id,
        tool=e.plan.tool,
        kind=e.plan.kind,
        session_id=e.session_id,
        delegation_id=e.delegation_id,
        committed_at=e.committed_at,
        expires_at=exp,
        seconds_remaining=(exp - now) if exp is not None else None,
        one_shot=e.plan.one_shot,
        residue=e.plan.residue,
        gates=tuple(g.name for g in e.plan.gates),
        reason=reason,
    )


def build(
    entries: list[JournalEntry],
    *,
    now: float | None = None,
    warn_within: float = DEFAULT_WARN_WITHIN,
) -> Horizon:
    """Compute the horizon from journal entries.

    Only ``COMMITTED`` and ``EXPIRED`` entries are considered. A ``PLANNED`` entry's
    action never ran, so it is not exposure; a ``REVERSED`` one is already resolved;
    an ``ABANDONED`` one was discarded. Counting any of those would inflate the
    picture with things nobody needs to act on.

    ``FAILED`` entries *are* counted, as standing exposure — an undo that was
    attempted and failed is the worst position to be in, and it must not disappear
    from the view just because it is terminal.
    """
    when = now if now is not None else time.time()
    h = Horizon(at=when, warn_within=warn_within)

    closing: list[HorizonEntry] = []
    indefinite: list[HorizonEntry] = []
    expired: list[HorizonEntry] = []
    standing: list[HorizonEntry] = []
    broken: list[HorizonEntry] = []

    for e in entries:
        if e.state is JournalState.EXPIRED:
            expired.append(_entry(e, now=when, reason="undo window closed"))
            continue
        if e.state is JournalState.FAILED:
            standing.append(
                _entry(e, now=when, reason=f"undo was attempted and failed: {e.error or '?'}")
            )
            continue
        if e.state is not JournalState.COMMITTED:
            continue

        plan = e.plan
        if plan.kind.is_one_way:
            standing.append(
                _entry(e, now=when, reason=f"{plan.kind.value}: no undo path exists")
            )
            continue
        if plan.is_broken:
            detail = (
                f"unresolved inverse arguments {list(plan.unresolved_args)}"
                if plan.unresolved_args
                else (plan.snapshot_error or "incomplete plan")
            )
            broken.append(_entry(e, now=when, reason=detail))
            continue
        if e.is_expired(now=when):
            # Not yet transitioned by expire_stale(), but already past its window.
            expired.append(
                _entry(e, now=when, reason="past its window; not yet swept by expire_stale()")
            )
            continue

        if e.expires_at is None:
            indefinite.append(_entry(e, now=when))
        else:
            closing.append(_entry(e, now=when))

    closing.sort(key=lambda x: x.seconds_remaining if x.seconds_remaining is not None else 0.0)
    h.closing = tuple(closing)
    h.open_indefinitely = tuple(indefinite)
    h.expired = tuple(expired)
    h.standing_exposure = tuple(standing)
    h.broken = tuple(broken)

    if broken:
        h.notes.append(
            f"{len(broken)} action(s) claim an undo path that could not actually be "
            "executed. These are the dangerous ones: they read as recoverable in every "
            "report except this one."
        )
    if h.closing_soon:
        h.notes.append(
            f"{len(h.closing_soon)} undo window(s) close within "
            f"{warn_within / 3600:.1f}h. After that the choice is gone, not merely harder."
        )
    if standing and not closing:
        h.notes.append(
            "Nothing is counting down, but that is not the same as safe — "
            f"{len(standing)} committed action(s) were never undoable at all."
        )
    return h


def render(h: Horizon) -> str:
    """Human-readable horizon, for an operator glancing at it during an incident."""
    lines = ["REVERSIBILITY HORIZON", "=" * 62]
    ttc = h.time_to_first_close
    nxt = h.next_to_close
    if ttc is None or nxt is None:
        lines.append("time to first close   —  nothing is counting down")
    else:
        lines.append(f"time to first close   {ttc / 60:.1f} min  ({nxt.tool})")
    lines.append(
        f"recoverable now       {h.undoable_count} of "
        f"{h.undoable_count + h.unrecoverable_count}  ({h.recoverable_fraction:.0%})"
    )
    lines.append("")
    lines.append(f"  closing            {len(h.closing):4d}   undoable, on a clock")
    lines.append(f"    within {h.warn_within / 3600:.0f}h        {len(h.closing_soon):4d}   act now")
    lines.append(f"  open indefinitely  {len(h.open_indefinitely):4d}   undoable, no deadline")
    lines.append(f"  expired            {len(h.expired):4d}   window closed")
    lines.append(f"  standing exposure  {len(h.standing_exposure):4d}   never undoable")
    lines.append(f"  broken             {len(h.broken):4d}   claims an undo it cannot run")
    lines.append("")

    if h.closing_soon:
        lines.append("CLOSING SOON")
        for e in h.closing_soon[:10]:
            mins = (e.seconds_remaining or 0) / 60
            flag = " ONE-SHOT" if e.one_shot else ""
            lines.append(f"  {mins:7.1f} min  {e.tool:38s}{flag}")
        lines.append("")

    if h.broken:
        lines.append("BROKEN UNDO PATHS  (look recoverable, are not)")
        for e in h.broken[:8]:
            lines.append(f"  {e.tool:38s} {e.reason[:60]}")
        lines.append("")

    if h.standing_exposure:
        lines.append("STANDING EXPOSURE  (committed, no undo path)")
        for e in h.standing_exposure[:8]:
            lines.append(f"  {e.tool:38s} {e.reason[:60]}")
        if len(h.standing_exposure) > 8:
            lines.append(f"  ... and {len(h.standing_exposure) - 8} more")
        lines.append("")

    for note in h.notes:
        lines.append(f"note: {note}")
    if h.notes:
        lines.append("")
    lines.append(
        "MTTR measures how fast you recover. This measures how long you still can."
    )
    return "\n".join(lines)


__all__ = ["Horizon", "HorizonEntry", "build", "render", "DEFAULT_WARN_WITHIN"]
