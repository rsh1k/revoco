"""
praetor.reversal.budget
=======================
An irreversibility budget: a ceiling on how much unrecoverable exposure one grant
may accumulate before a human has to re-authorize.

Why this exists — a gap the benchmark measured
----------------------------------------------
Praetor already detects unrecoverable fan-out (PRA01). The containment benchmark
showed that detection is structurally too late: PRA01 is a threshold detector, so
in the irreversible-fan-out scenario **four one-way wires had already left** before
the pattern became visible. The scenario scored uncontained, and no amount of
threshold tuning fixes it — a detector needs evidence, and the evidence is the
damage.

A budget inverts that. Every irreversible action debits an account, and the first
action that *would* overdraw it is refused. The control moves from "notice the
fourth wire" to "refuse the third", which is the difference between an alert and a
prevention.

Prior art, and where this improves on it
---------------------------------------
The concept is not new. *The Controllability Trap* (arXiv 2603.03515) proposes an
irreversibility budget for military AI agents: score each tool call on a
0–1 irreversibility scale, keep a running total, and pause for human
re-authorization at the ceiling. As far as can be determined it is a governance
framework rather than a shipped implementation.

This differs in one way that matters, and it comes straight from the adapter work:
**the paper scores per tool; this scores per resolved action.** ``aws.s3.delete_object``
has no single irreversibility score. Against a versioned bucket it is recoverable
and should cost almost nothing; against an unversioned bucket it is final and
should cost full price. A budget keyed on tool names would either bankrupt agents
doing safe cleanup or hand out free credit for permanent deletion. Debiting the
*authorize-phase-resolved* classification — the same one that already degrades when
a gate is closed — prices the action that is actually about to happen.

Two further refinements
-----------------------
**Risk-weighted.** An irreversible low-consequence action (a notification) and an
irreversible high-consequence one (a wire transfer) are both "irreversible" and are
not remotely the same exposure. Cost scales with the caller-assigned risk band, so
the ceiling means something across mixed traffic.

**Residue is not free.** A compensable action whose undo leaves named residue costs
more than one that restores cleanly. Otherwise "compensable" becomes a loophole:
you could void a thousand payments and call the exposure zero while a thousand
remittance advices sat in suppliers' inboxes.

Replenishment is deliberately manual. The budget resets when a human issues a fresh
delegation, because the entire purpose is to force a person back into the loop after
a defined quantity of one-way action. An automatic refill would be a rate limiter
wearing a governance costume.
"""

from __future__ import annotations

import threading
from dataclasses import dataclass, field
from typing import Any

from ..core.errors import ValidationError
from .model import Reversibility

# Base cost per unit of risk, by resolved reversal posture.
#
# UNKNOWN costs the same as IRREVERSIBLE rather than more: it *ranks* lower
# (fail-safe ordering, an unclassified tool is worse than a known one-way door),
# but for accounting purposes the worst case is that it turns out irreversible, and
# charging above full price would let a single unclassified read exhaust a budget.
DEFAULT_WEIGHTS: dict[Reversibility, float] = {
    Reversibility.REVERSIBLE: 0.0,
    Reversibility.COMPENSABLE: 0.25,
    Reversibility.IRREVERSIBLE: 1.0,
    Reversibility.UNKNOWN: 1.0,
}

# Surcharge applied to a compensable action whose undo leaves named residue.
DEFAULT_RESIDUE_SURCHARGE = 0.15


@dataclass(frozen=True)
class Charge:
    """What one action would cost, and why — so a refusal can be explained."""

    tool: str
    kind: Reversibility
    risk: int
    base_weight: float
    residue_surcharge: float
    cost: float

    def to_dict(self) -> dict[str, Any]:
        return {
            "tool": self.tool,
            "kind": self.kind.value,
            "risk": self.risk,
            "base_weight": self.base_weight,
            "residue_surcharge": self.residue_surcharge,
            "cost": round(self.cost, 6),
        }

    @property
    def explanation(self) -> str:
        parts = [f"{self.kind.value} action at risk {self.risk}"]
        if self.residue_surcharge:
            parts.append(f"plus {self.residue_surcharge} residue surcharge")
        return f"{' '.join(parts)} costs {self.cost:.3f}"


@dataclass
class BudgetState:
    """Consumption against one ceiling."""

    scope_id: str
    ceiling: float
    spent: float = 0.0
    charges: list[Charge] = field(default_factory=list)
    refusals: int = 0

    @property
    def remaining(self) -> float:
        return max(0.0, self.ceiling - self.spent)

    @property
    def exhausted(self) -> bool:
        return self.spent >= self.ceiling

    @property
    def utilization(self) -> float:
        return min(1.0, self.spent / self.ceiling) if self.ceiling else 1.0

    def to_dict(self) -> dict[str, Any]:
        return {
            "scope_id": self.scope_id,
            "ceiling": self.ceiling,
            "spent": round(self.spent, 6),
            "remaining": round(self.remaining, 6),
            "utilization": round(self.utilization, 4),
            "exhausted": self.exhausted,
            "charged_actions": len(self.charges),
            "refusals": self.refusals,
        }


class IrreversibilityBudget:
    """Tracks unrecoverable exposure per scope and refuses overdrafts.

    ``ceiling`` is denominated in *irreversible-actions-at-full-risk*: a ceiling of
    2.0 permits two maximum-risk one-way actions, or eight at risk 25, or a large
    number of cleanly reversible ones (which cost nothing at all).

    Reversible actions being free is the point. The budget is not a rate limiter —
    it constrains only the exposure that cannot be undone, so an agent doing
    recoverable work is never throttled, and the cheapest way for a team to buy
    headroom is to make their surface recoverable.
    """

    def __init__(
        self,
        ceiling: float = 3.0,
        *,
        weights: dict[Reversibility, float] | None = None,
        residue_surcharge: float = DEFAULT_RESIDUE_SURCHARGE,
        min_risk_to_charge: int = 1,
    ) -> None:
        if ceiling <= 0:
            raise ValidationError("budget ceiling must be positive")
        self.ceiling = float(ceiling)
        self.weights = dict(weights or DEFAULT_WEIGHTS)
        self.residue_surcharge = float(residue_surcharge)
        self.min_risk_to_charge = min_risk_to_charge
        self._states: dict[str, BudgetState] = {}
        self._lock = threading.Lock()

    # ---- pricing ----------------------------------------------------------
    def price(
        self,
        *,
        tool: str,
        kind: Reversibility,
        risk: int,
        has_residue: bool = False,
    ) -> Charge:
        """What this action would cost. Pure; charges nothing."""
        base = self.weights.get(kind, 1.0)
        surcharge = (
            self.residue_surcharge
            if (has_residue and kind is Reversibility.COMPENSABLE)
            else 0.0
        )
        if risk < self.min_risk_to_charge or base == 0.0:
            # A free action stays free even with residue: a reversible action's
            # residue is by definition nothing, and charging for reads would make
            # the budget a general rate limiter.
            cost = 0.0
            surcharge = 0.0
        else:
            cost = (base + surcharge) * (risk / 100.0)
        return Charge(
            tool=tool, kind=kind, risk=risk, base_weight=base,
            residue_surcharge=surcharge, cost=cost,
        )

    # ---- checking and charging -------------------------------------------
    def state(self, scope_id: str) -> BudgetState:
        with self._lock:
            return self._states.setdefault(
                scope_id, BudgetState(scope_id=scope_id, ceiling=self.ceiling)
            )

    def would_exceed(self, scope_id: str, charge: Charge) -> bool:
        if charge.cost <= 0:
            return False
        st = self.state(scope_id)
        with self._lock:
            return (st.spent + charge.cost) > st.ceiling

    def check(
        self,
        scope_id: str,
        *,
        tool: str,
        kind: Reversibility,
        risk: int,
        has_residue: bool = False,
    ) -> tuple[bool, Charge, str]:
        """Decide before the action runs. Returns ``(ok, charge, reason)``.

        Nothing is debited here. The caller commits only once the forward action
        actually succeeded, so a blocked or failed call does not consume budget —
        otherwise a flapping integration would exhaust the ceiling without ever
        having changed anything.
        """
        charge = self.price(tool=tool, kind=kind, risk=risk, has_residue=has_residue)
        if charge.cost <= 0:
            return True, charge, "no unrecoverable exposure; free"
        st = self.state(scope_id)
        if (st.spent + charge.cost) > st.ceiling:
            with self._lock:
                st.refusals += 1
            return (
                False,
                charge,
                (
                    f"irreversibility budget exhausted for this grant: "
                    f"{st.spent:.3f} of {st.ceiling:.3f} already committed and this "
                    f"action costs {charge.cost:.3f}. A human must re-authorize before "
                    f"more unrecoverable work proceeds."
                ),
            )
        return (
            True,
            charge,
            f"{charge.explanation}; {st.remaining:.3f} of {st.ceiling:.3f} remaining",
        )

    def commit(self, scope_id: str, charge: Charge) -> BudgetState:
        """Debit after the forward action succeeded."""
        st = self.state(scope_id)
        if charge.cost <= 0:
            return st
        with self._lock:
            st.spent += charge.cost
            st.charges.append(charge)
        return st

    def refund(self, scope_id: str, charge: Charge) -> BudgetState:
        """Credit back exposure that was successfully undone.

        Not merely bookkeeping tidiness — it is what makes the budget cooperate
        with the reversal layer instead of fighting it. An agent that cleans up
        after itself recovers headroom, so the incentive points at repairing
        exposure rather than at hoarding it.
        """
        st = self.state(scope_id)
        if charge.cost <= 0:
            return st
        with self._lock:
            st.spent = max(0.0, st.spent - charge.cost)
        return st

    def reset(self, scope_id: str) -> BudgetState:
        """Clear consumption for a scope — the human re-authorization path."""
        with self._lock:
            st = BudgetState(scope_id=scope_id, ceiling=self.ceiling)
            self._states[scope_id] = st
            return st

    # ---- reporting --------------------------------------------------------
    def report(self) -> dict[str, Any]:
        with self._lock:
            states = [s.to_dict() for s in self._states.values()]
        return {
            "ceiling": self.ceiling,
            "weights": {k.value: v for k, v in self.weights.items()},
            "residue_surcharge": self.residue_surcharge,
            "scopes": states,
            "exhausted_scopes": [s["scope_id"] for s in states if s["exhausted"]],
            "total_unrecoverable_exposure": round(sum(s["spent"] for s in states), 6),
        }


__all__ = [
    "IrreversibilityBudget",
    "BudgetState",
    "Charge",
    "DEFAULT_WEIGHTS",
    "DEFAULT_RESIDUE_SURCHARGE",
]
