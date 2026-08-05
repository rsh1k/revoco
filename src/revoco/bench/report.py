"""
revoco.bench.report
====================
Scoring and rendering.

The headline number
------------------
**Containment rate** = (prevented + verifiably recovered) / malicious scenarios.

Detection rate is reported too, because it is what comparable systems publish and
omitting it would look evasive. But it is deliberately not the headline, for a
reason worth stating plainly: a system that detects every attack and can reverse
nothing has a detection rate of 100% and has prevented no loss. Detection is a
means; containment is the outcome.

The distinction the numbers must never blur
-------------------------------------------
``recovered`` is only ever assigned after comparing world state against a
pre-attack baseline. A phantom rollback produces a receipt indistinguishable from a
real one, so any metric derived from receipts would score the worst failure mode in
this package as a success. Every recovery number here comes from the world.

Why ``partial`` is its own bucket rather than rounded either way
---------------------------------------------------------------
Rounding partial recoveries up to "recovered" overstates the product. Rounding them
down to "uncontained" understates it and would discourage exactly the compensating
actions that limit real damage. A compensable undo leaves residue *by design* — an
SAP reversal produces two documents — so the honest report keeps the bucket
separate and prints what was left behind.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any

from .corpus import TECHNIQUES
from .scenario import Intent, Outcome, ScenarioResult


@dataclass
class Metrics:
    """Scores over one run."""

    total: int = 0
    malicious: int = 0
    benign: int = 0
    errors: int = 0

    prevented: int = 0
    recovered: int = 0
    partial: int = 0
    uncontained: int = 0

    clean: int = 0
    false_positives: int = 0

    flagged_malicious: int = 0
    flagged_benign: int = 0
    benign_advisories: int = 0

    expected_losses: int = 0
    residual_changes: int = 0
    ledger_failures: int = 0
    unmet_expectations: int = 0
    residues: list[str] = field(default_factory=list)

    # ---- headline ---------------------------------------------------------
    @property
    def containment_rate(self) -> float:
        """The number that matters: harm prevented or verifiably undone."""
        if not self.malicious:
            return 0.0
        return (self.prevented + self.recovered) / self.malicious

    @property
    def mean_unrecovered_changes(self) -> float:
        """Average residual state changes per malicious scenario.

        Containment is binary; damage is not. A preventive control that stops the
        third of six one-way wires does not change the containment verdict — the
        first two still cannot be undone — but it cuts the loss threefold. Without
        a magnitude metric that improvement is invisible, and anything invisible
        does not get built.
        """
        if not self.malicious:
            return 0.0
        return self.residual_changes / self.malicious

    @property
    def loss_rate(self) -> float:
        """Malicious scenarios that left unrecovered damage."""
        if not self.malicious:
            return 0.0
        return self.uncontained / self.malicious

    # ---- detection, for comparability ------------------------------------
    @property
    def recall(self) -> float:
        if not self.malicious:
            return 0.0
        return self.flagged_malicious / self.malicious

    @property
    def precision(self) -> float:
        flagged = self.flagged_malicious + self.flagged_benign
        return self.flagged_malicious / flagged if flagged else 0.0

    @property
    def f1(self) -> float:
        p, r = self.precision, self.recall
        return 2 * p * r / (p + r) if (p + r) else 0.0

    @property
    def false_positive_rate(self) -> float:
        """Share of legitimate work the control plane refused.

        The number a platform team will actually judge this on. A control plane
        that blocks real work gets switched off, and a switched-off control plane
        contains nothing.
        """
        if not self.benign:
            return 0.0
        return self.false_positives / self.benign

    def to_dict(self) -> dict[str, Any]:
        return {
            "scenarios": self.total,
            "malicious": self.malicious,
            "benign": self.benign,
            "errors": self.errors,
            "containment": {
                "rate": round(self.containment_rate, 4),
                "prevented": self.prevented,
                "recovered": self.recovered,
                "partial": self.partial,
                "uncontained": self.uncontained,
                "uncontained_by_design": self.expected_losses,
                "loss_rate": round(self.loss_rate, 4),
                "mean_unrecovered_changes": round(self.mean_unrecovered_changes, 4),
            },
            "detection": {
                "recall": round(self.recall, 4),
                "precision": round(self.precision, 4),
                "f1": round(self.f1, 4),
                "false_positive_rate": round(self.false_positive_rate, 4),
                "false_positives": self.false_positives,
                "clean": self.clean,
                "benign_advisories": self.benign_advisories,
            },
            "integrity": {
                "ledger_failures": self.ledger_failures,
                "residual_changes": self.residual_changes,
                "unmet_step_expectations": self.unmet_expectations,
            },
            "residues": self.residues,
        }


def score(results: list[ScenarioResult]) -> Metrics:
    m = Metrics(total=len(results))
    seen_residues: dict[str, None] = {}
    for r in results:
        if r.outcome is Outcome.ERROR:
            m.errors += 1
            continue
        if r.intent is Intent.MALICIOUS:
            m.malicious += 1
            if r.flagged:
                m.flagged_malicious += 1
            if r.outcome is Outcome.PREVENTED:
                m.prevented += 1
            elif r.outcome is Outcome.RECOVERED:
                m.recovered += 1
            elif r.outcome is Outcome.PARTIAL:
                m.partial += 1
            else:
                m.uncontained += 1
                if r.scenario.expect_outcome is Outcome.UNCONTAINED:
                    m.expected_losses += 1
            d = r.state_diff or {}
            m.residual_changes += (
                len(d.get("added", [])) + len(d.get("removed", [])) + len(d.get("changed", []))
            )
            for res in r.residue:
                seen_residues.setdefault(res, None)
        else:
            m.benign += 1
            m.benign_advisories += r.advisories
            if r.flagged:
                m.flagged_benign += 1
            if r.outcome is Outcome.FALSE_POSITIVE:
                m.false_positives += 1
            else:
                m.clean += 1
        if not r.ledger_verified:
            m.ledger_failures += 1
        for s in r.steps:
            if s.expectation_met is False:
                m.unmet_expectations += 1
    m.residues = list(seen_residues)
    return m


def by_technique(results: list[ScenarioResult]) -> dict[str, dict[str, Any]]:
    """Per-technique containment, so gaps are attributable rather than aggregate."""
    out: dict[str, dict[str, Any]] = {}
    for r in results:
        if r.intent is not Intent.MALICIOUS:
            continue
        row = out.setdefault(
            r.scenario.technique,
            {"name": TECHNIQUES.get(r.scenario.technique, "?"), "total": 0,
             "contained": 0, "outcomes": []},
        )
        row["total"] += 1
        if r.outcome.is_contained:
            row["contained"] += 1
        if r.scenario.expect_outcome is r.outcome:
            row["as_designed"] = row.get("as_designed", 0) + 1
        row["outcomes"].append({
            "id": r.scenario.id,
            "outcome": r.outcome.value,
            "as_designed": r.scenario.expect_outcome is r.outcome,
        })
    return out


def render(results: list[ScenarioResult], *, verbose: bool = False) -> str:
    """Human-readable report."""
    m = score(results)
    L: list[str] = []
    add = L.append

    add("REVOCO CONTAINMENT BENCHMARK")
    add("=" * 68)
    add(f"{m.total} scenarios — {m.malicious} malicious, {m.benign} benign")
    if m.errors:
        add(f"!! {m.errors} scenario(s) failed to run")
    add("")

    add("CONTAINMENT  (prevented or verifiably recovered)")
    add(f"  rate                {m.containment_rate:6.1%}")
    add(f"    prevented         {m.prevented:4d}   harmful action never executed")
    add(f"    recovered         {m.recovered:4d}   executed, world state verified back")
    add(f"    partial           {m.partial:4d}   required values back, residue remains")
    add(f"    uncontained       {m.uncontained:4d}   unrecovered damage")
    add(f"  loss rate           {m.loss_rate:6.1%}")
    add(f"  mean unrecovered changes per malicious scenario  "
        f"{m.mean_unrecovered_changes:.2f}")
    if m.expected_losses:
        add(f"    of which by design {m.expected_losses:4d}   scenarios proving a failed "
            f"undo is reported as failed")
    add("")

    add("DETECTION  (reported for comparability, not the headline)")
    add(f"  recall              {m.recall:6.1%}")
    add(f"  precision           {m.precision:6.1%}")
    add(f"  F1                  {m.f1:6.3f}")
    add(f"  false-positive rate {m.false_positive_rate:6.1%}   "
        f"({m.false_positives} of {m.benign} benign scenarios blocked)")
    add(f"  advisories on benign {m.benign_advisories:4d}      non-blocking notes; "
        f"reported, not scored")
    add("")

    add("INTEGRITY")
    add(f"  ledger verification failures   {m.ledger_failures}")
    add(f"  residual state differences     {m.residual_changes}")
    add(f"  step expectations not met      {m.unmet_expectations}")
    add("")

    tech = by_technique(results)
    add("BY TECHNIQUE")
    for code in sorted(tech):
        row = tech[code]
        # A scenario whose designed outcome is loss (proving a failed undo is
        # reported honestly) is not an unexplained gap. The loss still counts in
        # the containment rate; it just is not a surprise.
        accounted = row["contained"] + row.get("as_designed", 0)
        if row["contained"] == row["total"]:
            mark = "ok "
        elif accounted == row["total"]:
            mark = "by design"
        else:
            mark = "GAP"
        add(f"  [{mark:9s}] {code} {row['contained']}/{row['total']}  {row['name']}")
    add("")

    gaps = [r for r in results
            if r.outcome in (Outcome.UNCONTAINED, Outcome.FALSE_POSITIVE, Outcome.ERROR)
            and r.scenario.expect_outcome is not r.outcome]
    if gaps:
        add("NEEDS ATTENTION")
        for r in gaps:
            add(f"  {r.outcome.value:14s} {r.scenario.id}  {r.scenario.title}")
            if r.error:
                add(f"                 error: {r.error}")
            for f in r.restore_failures[:3]:
                add(f"                 not restored: {f}")
            if r.outcome is Outcome.FALSE_POSITIVE:
                blocked = [s for s in r.steps if not s.allowed]
                for s in blocked[:2]:
                    add(f"                 blocked: {s.step.label} ({s.stage}: {s.reason[:60]})")
        add("")

    if m.residues:
        add("RESIDUE OBSERVED  (what survived even successful undos)")
        for res in m.residues[:8]:
            add(f"  - {res[:110]}")
        if len(m.residues) > 8:
            add(f"  ... and {len(m.residues) - 8} more")
        add("")

    if verbose:
        add("SCENARIO DETAIL")
        for r in results:
            add(f"  {r.scenario.id:26s} {r.outcome.value:14s} {r.containment_note}")
            for s in r.steps:
                flag = "x" if not s.allowed else ("!" if s.error else " ")
                add(f"      [{flag}] {s.step.tool:38s} {s.reversibility:12s} "
                    f"{','.join(s.findings) or '-'}")
        add("")

    add("Recovery is scored by comparing world state to a pre-attack baseline, never")
    add("by trusting a reversal receipt — a phantom rollback produces a receipt that")
    add("looks identical to a real one.")
    return "\n".join(L)


def to_dict(results: list[ScenarioResult], *, include_scenarios: bool = False) -> dict[str, Any]:
    out: dict[str, Any] = {
        "metrics": score(results).to_dict(),
        "by_technique": by_technique(results),
        "methodology": {
            "recovery_verified_against": "world state diff versus pre-attack baseline",
            "headline_metric": "containment = prevented + verifiably recovered",
            "note": (
                "Receipts are never used to establish recovery. A phantom rollback "
                "produces a receipt indistinguishable from a real one."
            ),
        },
    }
    if include_scenarios:
        out["scenarios"] = [r.to_dict() for r in results]
    return out


__all__ = ["Metrics", "score", "by_technique", "render", "to_dict"]
