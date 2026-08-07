#!/usr/bin/env python3
"""Export the benchmark corpus as JSON for detent's routing experiment.

Why this exists
---------------
detent asks whether routing agent work by *consequence* beats routing it by
*difficulty*. Answering that needs a realistic distribution of consequence across
agent traffic — how much of what an agent actually does is reversible, how much is
compensable, how much is permanent. That distribution is the one part of the
experiment that must not be invented, because it is the part that decides the
answer. Guess it high and consequence-aware routing looks essential; guess it low
and it looks like overhead.

So it is measured here, against the same registry and the same corpus the
containment benchmark runs on. Every step is classified by
``ReversalEngine.classify(tool, args)`` — the real function, with authorize-phase
gates evaluated — not by a lookup table written for this script.

What is deliberately *not* exported
-----------------------------------
No difficulty label. The corpus has no ground truth for how hard a step is for a
model to get right, and inventing one here would let the baseline be tuned by
whoever writes the export. detent derives difficulty from step features on its
own side, and both routing policies read the same derived value, so consequence
is the only variable that differs between them.

Gate answers
------------
Scenario-supplied answers are honoured; unlisted gates default to open, matching
``bench.harness``. That default is the *opposite* of the production one, where an
unverifiable gate closes. Keeping the benchmark's convention here means the
exported distribution reflects the control plane's behaviour rather than the
integrator's gate coverage, which is the same separation the benchmark makes.

Usage
-----
    python scripts/export_corpus.py > corpus.json
"""

from __future__ import annotations

import argparse
import json
import sys
from typing import Any

sys.path.insert(0, "src")

from revoco.adapters import registry_for  # noqa: E402
from revoco.bench.corpus import TECHNIQUES, all_scenarios  # noqa: E402
from revoco.bench.scenario import Intent, Scenario  # noqa: E402
from revoco.reversal.engine import ReversalEngine  # noqa: E402
from revoco.reversal.model import GateContext, Reversibility  # noqa: E402

SCHEMA_VERSION = 1


def _engine_for(scenario: Scenario) -> ReversalEngine:
    """An engine wired the way the benchmark wires one, for this scenario."""

    def gate_evaluator(ctx: GateContext) -> bool | str:
        return scenario.gate_answers.get(ctx.gate.name, True)

    return ReversalEngine(
        registry=scenario.registry or registry_for(),
        gate_evaluator=gate_evaluator,
    )


def _arg_shape(args: dict[str, Any]) -> dict[str, Any]:
    """Structural facts about a call's arguments, with the values left behind.

    detent's difficulty heuristic reads shape, not content. Exporting shape rather
    than the raw arguments keeps scenario payloads — which include planted
    injection strings and fake bank details — out of the artifact, so the corpus
    can be published without republishing attack text.
    """
    return {
        "count": len(args),
        "keys": sorted(args),
        "max_depth": _depth(args),
        "total_len": sum(len(str(v)) for v in args.values()),
    }


def _depth(value: Any, at: int = 0) -> int:
    if isinstance(value, dict):
        return max((_depth(v, at + 1) for v in value.values()), default=at)
    if isinstance(value, (list, tuple)):
        return max((_depth(v, at + 1) for v in value), default=at)
    return at


def export() -> dict[str, Any]:
    scenarios = all_scenarios()
    out_scenarios: list[dict[str, Any]] = []
    counts: dict[str, int] = {k.value: 0 for k in Reversibility}
    unregistered: set[str] = set()

    for sc in scenarios:
        engine = _engine_for(sc)
        steps: list[dict[str, Any]] = []
        for i, step in enumerate(sc.steps):
            kind = engine.classify(step.tool, dict(step.args))
            counts[kind.value] += 1
            if engine.registry.get(step.tool) is None:
                unregistered.add(step.tool)
            steps.append(
                {
                    "index": i,
                    "tool": step.tool,
                    "action": step.action,
                    "risk": step.risk,
                    "harmful": step.harmful,
                    "legitimately_refusable": step.legitimately_refusable,
                    "description": step.description,
                    "reversibility": kind.value,
                    "args": _arg_shape(dict(step.args)),
                }
            )
        out_scenarios.append(
            {
                "id": sc.id,
                "title": sc.title,
                "intent": sc.intent.value,
                "technique": sc.technique,
                "asi_codes": list(sc.asi_codes),
                "steps": steps,
            }
        )

    total_steps = sum(counts.values())
    return {
        "schema_version": SCHEMA_VERSION,
        "source": "revoco.bench.corpus",
        "provenance": {
            "classifier": "revoco.reversal.engine.ReversalEngine.classify",
            "registry": "revoco.adapters.registry_for() — all surfaces",
            "note": (
                "Reversibility is measured, not labelled by hand. Difficulty is "
                "deliberately absent; detent derives it identically for both policies."
            ),
        },
        "techniques": TECHNIQUES,
        "totals": {
            "scenarios": len(scenarios),
            "malicious": sum(1 for s in scenarios if s.intent is Intent.MALICIOUS),
            "benign": sum(1 for s in scenarios if s.intent is Intent.BENIGN),
            "steps": total_steps,
            "reversibility": counts,
            "unregistered_tools": sorted(unregistered),
        },
        "scenarios": out_scenarios,
    }


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("-o", "--out", help="write here instead of stdout")
    ap.add_argument("--summary", action="store_true", help="print the distribution to stderr")
    ns = ap.parse_args()

    data = export()
    text = json.dumps(data, indent=2, sort_keys=False) + "\n"
    if ns.out:
        with open(ns.out, "w", encoding="utf-8") as fh:
            fh.write(text)
    else:
        sys.stdout.write(text)

    if ns.summary or ns.out:
        t = data["totals"]
        print(
            f"{t['scenarios']} scenarios "
            f"({t['malicious']} malicious / {t['benign']} benign), "
            f"{t['steps']} steps",
            file=sys.stderr,
        )
        for kind, n in t["reversibility"].items():
            pct = 100.0 * n / t["steps"] if t["steps"] else 0.0
            print(f"  {kind:<12} {n:>4}  {pct:5.1f}%", file=sys.stderr)
        if t["unregistered_tools"]:
            print(
                f"  {len(t['unregistered_tools'])} tools have no spec "
                f"(classified UNKNOWN): {', '.join(t['unregistered_tools'][:8])}"
                + (" ..." if len(t["unregistered_tools"]) > 8 else ""),
                file=sys.stderr,
            )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
