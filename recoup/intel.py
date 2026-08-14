"""Threat intelligence from what the agents actually did.

The journal is a behavioural record of an agent estate, and that is a data
source nobody else has in this shape. What it supports is narrow and real:
noticing when an agent starts behaving unlike itself.

Every detection here is behavioural and deterministic. There is no model in this
module, and that is a deliberate choice rather than a limitation to apologise
for. The forensics literature is clear that hallucination rates acceptable for
triage are not acceptable for evidence under adversarial challenge, so anything
that might end up in front of an auditor is computed, explainable, and
reproducible from the journal. A model can help someone *read* these findings;
it must not be what produces them.

Findings carry MITRE ATLAS technique identifiers where one fits. That is for
interoperability, not coverage: a finding that names a technique the customer's
threat model already tracks lands in an existing process instead of starting a
new one. ATLAS is explicitly described as reacting to rather than predicting
agentic technique, so a mapping is a translation and never a claim of adequacy.

The baseline problem, stated plainly
------------------------------------
Every detection here compares a window against a baseline drawn from the same
journal. If the baseline period already contained the compromise, the compromise
is the norm and nothing fires. This is the same hazard `suggest` carries, and it
is not solvable by being cleverer about the statistics — only by saying so, and
by reporting how much baseline each finding rests on.
"""

from __future__ import annotations

from collections import Counter, defaultdict
from dataclasses import dataclass, field
from typing import Any, Iterator

from .analyse import Observation

# ATLAS identifiers used below. Kept in one place so a mapping change is one
# edit rather than a search, and so the ones that are genuinely approximate are
# visible together.
ATLAS = {
    "privilege_drift": "AML.T0054",       # LLM jailbreak / expanded capability use
    "tool_abuse": "AML.T0053",            # LLM plugin compromise
    "exfiltration": "AML.T0057",          # LLM data leakage
    "config_tamper": "AML.T0058",         # agent configuration tampering
    "volume_anomaly": "",                 # no ATLAS technique fits; left empty
}


@dataclass
class Finding:
    rule: str
    severity: str            # high | medium | low
    agent_id: str
    summary: str
    evidence: dict[str, Any] = field(default_factory=dict)
    atlas: str = ""

    def __str__(self) -> str:
        tag = f" [{self.atlas}]" if self.atlas else ""
        return f"[{self.severity}]{tag} {self.agent_id}: {self.summary}"


@dataclass
class Baseline:
    """What normal looked like, per agent."""

    tools: dict[str, set[str]] = field(default_factory=lambda: defaultdict(set))
    calls: Counter = field(default_factory=Counter)
    irreversible: Counter = field(default_factory=Counter)
    refused: Counter = field(default_factory=Counter)
    total: int = 0

    def observe(self, o: Observation) -> None:
        self.tools[o.agent_id].add(o.tool)
        self.calls[o.agent_id] += 1
        self.total += 1
        if o.reversibility in ("irreversible", "unknown"):
            self.irreversible[o.agent_id] += 1
        if not o.allowed:
            self.refused[o.agent_id] += 1


# An agent needs at least this many baseline calls before "it never did that
# before" means anything. Below it, everything is new because there is no
# history, and firing on that would bury the real signal on day one.
MIN_BASELINE = 30

# A refusal rate this far above an agent's own baseline is worth surfacing. An
# agent repeatedly reaching for things the policy denies is either misconfigured
# or being steered, and both are worth a look.
REFUSAL_MULTIPLE = 3.0

# Volume this many times the baseline rate. Deliberately loose: agent traffic is
# bursty by nature and a tight threshold here produces noise, which trains
# people to stop reading.
VOLUME_MULTIPLE = 5.0


def analyse(baseline_obs: Iterator[Observation],
            window_obs: Iterator[Observation]) -> dict[str, Any]:
    """Compare a window against a baseline and report what changed.

    Both are streams of the same journal, split by the caller. Keeping the split
    external means the caller decides what "normal" was, which is a judgement
    that belongs to whoever knows when the estate last changed.
    """
    base = Baseline()
    for o in baseline_obs:
        base.observe(o)

    window = Baseline()
    win_rows: list[Observation] = []
    for o in window_obs:
        window.observe(o)
        win_rows.append(o)

    findings: list[Finding] = []
    thin: list[str] = []

    for agent in sorted(window.calls):
        seen = base.calls[agent]
        if seen < MIN_BASELINE:
            thin.append(agent)
            continue

        # Privilege drift: a tool this agent has never touched before. The most
        # useful single signal in the set, because a hijacked agent has to reach
        # for something new to do anything interesting.
        new_tools = window.tools[agent] - base.tools[agent]
        if new_tools:
            irreversible_new = {
                o.tool for o in win_rows
                if o.agent_id == agent and o.tool in new_tools
                and o.reversibility in ("irreversible", "unknown")}
            findings.append(Finding(
                rule="privilege-drift",
                severity="high" if irreversible_new else "medium",
                agent_id=agent,
                summary=(f"used {len(new_tools)} tool(s) never seen in baseline: "
                         f"{', '.join(sorted(new_tools))}"
                         + (f" — {', '.join(sorted(irreversible_new))} cannot be undone"
                            if irreversible_new else "")),
                evidence={"new_tools": sorted(new_tools),
                          "irreversible": sorted(irreversible_new),
                          "baseline_calls": seen},
                atlas=ATLAS["privilege_drift"]))

        # Refusal spike: reaching for things the policy denies.
        base_rate = base.refused[agent] / seen
        win_rate = window.refused[agent] / max(window.calls[agent], 1)
        if window.refused[agent] >= 3 and win_rate > max(base_rate * REFUSAL_MULTIPLE, 0.05):
            findings.append(Finding(
                rule="refusal-spike", severity="medium", agent_id=agent,
                summary=(f"{window.refused[agent]} refused call(s), "
                         f"{win_rate:.0%} of its traffic against a baseline of "
                         f"{base_rate:.0%}"),
                evidence={"refused": window.refused[agent],
                          "window_rate": round(win_rate, 3),
                          "baseline_rate": round(base_rate, 3)},
                atlas=ATLAS["tool_abuse"]))

        # Irreversible work appearing where there was none.
        if window.irreversible[agent] and not base.irreversible[agent]:
            findings.append(Finding(
                rule="new-irreversible-work", severity="high", agent_id=agent,
                summary=(f"took {window.irreversible[agent]} action(s) nothing can "
                         f"undo, having taken none in baseline"),
                evidence={"count": window.irreversible[agent],
                          "baseline_calls": seen},
                atlas=ATLAS["tool_abuse"]))

        # Volume anomaly, rate-normalised so a longer window is not an alert.
        if base.total and window.total:
            base_share = seen / base.total
            win_share = window.calls[agent] / window.total
            if base_share > 0 and win_share > base_share * VOLUME_MULTIPLE:
                findings.append(Finding(
                    rule="volume-anomaly", severity="low", agent_id=agent,
                    summary=(f"{win_share:.0%} of traffic against a baseline share "
                             f"of {base_share:.0%}"),
                    evidence={"window_share": round(win_share, 3),
                              "baseline_share": round(base_share, 3)},
                    atlas=ATLAS["volume_anomaly"]))

    # An agent that appears only in the window has no baseline at all, which is
    # itself worth saying: a new agent nobody mentioned is the agent-sprawl
    # problem arriving in person.
    unseen = sorted(set(window.calls) - set(base.calls))
    for agent in unseen:
        findings.append(Finding(
            rule="unknown-agent", severity="medium", agent_id=agent,
            summary=(f"absent from baseline entirely; {window.calls[agent]} call(s) "
                     f"from an agent nobody has seen before"),
            evidence={"calls": window.calls[agent]},
            atlas=ATLAS["config_tamper"]))

    order = {"high": 0, "medium": 1, "low": 2}
    findings.sort(key=lambda f: (order[f.severity], f.agent_id))

    return {
        "findings": findings,
        "baseline_calls": base.total,
        "window_calls": window.total,
        # Reported rather than hidden. A caller that does not know how much
        # baseline sits behind a finding cannot judge it.
        "insufficient_baseline": sorted(set(thin)),
        "caveat": (
            "Every detection compares a window against a baseline drawn from the "
            "same journal. If the baseline already contained the compromise, the "
            "compromise is the norm and nothing here fires. These findings are "
            "behavioural and deterministic; none of them is proof of anything."),
    }


def summarise(result: dict[str, Any]) -> str:
    """A short readable digest, for a terminal or an alert body."""
    fs = result["findings"]
    if not fs:
        return (f"nothing anomalous across {result['window_calls']:,} calls "
                f"against a {result['baseline_calls']:,}-call baseline")
    by = Counter(f.severity for f in fs)
    parts = [f"{by[s]} {s}" for s in ("high", "medium", "low") if by[s]]
    return f"{len(fs)} finding(s): {', '.join(parts)}"
