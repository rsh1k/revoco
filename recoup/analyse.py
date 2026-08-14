"""What the estate actually does, and what policy would fit it.

The security half of this product asks whether an action can be undone. This is
the other half: the enforcer sees every tool call every agent makes, and that
stream answers questions teams currently cannot answer at all.

Three things come out of it.

**Inventory.** Which agents exist, which tools they really call, how much of
their work is irreversible. "We have forty agents and nobody knows what they do"
is a common and expensive state, and the data to fix it is already flowing
through the gate.

**Suggest.** The tightest policy that would have allowed everything actually
observed. Writing agent policy by hand is miserable and the main reason people
run everything wide open; deriving a draft from real traffic removes the blank
page.

**Simulate.** Run a candidate policy against recorded traffic and show exactly
what would change. This is what makes it safe to turn enforcement on, and it is
the same evaluator the enforcer uses, so the answer is the one the gate would
actually give.

The hazard, stated plainly
--------------------------
Generating policy from observation bakes in whatever the observation contained.
If an agent did something it should not have during the window, the suggested
policy blesses it; if the window was too short, the policy breaks work that
simply had not happened yet. AWS learned this publicly with IAM policy
generation from CloudTrail.

So `suggest` never emits a policy on its own authority. It reports how much
evidence sits behind every clause, flags anything seen only a handful of times
as thin, refuses to widen a rule on the strength of a single observation without
saying so, and marks irreversible tools for review rather than quietly allowing
them because they happened to occur. The output is a draft for a human, and it
says so.
"""

from __future__ import annotations

import json
from collections import Counter, defaultdict
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Iterator

# Below this many observations a clause is reported as thin evidence. Not a
# threshold for correctness — a prompt to go and look, because the difference
# between "this agent reads invoices" and "this agent read an invoice once" is
# the difference between a rule and a coincidence.
THIN_EVIDENCE = 5


@dataclass
class Observation:
    tool: str
    action: str
    agent_id: str
    reversibility: str
    effect: str
    allowed: bool
    risk: int = 0
    roles: tuple[str, ...] = ()
    at: str = ""


def read(path: str | Path) -> Iterator[Observation]:
    """Stream a journal. Malformed lines are skipped, not fatal.

    A journal is written by a process that may have been killed mid-line, so a
    truncated final record is normal rather than exceptional. Refusing to
    analyse a month of traffic because of one bad byte would be the wrong call.
    """
    with open(path, encoding="utf-8") as fh:
        for line in fh:
            line = line.strip()
            if not line:
                continue
            try:
                d = json.loads(line)
                yield Observation(
                    tool=d["tool"], action=d.get("action", "write"),
                    agent_id=d.get("agent_id", ""),
                    reversibility=d.get("reversibility", "unknown"),
                    effect=d.get("effect", ""), allowed=bool(d.get("allowed")),
                    risk=int(d.get("risk", 0)),
                    roles=tuple(d.get("roles") or ()), at=d.get("at", ""),
                )
            except (json.JSONDecodeError, KeyError, TypeError, ValueError):
                continue


@dataclass
class AgentProfile:
    agent_id: str
    calls: int = 0
    tools: Counter = field(default_factory=Counter)
    actions: Counter = field(default_factory=Counter)
    reversibility: Counter = field(default_factory=Counter)
    roles: set[str] = field(default_factory=set)
    max_risk: int = 0
    first_seen: str = ""
    last_seen: str = ""

    @property
    def irreversible_share(self) -> float:
        risky = sum(n for k, n in self.reversibility.items()
                    if k in ("irreversible", "unknown"))
        return risky / self.calls if self.calls else 0.0


def inventory(observations: Iterator[Observation]) -> dict[str, Any]:
    """Who is doing what, and how much of it cannot be taken back."""
    agents: dict[str, AgentProfile] = {}
    tools: Counter = Counter()
    tool_rev: dict[str, str] = {}
    total = 0

    for o in observations:
        total += 1
        p = agents.setdefault(o.agent_id, AgentProfile(agent_id=o.agent_id))
        p.calls += 1
        p.tools[o.tool] += 1
        p.actions[o.action] += 1
        p.reversibility[o.reversibility] += 1
        p.roles.update(o.roles)
        p.max_risk = max(p.max_risk, o.risk)
        if o.at:
            p.first_seen = min(p.first_seen or o.at, o.at)
            p.last_seen = max(p.last_seen, o.at)
        tools[o.tool] += 1
        tool_rev[o.tool] = o.reversibility

    return {
        "calls": total,
        "agents": sorted(
            ({"agent_id": p.agent_id, "calls": p.calls,
              "tools": len(p.tools), "top_tools": p.tools.most_common(5),
              "roles": sorted(p.roles), "max_risk": p.max_risk,
              "irreversible_share": round(p.irreversible_share, 3),
              "first_seen": p.first_seen, "last_seen": p.last_seen}
             for p in agents.values()),
            key=lambda a: -a["calls"]),
        "tools": [{"tool": t, "calls": n, "reversibility": tool_rev.get(t, "unknown")}
                  for t, n in tools.most_common()],
        # The headline number. Everything else on this page is context for it.
        "irreversible_tools": sorted(
            t for t, r in tool_rev.items() if r in ("irreversible", "unknown")),
    }


def suggest(observations: Iterator[Observation], *,
            name: str = "suggested", thin: int = THIN_EVIDENCE) -> dict[str, Any]:
    """The tightest policy that would have allowed what actually happened.

    One rule per agent listing exactly the tools and actions it used, with risk
    capped at the highest seen. Irreversible tools are deliberately *not* rolled
    into the allow rule: they get their own approval clause, because the fact
    that something happened during the observation window is not evidence that
    it should have.
    """
    by_agent: dict[str, dict[str, Any]] = defaultdict(
        lambda: {"tools": Counter(), "actions": Counter(),
                 "max_risk": 0, "roles": set(), "irreversible": set()})
    total = 0

    for o in observations:
        total += 1
        a = by_agent[o.agent_id]
        a["tools"][o.tool] += 1
        a["actions"][o.action] += 1
        a["max_risk"] = max(a["max_risk"], o.risk)
        a["roles"].update(o.roles)
        if o.reversibility in ("irreversible", "unknown"):
            a["irreversible"].add(o.tool)

    rules: list[dict[str, Any]] = []
    notes: list[str] = []

    # Irreversible work goes first so it wins on first-match, whichever agent
    # did it. Ordering it after the allow rules would make the approval clause
    # unreachable, which is the kind of bug a generated policy should not ship.
    all_irreversible = sorted({t for a in by_agent.values() for t in a["irreversible"]})
    if all_irreversible:
        rules.append({
            "id": "irreversible-needs-a-human",
            "effect": "require_approval",
            "tools": all_irreversible,
            "reason": "observed in traffic, but nothing can undo it",
        })
        notes.append(
            f"{len(all_irreversible)} tool(s) with no undo were observed and are set "
            f"to require approval, not allowed. They happened; that is not the same "
            f"as them being intended.")

    for agent_id, a in sorted(by_agent.items()):
        tools = sorted(t for t in a["tools"] if t not in a["irreversible"])
        if not tools:
            continue
        rules.append({
            "id": f"allow-{agent_id or 'unattributed'}",
            "effect": "allow",
            "agents": [agent_id] if agent_id else ["*"],
            "tools": tools,
            "actions": sorted(a["actions"]),
            "max_risk": a["max_risk"],
            "reason": f"observed behaviour of {agent_id or 'unattributed callers'}",
        })
        weak = sorted(t for t in tools if a["tools"][t] < thin)
        if weak:
            notes.append(
                f"{agent_id or 'unattributed'}: {len(weak)} tool(s) seen fewer than "
                f"{thin} times ({', '.join(weak[:6])}"
                f"{'…' if len(weak) > 6 else ''}). Thin evidence — confirm these are "
                f"real duties before relying on the clause.")

    if "" in by_agent:
        notes.append(
            "Some observations carry no agent id, so their clause matches any caller. "
            "That is as tight as the data allows; authenticating callers would let "
            "this be narrowed.")

    return {
        "policy": {"name": name, "version": "1", "default_effect": "deny",
                   "rules": rules},
        "evidence": {"observations": total, "agents": len(by_agent),
                     "thin_threshold": thin},
        "notes": notes,
        "warning": (
            "Generated from observed traffic. It allows what happened, which is not "
            "the same as what should be allowed: anything the agents did wrong during "
            "the window is blessed here, and anything they had not done yet is "
            "missing. Review every clause before enforcing."),
    }


@dataclass
class Change:
    tool: str
    action: str
    agent_id: str
    was: str
    now: str
    count: int = 0


def simulate(observations: Iterator[Observation], bundle: dict[str, Any]) -> dict[str, Any]:
    """Replay recorded traffic against a candidate policy and diff the verdicts.

    Uses the same evaluator the enforcer does, so this is the answer the gate
    would actually give rather than an approximation of it. The question it
    exists to answer is the one that decides whether enforcement gets turned on:
    what would have broken?
    """
    from .bundle import Call, evaluate

    newly_blocked: dict[tuple, Change] = {}
    newly_allowed: dict[tuple, Change] = {}
    unchanged = 0
    total = 0

    for o in observations:
        total += 1
        verdict = evaluate(bundle, Call(
            tool=o.tool, action=o.action, agent_id=o.agent_id,
            roles=o.roles, risk=o.risk, reversibility=o.reversibility))

        # `allowed` in the journal is the *policy's* answer, recorded even when
        # shadow mode let the call through anyway. Comparing against the shadowed
        # outcome instead would report every shadow deployment as "nothing
        # changes", which is exactly backwards.
        if verdict.allowed == o.allowed:
            unchanged += 1
            continue

        key = (o.tool, o.action, o.agent_id)
        bucket = newly_blocked if o.allowed else newly_allowed
        entry = bucket.get(key)
        if entry is None:
            bucket[key] = Change(
                tool=o.tool, action=o.action, agent_id=o.agent_id,
                was=o.effect, now=verdict.effect, count=1)
        else:
            entry.count += 1

    def rows(d: dict[tuple, Change]) -> list[dict[str, Any]]:
        return sorted(
            ({"tool": c.tool, "action": c.action, "agent_id": c.agent_id,
              "was": c.was, "now": c.now, "calls": c.count} for c in d.values()),
            key=lambda r: -r["calls"])

    blocked_calls = sum(c.count for c in newly_blocked.values())
    return {
        "observations": total,
        "unchanged": unchanged,
        "newly_blocked_calls": blocked_calls,
        "newly_allowed_calls": sum(c.count for c in newly_allowed.values()),
        # The number someone actually decides on. A candidate policy that would
        # have stopped 4% of real traffic is a different proposition from one
        # that stops 0.01%, and the percentage is what makes that legible.
        "would_break_pct": round(100.0 * blocked_calls / total, 3) if total else 0.0,
        "newly_blocked": rows(newly_blocked),
        "newly_allowed": rows(newly_allowed),
    }
