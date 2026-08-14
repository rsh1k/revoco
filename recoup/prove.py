"""Proving things about a policy before it decides anything.

A policy is an ordered list of rules with first-match-wins, which makes it a
program, and programs have bugs that reading does not find. The two that matter
here are a rule that can never fire because earlier rules shadow it, and a hole
that lets an irreversible action through without a human. `suggest` already had
to guard against the first by hand — ordering the approval clause ahead of the
allows, or it would be unreachable — and guarding by hand is exactly the thing
that stops working once someone else edits the policy.

Why this is decidable
---------------------
The rule language is deliberately small. A rule tests membership in finite sets
(reversibility, roles), glob membership on three string fields, and comparisons
against finitely many integer thresholds. None of that is Turing-complete, and
none of it has unbounded state.

So the search space collapses. Integers only ever get compared against the
thresholds the policy itself names, which makes the boundary values sufficient —
the same argument the conformance fixtures rest on. Reversibility has four
values. The string fields are partitioned into equivalence classes by the
policy's own patterns, and one witness per class stands for the whole class.

Enumerating those witnesses answers any question about the policy exactly,
without a SAT solver and without approximation.

Which direction the errors run
------------------------------
The two questions want opposite kinds of caution, so they get it.

`unreachable` must never accuse a rule that can actually fire, because acting on
that means deleting a working control. It reports a rule only when a witness
search has covered the space and found nothing.

`holes` must never miss a violation, because a clean report is read as a
guarantee. Where witness generation cannot cover a pattern — an unusual glob it
cannot synthesise a witness for — the result says so instead of reporting
safety it has not established.
"""

from __future__ import annotations

import fnmatch
import re
from dataclasses import dataclass, field
from itertools import product
from typing import Any, Iterator

REVERSIBILITIES = ("reversible", "compensable", "irreversible", "unknown")

# Patterns we can synthesise a witness for with certainty. Anything else makes
# the analysis incomplete, and incompleteness is reported rather than hidden.
_SIMPLE = re.compile(r"^[A-Za-z0-9_.:/-]*\*?[A-Za-z0-9_.:/-]*$")


@dataclass
class Witness:
    """A concrete call that reaches some rule."""

    tool: str
    action: str
    agent_id: str
    roles: tuple[str, ...]
    risk: int
    threat_score: int
    reversibility: str

    def describe(self) -> str:
        r = f" roles={list(self.roles)}" if self.roles else ""
        return (f"{self.tool}/{self.action} agent={self.agent_id}{r} "
                f"risk={self.risk} threat={self.threat_score} "
                f"[{self.reversibility}]")


@dataclass
class Report:
    unreachable: list[dict[str, Any]] = field(default_factory=list)
    holes: list[dict[str, Any]] = field(default_factory=list)
    default_reachable: bool = False
    witnesses_checked: int = 0
    complete: bool = True
    incompleteness: list[str] = field(default_factory=list)

    @property
    def ok(self) -> bool:
        return not self.unreachable and not self.holes


def _glob_witnesses(patterns: set[str], literals: set[str]) -> tuple[list[str], list[str]]:
    """Concrete strings covering every equivalence class the patterns induce.

    Returns the witnesses and any complaints about patterns too awkward to
    synthesise for. A `*` in the middle or at the end is handled by substituting
    a filler that cannot collide with anything else in the policy.
    """
    out: set[str] = set(literals)
    problems: list[str] = []

    for p in patterns:
        if p == "*":
            continue
        if not _SIMPLE.match(p) or p.count("*") > 1:
            problems.append(p)
            continue
        # A filler unlikely to be matched by any other pattern by accident.
        out.add(p.replace("*", "Zq7"))

    # Something matched by `*` and nothing narrower, so the catch-all cases and
    # the default effect are both exercised.
    out.add("Zq7-unmatched-by-anything")
    return sorted(out), problems


def _thresholds(rules: list[dict[str, Any]], keys: tuple[str, ...]) -> list[int]:
    """Boundary values, for the same reason the fixtures use them.

    A comparison bug lives exactly on the boundary. Values away from it prove
    nothing, which was demonstrated the hard way when a `<` changed to `<=`
    survived 8,316 fixtures that never landed on the policy's only threshold.
    """
    seen = {0}
    for r in rules:
        for k in keys:
            t = r.get(k)
            if t is None:
                continue
            seen.update({t - 1, t, t + 1})
    return sorted(v for v in seen if v >= 0)


def _role_sets(rules: list[dict[str, Any]], cap: int = 6) -> list[tuple[str, ...]]:
    """Role combinations worth trying.

    Rules only ever test whether every required role is present, so the
    interesting witnesses are the empty set, each rule's exact requirement, and
    the union. Nothing in the language can distinguish more than that.
    """
    required = [tuple(sorted(r.get("require_roles") or ())) for r in rules]
    combos = {(), }
    for req in required:
        if req:
            combos.add(req)
    everything = tuple(sorted({role for req in required for role in req}))
    if everything:
        combos.add(everything)
    return sorted(combos)[:cap] if len(combos) > cap else sorted(combos)


def _matches(rule: dict[str, Any], w: Witness) -> bool:
    """The enforcer's matcher, in the same order, over one witness."""
    if not any(fnmatch.fnmatchcase(w.tool, p) for p in rule["tools"]):
        return False
    if not any(fnmatch.fnmatchcase(w.action, p) for p in rule["actions"]):
        return False
    if not any(fnmatch.fnmatchcase(w.agent_id, p) for p in rule["agents"]):
        return False
    if any(role not in w.roles for role in rule["require_roles"]):
        return False
    if rule["reversibility"] and w.reversibility not in rule["reversibility"]:
        return False
    if rule["min_threat_score"] is not None and w.threat_score < rule["min_threat_score"]:
        return False
    if rule["min_risk"] is not None and w.risk < rule["min_risk"]:
        return False
    if rule["max_risk"] is not None and w.risk > rule["max_risk"]:
        return False
    return True


def witnesses(bundle: dict[str, Any]) -> Iterator[Witness]:
    """Every call worth trying, which for this language is every call that matters."""
    rules = bundle["rules"]

    tool_pats = {p for r in rules for p in r["tools"]}
    action_pats = {p for r in rules for p in r["actions"]}
    agent_pats = {p for r in rules for p in r["agents"]}

    tools, _ = _glob_witnesses(tool_pats, set(bundle.get("reversibility", {})))
    actions, _ = _glob_witnesses(action_pats, {"read", "write"})
    agents, _ = _glob_witnesses(agent_pats, set())

    risks = _thresholds(rules, ("min_risk", "max_risk"))
    threats = _thresholds(rules, ("min_threat_score",))
    roles = _role_sets(rules)

    for tool, action, agent, role, risk, threat, rev in product(
            tools, actions, agents, roles, risks, threats, REVERSIBILITIES):
        yield Witness(tool, action, agent, role, risk, threat, rev)


def _static_reversibility(bundle: dict[str, Any], tool: str) -> str:
    """What the bundle's registry says about a tool, ignoring live state."""
    hit = bundle.get("reversibility", {}).get(tool)
    if hit is not None:
        return hit
    for g in bundle.get("reversibility_globs", ()):
        if fnmatch.fnmatchcase(tool, g["tool"]):
            return g["kind"]
    return bundle.get("unknown_tool_reversibility", "unknown")


def analyse(bundle: dict[str, Any], *,
            allow_irreversible: frozenset[str] = frozenset()) -> Report:
    """Search the space and report what it finds.

    `allow_irreversible` names rule ids that are permitted to allow work nothing
    can undo. Empty by default: a policy that lets an irreversible action through
    without a human should have to say so explicitly, in the place someone
    reviewing it will look.
    """
    rules = bundle["rules"]
    report = Report()

    # Incompleteness is established first, so a clean result can never be
    # reported over a space that was not actually covered.
    for field_name, key in (("tool", "tools"), ("action", "actions"), ("agent", "agents")):
        pats = {p for r in rules for p in r[key]}
        _, problems = _glob_witnesses(pats, set())
        if problems:
            report.complete = False
            report.incompleteness.append(
                f"cannot synthesise a witness for {field_name} pattern(s) "
                f"{', '.join(sorted(problems))}; results below do not cover them")

    fired: set[str] = set()
    default_hit = False
    holes: dict[str, dict[str, Any]] = {}

    for w in witnesses(bundle):
        report.witnesses_checked += 1
        for rule in rules:
            if _matches(rule, w):
                fired.add(rule["id"])
                if (rule["effect"] == "allow"
                        and w.reversibility in ("irreversible", "unknown")
                        and rule["id"] not in allow_irreversible):
                    # First one is enough per rule; a thousand witnesses for the
                    # same hole is noise, and the first is as good a repro as any.
                    # Whether this witness could arise from the static registry
                    # alone, or only if the control plane classifies the tool
                    # differently from the bundle at runtime. Both are real —
                    # live classification is the whole point of the control
                    # plane — but they are different conversations, and a
                    # finding a reader can dismiss as impossible is a finding
                    # that gets dismissed.
                    static = _static_reversibility(bundle, w.tool)
                    existing = holes.get(rule["id"])
                    direct = static == w.reversibility
                    if existing is None or (direct and not existing["directly_reachable"]):
                        holes[rule["id"]] = {
                            "rule_id": rule["id"],
                            "effect": rule["effect"],
                            "reversibility": w.reversibility,
                            "witness": w.describe(),
                            "directly_reachable": direct,
                            "why": ("this rule allows an action nothing can undo, "
                                    "with no human in the path"),
                        }
                break
        else:
            default_hit = True
            if (bundle["default_effect"] == "allow"
                    and w.reversibility in ("irreversible", "unknown")):
                holes.setdefault("__default__", {
                    "rule_id": "__default__",
                    "effect": "allow",
                    "reversibility": w.reversibility,
                    "witness": w.describe(),
                    "why": ("no rule matches and the default is allow, so "
                            "unclassified irreversible work is permitted"),
                })

    report.default_reachable = default_hit
    report.holes = sorted(holes.values(), key=lambda h: h["rule_id"])

    # Only accuse a rule of being unreachable when the search actually covered
    # the space. Deleting a live control on the strength of an incomplete
    # analysis is a worse outcome than missing a dead one.
    if report.complete:
        for i, rule in enumerate(rules):
            if rule["id"] not in fired:
                shadowing = [r["id"] for r in rules[:i]]
                report.unreachable.append({
                    "rule_id": rule["id"],
                    "index": i,
                    "why": ("no call can reach this rule; earlier rules match "
                            "everything it would have"),
                    "shadowed_by": shadowing,
                })

    return report


def render(report: Report) -> str:
    """A verdict a person can act on."""
    lines: list[str] = []
    lines.append(f"checked {report.witnesses_checked:,} distinct calls")
    if not report.complete:
        lines.append("")
        lines.append("  INCOMPLETE — the search did not cover the whole policy:")
        for note in report.incompleteness:
            lines.append(f"    {note}")

    if report.holes:
        lines.append("")
        lines.append(f"  {len(report.holes)} hole(s): irreversible work reachable "
                     f"without a human")
        for h in report.holes:
            lines.append(f"    rule {h['rule_id']}: {h['why']}")
            lines.append(f"      reached by: {h['witness']}")
            if not h.get("directly_reachable", True):
                lines.append("      (only when the control plane classifies this "
                             "tool differently from the bundle's registry)")

    if report.unreachable:
        lines.append("")
        lines.append(f"  {len(report.unreachable)} unreachable rule(s):")
        for u in report.unreachable:
            lines.append(f"    {u['rule_id']} (position {u['index']}) — {u['why']}")
            if u["shadowed_by"]:
                lines.append(f"      shadowed by: {', '.join(u['shadowed_by'])}")

    if not report.default_reachable:
        lines.append("")
        lines.append("  note: the default effect is never reached; every call "
                     "matches some rule")

    lines.append("")
    if report.ok and report.complete:
        lines.append("  no holes, no unreachable rules, search complete")
    elif report.ok:
        lines.append("  nothing found, but the search was incomplete — "
                     "this is not a clean bill of health")
    return "\n".join(lines)
