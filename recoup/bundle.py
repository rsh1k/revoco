"""Compiling a revoco policy into something a Go process can evaluate.

The enforcer runs in the request path of every tool call, in a container next to
the agent, in a customer's own VPC. It cannot import revoco, so the policy has to
cross a language boundary — and the moment a policy crosses a language boundary
it acquires a second implementation, which is where gates start disagreeing with
themselves.

Two decisions here exist to make that disagreement loud rather than silent.

**Every field is written explicitly.** revoco defaults an unspecified `tools` to
`("*",)`. Emitting nothing and expecting Go to invent the same default is a bug
waiting for the day someone changes one of the two. So the compiler spells out
every field and the enforcer rejects a rule that is missing one.

**Anything not expressible is refused, not approximated.** A rule carrying a
condition or a budget does not compile. The tempting alternative — drop the
condition and emit the rest — produces a rule that matches strictly more calls
than the author wrote, which is a silent widening of a security policy. Failing
the build is the only honest option.
"""

from __future__ import annotations

import json
from dataclasses import dataclass
from typing import Any

# Bumped to 2 when rules gained `min_reversibility`. The enforcer refuses a
# schema it does not recognise rather than guessing which rules changed meaning,
# so a version mismatch is a loud startup failure instead of a policy that
# quietly means something else.
SCHEMA = 2


class BundleError(RuntimeError):
    """A policy that cannot be compiled without changing what it means."""


def _floor(rule: Any) -> str | None:
    """A rule's reversibility floor, if it states one.

    revoco gained this after the bundle schema was first written. Dropping it
    silently would compile "allow anything at least as recoverable as
    compensable" into a rule with an empty posture list — and an empty list means
    *any* posture to the enforcer, so the floor would become a wildcard that
    admits irreversible work. Widening a rule during compilation is the one thing
    this module refuses to do.
    """
    floor = getattr(rule, "min_reversibility", None)
    if floor is None:
        return None
    return getattr(floor, "value", str(floor))


def _rule_to_dict(rule: Any) -> dict[str, Any]:
    """One rule, with every field stated."""
    # `AlwaysTrue` is the no-op condition; anything else changes which calls the
    # rule matches and cannot be represented in schema 1.
    cond = getattr(rule, "condition", None)
    if cond is not None and type(cond).__name__ != "AlwaysTrue":
        raise BundleError(
            f"rule {rule.id!r} carries a condition ({type(cond).__name__}), which "
            f"schema {SCHEMA} cannot express. Compiling it without the condition "
            f"would widen the rule. Either lift the condition into the control "
            f"plane or extend the schema."
        )
    if getattr(rule, "budget", None) is not None:
        raise BundleError(
            f"rule {rule.id!r} carries a budget, which participates in matching "
            f"and needs per-session counters the enforcer does not hold. Budgeted "
            f"rules stay in the control plane."
        )

    return {
        "id": rule.id,
        "effect": rule.effect.value,
        "tools": list(rule.tools),
        "actions": list(rule.actions),
        "agents": list(rule.agents),
        "require_roles": list(rule.require_roles),
        "reversibility": [r.value for r in rule.reversibility],
        "min_reversibility": _floor(rule),
        "min_risk": rule.min_risk,
        "max_risk": rule.max_risk,
        "min_threat_score": rule.min_threat_score,
        "redact_fields": list(rule.redact_fields),
        "reason": rule.reason or f"matched rule {rule.id}",
    }


def compile_bundle(policy: Any, registry: Any = None, *,
                   unknown: str = "unknown") -> dict[str, Any]:
    """Turn a `Policy` (+ optional `InverseRegistry`) into a portable bundle.

    `registry` supplies the static half of reversibility: which tools have a
    declared inverse and of what kind. The dynamic half — whether that inverse
    can actually run right now — stays with the control plane, because answering
    it means reading the world.
    """
    # revoco resolves a tool to a spec by trying exact names first and then glob
    # patterns *in registration order*, returning the first glob that matches.
    # Flattening both into one dict would lose that ordering and silently change
    # which spec wins, so the two are carried separately and the enforcer walks
    # them in the same sequence.
    exact: dict[str, str] = {}
    globs: list[dict[str, str]] = []
    if registry is not None:
        for spec in registry.all():
            kind = getattr(spec.kind, "value", str(spec.kind))
            if any(c in spec.tool for c in "*?["):
                globs.append({"tool": spec.tool, "kind": kind})
            else:
                exact[spec.tool] = kind

    return {
        "schema": SCHEMA,
        "policy_id": f"{policy.name}@{policy.version}",
        "default_effect": policy.default_effect.value,
        "reversibility": dict(sorted(exact.items())),
        "reversibility_globs": globs,
        "unknown_tool_reversibility": unknown,
        "rules": [_rule_to_dict(r) for r in policy.rules],
    }


def classify(bundle: dict[str, Any], tool: str) -> str:
    """Reversibility of `tool`: exact match, then globs in order, then unknown."""
    hit = bundle["reversibility"].get(tool)
    if hit is not None:
        return hit
    for g in bundle.get("reversibility_globs", ()):
        if _glob(tool, g["tool"]):
            return g["kind"]
    return bundle["unknown_tool_reversibility"]


def dumps(bundle: dict[str, Any]) -> str:
    """Canonical JSON, so a bundle digest is stable across machines."""
    return json.dumps(bundle, sort_keys=True, separators=(",", ":"))


# ---------------------------------------------------------------------------
# The reference evaluator.
# ---------------------------------------------------------------------------
# This mirrors revoco's PolicyEngine against the *bundle* rather than against
# live objects. It exists so the fixtures can be generated from the same input
# the Go enforcer sees, which is what makes a mismatch mean "the two runtimes
# disagree" rather than "the two runtimes were asked different questions".


@dataclass(frozen=True)
class Call:
    tool: str
    action: str = "write"
    agent_id: str = "agent"
    roles: tuple[str, ...] = ()
    risk: int = 0
    threat_score: int = 0
    reversibility: str | None = None      # None -> look it up in the bundle


@dataclass(frozen=True)
class Verdict:
    effect: str
    rule_id: str
    reason: str
    reversibility: str
    allowed: bool


def _glob(value: str, pattern: str) -> bool:
    """Python `fnmatch.fnmatchcase` semantics, which the enforcer reimplements."""
    import fnmatch

    return fnmatch.fnmatchcase(value, pattern)


# Mirrors reversibilityRank in internal/decision/decision.go and
# Reversibility.rank in revoco. An unrecognised posture ranks below every floor
# rather than above it: a rank this build cannot compare is one it must not
# wave through.
_RANK = {"unknown": 0, "irreversible": 1, "compensable": 2, "reversible": 3,
         "idempotent": 4}


def _any_glob(value: str, patterns: list[str]) -> bool:
    return any(_glob(value, p) for p in patterns)


def evaluate(bundle: dict[str, Any], call: Call) -> Verdict:
    """First match wins. Kept deliberately close to revoco's `_rule_matches`."""
    rev = call.reversibility or classify(bundle, call.tool)

    for rule in bundle["rules"]:
        if not _any_glob(call.tool, rule["tools"]):
            continue
        if not _any_glob(call.action, rule["actions"]):
            continue
        if not _any_glob(call.agent_id, rule["agents"]):
            continue
        if rule["require_roles"] and not all(r in call.roles for r in rule["require_roles"]):
            continue
        floor = rule.get("min_reversibility")
        if floor is not None and _RANK.get(rev, -1) < _RANK.get(floor, 99):
            continue
        if rule["reversibility"] and rev not in rule["reversibility"]:
            continue
        if rule["min_threat_score"] is not None and call.threat_score < rule["min_threat_score"]:
            continue
        if rule["min_risk"] is not None and call.risk < rule["min_risk"]:
            continue
        if rule["max_risk"] is not None and call.risk > rule["max_risk"]:
            continue
        return Verdict(
            effect=rule["effect"],
            rule_id=rule["id"],
            reason=rule["reason"],
            reversibility=rev,
            allowed=rule["effect"] == "allow",
        )

    default = bundle["default_effect"]
    return Verdict(
        effect=default,
        rule_id="__default__",
        reason=f"no rule matched; default {default}",
        reversibility=rev,
        allowed=default == "allow",
    )
