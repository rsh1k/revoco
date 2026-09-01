"""
revoco.gate.policy
===================
Declarative, version-controllable policy-as-code.

A policy is an ordered list of rules. For a given tool call, rules are evaluated
top to bottom and the FIRST matching rule wins, like a firewall ruleset. If
nothing matches, ``default_effect`` applies — which should be DENY for a
locked-down posture.

A rule matches on: which tool, which agent (id glob and/or required roles), the
action's reversal posture, a threat-score floor, and an argument-aware
condition. It produces an Effect plus optional redaction fields and budget
tracking.

The schema is plain YAML/JSON so it diffs cleanly in a pull request. The point is
that a security team reviews policy the way it reviews Terraform.

New in the merged control plane
-------------------------------
``reversibility`` lets a rule match on whether the action can be undone::

    - id: no-undo-needs-a-human
      effect: require_approval
      reversibility: [irreversible, unknown]
      reason: "No rollback path exists, so a person must own this decision."

Those five lines are the thesis of this whole package. Enforcement stops being a
question only about permission ("may this agent do it?") and starts also being a
question about recoverability ("and can we take it back if it was wrong?").
Unclassified tools are grouped with irreversible ones deliberately: the safe
reading of "we have not mapped an undo for this yet" is "assume there is none".

``reversibility`` is an exact set, and the mirror of the rule above is easy to
forget: an *allow* rule naming ``[reversible, compensable]`` silently excludes
``idempotent``, refusing the one class of action that changed nothing at all.
Every value added to the taxonomy repeats that, in every policy anyone has
already written, and the failure is silent — the new class matches no rule and
falls through to the default effect.

So allow rules should state a floor instead::

    - id: undoable-writes
      effect: allow
      min_reversibility: compensable

which admits compensable, reversible and idempotent by rank, and keeps admitting
whatever safer class is defined next. The two are mutually exclusive: a rule
gives a set or a floor, never both.
"""

from __future__ import annotations

import json
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from ..core.errors import PolicyError
from ..reversal.model import Reversibility
from .conditions import AlwaysTrue, Condition, parse_condition
from .decision import Effect

__all__ = ["Policy", "Rule", "Budget", "load_policy", "starter_policy"]


@dataclass(frozen=True)
class Budget:
    """A cumulative ceiling enforced across a session.

    ``{"key": "refund_total", "field": "amount", "limit": 2000}`` means: sum the
    ``amount`` argument across all calls matching this rule within one session;
    once the running total would exceed 2000 the rule stops matching, so
    evaluation falls through to whatever rule or default handles the over-limit
    case. Budgets are what make enforcement stateful rather than per-call.
    """

    key: str
    field: str
    limit: float


@dataclass(frozen=True)
class Rule:
    id: str
    effect: Effect
    tools: tuple[str, ...] = ("*",)          # globs
    agents: tuple[str, ...] = ("*",)         # agent-id globs
    require_roles: tuple[str, ...] = ()      # agent must hold ALL of these
    actions: tuple[str, ...] = ("*",)        # action-type globs: read/write/...
    reversibility: tuple[Reversibility, ...] = ()   # exact set; empty = any
    # A floor instead of a set, compared on rank. Prefer it in allow rules: a set
    # has to be revisited every time the taxonomy gains a value, and the failure
    # mode of forgetting is silent — the new class matches nothing and falls
    # through to the default effect.
    min_reversibility: Reversibility | None = None
    condition: Condition = field(default_factory=AlwaysTrue)
    redact_fields: tuple[str, ...] = ()
    budget: Budget | None = None
    min_threat_score: int | None = None
    max_risk: int | None = None
    # Lower bound on the caller-assigned risk band. Added because the containment
    # benchmark showed a reversibility-only escalation rule is too blunt to ship:
    # sending an email is irreversible AND entirely routine, so "escalate anything
    # irreversible" sends every notification to a human and the control plane gets
    # switched off inside a week. Pairing reversibility with a risk floor is what
    # separates irreversible-and-consequential from irreversible-and-ordinary.
    min_risk: int | None = None
    reason: str = ""
    obligations: dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> dict[str, Any]:
        return {
            "id": self.id,
            "effect": self.effect.value,
            "tools": list(self.tools),
            "agents": list(self.agents),
            "actions": list(self.actions),
            "require_roles": list(self.require_roles),
            "reversibility": [r.value for r in self.reversibility],
            "min_reversibility": (
                self.min_reversibility.value if self.min_reversibility else None
            ),
            "when": self.condition.to_dict(),
            "redact_fields": list(self.redact_fields),
            "budget": (
                {"key": self.budget.key, "field": self.budget.field, "limit": self.budget.limit}
                if self.budget
                else None
            ),
            "min_threat_score": self.min_threat_score,
            "max_risk": self.max_risk,
            "min_risk": self.min_risk,
            "reason": self.reason,
            "obligations": self.obligations,
        }


@dataclass(frozen=True)
class Policy:
    rules: tuple[Rule, ...]
    default_effect: Effect = Effect.DENY
    version: str = "0"
    name: str = "unnamed-policy"

    def digest(self) -> str:
        """Content digest of the policy.

        Recorded alongside every decision so an evidence pack can prove which
        exact ruleset produced a given verdict. "We had a control" is not an
        answer an auditor can test; "this decision was made under policy
        sha256:ab12... , here is that document" is.
        """
        from ..core import crypto

        return crypto.digest_of(
            {
                "name": self.name,
                "version": self.version,
                "default_effect": self.default_effect.value,
                "rules": [r.to_dict() for r in self.rules],
            }
        )

    def to_dict(self) -> dict[str, Any]:
        return {
            "name": self.name,
            "version": self.version,
            "default_effect": self.default_effect.value,
            "digest": self.digest(),
            "rules": [r.to_dict() for r in self.rules],
        }


_VALID_EFFECTS = {e.value for e in Effect}
_VALID_REVERSIBILITY = {r.value for r in Reversibility}


def _parse_rule(raw: dict[str, Any], index: int) -> Rule:
    rid = str(raw.get("id") or f"rule-{index}")

    effect_str = raw.get("effect")
    if effect_str not in _VALID_EFFECTS:
        raise PolicyError(
            f"rule '{rid}': effect must be one of {sorted(_VALID_EFFECTS)}, got {effect_str!r}"
        )
    effect = Effect(effect_str)

    def as_tuple(value: Any, name: str) -> tuple[str, ...]:
        if value is None:
            return ()
        if isinstance(value, str):
            return (value,)
        if isinstance(value, list) and all(isinstance(v, str) for v in value):
            return tuple(value)
        raise PolicyError(f"rule '{rid}': '{name}' must be a string or list of strings")

    tools = as_tuple(raw.get("tools", "*"), "tools") or ("*",)
    agents = as_tuple(raw.get("agents", "*"), "agents") or ("*",)
    actions = as_tuple(raw.get("actions", "*"), "actions") or ("*",)
    require_roles = as_tuple(raw.get("require_roles"), "require_roles")
    redact_fields = as_tuple(raw.get("redact_fields"), "redact_fields")

    rev_raw = as_tuple(raw.get("reversibility"), "reversibility")
    for r in rev_raw:
        if r not in _VALID_REVERSIBILITY:
            raise PolicyError(
                f"rule '{rid}': reversibility must be from {sorted(_VALID_REVERSIBILITY)}, got {r!r}"
            )
    reversibility = tuple(Reversibility(r) for r in rev_raw)

    min_rev_raw = raw.get("min_reversibility")
    min_reversibility = None
    if min_rev_raw is not None:
        if min_rev_raw not in _VALID_REVERSIBILITY:
            raise PolicyError(
                f"rule '{rid}': min_reversibility must be one of "
                f"{sorted(_VALID_REVERSIBILITY)}, got {min_rev_raw!r}"
            )
        if reversibility:
            raise PolicyError(
                f"rule '{rid}': give either 'reversibility' (an exact set) or "
                "'min_reversibility' (a floor), not both — two answers to which "
                "postures match is no answer"
            )
        min_reversibility = Reversibility(min_rev_raw)

    condition = parse_condition(raw.get("when")) if raw.get("when") is not None else AlwaysTrue()

    budget = None
    # `is not None` rather than `in raw`: to_dict() writes every field explicitly,
    # including `"budget": null`, so a rule could not be loaded back from its own
    # serialized form. Anything that compiles a policy to a portable bundle round
    # trips through exactly this path.
    if raw.get("budget") is not None:
        b = raw["budget"]
        try:
            budget = Budget(key=str(b["key"]), field=str(b["field"]), limit=float(b["limit"]))
        except (KeyError, TypeError, ValueError) as exc:
            raise PolicyError(f"rule '{rid}': budget needs key, field, numeric limit") from exc

    if effect is Effect.REDACT and not redact_fields:
        raise PolicyError(f"rule '{rid}': effect 'redact' requires redact_fields")

    def opt_int(name: str) -> int | None:
        # Same reason as `budget` above: an explicitly serialized null means absent,
        # not malformed, or a rule cannot survive its own to_dict().
        if raw.get(name) is None:
            return None
        try:
            return int(raw[name])
        except (TypeError, ValueError) as exc:
            raise PolicyError(f"rule '{rid}': {name} must be an integer") from exc

    return Rule(
        id=rid,
        effect=effect,
        tools=tools,
        agents=agents,
        actions=actions,
        require_roles=require_roles,
        reversibility=reversibility,
        min_reversibility=min_reversibility,
        condition=condition,
        redact_fields=redact_fields,
        budget=budget,
        min_threat_score=opt_int("min_threat_score"),
        max_risk=opt_int("max_risk"),
        min_risk=opt_int("min_risk"),
        reason=str(raw.get("reason", "")),
        obligations=dict(raw.get("obligations", {})),
    )


def load_policy(source: str | Path | dict[str, Any]) -> Policy:
    """Load a policy from a YAML/JSON path or an already-parsed dict."""
    if isinstance(source, dict):
        data = source
    else:
        path = Path(source)
        text = path.read_text()
        if path.suffix in (".yaml", ".yml"):
            try:
                import yaml
            except ImportError as exc:
                raise PolicyError(
                    "PyYAML not installed; use JSON or "
                    "`pip install revoco[yaml]`"
                ) from exc
            data = yaml.safe_load(text)
        else:
            data = json.loads(text)

    if not isinstance(data, dict):
        raise PolicyError("policy root must be a mapping")

    default_str = data.get("default_effect", "deny")
    if default_str not in _VALID_EFFECTS:
        raise PolicyError(f"default_effect must be one of {sorted(_VALID_EFFECTS)}")

    raw_rules = data.get("rules", [])
    if not isinstance(raw_rules, list):
        raise PolicyError("'rules' must be a list")

    rules = tuple(_parse_rule(r, i) for i, r in enumerate(raw_rules))

    seen: set[str] = set()
    for r in rules:
        if r.id in seen:
            raise PolicyError(f"duplicate rule id: {r.id}")
        seen.add(r.id)

    return Policy(
        rules=rules,
        default_effect=Effect(default_str),
        version=str(data.get("version", "0")),
        name=str(data.get("name", "unnamed-policy")),
    )


# ---------------------------------------------------------------------------
# A starter policy demonstrating the reversibility-aware posture.
# ---------------------------------------------------------------------------

STARTER_POLICY: dict[str, Any] = {
    "name": "ap-reversibility-first",
    "version": "1",
    "default_effect": "deny",
    "rules": [
        {
            "id": "reads-always-fine",
            "effect": "allow",
            "actions": ["read"],
            "reason": "Reads change nothing and carry no rollback obligation.",
        },
        {
            "id": "hold-injection-suspects",
            "effect": "require_approval",
            "min_threat_score": 4,
            "reason": "Arguments carry markers of injected instructions; a human decides.",
        },
        {
            "id": "no-undo-needs-a-human",
            "effect": "require_approval",
            "reversibility": ["irreversible", "unknown"],
            "reason": (
                "No rollback path exists for this action, so a person must own the "
                "decision rather than inherit it from an agent."
            ),
        },
        {
            "id": "bounded-reversible-payments",
            "effect": "allow",
            "tools": ["invoices.pay", "invoices.approve"],
            "min_reversibility": "compensable",
            "budget": {"key": "payments_total", "field": "amount", "limit": 25_000},
            "reason": "Undoable payment within the session ceiling.",
        },
        {
            "id": "vendor-master-changes-are-reviewed",
            "effect": "require_approval",
            "tools": ["vendors.*"],
            "reason": (
                "Vendor-master edits are the standard payment-fraud vector; they are "
                "reversible here, but they still get a second pair of eyes."
            ),
        },
    ],
}


def starter_policy() -> Policy:
    """The illustrative reversibility-first policy, parsed."""
    return load_policy(STARTER_POLICY)
