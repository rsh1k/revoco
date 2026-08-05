"""
praetor.gate.decision
=====================
Decision types: the vocabulary the enforcement layer speaks.

A policy evaluation always produces exactly one Decision. The four effects cover
the real enforcement modes an enterprise needs:

  ALLOW             forward the call unchanged
  DENY              block the call
  REQUIRE_APPROVAL  pause and ask a human
  REDACT            forward, but with named argument fields masked

Keeping this set small and explicit is deliberate: every code path that touches
enforcement must handle all four, so exhaustiveness is structural rather than
remembered.
"""

from __future__ import annotations

import enum
from dataclasses import dataclass, field
from typing import Any


class Effect(enum.Enum):
    ALLOW = "allow"
    DENY = "deny"
    REQUIRE_APPROVAL = "require_approval"
    REDACT = "redact"


@dataclass(frozen=True)
class Decision:
    """The outcome of evaluating one tool call against policy.

    ``effect``        what to do with the call
    ``rule_id``       which rule produced this decision (audit + debugging)
    ``reason``        human-readable explanation
    ``redact_fields`` for REDACT: dotted paths into the arguments to mask
    ``obligations``   free-form metadata the enforcement layer may act on
                      (e.g. ``{"notify": "secops-slack"}``). Open on purpose so
                      behavior can be extended without changing this type.
    """

    effect: Effect
    rule_id: str
    reason: str
    redact_fields: tuple[str, ...] = ()
    obligations: dict[str, Any] = field(default_factory=dict)

    @property
    def allowed(self) -> bool:
        return self.effect is Effect.ALLOW

    @property
    def blocks(self) -> bool:
        return self.effect in (Effect.DENY, Effect.REQUIRE_APPROVAL)

    def to_dict(self) -> dict[str, Any]:
        return {
            "effect": self.effect.value,
            "rule_id": self.rule_id,
            "reason": self.reason,
            "redact_fields": list(self.redact_fields),
            "obligations": self.obligations,
        }
