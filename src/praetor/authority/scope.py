"""
praetor.authority.scope
=======================
The capability model.

A :class:`Scope` is the set of authorities a principal may exercise: which
tools it may call, which action types it may perform, the maximum risk level it
may reach, and arbitrary key/value constraints (e.g. ``max_amount_usd``).

The critical security property is **attenuation**: when authority is delegated
onward, the child scope must be a *subset* of the parent scope. A sub-agent can
only ever lose authority, never gain it. Same principle as SPKI/SDSI and
macaroons, and it is what stops a deep delegation chain from silently
escalating privilege.

New in the merged control plane
-------------------------------
``min_reversibility`` states the weakest reversal posture an action taken under
this scope may have. A grant can therefore say "this agent may only take
actions I can undo" — authority and recoverability expressed in the same
object, and attenuated by the same rule as everything else. This is the hook
that lets the reversal engine act as a real authorization gate rather than a
logging sidecar.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any

from ..core.errors import ValidationError
from ..reversal.model import Reversibility

# A sentinel meaning "all tools" / "all actions". Use sparingly; a root human
# grant may use it, but every sub-delegation should narrow it.
WILDCARD = "*"

_MAX_SET_SIZE = 4096
_MAX_STR_LEN = 512


def _validate_token_set(values: set[str], name: str) -> set[str]:
    if len(values) > _MAX_SET_SIZE:
        raise ValidationError(f"{name} exceeds maximum size {_MAX_SET_SIZE}")
    for v in values:
        if not isinstance(v, str):
            raise ValidationError(f"{name} entries must be strings")
        if len(v) == 0 or len(v) > _MAX_STR_LEN:
            raise ValidationError(f"{name} entry has invalid length")
    return set(values)


@dataclass(frozen=True)
class Scope:
    """An immutable set of authorities.

    ``max_risk`` is a 0-100 band used by detectors and approval gates; lower is
    safer. ``constraints`` carries numeric/string limits; numeric values are
    attenuated by "child must be <= parent".

    A constraint key of the form ``max:<dotted.arg.path>`` is **enforced** at
    action time as an upper bound on that call argument, using the tightest cap
    anywhere in the chain::

        Scope.make(tools={"invoices.pay"}, constraints={"max:amount": 50_000})

    Any other constraint key is free-form metadata that policy and detectors may
    read but nothing enforces automatically. The explicit prefix exists so the
    difference is visible in the grant itself — a key that merely looks like a
    limit is worse than no limit, because authority gets delegated more freely on
    the strength of it.
    """

    allowed_tools: frozenset[str] = field(default_factory=frozenset)
    allowed_actions: frozenset[str] = field(default_factory=frozenset)
    max_risk: int = 0
    constraints: tuple[tuple[str, Any], ...] = field(default_factory=tuple)
    min_reversibility: Reversibility = Reversibility.UNKNOWN

    def __post_init__(self) -> None:
        _validate_token_set(set(self.allowed_tools), "allowed_tools")
        _validate_token_set(set(self.allowed_actions), "allowed_actions")
        if not isinstance(self.max_risk, int) or not (0 <= self.max_risk <= 100):
            raise ValidationError("max_risk must be an int in [0, 100]")
        if not isinstance(self.min_reversibility, Reversibility):
            raise ValidationError("min_reversibility must be a Reversibility")

    # ---- constructors -----------------------------------------------------
    @classmethod
    def make(
        cls,
        tools: set[str] | None = None,
        actions: set[str] | None = None,
        max_risk: int = 0,
        constraints: dict[str, Any] | None = None,
        min_reversibility: Reversibility = Reversibility.UNKNOWN,
    ) -> Scope:
        return cls(
            allowed_tools=frozenset(tools or set()),
            allowed_actions=frozenset(actions or set()),
            max_risk=max_risk,
            constraints=tuple(sorted((constraints or {}).items())),
            min_reversibility=min_reversibility,
        )

    @property
    def constraint_map(self) -> dict[str, Any]:
        return dict(self.constraints)

    # ---- capability checks ------------------------------------------------
    def _tool_allowed(self, tool: str) -> bool:
        return WILDCARD in self.allowed_tools or tool in self.allowed_tools

    def _action_allowed(self, action: str) -> bool:
        return WILDCARD in self.allowed_actions or action in self.allowed_actions

    def permits_action(self, tool: str, action: str, risk: int) -> bool:
        """Whether a concrete action is within this scope."""
        return (
            self._tool_allowed(tool)
            and self._action_allowed(action)
            and 0 <= risk <= self.max_risk
        )

    def permits_reversibility(self, kind: Reversibility) -> bool:
        """Whether an action with reversal posture ``kind`` is within scope.

        ``UNKNOWN`` as the scope's floor means "no requirement stated".
        """
        if self.min_reversibility is Reversibility.UNKNOWN:
            return True
        return kind.rank >= self.min_reversibility.rank

    def contains(self, child: Scope) -> bool:
        """True iff ``child`` is an attenuation (subset) of ``self``.

        This is the recursive-delegation safety check.
        """
        # Tools: every child tool must be permitted by the parent.
        if WILDCARD not in self.allowed_tools:
            if WILDCARD in child.allowed_tools:
                return False
            if not child.allowed_tools.issubset(self.allowed_tools):
                return False
        # Actions: same rule.
        if WILDCARD not in self.allowed_actions:
            if WILDCARD in child.allowed_actions:
                return False
            if not child.allowed_actions.issubset(self.allowed_actions):
                return False
        # Risk must not increase.
        if child.max_risk > self.max_risk:
            return False
        # A child may only demand an equal or STRICTER reversal floor. Relaxing
        # the floor downward would let a sub-agent take irreversible actions
        # under authority granted on the promise that everything was undoable —
        # exactly the escalation this field exists to prevent.
        if self.min_reversibility is not Reversibility.UNKNOWN:
            if child.min_reversibility is Reversibility.UNKNOWN:
                return False
            if child.min_reversibility.rank < self.min_reversibility.rank:
                return False
        # Numeric constraints follow capability/caveat semantics: a parent cap
        # always binds the child via the chain (see effective_constraints), so a
        # child that omits a cap *inherits* it — that is not escalation. A child
        # may only ever tighten. Therefore the only violation is a child that
        # *states* a looser (larger) value than the parent's cap.
        parent_c = self.constraint_map
        child_c = child.constraint_map
        for key, parent_val in parent_c.items():
            if isinstance(parent_val, (int, float)) and not isinstance(parent_val, bool):
                if key in child_c:
                    child_val = child_c[key]
                    if not isinstance(child_val, (int, float)) or child_val > parent_val:
                        return False
        return True

    @staticmethod
    def effective_constraints(chain_scopes: list[Scope]) -> dict[str, Any]:
        """Tightest numeric cap for each key across a chain of scopes.

        Because caps are inherited, the authority actually in force at the leaf
        is the minimum of every ancestor's cap. Action-time enforcement uses
        this so an omitted cap still binds.
        """
        effective: dict[str, Any] = {}
        for s in chain_scopes:
            for key, val in s.constraint_map.items():
                if isinstance(val, (int, float)) and not isinstance(val, bool):
                    effective[key] = min(effective.get(key, val), val)
        return effective

    @staticmethod
    def effective_reversibility_floor(chain_scopes: list[Scope]) -> Reversibility:
        """The strictest reversal floor anywhere in the chain.

        Same inheritance logic as numeric caps: an ancestor's requirement binds
        every descendant, so the floor in force at the leaf is the maximum.
        """
        floor = Reversibility.UNKNOWN
        for s in chain_scopes:
            if s.min_reversibility is Reversibility.UNKNOWN:
                continue
            if floor is Reversibility.UNKNOWN or s.min_reversibility.rank > floor.rank:
                floor = s.min_reversibility
        return floor

    def to_dict(self) -> dict[str, Any]:
        return {
            "allowed_tools": sorted(self.allowed_tools),
            "allowed_actions": sorted(self.allowed_actions),
            "max_risk": self.max_risk,
            "constraints": dict(self.constraints),
            "min_reversibility": self.min_reversibility.value,
        }

    @classmethod
    def from_dict(cls, d: dict[str, Any]) -> Scope:
        return cls.make(
            tools=set(d.get("allowed_tools", [])),
            actions=set(d.get("allowed_actions", [])),
            max_risk=int(d.get("max_risk", 0)),
            constraints=dict(d.get("constraints", {})),
            min_reversibility=Reversibility(
                d.get("min_reversibility", Reversibility.UNKNOWN.value)
            ),
        )
