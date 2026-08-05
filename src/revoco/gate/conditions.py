"""
revoco.gate.conditions
=======================
A small, SAFE predicate language over tool-call arguments.

Policies need to say things like "amount under 500" or "path starts with /etc".
The unsafe way is ``eval()`` on a string, which hands arbitrary code execution
to whoever writes policy — defeating the entire purpose of having a policy
layer. Instead this module defines a tiny declarative condition tree built from
plain dicts. There is no code execution anywhere in it.

Condition forms (as they appear under a rule's ``when:`` key)::

  {"field": "amount", "op": "lt", "value": 500}
  {"field": "path", "op": "startswith", "value": "/etc"}
  {"all": [ {...}, {...} ]}          # logical AND
  {"any": [ {...}, {...} ]}          # logical OR
  {"not": {...}}                     # negation

``field`` is a dotted path into the call arguments, e.g. ``filters.region``.
Supported ops: eq ne lt le gt ge in not_in contains startswith endswith regex
exists.
"""

from __future__ import annotations

import re
from dataclasses import dataclass
from typing import Any

from ..core.errors import PolicyError

# Bound on regex work per evaluation. A pathological pattern in policy is a
# denial-of-service against the control plane itself, and a control plane that
# stops answering is a control plane that fails open somewhere downstream.
_MAX_REGEX_INPUT = 8192


def _resolve(path: str, args: dict[str, Any]) -> tuple[bool, Any]:
    """Resolve a dotted path. Returns ``(found, value)``."""
    cur: Any = args
    for part in path.split("."):
        if isinstance(cur, dict) and part in cur:
            cur = cur[part]
        else:
            return False, None
    return True, cur


class Condition:
    """Base condition. Subclasses implement :meth:`evaluate`."""

    def evaluate(self, args: dict[str, Any]) -> bool:  # pragma: no cover
        raise NotImplementedError

    def to_dict(self) -> Any:  # pragma: no cover
        raise NotImplementedError


@dataclass(frozen=True)
class AlwaysTrue(Condition):
    def evaluate(self, args: dict[str, Any]) -> bool:
        return True

    def to_dict(self) -> Any:
        return None


@dataclass(frozen=True)
class Comparison(Condition):
    field: str
    op: str
    value: Any = None

    def evaluate(self, args: dict[str, Any]) -> bool:
        found, actual = _resolve(self.field, args)

        if self.op == "exists":
            return found
        if not found:
            # A missing field can never satisfy a value comparison. Deliberate
            # fail-safe: absent data does not accidentally match.
            return False

        op, v = self.op, self.value
        try:
            if op == "eq":
                return actual == v
            if op == "ne":
                return actual != v
            if op == "lt":
                return _num(actual) < _num(v)
            if op == "le":
                return _num(actual) <= _num(v)
            if op == "gt":
                return _num(actual) > _num(v)
            if op == "ge":
                return _num(actual) >= _num(v)
            if op == "in":
                return actual in v
            if op == "not_in":
                return actual not in v
            if op == "contains":
                return v in actual
            if op == "startswith":
                return str(actual).startswith(str(v))
            if op == "endswith":
                return str(actual).endswith(str(v))
            if op == "regex":
                return re.search(str(v), str(actual)[:_MAX_REGEX_INPUT]) is not None
        except (TypeError, ValueError):
            # Type mismatch (e.g. `lt` on a string) fails the condition rather
            # than crashing. Failing the condition is safer than failing the
            # request open.
            return False

        raise PolicyError(f"unknown op: {op}")

    def to_dict(self) -> Any:
        return {"field": self.field, "op": self.op, "value": self.value}


def _num(x: Any) -> float:
    if isinstance(x, bool):  # bool subclasses int; reject to avoid surprises
        raise ValueError("bool not comparable as number")
    return float(x)


@dataclass(frozen=True)
class And(Condition):
    parts: tuple[Condition, ...]

    def evaluate(self, args: dict[str, Any]) -> bool:
        return all(p.evaluate(args) for p in self.parts)

    def to_dict(self) -> Any:
        return {"all": [p.to_dict() for p in self.parts]}


@dataclass(frozen=True)
class Or(Condition):
    parts: tuple[Condition, ...]

    def evaluate(self, args: dict[str, Any]) -> bool:
        return any(p.evaluate(args) for p in self.parts)

    def to_dict(self) -> Any:
        return {"any": [p.to_dict() for p in self.parts]}


@dataclass(frozen=True)
class Not(Condition):
    inner: Condition

    def evaluate(self, args: dict[str, Any]) -> bool:
        return not self.inner.evaluate(args)

    def to_dict(self) -> Any:
        return {"not": self.inner.to_dict()}


_VALID_OPS = {
    "eq", "ne", "lt", "le", "gt", "ge", "in", "not_in",
    "contains", "startswith", "endswith", "regex", "exists",
}

_MAX_DEPTH = 32


def parse_condition(raw: Any, _depth: int = 0) -> Condition:
    """Build a Condition tree from plain data. Raises PolicyError on bad input."""
    if _depth > _MAX_DEPTH:
        raise PolicyError(f"condition nesting exceeds {_MAX_DEPTH} levels")
    if raw is None:
        return AlwaysTrue()
    if not isinstance(raw, dict):
        raise PolicyError(f"condition must be a mapping, got {type(raw).__name__}")

    if "all" in raw:
        return And(tuple(parse_condition(p, _depth + 1) for p in raw["all"]))
    if "any" in raw:
        return Or(tuple(parse_condition(p, _depth + 1) for p in raw["any"]))
    if "not" in raw:
        return Not(parse_condition(raw["not"], _depth + 1))

    if "field" in raw and "op" in raw:
        op = raw["op"]
        if op not in _VALID_OPS:
            raise PolicyError(f"unknown condition op {op!r}; valid: {sorted(_VALID_OPS)}")
        return Comparison(field=str(raw["field"]), op=op, value=raw.get("value"))

    raise PolicyError(f"unrecognized condition shape: {raw!r}")
