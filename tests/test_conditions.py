"""The condition operators, which decide whether a policy rule matches.

Before this file, two of thirteen operators had a test. The other eleven gate
real authorization decisions and nothing exercised them, so an inverted
comparison in any of them would have mis-authorized silently and passed CI.

Each operator is asserted in both directions. An operator tested only where it
returns True cannot distinguish a working comparison from `return True`.
"""

from __future__ import annotations

import pytest

from revoco.core.errors import PolicyError
from revoco.gate.conditions import parse_condition


def ev(cond: dict, args: dict) -> bool:
    return parse_condition(cond).evaluate(args)


def cmp_(field: str, op: str, value=None) -> dict:
    return {"field": field, "op": op, "value": value}


# ---- every operator, both directions ---------------------------------------

@pytest.mark.parametrize("op,value,matching,not_matching", [
    ("eq",         500,       500,        501),
    ("ne",         500,       501,        500),
    ("lt",         500,       499,        500),
    ("le",         500,       500,        501),
    ("gt",         500,       501,        500),
    ("ge",         500,       500,        499),
    ("in",         [1, 2, 3], 2,          9),
    ("not_in",     [1, 2, 3], 9,          2),
    ("contains",   "ab",      "xabx",     "xx"),
    ("startswith", "/etc",    "/etc/x",   "/usr/etc"),
    ("endswith",   ".pem",    "k.pem",    "k.pub"),
    ("regex",      r"^s3://", "s3://b/k", "gs://b/k"),
])
def test_each_operator_separates_a_match_from_a_non_match(op, value, matching, not_matching):
    assert ev(cmp_("f", op, value), {"f": matching}) is True
    assert ev(cmp_("f", op, value), {"f": not_matching}) is False


def test_exists_reports_presence_not_truthiness():
    """A field set to zero, empty string or false is present. Conflating
    presence with truthiness would let `amount: 0` look like no amount."""
    assert ev(cmp_("f", "exists"), {"f": 0}) is True
    assert ev(cmp_("f", "exists"), {"f": ""}) is True
    assert ev(cmp_("f", "exists"), {"f": False}) is True
    assert ev(cmp_("f", "exists"), {}) is False


# ---- the fail-safe directions ----------------------------------------------

def test_a_missing_field_never_satisfies_a_comparison():
    """Absent data must not accidentally match. `ne` is the trap: a missing
    field is arguably 'not equal' to anything, and treating it that way would
    make an absent argument satisfy a restriction meant to exclude a value."""
    for op, value in (("eq", 1), ("ne", 1), ("lt", 1), ("gt", 1),
                      ("in", [1]), ("not_in", [1]), ("contains", "a"),
                      ("startswith", "a"), ("endswith", "a"), ("regex", "a")):
        assert ev(cmp_("absent", op, value), {"present": 1}) is False, op


def test_a_type_mismatch_fails_the_condition_rather_than_the_request():
    """`lt` against a string is a policy-authoring mistake. Raising would fail
    the request open or crash the gate; failing the condition is the safe
    direction and the rule simply does not match."""
    assert ev(cmp_("f", "lt", 5), {"f": "not-a-number"}) is False
    assert ev(cmp_("f", "gt", 5), {"f": None}) is False
    assert ev(cmp_("f", "contains", "a"), {"f": 5}) is False


def test_a_boolean_is_not_silently_compared_as_a_number():
    """`True` is `1` in Python. Allowing it through a numeric comparison means
    `approved: true` would satisfy `amount ge 1`, which is nonsense a policy
    author would never intend and would never see."""
    assert ev(cmp_("f", "ge", 1), {"f": True}) is False
    assert ev(cmp_("f", "lt", 1), {"f": False}) is False


def test_regex_input_is_bounded():
    """An unbounded regex over attacker-supplied arguments is a denial-of-service
    surface. Input is truncated before matching, so a pattern anchored past the
    cap cannot be made to match by sending more data."""
    from revoco.gate.conditions import _MAX_REGEX_INPUT

    huge = "a" * (_MAX_REGEX_INPUT + 50) + "NEEDLE"
    assert ev(cmp_("f", "regex", "NEEDLE"), {"f": huge}) is False
    assert ev(cmp_("f", "regex", "NEEDLE"), {"f": "NEEDLE"}) is True


# ---- structure --------------------------------------------------------------

def test_nested_fields_resolve_by_dotted_path():
    assert ev(cmp_("a.b.c", "eq", 1), {"a": {"b": {"c": 1}}}) is True
    assert ev(cmp_("a.b.c", "eq", 1), {"a": {"b": {}}}) is False


def test_and_or_not_compose():
    inner = [cmp_("x", "eq", 1), cmp_("y", "eq", 2)]
    assert ev({"all": inner}, {"x": 1, "y": 2}) is True
    assert ev({"all": inner}, {"x": 1, "y": 3}) is False
    assert ev({"any": inner}, {"x": 1, "y": 3}) is True
    assert ev({"any": inner}, {"x": 9, "y": 3}) is False
    assert ev({"not": cmp_("x", "eq", 1)}, {"x": 2}) is True
    assert ev({"not": cmp_("x", "eq", 1)}, {"x": 1}) is False


def test_an_unknown_operator_is_refused_at_parse_time():
    """Rejecting at parse rather than evaluation means a typo fails when the
    policy is loaded, not on the one call that happens to reach the rule."""
    with pytest.raises(PolicyError, match="op"):
        parse_condition(cmp_("f", "approximately", 1))
