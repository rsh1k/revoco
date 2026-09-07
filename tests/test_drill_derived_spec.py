"""A drill must be able to see a spec the classifier derived, not just a declared one.

`DrillRunner` resolved the canary's spec with `registry.get`, which only knows
declared specs. A classifier-backed command therefore reported NOT_DRILLABLE --
"nothing here to prove" -- when the truth was that the runner could not see it.
The two readings are opposite and the report showed the reassuring one.
"""

from __future__ import annotations

from typing import Any

from revoco.drills import Canary, DrillOutcome, DrillRunner
from revoco.reversal.model import InverseSpec, Reversibility
from revoco.reversal.registry import InverseRegistry

TOOL = "shell.guarded"


class World:
    """A single value, changed by the forward call and put back by the inverse."""

    def __init__(self) -> None:
        self.value = "before"
        self.saved: str | None = None

    def execute(self, tool: str, args: dict[str, Any]) -> dict[str, Any]:
        if tool == TOOL:
            self.saved = self.value
            self.value = "after"
            return {"saved": self.saved}
        if tool == "world.restore":
            self.value = args.get("saved") or self.saved or self.value
            return {"restored": True}
        raise AssertionError(f"unexpected tool {tool}")

    def read(self, tool: str, args: dict[str, Any]) -> dict[str, Any]:
        return {"value": self.value}


def _spec() -> InverseSpec:
    return InverseSpec(
        tool=TOOL,
        kind=Reversibility.REVERSIBLE,
        inverse_tool="world.restore",
        # No arg_map: the executor restores from what it saved on the way in.
        # The point under test is that the drill *sees* a derived spec at all,
        # not how its arguments are wired.
    )


def _canary() -> Canary:
    world = World()
    return world, Canary(
        tool=TOOL,
        args={"command": "rm -rf build"},
        verify=lambda: {"value": world.value},
        label="derived",
    )


def test_without_a_classifier_a_derived_spec_is_invisible() -> None:
    """The behaviour that was wrong, pinned so the fix cannot silently revert."""
    world, canary = _canary()
    runner = DrillRunner(
        InverseRegistry(), executor=world.execute, state_reader=world.read
    )
    assert runner.drill(canary).outcome is DrillOutcome.NOT_DRILLABLE


def test_with_a_classifier_the_derived_spec_is_drilled() -> None:
    world, canary = _canary()
    runner = DrillRunner(
        InverseRegistry(),
        executor=world.execute,
        state_reader=world.read,
        command_classifier=lambda tool, args: _spec() if tool == TOOL else None,
    )
    result = runner.drill(canary)
    assert result.outcome is DrillOutcome.PASSED, result.summary
    assert result.declared_kind is Reversibility.REVERSIBLE
    assert world.value == "before", "the inverse actually ran"


def test_a_declared_spec_still_wins_over_a_derived_one() -> None:
    """Same bound as in the engine: the classifier fills holes, never overrides."""
    world, canary = _canary()
    registry = InverseRegistry()
    registry.register(
        InverseSpec(tool=TOOL, kind=Reversibility.IRREVERSIBLE, notes="declared")
    )
    runner = DrillRunner(
        registry,
        executor=world.execute,
        state_reader=world.read,
        command_classifier=lambda tool, args: _spec(),
    )
    # IRREVERSIBLE is not undoable, so the declared spec makes this not drillable.
    result = runner.drill(canary)
    assert result.outcome is DrillOutcome.NOT_DRILLABLE
    assert result.declared_kind is Reversibility.IRREVERSIBLE


# ---- a seam that answers wrongly is not the same as one that declines --------

def _events() -> tuple[list[tuple[str, dict[str, Any]]], Any]:
    seen: list[tuple[str, dict[str, Any]]] = []
    return seen, lambda name, payload: seen.append((name, payload))


def test_a_raising_classifier_is_reported_not_just_swallowed() -> None:
    """Found the hard way: a TypeError in a classifier looked like "no opinion".

    The engine must not let a broken seam take the call down, so it returns None
    -- but None is also what a classifier says when it has nothing to offer. One
    that raises on every call would otherwise be indistinguishable from one that
    was never wired up at all.
    """
    from revoco.reversal.engine import EVT_SEAM_FAILED, ReversalEngine

    seen, sink = _events()

    def broken(tool: str, args: dict[str, Any]) -> InverseSpec:
        raise TypeError("unexpected keyword argument 'capture'")

    engine = ReversalEngine(
        InverseRegistry(), command_classifier=broken, on_event=sink
    )
    assert engine.spec_for(TOOL, {"command": "x"}) is None
    failures = [p for n, p in seen if n == EVT_SEAM_FAILED]
    assert len(failures) == 1
    assert failures[0]["seam"] == "command_classifier"
    assert "TypeError" in failures[0]["error"]


def test_a_classifier_returning_the_wrong_type_is_reported() -> None:
    from revoco.reversal.engine import EVT_SEAM_FAILED, ReversalEngine

    seen, sink = _events()
    engine = ReversalEngine(
        InverseRegistry(),
        command_classifier=lambda t, a: Reversibility.REVERSIBLE,  # type: ignore[arg-type,return-value]
        on_event=sink,
    )
    assert engine.spec_for(TOOL, {"command": "x"}) is None
    failures = [p for n, p in seen if n == EVT_SEAM_FAILED]
    assert failures and "not an InverseSpec" in failures[0]["error"]


def test_a_hook_trying_to_raise_a_posture_is_reported() -> None:
    """The refusal already happened; now it is visible.

    A hook that only ever downgrades is the invariant. One attempting an upgrade
    is a bug or a hostile integration, and it was being declined in silence.
    """
    from revoco.reversal.engine import EVT_SEAM_FAILED, ReversalEngine

    seen, sink = _events()
    registry = InverseRegistry()
    registry.register(
        InverseSpec(tool=TOOL, kind=Reversibility.IRREVERSIBLE, notes="declared")
    )
    engine = ReversalEngine(
        registry,
        classify_hook=lambda tool, kind: Reversibility.REVERSIBLE,
        on_event=sink,
    )
    assert engine.classify(TOOL, {}) is Reversibility.IRREVERSIBLE
    failures = [p for n, p in seen if n == EVT_SEAM_FAILED]
    assert failures and failures[0]["seam"] == "classify_hook"
    assert "would raise" in failures[0]["error"]


def test_a_working_seam_emits_nothing() -> None:
    """Otherwise the event is noise and stops meaning anything."""
    from revoco.reversal.engine import EVT_SEAM_FAILED, ReversalEngine

    seen, sink = _events()
    engine = ReversalEngine(
        InverseRegistry(), command_classifier=lambda t, a: _spec(), on_event=sink
    )
    assert engine.spec_for(TOOL, {"command": "x"}) is not None
    assert not [p for n, p in seen if n == EVT_SEAM_FAILED]
