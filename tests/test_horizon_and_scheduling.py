"""The reversibility horizon, and drill scheduling.

Both exist to make a perishable capability visible before it perishes: the horizon
so an operator can see an undo window closing, the scheduler so proof gets renewed
before it lapses rather than after.
"""

from __future__ import annotations

from revoco.drills import DrillOutcome, DrillResult, RecoverabilityRegister
from revoco.reversal import (
    InverseRegistry,
    InverseSpec,
    ReversalEngine,
    Reversibility,
)
from revoco.reversal.horizon import build, render

NOW = 1_000_000.0

_SPECS = [
    InverseSpec(tool="a.long", kind=Reversibility.COMPENSABLE, inverse_tool="a.undo",
                window_seconds=1800.0, residue="r"),
    InverseSpec(tool="b.short", kind=Reversibility.COMPENSABLE, inverse_tool="b.undo",
                window_seconds=300.0, residue="r"),
    InverseSpec(tool="c.nodeadline", kind=Reversibility.REVERSIBLE, inverse_tool="c.undo"),
    InverseSpec(tool="d.oneway", kind=Reversibility.IRREVERSIBLE),
    InverseSpec(tool="e.gappy", kind=Reversibility.REVERSIBLE, inverse_tool="e.undo",
                arg_map=(("x", "snapshot.never_captured"),),
                snapshot_fields=("never_captured",)),
]


def _engine_with(*tools: str, now: float = NOW) -> ReversalEngine:
    eng = ReversalEngine(InverseRegistry(_SPECS))
    for i, tool in enumerate(tools):
        plan = eng.plan(tool, {}, now=now)
        j = eng.open_journal(plan, session_id="s1", delegation_id="dlg-1")
        eng.commit(j.id, action_id=f"act{i}", result={}, now=now)
    return eng


# ---------------------------------------------------------------------------
# The metric
# ---------------------------------------------------------------------------


def test_time_to_first_close_is_the_soonest_deadline():
    """The one forward-looking number: how long you still have the choice."""
    eng = _engine_with("a.long", "b.short")
    h = eng.horizon(now=NOW + 60)
    assert h.time_to_first_close == 240.0          # b.short: 300 - 60
    assert h.next_to_close.tool == "b.short"


def test_closing_windows_are_sorted_soonest_first():
    eng = _engine_with("a.long", "b.short")
    h = eng.horizon(now=NOW)
    assert [e.tool for e in h.closing] == ["b.short", "a.long"]


def test_nothing_counting_down_reports_none_not_zero():
    """Zero would read as 'the window just closed', which is the opposite."""
    eng = _engine_with("c.nodeadline")
    h = eng.horizon(now=NOW)
    assert h.time_to_first_close is None
    assert h.undoable_count == 1


def test_no_deadline_is_not_the_same_as_safe():
    """A horizon with nothing counting down still says what was never undoable."""
    eng = _engine_with("d.oneway")
    h = eng.horizon(now=NOW)
    assert h.time_to_first_close is None
    assert h.unrecoverable_count == 1
    assert any("not the same as safe" in n for n in h.notes)


# ---------------------------------------------------------------------------
# The five states, kept apart
# ---------------------------------------------------------------------------


def test_each_state_is_reported_separately():
    eng = _engine_with("a.long", "c.nodeadline", "d.oneway", "e.gappy")
    h = eng.horizon(now=NOW)
    assert [e.tool for e in h.closing] == ["a.long"]
    assert [e.tool for e in h.open_indefinitely] == ["c.nodeadline"]
    assert [e.tool for e in h.standing_exposure] == ["d.oneway"]
    assert [e.tool for e in h.broken] == ["e.gappy"]


def test_a_broken_plan_is_not_counted_as_recoverable():
    """It reads as recoverable in every report except this one."""
    eng = _engine_with("e.gappy")
    h = eng.horizon(now=NOW)
    assert h.undoable_count == 0
    assert h.unrecoverable_count == 1
    assert "never_captured" in h.broken[0].reason or "x" in h.broken[0].reason
    assert any("dangerous" in n for n in h.notes)


def test_standing_exposure_is_distinguished_from_an_expired_window():
    """A window that never existed is a different problem from one that closed."""
    eng = _engine_with("b.short", "d.oneway")
    h = eng.horizon(now=NOW + 400)          # b.short's 300s window has passed
    assert [e.tool for e in h.expired] == ["b.short"]
    assert [e.tool for e in h.standing_exposure] == ["d.oneway"]


def test_a_window_past_its_deadline_shows_as_expired_before_the_sweep_runs():
    """expire_stale() is periodic; the horizon must not wait for it."""
    eng = _engine_with("b.short")
    h = eng.horizon(now=NOW + 9999)
    assert len(h.expired) == 1
    assert "not yet swept" in h.expired[0].reason


def test_a_failed_undo_stays_visible_as_standing_exposure():
    """Terminal, but the worst position to be in — it must not vanish from the view."""
    eng = _engine_with("a.long")
    entry = next(iter(eng.entries()))

    def boom(tool, args):
        raise RuntimeError("system refused")

    receipt = eng.reverse(entry.id, boom, now=NOW + 10)
    assert not receipt.ok
    h = eng.horizon(now=NOW + 20)
    assert len(h.standing_exposure) == 1
    assert "attempted and failed" in h.standing_exposure[0].reason


def test_planned_and_reversed_entries_are_excluded():
    """Neither is exposure: one never ran, the other is already resolved."""
    eng = ReversalEngine(InverseRegistry(_SPECS))
    # planned but never committed
    eng.open_journal(eng.plan("a.long", {}, now=NOW), session_id="s1")
    # committed then successfully reversed
    p = eng.plan("c.nodeadline", {}, now=NOW)
    j = eng.open_journal(p, session_id="s1")
    eng.commit(j.id, action_id="act", result={}, now=NOW)
    eng.reverse(j.id, lambda t, a: {}, now=NOW + 1)

    h = eng.horizon(now=NOW + 2)
    assert h.undoable_count == 0
    assert h.unrecoverable_count == 0


# ---------------------------------------------------------------------------
# Scoping and rendering
# ---------------------------------------------------------------------------


def test_the_horizon_can_be_scoped_to_a_grant():
    """During an incident the question is about one compromised grant, not the world."""
    eng = ReversalEngine(InverseRegistry(_SPECS))
    for i, (tool, dlg) in enumerate([("a.long", "dlg-a"), ("b.short", "dlg-b")]):
        p = eng.plan(tool, {}, now=NOW)
        j = eng.open_journal(p, session_id="s", delegation_id=dlg)
        eng.commit(j.id, action_id=f"act{i}", result={}, now=NOW)

    assert [e.tool for e in eng.horizon(now=NOW, delegation_id="dlg-a").closing] == ["a.long"]
    assert eng.horizon(now=NOW, delegation_id="dlg-b").next_to_close.tool == "b.short"


def test_closing_soon_respects_the_warn_window():
    eng = _engine_with("a.long", "b.short")
    assert len(eng.horizon(now=NOW, warn_within=600.0).closing_soon) == 1    # only b.short
    assert len(eng.horizon(now=NOW, warn_within=3600.0).closing_soon) == 2


def test_recoverable_fraction_is_one_when_there_is_nothing_to_recover():
    """An empty journal is not 0% recoverable; it is vacuously fine."""
    h = build([], now=NOW)
    assert h.recoverable_fraction == 1.0
    assert h.time_to_first_close is None


def test_render_leads_with_the_metric_and_states_what_it_means():
    eng = _engine_with("a.long", "b.short", "d.oneway", "e.gappy")
    out = render(eng.horizon(now=NOW))
    assert "time to first close" in out
    assert "STANDING EXPOSURE" in out
    assert "BROKEN UNDO PATHS" in out
    assert "how long you still can" in out


def test_horizon_serializes_for_a_dashboard():
    eng = _engine_with("a.long", "d.oneway")
    d = eng.horizon(now=NOW).to_dict()
    assert d["undoable"] == 1
    assert d["counts"]["standing_exposure"] == 1
    assert d["time_to_first_close"] == 1800.0


def test_control_plane_exposes_the_horizon():
    from revoco import ControlPlane

    cp = ControlPlane(inverse_registry=InverseRegistry(_SPECS))
    assert cp.horizon().undoable_count == 0


# ---------------------------------------------------------------------------
# Drill scheduling
# ---------------------------------------------------------------------------


def _register(**at: tuple[DrillOutcome, float]) -> RecoverabilityRegister:
    reg = RecoverabilityRegister(stale_after=86_400.0)
    for tool, (outcome, when) in at.items():
        reg.record(DrillResult(
            # Only the first underscore becomes a dot, so `b_less_old` maps to
            # `b.less_old` rather than `b.less.old` and the lookup actually hits.
            id="d", tool=tool.replace("_", ".", 1), outcome=outcome,
            declared_kind=Reversibility.REVERSIBLE, at=when, duration_ms=1.0,
        ))
    return reg


def test_a_failing_drill_outranks_one_that_never_ran():
    """A proven capability that broke is a live regression against something in use."""
    reg = _register(
        a_failing=(DrillOutcome.FAILED, NOW - 100),
    )
    due = reg.due(["a.failing", "z.never"], now=NOW)
    assert [d.tool for d in due] == ["a.failing", "z.never"]
    assert due[0].urgency == "failing"
    assert due[1].urgency == "never_drilled"


def test_proof_is_refreshed_before_it_lapses_not_after():
    """Waiting for expiry would leave tools classified irreversible purely because
    the scheduler had not got to them, which makes the gate feel like a bug."""
    reg = _register(a_ageing=(DrillOutcome.PASSED, NOW - 75_000))   # 86% through a 24h window
    due = reg.due(["a.ageing"], now=NOW, refresh_at=0.8)
    assert [d.urgency for d in due] == ["ageing"]
    # A tighter refresh threshold means it is not yet due.
    assert reg.due(["a.ageing"], now=NOW, refresh_at=0.95) == []


def test_a_fresh_proof_is_not_due():
    reg = _register(a_fresh=(DrillOutcome.PASSED, NOW - 3600))
    assert reg.due(["a.fresh"], now=NOW) == []


def test_a_stale_proof_says_the_gate_is_already_demoting_it():
    reg = _register(a_stale=(DrillOutcome.PASSED, NOW - 200_000))
    due = reg.due(["a.stale"], now=NOW)
    assert due[0].urgency == "stale"
    assert "already treating this as irreversible" in due[0].reason


def test_an_irreversible_tool_is_never_due():
    """Nothing to prove, so scheduling it forever would be pure noise."""
    reg = _register(a_oneway=(DrillOutcome.NOT_DRILLABLE, NOW - 999_999))
    assert reg.due(["a.oneway"], now=NOW) == []


def test_the_batch_throttle_drops_the_least_urgent_work():
    """Drilling everything at once means real writes and undos against production."""
    reg = _register(
        a_failing=(DrillOutcome.FAILED, NOW - 10),
        b_stale=(DrillOutcome.PASSED, NOW - 200_000),
        c_ageing=(DrillOutcome.PASSED, NOW - 75_000),
    )
    tools = ["a.failing", "b.stale", "c.ageing", "z.never"]
    assert [d.tool for d in reg.due(tools, now=NOW, max_batch=2)] == ["a.failing", "z.never"]
    assert len(reg.due(tools, now=NOW)) == 4


def test_within_an_urgency_band_the_stalest_goes_first():
    reg = _register(
        a_old=(DrillOutcome.PASSED, NOW - 300_000),
        b_less_old=(DrillOutcome.PASSED, NOW - 100_000),
    )
    assert [d.tool for d in reg.due(["b.less_old", "a.old"], now=NOW)] == ["a.old", "b.less_old"]


def test_drill_due_runs_only_what_is_needed_and_records_as_it_goes():
    """A batch cut short by the throttle still improves the picture."""
    from revoco.bench.world import VERB_UPDATE, ToolBinding, World
    from revoco.drills import Canary, DrillRunner

    spec = InverseSpec(
        tool="v.update", kind=Reversibility.REVERSIBLE, inverse_tool="v.restore",
        arg_map=(("id", "args.id"), ("val", "snapshot.val")), snapshot_fields=("val",),
    )
    w = World().bind(
        ToolBinding("v.update", VERB_UPDATE, kind="r", id_arg="id", field_args=("val",)),
        ToolBinding("v.restore", VERB_UPDATE, kind="r", id_arg="id", field_args=("val",)),
    ).seed("r", "CANARY", val="good")

    runner = DrillRunner(InverseRegistry([spec]), executor=w.executor,
                        state_reader=w.state_reader)
    canary = Canary(tool="v.update", args={"id": "CANARY", "val": "drill"},
                    verify=lambda: dict(w.get("r", "CANARY") or {}))
    reg = RecoverabilityRegister(stale_after=86_400.0)

    first = runner.drill_due(reg, [canary], now=NOW)
    assert len(first) == 1 and first[0].outcome is DrillOutcome.PASSED
    assert reg.is_proven("v.update", now=NOW)
    # Now fresh, so a second immediate pass does nothing.
    assert runner.drill_due(reg, [canary], now=NOW) == []
    # And the canary was left as it was found.
    assert w.get("r", "CANARY") == {"val": "good"}
