"""The reversal engine: planning, the deferred/unresolved distinction, cascades."""

from __future__ import annotations

import pytest

from revoco.core.errors import (
    AlreadyReversed,
    NotReversible,
    ReversalPlanMissing,
    ReversalWindowExpired,
    ValidationError,
)
from revoco.reversal import (
    InverseRegistry,
    InverseSpec,
    JournalState,
    ReversalEngine,
    Reversibility,
    ap_starter_registry,
)

# ---- spec validation ------------------------------------------------------


def test_compensable_must_name_its_residue():
    with pytest.raises(ValidationError, match="residue"):
        InverseSpec(tool="a.b", kind=Reversibility.COMPENSABLE, inverse_tool="a.undo")


def test_undoable_kind_requires_an_inverse_tool():
    with pytest.raises(ValidationError, match="inverse_tool"):
        InverseSpec(tool="a.b", kind=Reversibility.REVERSIBLE)


def test_irreversible_must_not_name_an_inverse_tool():
    with pytest.raises(ValidationError, match="must not name"):
        InverseSpec(tool="a.b", kind=Reversibility.IRREVERSIBLE, inverse_tool="a.undo")


def test_bad_arg_source_is_rejected():
    with pytest.raises(ValidationError, match="source"):
        InverseSpec(
            tool="a.b", kind=Reversibility.REVERSIBLE, inverse_tool="a.undo",
            arg_map=(("x", "nonsense.y"),),
        )


def test_spec_round_trips_through_dict():
    spec = InverseSpec(
        tool="v.update", kind=Reversibility.REVERSIBLE, inverse_tool="v.update",
        arg_map=(("id", "args.id"), ("bank", "snapshot.bank")),
        snapshot_fields=("bank",), window_seconds=60.0,
    )
    assert InverseSpec.from_dict(spec.to_dict()) == spec


# ---- registry -------------------------------------------------------------


def test_unregistered_tool_classifies_as_unknown_not_reversible():
    reg = InverseRegistry()
    assert reg.classify("anything.at.all") is Reversibility.UNKNOWN


def test_exact_match_beats_a_glob():
    reg = InverseRegistry(
        [
            InverseSpec(tool="inv.*", kind=Reversibility.IRREVERSIBLE),
            InverseSpec(tool="inv.approve", kind=Reversibility.REVERSIBLE,
                        inverse_tool="inv.unapprove"),
        ]
    )
    assert reg.classify("inv.approve") is Reversibility.REVERSIBLE
    assert reg.classify("inv.other") is Reversibility.IRREVERSIBLE


def test_coverage_reports_the_unclassified_gap():
    reg = ap_starter_registry()
    cov = reg.coverage(["invoices.pay", "payments.wire", "totally.unmapped"])
    assert cov["total_tools"] == 3
    assert cov["by_kind"]["unknown"] == ["totally.unmapped"]
    assert cov["undoable"] == 1


# ---- planning: deferred vs unresolved ------------------------------------


def test_result_derived_args_are_deferred_not_unresolved():
    """A payment id you only learn from the response is a normal deferral.

    Treating it as a defect would make every result-bound inverse look broken.
    """
    eng = ReversalEngine(
        ap_starter_registry(),
        state_reader=lambda t, a, f: {"status": "approved", "paid_amount": 0.0,
                                      "payment_id": None},
    )
    plan = eng.plan("invoices.pay", {"invoice_id": "INV-1", "amount": 100})
    assert "payment_id" in plan.deferred_args
    assert plan.unresolved_args == ()
    assert not plan.is_broken       # nothing wrong yet
    assert not plan.is_complete     # but not runnable yet either


def test_missing_snapshot_field_is_a_real_hole():
    eng = ReversalEngine(ap_starter_registry(), state_reader=lambda t, a, f: {})
    plan = eng.plan("vendors.update", {"vendor_id": "V-1", "bank_account": "NEW"})
    assert "bank_account" in plan.unresolved_args
    assert plan.is_broken


def test_absent_state_reader_is_reported_not_silently_ignored():
    eng = ReversalEngine(ap_starter_registry())  # no state_reader
    plan = eng.plan("vendors.update", {"vendor_id": "V-1", "bank_account": "NEW"})
    assert plan.snapshot_error is not None
    assert plan.is_broken


def test_a_broken_state_reader_does_not_break_the_caller():
    def boom(tool, args, fields):
        raise RuntimeError("ERP down")

    eng = ReversalEngine(ap_starter_registry(), state_reader=boom)
    plan = eng.plan("vendors.update", {"vendor_id": "V-1", "bank_account": "NEW"})
    assert "ERP down" in (plan.snapshot_error or "")
    assert plan.is_broken


def test_commit_binds_deferred_args():
    eng = ReversalEngine(ap_starter_registry())
    plan = eng.plan("invoices.pay", {"invoice_id": "INV-1", "amount": 100})
    j = eng.open_journal(plan, session_id="s1")
    entry = eng.commit(j.id, action_id="act_1", result={"payment_id": "PAY-9"})
    assert entry.plan.inverse_args["payment_id"] == "PAY-9"
    assert entry.plan.deferred_args == ()
    assert entry.plan.is_complete


def test_a_deferred_arg_the_response_never_supplied_becomes_a_real_hole():
    eng = ReversalEngine(ap_starter_registry())
    plan = eng.plan("invoices.pay", {"invoice_id": "INV-1", "amount": 100})
    j = eng.open_journal(plan, session_id="s1")
    entry = eng.commit(j.id, action_id="act_1", result={})  # no payment_id
    assert "payment_id" in entry.plan.unresolved_args
    assert entry.plan.is_broken


# ---- execution ------------------------------------------------------------


@pytest.fixture
def vendor_engine():
    """A reversible vendor-update with a working snapshot reader."""
    state = {"V-1": {"bank_account": "REAL-1111", "remit_to": "a@b.example"}}
    calls: list[tuple[str, dict]] = []

    def reader(tool, args, fields):
        src = state.get(args["vendor_id"], {})
        return {f: src[f] for f in fields if f in src}

    def executor(tool, args):
        calls.append((tool, dict(args)))
        if tool == "vendors.update":
            state[args["vendor_id"]].update(
                {k: v for k, v in args.items() if k in ("bank_account", "remit_to")}
            )
            return dict(state[args["vendor_id"]])
        raise KeyError(tool)

    eng = ReversalEngine(ap_starter_registry(), state_reader=reader)
    return eng, state, executor, calls


def test_reverse_restores_prior_state(vendor_engine):
    eng, state, executor, _calls = vendor_engine
    plan = eng.plan("vendors.update", {"vendor_id": "V-1", "bank_account": "MULE-9999"})
    j = eng.open_journal(plan, session_id="s1")
    # The forward action happens (simulated).
    state["V-1"]["bank_account"] = "MULE-9999"
    eng.commit(j.id, action_id="act_1", result={})
    receipt = eng.reverse("act_1", executor)
    assert receipt.ok
    assert state["V-1"]["bank_account"] == "REAL-1111"
    assert eng.get(j.id).state is JournalState.REVERSED


def test_reverse_accepts_either_a_journal_id_or_an_action_id(vendor_engine):
    eng, state, executor, _ = vendor_engine
    plan = eng.plan("vendors.update", {"vendor_id": "V-1", "bank_account": "X"})
    j = eng.open_journal(plan, session_id="s1")
    eng.commit(j.id, action_id="act_1", result={})
    assert eng.reverse(j.id, executor).ok


def test_reversing_twice_raises_rather_than_applying_the_inverse_again(vendor_engine):
    eng, state, executor, _ = vendor_engine
    plan = eng.plan("vendors.update", {"vendor_id": "V-1", "bank_account": "X"})
    j = eng.open_journal(plan, session_id="s1")
    eng.commit(j.id, action_id="act_1", result={})
    eng.reverse("act_1", executor)
    with pytest.raises(AlreadyReversed):
        eng.reverse("act_1", executor)


def test_a_planned_but_uncommitted_action_has_nothing_to_undo(vendor_engine):
    eng, _state, executor, _ = vendor_engine
    plan = eng.plan("vendors.update", {"vendor_id": "V-1", "bank_account": "X"})
    j = eng.open_journal(plan, session_id="s1")
    with pytest.raises(ReversalPlanMissing):
        eng.reverse(j.id, executor)


def test_irreversible_actions_refuse_to_pretend(vendor_engine):
    eng, _state, executor, _ = vendor_engine
    plan = eng.plan("payments.wire", {"amount": 1})
    j = eng.open_journal(plan, session_id="s1")
    eng.commit(j.id, action_id="act_w", result={})
    with pytest.raises(NotReversible):
        eng.reverse("act_w", executor)


def test_an_executor_failure_yields_a_receipt_not_an_exception(vendor_engine):
    eng, state, _executor, _ = vendor_engine

    def failing(tool, args):
        raise RuntimeError("ERP rejected the reversal")

    plan = eng.plan("vendors.update", {"vendor_id": "V-1", "bank_account": "X"})
    j = eng.open_journal(plan, session_id="s1")
    eng.commit(j.id, action_id="act_1", result={})
    receipt = eng.reverse("act_1", failing)
    assert not receipt.ok
    assert "ERP rejected" in (receipt.error or "")
    assert eng.get(j.id).state is JournalState.FAILED


def test_the_undo_window_closes(vendor_engine):
    eng, _state, executor, _ = vendor_engine
    plan = eng.plan("invoices.pay", {"invoice_id": "INV-1", "amount": 1}, now=1000.0)
    j = eng.open_journal(plan, session_id="s1")
    eng.commit(j.id, action_id="act_p", result={"payment_id": "PAY-1"}, now=1000.0)
    with pytest.raises(ReversalWindowExpired):
        eng.reverse("act_p", executor, now=1000.0 + 86_401)
    assert eng.get(j.id).state is JournalState.EXPIRED


def test_expire_stale_flags_windows_that_closed_unnoticed(vendor_engine):
    eng, _state, _executor, _ = vendor_engine
    plan = eng.plan("invoices.pay", {"invoice_id": "INV-1", "amount": 1}, now=1000.0)
    j = eng.open_journal(plan, session_id="s1")
    eng.commit(j.id, action_id="act_p", result={"payment_id": "PAY-1"}, now=1000.0)
    assert eng.expire_stale(now=1000.0 + 86_401) == [j.id]


# ---- cascades -------------------------------------------------------------


def test_cascade_undoes_newest_first():
    """LIFO ordering. Compensating transactions do not commute."""
    order: list[str] = []

    def executor(tool, args):
        order.append(args.get("marker", tool))
        return {}

    reg = InverseRegistry(
        [
            InverseSpec(
                tool="thing.do", kind=Reversibility.REVERSIBLE, inverse_tool="thing.undo",
                arg_map=(("marker", "args.marker"),),
            )
        ]
    )
    eng = ReversalEngine(reg)
    for i, when in enumerate([100.0, 200.0, 300.0]):
        plan = eng.plan("thing.do", {"marker": f"step{i}"}, now=when)
        j = eng.open_journal(plan, session_id="s1", delegation_id="dlg_1")
        eng.commit(j.id, action_id=f"act_{i}", result={}, now=when)

    report = eng.reverse_cascade(executor=executor, session_id="s1")
    assert report.ok
    assert report.reversed_ok == 3
    assert order == ["step2", "step1", "step0"]


def test_cascade_counts_skips_separately_from_failures():
    """An action with no undo path is skipped, never counted as reversed."""
    reg = InverseRegistry(
        [
            InverseSpec(tool="ok.do", kind=Reversibility.REVERSIBLE, inverse_tool="ok.undo"),
            InverseSpec(tool="nope.do", kind=Reversibility.IRREVERSIBLE),
        ]
    )
    eng = ReversalEngine(reg)
    for i, tool in enumerate(["ok.do", "nope.do", "ok.do"]):
        plan = eng.plan(tool, {}, now=100.0 + i)
        j = eng.open_journal(plan, session_id="s1")
        eng.commit(j.id, action_id=f"act_{i}", result={}, now=100.0 + i)

    report = eng.reverse_cascade(executor=lambda t, a: {}, session_id="s1")
    assert report.reversed_ok == 2
    assert report.skipped == 1
    assert report.failed == 0
    assert report.ok  # nothing failed, even though not everything was undoable


def test_cascade_stops_early_on_failure_when_asked():
    reg = InverseRegistry(
        [InverseSpec(tool="t.do", kind=Reversibility.REVERSIBLE, inverse_tool="t.undo")]
    )
    eng = ReversalEngine(reg)
    for i in range(3):
        plan = eng.plan("t.do", {}, now=100.0 + i)
        j = eng.open_journal(plan, session_id="s1")
        eng.commit(j.id, action_id=f"act_{i}", result={}, now=100.0 + i)

    def always_fails(tool, args):
        raise RuntimeError("no")

    report = eng.reverse_cascade(
        executor=always_fails, session_id="s1", stop_on_error=True
    )
    assert report.stopped_early
    assert report.failed == 1
    assert not report.ok


def test_cascade_surfaces_residue_from_compensated_actions():
    eng = ReversalEngine(ap_starter_registry())
    plan = eng.plan("invoices.pay", {"invoice_id": "INV-1", "amount": 1}, now=100.0)
    j = eng.open_journal(plan, session_id="s1")
    eng.commit(j.id, action_id="act_p", result={"payment_id": "PAY-1"}, now=100.0)
    report = eng.reverse_cascade(executor=lambda t, a: {}, session_id="s1", now=110.0)
    assert report.reversed_ok == 1
    assert any("remittance advice" in r for r in report.residues)


def test_cascade_requires_exactly_one_selector():
    eng = ReversalEngine()
    with pytest.raises(ValueError):
        eng.reverse_cascade(executor=lambda t, a: {})
    with pytest.raises(ValueError):
        eng.reverse_cascade(executor=lambda t, a: {}, session_id="a", delegation_id="b")
