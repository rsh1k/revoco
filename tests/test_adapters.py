"""Adapter specs, sequenced undos, and event-bounded gates.

These specs are unvalidated against live systems, so what is tested here is that
they *encode the documented semantics correctly* and that the engine honors them.
That is the part this repository can actually guarantee.
"""

from __future__ import annotations

import pytest

from revoco.adapters import sap_registry, workday_registry
from revoco.adapters.sap import GATE_PERIOD_OPEN, SAP_SPECS
from revoco.adapters.workday import GATE_PAYROLL_NOT_RUN, WORKDAY_SPECS
from revoco.core.errors import ReversalGateClosed, ValidationError
from revoco.reversal import (
    InverseRegistry,
    InverseSpec,
    JournalState,
    ReversalEngine,
    Reversibility,
)
from revoco.reversal.model import InverseStep, ReversalGate

# ---------------------------------------------------------------------------
# Semantic assertions about the specs themselves
# ---------------------------------------------------------------------------


def test_no_sap_financial_posting_claims_to_be_exactly_reversible():
    """SAP reverses; it does not delete. An FI posting can never be REVERSIBLE."""
    postings = {"sap.journalentry.post", "sap.payment.post"}
    for spec in SAP_SPECS:
        if spec.tool in postings:
            assert spec.kind is Reversibility.COMPENSABLE, spec.tool
            assert spec.residue, f"{spec.tool} must name what survives the reversal"


def test_sap_reversal_is_one_shot():
    """A reversal document cannot itself be reversed."""
    by_tool = {s.tool: s for s in SAP_SPECS}
    assert by_tool["sap.journalentry.post"].one_shot
    assert by_tool["sap.payment.post"].one_shot
    # And the reversal operation itself is registered as irreversible, so an
    # agent calling it directly escalates rather than inheriting false safety.
    assert by_tool["sap.journalentry.reverse"].kind is Reversibility.IRREVERSIBLE


def test_sap_payment_reversal_is_an_ordered_three_step_sequence():
    """Void the medium, reset the clearing, then post the reversal."""
    spec = {s.tool: s for s in SAP_SPECS}["sap.payment.post"]
    assert [s.tool for s in spec.effective_steps] == [
        "sap.paymentmedium.void",
        "sap.clearing.reset",
        "sap.journalentry.reverse",
    ]
    # Every step is critical: a partial payment reversal is worse than none.
    assert all(s.critical for s in spec.effective_steps)


def test_sap_parked_document_is_the_reversible_contrast():
    """Parking never posts, so deleting it is a true inverse with no ledger trace."""
    spec = {s.tool: s for s in SAP_SPECS}["sap.journalentry.park"]
    assert spec.kind is Reversibility.REVERSIBLE
    assert not spec.residue


def test_sap_vendor_bank_update_captures_prior_values_and_restores_them():
    """The fraud-critical spec: SAP's own change log is not a dependable fallback."""
    spec = {s.tool: s for s in SAP_SPECS}["sap.supplier.bank.update"]
    assert spec.kind is Reversibility.REVERSIBLE
    assert "BankAccount" in spec.snapshot_fields
    assert "IBAN" in spec.snapshot_fields
    args = dict(spec.arg_map)
    assert args["BankAccount"] == "snapshot.BankAccount"
    assert args["IBAN"] == "snapshot.IBAN"


def test_workday_rescind_family_is_one_shot_and_gated_on_payroll():
    rescinders = [s for s in WORKDAY_SPECS if s.inverse_tool == "workday.bp.rescind"]
    assert rescinders
    for spec in rescinders:
        assert spec.one_shot, spec.tool
        assert GATE_PAYROLL_NOT_RUN in spec.gates, spec.tool


def test_workday_rescind_itself_is_irreversible():
    by_tool = {s.tool: s for s in WORKDAY_SPECS}
    assert by_tool["workday.bp.rescind"].kind is Reversibility.IRREVERSIBLE


def test_workday_correct_is_compensable_not_reversible():
    """The value is restored exactly; the record of what happened is not."""
    spec = {s.tool: s for s in WORKDAY_SPECS}["workday.compensation.correct"]
    assert spec.kind is Reversibility.COMPENSABLE
    assert "effective-dated history" in spec.residue


def test_workday_payroll_completion_destroys_other_undo_paths():
    spec = {s.tool: s for s in WORKDAY_SPECS}["workday.payroll.complete"]
    assert spec.kind is Reversibility.IRREVERSIBLE


def test_every_adapter_spec_round_trips_through_dict():
    for spec in SAP_SPECS + WORKDAY_SPECS:
        assert InverseSpec.from_dict(spec.to_dict()) == spec, spec.tool


def test_adapter_coverage_reports_are_computable():
    reg = sap_registry()
    tools = [s.tool for s in SAP_SPECS]
    cov = reg.coverage(tools)
    assert cov["by_kind"]["unknown"] == []
    assert cov["classified_pct"] == 100.0


# ---------------------------------------------------------------------------
# Sequenced undo execution
# ---------------------------------------------------------------------------


class FakeSAP:
    """Records the order and arguments of every inverse call."""

    def __init__(self, fail_on: str | None = None) -> None:
        self.calls: list[tuple[str, dict]] = []
        self.fail_on = fail_on

    def __call__(self, tool: str, args: dict):
        self.calls.append((tool, dict(args)))
        if tool == self.fail_on:
            raise RuntimeError(f"{tool} rejected by SAP")
        return {"ok": True, "tool": tool}

    @property
    def order(self) -> list[str]:
        return [t for t, _ in self.calls]


def _committed_payment(engine: ReversalEngine, *, now: float = 100.0):
    plan = engine.plan(
        "sap.payment.post",
        {"CompanyCode": "1000", "SupplierInvoice": "INV-1"},
        now=now,
    )
    j = engine.open_journal(plan, session_id="s1", delegation_id="dlg_1")
    engine.commit(
        j.id,
        action_id="act_pay",
        result={"PaymentDocument": "5000001234", "FiscalYear": "2026"},
        now=now,
    )
    return j


def _open_all_gates(ctx):
    return True


def test_multi_step_undo_runs_in_declaration_order():
    eng = ReversalEngine(sap_registry(), gate_evaluator=_open_all_gates)
    _committed_payment(eng)
    executor = FakeSAP()
    receipt = eng.reverse("act_pay", executor, now=110.0)

    assert receipt.ok
    assert executor.order == [
        "sap.paymentmedium.void",
        "sap.clearing.reset",
        "sap.journalentry.reverse",
    ]
    assert len(receipt.steps) == 3
    assert all(s.ok for s in receipt.steps)


def test_result_derived_args_reach_every_step():
    eng = ReversalEngine(sap_registry(), gate_evaluator=_open_all_gates)
    _committed_payment(eng)
    executor = FakeSAP()
    eng.reverse("act_pay", executor, now=110.0)
    for _tool, args in executor.calls:
        # The payment document number was only known from the forward response.
        assert args.get("PaymentDocument") == "5000001234" or (
            args.get("ClearingDocument") == "5000001234"
        ) or args.get("AccountingDocument") == "5000001234"


def test_a_failing_critical_step_aborts_the_rest():
    """If the cheque void fails, resetting the clearing would desync the ledger."""
    eng = ReversalEngine(sap_registry(), gate_evaluator=_open_all_gates)
    j = _committed_payment(eng)
    executor = FakeSAP(fail_on="sap.paymentmedium.void")
    receipt = eng.reverse("act_pay", executor, now=110.0)

    assert not receipt.ok
    assert executor.order == ["sap.paymentmedium.void"]   # stopped dead
    assert receipt.steps[0].ok is False
    assert receipt.steps[1].skipped and receipt.steps[2].skipped
    assert eng.get(j.id).state is JournalState.FAILED
    assert "void_medium" in (receipt.error or "")


def test_a_mid_sequence_failure_is_reported_with_its_step_name():
    eng = ReversalEngine(sap_registry(), gate_evaluator=_open_all_gates)
    _committed_payment(eng)
    executor = FakeSAP(fail_on="sap.clearing.reset")
    receipt = eng.reverse("act_pay", executor, now=110.0)
    assert not receipt.ok
    assert "reset_clearing" in (receipt.error or "")
    assert receipt.steps[0].ok          # the void did happen
    assert receipt.steps[2].skipped     # the reversal did not


def test_a_non_critical_step_failure_does_not_abort():
    spec = InverseSpec(
        tool="thing.do",
        kind=Reversibility.REVERSIBLE,
        steps=(
            InverseStep(name="notify", tool="notify.send", critical=False),
            InverseStep(name="restore", tool="thing.restore"),
        ),
    )
    eng = ReversalEngine(InverseRegistry([spec]))
    plan = eng.plan("thing.do", {}, now=1.0)
    j = eng.open_journal(plan, session_id="s")
    eng.commit(j.id, action_id="a1", result={}, now=1.0)
    executor = FakeSAP(fail_on="notify.send")
    receipt = eng.reverse("a1", executor, now=2.0)
    assert not receipt.ok                    # honest: something did fail
    assert executor.order == ["notify.send", "thing.restore"]   # but it continued


def test_a_step_can_consume_an_earlier_step_result():
    spec = InverseSpec(
        tool="chain.do",
        kind=Reversibility.REVERSIBLE,
        steps=(
            InverseStep(name="first", tool="chain.begin"),
            InverseStep(
                name="second",
                tool="chain.finish",
                arg_map=(("handle", "step.first.token"),),
            ),
        ),
    )
    eng = ReversalEngine(InverseRegistry([spec]))
    plan = eng.plan("chain.do", {}, now=1.0)
    # A step-derived arg is pending, not broken — the plan is still sound.
    assert not plan.is_broken
    assert "handle" in plan.steps[1].from_prior_step

    j = eng.open_journal(plan, session_id="s")
    eng.commit(j.id, action_id="a1", result={}, now=1.0)

    calls: list[tuple[str, dict]] = []

    def executor(tool, args):
        calls.append((tool, dict(args)))
        return {"token": "TOK-7"} if tool == "chain.begin" else {}

    receipt = eng.reverse("a1", executor, now=2.0)
    assert receipt.ok
    assert calls[1][1]["handle"] == "TOK-7"


def test_a_forward_step_reference_is_rejected_at_construction():
    """Discovering a deadlocked sequence at undo time is the worst possible moment."""
    with pytest.raises(ValidationError, match="does not run before"):
        InverseSpec(
            tool="bad.do",
            kind=Reversibility.REVERSIBLE,
            steps=(
                InverseStep(name="a", tool="x", arg_map=(("v", "step.b.out"),)),
                InverseStep(name="b", tool="y"),
            ),
        )


def test_duplicate_step_names_are_rejected():
    with pytest.raises(ValidationError, match="duplicate step names"):
        InverseSpec(
            tool="bad.do",
            kind=Reversibility.REVERSIBLE,
            steps=(InverseStep(name="a", tool="x"), InverseStep(name="a", tool="y")),
        )


def test_specifying_both_shorthand_and_steps_is_rejected():
    with pytest.raises(ValidationError, match="not both"):
        InverseSpec(
            tool="bad.do",
            kind=Reversibility.REVERSIBLE,
            inverse_tool="x",
            steps=(InverseStep(name="a", tool="y"),),
        )


# ---------------------------------------------------------------------------
# Gates
# ---------------------------------------------------------------------------


def test_a_closed_gate_blocks_the_undo_and_touches_nothing():
    def payroll_has_run(ctx):
        if ctx.gate.name == "workday_payroll_not_run":
            return "payroll completed on 2026-07-31"
        return True

    eng = ReversalEngine(workday_registry(), gate_evaluator=payroll_has_run)
    plan = eng.plan("workday.compensation.request_change", {"Worker_Reference": "W-1"}, now=1.0)
    j = eng.open_journal(plan, session_id="s")
    eng.commit(j.id, action_id="a1", result={"Business_Process_Reference": "BP-9"}, now=1.0)

    executor = FakeSAP()
    with pytest.raises(ReversalGateClosed, match="payroll completed"):
        eng.reverse("a1", executor, now=2.0)
    assert executor.calls == []   # nothing was attempted


def test_a_blocked_gate_leaves_the_entry_recoverable_not_terminal():
    """A gate can reopen; marking it EXPIRED would report the rollback as gone."""
    eng = ReversalEngine(
        workday_registry(), gate_evaluator=lambda ctx: ctx.gate.name != "workday_payroll_not_run"
    )
    plan = eng.plan("workday.job.change_job", {"Worker_Reference": "W-1"}, now=1.0)
    j = eng.open_journal(plan, session_id="s")
    eng.commit(j.id, action_id="a1", result={"Business_Process_Reference": "BP-9"}, now=1.0)
    with pytest.raises(ReversalGateClosed):
        eng.reverse("a1", FakeSAP(), now=2.0)
    assert eng.get(j.id).state is JournalState.COMMITTED


def test_gate_closure_includes_the_remediation_text():
    eng = ReversalEngine(workday_registry(), gate_evaluator=lambda ctx: False)
    plan = eng.plan("workday.staffing.hire", {}, now=1.0)
    j = eng.open_journal(plan, session_id="s")
    eng.commit(j.id, action_id="a1", result={"Business_Process_Reference": "BP-1"}, now=1.0)
    with pytest.raises(ReversalGateClosed) as exc:
        eng.reverse("a1", FakeSAP(), now=2.0)
    assert "payroll partner" in str(exc.value)   # the remediation, not just the failure


def test_declared_gates_with_no_evaluator_refuse_to_run():
    """An unverifiable precondition is not a precondition."""
    eng = ReversalEngine(sap_registry())   # no gate_evaluator
    _committed_payment(eng)
    with pytest.raises(ReversalGateClosed, match="no gate evaluator"):
        eng.reverse("act_pay", FakeSAP(), now=110.0)


def test_an_exploding_gate_evaluator_fails_closed():
    def boom(ctx):
        raise RuntimeError("SAP unreachable")

    eng = ReversalEngine(sap_registry(), gate_evaluator=boom)
    _committed_payment(eng)
    with pytest.raises(ReversalGateClosed, match="SAP unreachable"):
        eng.reverse("act_pay", FakeSAP(), now=110.0)


def test_check_gates_reports_all_closures_not_just_the_first():
    eng = ReversalEngine(workday_registry(), gate_evaluator=lambda ctx: False)
    plan = eng.plan("workday.staffing.terminate", {}, now=1.0)
    j = eng.open_journal(plan, session_id="s")
    entry = eng.commit(j.id, action_id="a1", result={"Business_Process_Reference": "B"}, now=1.0)
    closed = eng.check_gates(entry)
    assert len(closed) == 4      # all four gates on this spec


def test_ungated_specs_need_no_evaluator():
    eng = ReversalEngine(sap_registry())
    plan = eng.plan("sap.supplier.block", {"BusinessPartner": "V1"}, now=1.0)
    assert plan.gates == ()


# ---------------------------------------------------------------------------
# Cascades over gated specs
# ---------------------------------------------------------------------------


def test_cascade_separates_gate_blocks_from_missing_undo_paths():
    """A blocked gate belongs on a worklist; a missing inverse is a loss."""
    eng = ReversalEngine(
        workday_registry(),
        gate_evaluator=lambda ctx: ctx.gate.name != "workday_payroll_not_run",
    )
    # One gated-and-blocked action...
    p1 = eng.plan("workday.compensation.request_change", {}, now=1.0)
    j1 = eng.open_journal(p1, session_id="s1")
    eng.commit(j1.id, action_id="a1", result={"Business_Process_Reference": "B1"}, now=1.0)
    # ...and one with no inverse at all.
    p2 = eng.plan("workday.payroll.complete", {}, now=2.0)
    j2 = eng.open_journal(p2, session_id="s1")
    eng.commit(j2.id, action_id="a2", result={}, now=2.0)

    report = eng.reverse_cascade(executor=FakeSAP(), session_id="s1", now=3.0)
    assert report.skipped == 2
    assert report.reversed_ok == 0
    assert len(report.blocked_by_gates) == 1
    assert "payroll" in report.blocked_by_gates[0]


def test_cascade_succeeds_over_gated_specs_when_gates_are_open():
    eng = ReversalEngine(workday_registry(), gate_evaluator=_open_all_gates)
    for i, tool in enumerate(
        ["workday.compensation.request_change", "workday.job.change_job"]
    ):
        p = eng.plan(tool, {"Worker_Reference": "W-1"}, now=float(i))
        j = eng.open_journal(p, session_id="s1")
        eng.commit(
            j.id, action_id=f"a{i}", result={"Business_Process_Reference": f"B{i}"},
            now=float(i),
        )
    report = eng.reverse_cascade(executor=FakeSAP(), session_id="s1", now=10.0)
    assert report.ok
    assert report.reversed_ok == 2
    # Both rescinds carry the same integration residue, deduplicated.
    assert any("integrations" in r for r in report.residues)


# ---------------------------------------------------------------------------
# Gate model validation
# ---------------------------------------------------------------------------


def test_a_gate_must_explain_itself():
    with pytest.raises(ValidationError, match="needs a description"):
        ReversalGate(name="mystery", description="")


def test_gate_round_trips():
    assert ReversalGate.from_dict(GATE_PERIOD_OPEN.to_dict()) == GATE_PERIOD_OPEN


def test_workspace_is_deliberately_absent_from_the_catalogue() -> None:
    """The workspace snapshot ships, but must not be listed as a surface.

    SURFACES is keyed by fixed tool name. The workspace mechanism has no fixed
    forward tool -- the shell classifier names it per call -- so listing it would
    advertise ``workspace.guarded_command``, which nobody can invoke. This test
    exists so that absence stays a decision: anyone "fixing" the omission by
    adding a placeholder entry fails here and reads why.
    """
    from revoco.adapters import SURFACES, all_specs
    from revoco.adapters.workspace import WORKSPACE_SPEC

    # Anchor first: "not in" is satisfied by an empty catalogue, so prove the
    # catalogue is populated before reading anything into the absence.
    assert "devops" in SURFACES, "catalogue is empty; the absence below proves nothing"

    # `workstation` is a real surface and `workspace` is the uncatalogued
    # mechanism. The names are one letter apart and mean different things; the
    # presence of the first is not evidence for the second.
    assert "workstation" in SURFACES
    assert "workspace" not in SURFACES
    assert all(
        spec.tool != WORKSPACE_SPEC.tool for spec in all_specs()
    ), "the placeholder forward tool must never reach the catalogue"


def test_surfaces_command_still_names_the_uncatalogued_mechanism() -> None:
    """Excluding it from the table must not make it vanish from the CLI.

    A reader who sees only the surface table would conclude the workspace undo
    does not exist. The mechanism is named below the table; if that line is ever
    dropped, the catalogue silently under-reports what is in the box.
    """
    import io
    from contextlib import redirect_stdout

    from revoco.adapters.workspace import WORKSPACE_SPEC
    from revoco.cli import main

    out = io.StringIO()
    with redirect_stdout(out):
        main(["surfaces"])
    text = out.getvalue()

    assert "workspace" in text
    assert WORKSPACE_SPEC.inverse_tool in text, "name the operation that is real"
    assert WORKSPACE_SPEC.tool not in text, "never advertise the placeholder"
