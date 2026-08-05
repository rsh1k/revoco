"""Irreversibility budget and recovery drills.

Two additions aimed at the same weakness from opposite ends: unrecoverable
exposure that nobody caps, and rollback claims that nobody verifies.
"""

from __future__ import annotations

import pytest

from revoco import ControlPlane, Scope, crypto
from revoco.bench import Harness
from revoco.bench.corpus import _MALICIOUS
from revoco.bench.world import VERB_UPDATE, ToolBinding, World
from revoco.drills import (
    Canary,
    DrillOutcome,
    DrillRunner,
    RecoverabilityRegister,
    attest,
    render_report,
)
from revoco.gate.policy import load_policy
from revoco.reversal import InverseRegistry, InverseSpec, Reversibility
from revoco.reversal.budget import IrreversibilityBudget

# ---------------------------------------------------------------------------
# Irreversibility budget
# ---------------------------------------------------------------------------


def test_reversible_work_is_free_so_the_budget_is_not_a_rate_limiter():
    b = IrreversibilityBudget(1.0)
    for _ in range(100):
        ok, charge, _ = b.check("g", tool="fs.write_file", kind=Reversibility.REVERSIBLE, risk=90)
        assert ok and charge.cost == 0.0
        b.commit("g", charge)
    assert b.state("g").spent == 0.0


def test_irreversible_work_is_priced_by_risk():
    b = IrreversibilityBudget(10.0)
    low = b.price(tool="t", kind=Reversibility.IRREVERSIBLE, risk=10)
    high = b.price(tool="t", kind=Reversibility.IRREVERSIBLE, risk=90)
    assert high.cost > low.cost
    # An irreversible action at full risk costs exactly one unit, which is what
    # makes a ceiling of 3.0 mean "three one-way actions".
    assert b.price(tool="t", kind=Reversibility.IRREVERSIBLE, risk=100).cost == pytest.approx(1.0)


def test_compensable_costs_less_than_irreversible_but_more_than_nothing():
    b = IrreversibilityBudget(10.0)
    comp = b.price(tool="t", kind=Reversibility.COMPENSABLE, risk=100)
    irr = b.price(tool="t", kind=Reversibility.IRREVERSIBLE, risk=100)
    assert 0 < comp.cost < irr.cost


def test_named_residue_surcharges_a_compensable_action():
    """Otherwise 'compensable' is a loophole for unbounded real-world side effects."""
    b = IrreversibilityBudget(10.0)
    clean = b.price(tool="t", kind=Reversibility.COMPENSABLE, risk=100, has_residue=False)
    messy = b.price(tool="t", kind=Reversibility.COMPENSABLE, risk=100, has_residue=True)
    assert messy.cost > clean.cost


def test_unknown_costs_the_same_as_irreversible_not_more():
    """It ranks lower for fail-safe ordering, but the worst case is still one-way."""
    b = IrreversibilityBudget(10.0)
    assert (
        b.price(tool="t", kind=Reversibility.UNKNOWN, risk=50).cost
        == b.price(tool="t", kind=Reversibility.IRREVERSIBLE, risk=50).cost
    )


def test_the_overdrawing_action_is_refused_before_it_runs():
    b = IrreversibilityBudget(1.5)   # risk-60 irreversible costs 0.6, so two fit
    ok, charge, _ = b.check("g", tool="w", kind=Reversibility.IRREVERSIBLE, risk=60)
    assert ok
    b.commit("g", charge)
    ok, charge, _ = b.check("g", tool="w", kind=Reversibility.IRREVERSIBLE, risk=60)
    assert ok
    b.commit("g", charge)
    ok, _charge, reason = b.check("g", tool="w", kind=Reversibility.IRREVERSIBLE, risk=60)
    assert not ok
    assert "re-authorize" in reason


def test_a_refusal_explains_itself_in_numbers():
    b = IrreversibilityBudget(0.5)
    _ok, charge, _ = b.check("g", tool="w", kind=Reversibility.IRREVERSIBLE, risk=40)
    b.commit("g", charge)
    _ok, _c, reason = b.check("g", tool="w", kind=Reversibility.IRREVERSIBLE, risk=40)
    assert "0.500" in reason and "0.400" in reason


def test_budgets_are_scoped_per_grant():
    b = IrreversibilityBudget(0.5)
    ok, charge, _ = b.check("grant-a", tool="w", kind=Reversibility.IRREVERSIBLE, risk=40)
    assert ok
    b.commit("grant-a", charge)
    # A different grant has its own ceiling, because the grant is the unit a human
    # authorized and therefore the unit they should be asked to renew.
    ok, _c, _r = b.check("grant-b", tool="w", kind=Reversibility.IRREVERSIBLE, risk=40)
    assert ok


def test_a_successful_undo_returns_headroom():
    """The incentive must point at repairing exposure, not hoarding it."""
    b = IrreversibilityBudget(1.0)
    _ok, charge, _ = b.check("g", tool="w", kind=Reversibility.COMPENSABLE, risk=100)
    b.commit("g", charge)
    spent = b.state("g").spent
    assert spent > 0
    b.refund("g", charge)
    assert b.state("g").spent == pytest.approx(0.0)


def test_reset_is_the_human_reauthorization_path():
    b = IrreversibilityBudget(0.5)
    _ok, charge, _ = b.check("g", tool="w", kind=Reversibility.IRREVERSIBLE, risk=60)
    b.commit("g", charge)
    assert b.state("g").exhausted
    b.reset("g")
    assert not b.state("g").exhausted


def test_budget_is_priced_on_the_resolved_posture_not_the_tool_name():
    """The improvement over the published irreversibility-budget framing.

    The same S3 delete is nearly free against a versioned bucket and full price
    against an unversioned one. A budget keyed on tool names would either bankrupt
    safe cleanup or hand out free credit for permanent deletion.
    """
    b = IrreversibilityBudget(10.0)
    versioned = b.price(tool="aws.s3.delete_object", kind=Reversibility.COMPENSABLE, risk=50)
    unversioned = b.price(tool="aws.s3.delete_object", kind=Reversibility.IRREVERSIBLE, risk=50)
    assert unversioned.cost > versioned.cost * 3


def test_budget_stops_the_fanout_the_detector_only_notices():
    """The measured gap, closed.

    PRA01 is a threshold detector, so four one-way wires land before the pattern is
    visible. A budget refuses earlier — same scenario, same rubber-stamping human.
    """
    import dataclasses

    base = next(s for s in _MALICIOUS if s.id == "M10-irreversible-fanout")
    detect_only = Harness().run(base)
    budgeted = Harness().run(dataclasses.replace(base, irreversibility_ceiling=1.5))

    landed_detect = sum(1 for s in detect_only.steps if s.executed)
    landed_budget = sum(1 for s in budgeted.steps if s.executed)
    assert landed_budget < landed_detect
    assert any(s.stage == "budget" for s in budgeted.steps if not s.allowed)


def test_the_corpus_keeps_both_halves_of_the_controlled_pair():
    """Baseline and treatment both stay, so the effect is attributable."""
    ids = {s.id for s in _MALICIOUS}
    assert {"M10-irreversible-fanout", "M18-fanout-under-budget"} <= ids
    pair = [s for s in _MALICIOUS if s.technique == "T09"]
    assert {s.irreversibility_ceiling for s in pair} == {None, 1.5}


# ---------------------------------------------------------------------------
# Recovery drills
# ---------------------------------------------------------------------------

_SPEC = InverseSpec(
    tool="vendor.update_bank",
    kind=Reversibility.REVERSIBLE,
    inverse_tool="vendor.restore_bank",
    arg_map=(("id", "args.id"), ("account", "snapshot.account")),
    snapshot_fields=("account",),
)


def _canary_world(*, honest: bool = True) -> World:
    """`honest=False` gives an inverse that accepts the call and writes nothing —
    the phantom rollback. The forward tool always works, so the drill has a real
    change to fail to undo."""
    w = World()
    w.bind(
        ToolBinding("vendor.update_bank", VERB_UPDATE, kind="vendor", id_arg="id",
                    field_args=("account",)),
        ToolBinding("vendor.restore_bank", VERB_UPDATE, kind="vendor", id_arg="id",
                    field_args=("account",) if honest else ()),
    )
    return w.seed("vendor", "CANARY-1", account="REAL-0001")


def _runner(world: World) -> DrillRunner:
    return DrillRunner(
        InverseRegistry([_SPEC]),
        executor=world.executor,
        state_reader=world.state_reader,
    )


def _canary(world: World) -> Canary:
    return Canary(
        tool="vendor.update_bank",
        args={"id": "CANARY-1", "account": "DRILL-9999"},
        verify=lambda: dict(world.get("vendor", "CANARY-1") or {}),
        label="canary-vendor",
    )


def test_a_working_inverse_passes_its_drill_and_leaves_state_intact():
    w = _canary_world(honest=True)
    result = _runner(w).drill(_canary(w))
    assert result.outcome is DrillOutcome.PASSED
    assert result.proves_recoverable
    assert w.get("vendor", "CANARY-1")["account"] == "REAL-0001"   # put back


def test_a_drill_catches_an_inverse_that_reports_success_and_restores_nothing():
    """The whole reason this exists.

    Every layer above believes this spec is REVERSIBLE. The receipt says ok. Only
    comparing state before and after reveals the truth — which is exactly the
    failure a schema check or a 200 response cannot see.
    """
    w = _canary_world(honest=False)   # the "inverse" writes no fields
    result = _runner(w).drill(_canary(w))
    assert result.outcome is DrillOutcome.FAILED
    assert "account" in result.mismatches
    assert "DID NOT RESTORE" in result.summary


def test_an_irreversible_tool_is_not_drillable_and_that_is_not_an_alarm():
    spec = InverseSpec(tool="wire.send", kind=Reversibility.IRREVERSIBLE)
    w = World().bind(ToolBinding("wire.send", VERB_UPDATE, kind="w", id_arg="id"))
    runner = DrillRunner(InverseRegistry([spec]), executor=w.executor)
    r = runner.drill(Canary(tool="wire.send", args={"id": "x"}, verify=lambda: {}))
    assert r.outcome is DrillOutcome.NOT_DRILLABLE
    assert not r.outcome.is_alarm


def test_a_broken_forward_call_is_distinguished_from_a_broken_inverse():
    w = _canary_world()
    w.reject.add("vendor.update_bank")
    r = _runner(w).drill(_canary(w))
    assert r.outcome is DrillOutcome.FORWARD_FAILED
    assert r.outcome.is_alarm


# ---------------------------------------------------------------------------
# Proof-gated classification: reversibility that expires
# ---------------------------------------------------------------------------


def test_proof_expires_and_a_stale_claim_stops_counting_as_reversible():
    reg = RecoverabilityRegister(stale_after=3600.0)
    w = _canary_world()
    result = _runner(w).drill(_canary(w), now=1000.0)
    reg.record(result)

    assert reg.is_proven("vendor.update_bank", now=1500.0)          # fresh
    assert not reg.is_proven("vendor.update_bank", now=99_000.0)    # stale

    # And the hook demotes the declared posture once the proof goes stale.
    assert (
        reg.classify_hook("vendor.update_bank", Reversibility.REVERSIBLE, now=1500.0)
        is Reversibility.REVERSIBLE
    )
    assert (
        reg.classify_hook("vendor.update_bank", Reversibility.REVERSIBLE, now=99_000.0)
        is Reversibility.IRREVERSIBLE
    )


def test_a_failing_drill_demotes_immediately_even_after_an_older_pass():
    reg = RecoverabilityRegister(stale_after=3600.0)
    w_ok = _canary_world(honest=True)
    reg.record(_runner(w_ok).drill(_canary(w_ok), now=1000.0))
    w_bad = _canary_world(honest=False)
    reg.record(_runner(w_bad).drill(_canary(w_bad), now=1100.0))
    assert not reg.is_proven("vendor.update_bank", now=1200.0)
    assert (
        reg.classify_hook("vendor.update_bank", Reversibility.REVERSIBLE, now=1200.0)
        is Reversibility.IRREVERSIBLE
    )


def test_an_undrilled_tool_keeps_its_declared_posture():
    """Demoting everything on day one would make the feature unadoptable."""
    reg = RecoverabilityRegister()
    assert (
        reg.classify_hook("never.drilled", Reversibility.REVERSIBLE)
        is Reversibility.REVERSIBLE
    )


def test_the_hook_can_never_upgrade_a_posture():
    """A hook that could raise a posture would manufacture recoverability."""
    from revoco.reversal.engine import ReversalEngine

    eng = ReversalEngine(
        InverseRegistry([InverseSpec(tool="x.go", kind=Reversibility.IRREVERSIBLE)]),
        classify_hook=lambda tool, kind: Reversibility.REVERSIBLE,
    )
    assert eng.classify("x.go") is Reversibility.IRREVERSIBLE


def test_an_exploding_hook_leaves_the_declared_posture_alone():
    from revoco.reversal.engine import ReversalEngine

    def boom(tool, kind):
        raise RuntimeError("register unreachable")

    eng = ReversalEngine(InverseRegistry([_SPEC]), classify_hook=boom)
    assert eng.classify("vendor.update_bank") is Reversibility.REVERSIBLE


def test_a_control_plane_with_a_stale_register_escalates_the_write():
    """End to end: the policy escalates because the proof went stale."""
    reg = RecoverabilityRegister(stale_after=1.0)
    w = _canary_world(honest=False)
    reg.record(_runner(w).drill(_canary(w)))   # a failing drill

    cp = ControlPlane(
        policy=load_policy({
            "name": "p", "default_effect": "deny",
            "rules": [
                {"id": "no-undo", "effect": "require_approval",
                 "reversibility": ["irreversible", "unknown"], "min_risk": 40},
                {"id": "ok", "effect": "allow",
                 "reversibility": ["reversible", "compensable"]},
            ],
        }),
        inverse_registry=InverseRegistry([_SPEC]),
        state_reader=w.state_reader,
        recoverability_register=reg,
        approval_hook=lambda *a: False,
    )
    h_priv, h_pub = crypto.generate_keypair()
    a_priv, a_pub = crypto.generate_keypair()
    owner = cp.register_human("Owner", h_pub)
    bot = cp.register_agent("bot", a_pub)
    grant = cp.issue_root_delegation(
        human_private_key=h_priv, human_id=owner.id, agent_id=bot.id,
        scope=Scope.make(tools={"vendor.update_bank"}, actions={"write"}, max_risk=80),
        purpose="maintain vendors", ttl_seconds=600,
    )
    v = cp.authorize(
        actor_private_key=a_priv, actor_id=bot.id, delegation_id=grant.id,
        tool="vendor.update_bank", args={"id": "V-9", "account": "NEW"},
        risk=60, description="maintain vendor bank details", session_id="s",
    )
    # The spec says REVERSIBLE. The evidence says otherwise, and the evidence wins.
    assert v.reversibility is Reversibility.IRREVERSIBLE
    assert not v.allowed


# ---------------------------------------------------------------------------
# Proof-of-recoverability attestation
# ---------------------------------------------------------------------------


def test_an_attestation_states_when_the_inverse_was_last_proven_and_verifies():
    reg = RecoverabilityRegister(stale_after=86_400.0)
    w = _canary_world()
    reg.record(_runner(w).drill(_canary(w), now=1000.0))

    priv, pub = crypto.generate_keypair()
    att = attest(
        action_id="act_1", tool="vendor.update_bank",
        reversibility=Reversibility.REVERSIBLE,
        plan_digest="d" * 64, plan_complete=True, register=reg,
        attestor_private_key=priv, attestor_id="revoco-1", now=4600.0,
    )
    assert att.proven
    assert att.proof_age_seconds == pytest.approx(3600.0)
    assert att.verify_signature(pub)
    assert "proven working against a canary 1.0h before" in att.statement


def test_an_attestation_admits_when_there_is_no_fresh_proof():
    """The artifact has to be able to say no, or it is marketing rather than evidence."""
    priv, _pub = crypto.generate_keypair()
    att = attest(
        action_id="act_2", tool="vendor.update_bank",
        reversibility=Reversibility.REVERSIBLE,
        plan_digest="e" * 64, plan_complete=True, register=RecoverabilityRegister(),
        attestor_private_key=priv, attestor_id="revoco-1", now=100.0,
    )
    assert not att.proven
    assert "had NOT been proven working" in att.statement


def test_an_attestation_for_an_irreversible_action_says_so_plainly():
    priv, _pub = crypto.generate_keypair()
    att = attest(
        action_id="act_3", tool="wire.send", reversibility=Reversibility.IRREVERSIBLE,
        plan_digest="0" * 64, plan_complete=False, register=None,
        attestor_private_key=priv, attestor_id="revoco-1",
    )
    assert "no rollback path existed, and this was known before it ran" in att.statement


def test_tampering_with_an_attestation_breaks_its_signature():
    import dataclasses

    priv, pub = crypto.generate_keypair()
    att = attest(
        action_id="act_4", tool="vendor.update_bank",
        reversibility=Reversibility.REVERSIBLE, plan_digest="f" * 64,
        plan_complete=True, register=None,
        attestor_private_key=priv, attestor_id="revoco-1",
    )
    assert att.verify_signature(pub)
    forged = dataclasses.replace(att, proven=True, proof_age_seconds=1.0)
    assert not forged.verify_signature(pub)


# ---------------------------------------------------------------------------
# Reporting
# ---------------------------------------------------------------------------


def test_coverage_reports_proven_rather_than_merely_declared_recoverability():
    reg = RecoverabilityRegister(stale_after=86_400.0)
    w = _canary_world()
    reg.record(_runner(w).drill(_canary(w), now=1000.0))
    cov = reg.coverage(["vendor.update_bank", "other.tool"], now=1100.0)
    assert cov["proven"] == ["vendor.update_bank"]
    assert cov["undrilled"] == ["other.tool"]
    assert cov["proven_pct"] == 50.0


def test_render_report_separates_failing_from_stale_from_proven():
    reg = RecoverabilityRegister(stale_after=1.0)
    w = _canary_world(honest=False)
    reg.record(_runner(w).drill(_canary(w)))
    out = render_report(reg)
    assert "failing their drill" in out
    assert "hypothesis" in out
