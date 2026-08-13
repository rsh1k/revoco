"""The full pipeline: stage attribution, caps, containment, evidence."""

from __future__ import annotations

import pytest

from revoco import ControlPlane, Scope, crypto
from revoco.controlplane import (
    STAGE_ALLOWED,
    STAGE_AUTHORITY,
    STAGE_DETECT,
    STAGE_ENFORCE,
)
from revoco.evidence import build_evidence_pack, readiness_report
from revoco.gate import Effect, load_policy
from revoco.reversal import InverseRegistry, InverseSpec, Reversibility, ap_starter_registry

PERMISSIVE = {
    "name": "test-permissive",
    "default_effect": "allow",
    "rules": [{"id": "allow-all", "effect": "allow"}],
}

REVERSIBILITY_FIRST = {
    "name": "test-reversibility-first",
    "default_effect": "deny",
    "rules": [
        {"id": "reads", "effect": "allow", "actions": ["read"]},
        {"id": "no-undo", "effect": "require_approval",
         "reversibility": ["irreversible", "unknown"]},
        {"id": "undoable", "effect": "allow", "reversibility": ["reversible", "compensable"]},
    ],
}


class FakeStore:
    """Minimal stand-in for a system of record."""

    def __init__(self) -> None:
        self.vendors = {"V-1": {"bank_account": "REAL-1111", "remit_to": "a@b.example"}}
        self.invoices = {"INV-1": {"status": "approved", "paid_amount": 0.0,
                                   "payment_id": None, "amount": 900.0}}
        self.calls: list[tuple[str, dict]] = []
        self._seq = 0

    def read_state(self, tool, args, fields):
        if tool.startswith("vendors.") and "vendor_id" in args:
            src = self.vendors.get(args["vendor_id"], {})
        elif tool.startswith("invoices.") and "invoice_id" in args:
            src = self.invoices.get(args["invoice_id"], {})
        else:
            src = {}
        return {f: src[f] for f in fields if f in src}

    def execute(self, tool, args):
        self.calls.append((tool, dict(args)))
        if tool == "vendors.update":
            v = self.vendors[args["vendor_id"]]
            for f in ("bank_account", "remit_to"):
                if args.get(f) is not None:
                    v[f] = args[f]
            return dict(v)
        if tool == "invoices.pay":
            self._seq += 1
            pid = f"PAY-{self._seq}"
            inv = self.invoices[args["invoice_id"]]
            inv.update(status="paid", paid_amount=float(args["amount"]), payment_id=pid)
            return {"payment_id": pid}
        if tool == "invoices.void_payment":
            inv = self.invoices[args["invoice_id"]]
            inv.update(status="approved", paid_amount=0.0, payment_id=None)
            return {"voided": args.get("payment_id")}
        if tool == "invoices.read":
            return self.invoices.get(args["invoice_id"])
        if tool == "noop.none":
            return None
        if tool == "payments.wire":
            return {"wire_id": "W-1"}
        raise KeyError(tool)


def build(policy=None, *, approval=None, scope_kw=None):
    """A control plane with a CFO, an agent, and a root grant."""
    store = FakeStore()
    cp = ControlPlane(
        policy=load_policy(policy or PERMISSIVE),
        inverse_registry=ap_starter_registry(),
        state_reader=store.read_state,
        approval_hook=approval,
    )
    h_priv, h_pub = crypto.generate_keypair()
    a_priv, a_pub = crypto.generate_keypair()
    cfo = cp.register_human("Alice (CFO)", h_pub)
    bot = cp.register_agent("ap-bot", a_pub, roles={"ap-clerk"})
    kw = dict(
        tools={"invoices.read", "invoices.pay", "vendors.update", "payments.wire"},
        actions={"read", "write"},
        max_risk=70,
    )
    kw.update(scope_kw or {})
    grant = cp.issue_root_delegation(
        human_private_key=h_priv, human_id=cfo.id, agent_id=bot.id,
        scope=Scope.make(**kw), purpose="pay approved supplier invoices",
        ttl_seconds=600,
    )
    return cp, store, bot, a_priv, grant, cfo, h_priv


# ---- happy path -----------------------------------------------------------


def test_allowed_action_traces_to_the_human_and_is_undoable():
    cp, store, bot, a_priv, grant, _cfo, _h = build()
    v = cp.authorize(
        actor_private_key=a_priv, actor_id=bot.id, delegation_id=grant.id,
        tool="vendors.update", args={"vendor_id": "V-1", "bank_account": "NEW-2222"},
        risk=50, description="update supplier remittance details", session_id="s1",
    )
    assert v.allowed
    assert v.stage == STAGE_ALLOWED
    assert v.human_root == "Alice (CFO)"
    assert v.undoable
    assert v.plan.snapshot["bank_account"] == "REAL-1111"   # captured BEFORE
    cp.confirm(v, result=store.execute("vendors.update", v.effective_args))
    assert store.vendors["V-1"]["bank_account"] == "NEW-2222"


def test_undo_restores_prior_state():
    cp, store, bot, a_priv, grant, _c, _h = build()
    v = cp.authorize(
        actor_private_key=a_priv, actor_id=bot.id, delegation_id=grant.id,
        tool="vendors.update", args={"vendor_id": "V-1", "bank_account": "MULE-9999"},
        risk=50, description="update remittance", session_id="s1",
    )
    cp.confirm(v, result=store.execute("vendors.update", v.effective_args))
    receipt = cp.undo(v.action_id, store.execute)
    assert receipt.ok
    assert store.vendors["V-1"]["bank_account"] == "REAL-1111"


def test_confirm_binds_a_result_derived_inverse_argument():
    cp, store, bot, a_priv, grant, _c, _h = build()
    v = cp.authorize(
        actor_private_key=a_priv, actor_id=bot.id, delegation_id=grant.id,
        tool="invoices.pay", args={"invoice_id": "INV-1", "amount": 900},
        risk=60, description="pay approved supplier invoice", session_id="s1",
    )
    assert v.undoable
    assert "payment_id" in v.plan.deferred_args
    cp.confirm(v, result=store.execute("invoices.pay", v.effective_args))
    entry = cp.reversal.for_action(v.action_id)
    assert entry.plan.inverse_args["payment_id"] == "PAY-1"
    assert entry.plan.is_complete


# ---- stage attribution ----------------------------------------------------


def test_policy_refusal_is_attributed_to_the_enforce_stage():
    cp, _store, bot, a_priv, grant, _c, _h = build(
        {"name": "deny-all", "default_effect": "deny", "rules": []}
    )
    v = cp.authorize(
        actor_private_key=a_priv, actor_id=bot.id, delegation_id=grant.id,
        tool="invoices.pay", args={"invoice_id": "INV-1", "amount": 1},
        risk=10, description="pay", session_id="s1",
    )
    assert not v.allowed
    assert v.stage == STAGE_ENFORCE


def test_out_of_scope_action_is_attributed_to_detection():
    cp, _store, bot, a_priv, grant, _c, _h = build(
        scope_kw={"tools": {"invoices.read"}, "actions": {"read"}, "max_risk": 10}
    )
    v = cp.authorize(
        actor_private_key=a_priv, actor_id=bot.id, delegation_id=grant.id,
        tool="invoices.pay", args={"invoice_id": "INV-1", "amount": 1},
        risk=60, description="pay invoice", session_id="s1",
    )
    assert not v.allowed
    assert v.stage == STAGE_DETECT
    assert "ASI02" in [f["code"] for f in v.findings]


def test_revoked_grant_is_attributed_to_the_authority_stage():
    cp, _store, bot, a_priv, grant, _c, _h = build()
    cp.authority.revoke_delegation(grant.id, "key leak")
    v = cp.authorize(
        actor_private_key=a_priv, actor_id=bot.id, delegation_id=grant.id,
        tool="invoices.read", action="read", args={"invoice_id": "INV-1"},
        risk=5, description="read invoice", session_id="s1",
    )
    assert not v.allowed
    assert v.stage == STAGE_AUTHORITY


def test_a_blocked_attempt_is_still_recorded_as_evidence():
    cp, _store, bot, a_priv, grant, _c, _h = build(
        {"name": "deny-all", "default_effect": "deny", "rules": []}
    )
    v = cp.authorize(
        actor_private_key=a_priv, actor_id=bot.id, delegation_id=grant.id,
        tool="invoices.pay", args={"invoice_id": "INV-1", "amount": 1},
        risk=10, description="pay", session_id="s1",
    )
    assert v.action_id                       # an action record exists
    assert cp.authority.get_action(v.action_id) is not None
    assert v.ledger_seq is not None
    assert cp.verify()


def test_unknown_delegation_raises_rather_than_silently_denying():
    from revoco.core.errors import ChainBroken

    cp, _store, bot, a_priv, _grant, _c, _h = build()
    with pytest.raises(ChainBroken):
        cp.authorize(
            actor_private_key=a_priv, actor_id=bot.id, delegation_id="dlg_nope",
            tool="invoices.read", action="read", args={}, risk=1, description="x",
        )


# ---- reversibility as an authorization input ------------------------------


def test_reversibility_floor_blocks_an_otherwise_permitted_action():
    """Every classic check passes; only recoverability is missing."""
    cp, _store, bot, a_priv, grant, _c, _h = build(
        scope_kw={"min_reversibility": Reversibility.COMPENSABLE}
    )
    v = cp.authorize(
        actor_private_key=a_priv, actor_id=bot.id, delegation_id=grant.id,
        tool="payments.wire",                 # in scope, under risk ceiling
        args={"beneficiary": "X", "amount": 100},
        risk=60, description="wire funds to supplier", session_id="s1",
    )
    assert not v.allowed
    assert v.reversibility is Reversibility.IRREVERSIBLE
    assert any("reversibility floor" in f["title"] for f in v.findings)
    # And it is the *only* reason: scope, risk, and policy all permitted it.
    assert len(v.findings) == 1


def test_policy_escalates_an_unclassified_tool_to_a_human():
    seen: list[str] = []

    def approver(tool, args, principal, decision):
        seen.append(tool)
        return False

    cp = ControlPlane(
        policy=load_policy(REVERSIBILITY_FIRST),
        inverse_registry=InverseRegistry(),   # nothing classified at all
        approval_hook=approver,
    )
    h_priv, h_pub = crypto.generate_keypair()
    a_priv, a_pub = crypto.generate_keypair()
    cfo = cp.register_human("CFO", h_pub)
    bot = cp.register_agent("bot", a_pub)
    grant = cp.issue_root_delegation(
        human_private_key=h_priv, human_id=cfo.id, agent_id=bot.id,
        scope=Scope.make(tools={"mystery.tool"}, actions={"write"}, max_risk=50),
        purpose="do a mystery thing", ttl_seconds=60,
    )
    v = cp.authorize(
        actor_private_key=a_priv, actor_id=bot.id, delegation_id=grant.id,
        tool="mystery.tool", args={}, risk=10, description="do a mystery thing",
        session_id="s1",
    )
    assert seen == ["mystery.tool"]
    assert not v.allowed
    assert v.effect is Effect.REQUIRE_APPROVAL


def test_approval_defaults_to_refusal_when_no_hook_is_wired_up():
    cp = ControlPlane(policy=load_policy(REVERSIBILITY_FIRST), inverse_registry=InverseRegistry())
    h_priv, h_pub = crypto.generate_keypair()
    a_priv, a_pub = crypto.generate_keypair()
    cfo = cp.register_human("CFO", h_pub)
    bot = cp.register_agent("bot", a_pub)
    grant = cp.issue_root_delegation(
        human_private_key=h_priv, human_id=cfo.id, agent_id=bot.id,
        scope=Scope.make(tools={"x.y"}, actions={"write"}, max_risk=50),
        purpose="x y", ttl_seconds=60,
    )
    v = cp.authorize(
        actor_private_key=a_priv, actor_id=bot.id, delegation_id=grant.id,
        tool="x.y", args={}, risk=1, description="x y", session_id="s1",
    )
    assert not v.allowed and not v.approved_by_human


def test_a_blocked_action_abandons_its_reversal_plan():
    cp, _store, bot, a_priv, grant, _c, _h = build(
        scope_kw={"tools": {"invoices.read"}, "actions": {"read"}, "max_risk": 10}
    )
    v = cp.authorize(
        actor_private_key=a_priv, actor_id=bot.id, delegation_id=grant.id,
        tool="invoices.pay", args={"invoice_id": "INV-1", "amount": 1},
        risk=60, description="pay invoice", session_id="s1",
    )
    entry = cp.reversal.get(v.journal_id)
    assert entry.state.value == "abandoned"


# ---- chain caps -----------------------------------------------------------


def test_a_delegated_cap_is_actually_enforced_against_the_argument():
    """The gap this closes: the cap used to be computed and never compared."""
    cp, _store, bot, a_priv, grant, _c, _h = build(
        scope_kw={"constraints": {"max:amount": 500}}
    )
    ok = cp.authorize(
        actor_private_key=a_priv, actor_id=bot.id, delegation_id=grant.id,
        tool="invoices.pay", args={"invoice_id": "INV-1", "amount": 400},
        risk=60, description="pay approved supplier invoice", session_id="s1",
    )
    assert ok.allowed
    over = cp.authorize(
        actor_private_key=a_priv, actor_id=bot.id, delegation_id=grant.id,
        tool="invoices.pay", args={"invoice_id": "INV-1", "amount": 600},
        risk=60, description="pay approved supplier invoice", session_id="s1",
    )
    assert not over.allowed
    assert any("exceeds a delegated cap" in f["title"] for f in over.findings)


def test_the_tightest_cap_in_the_chain_binds():
    cp, _store, bot, a_priv, grant, cfo, h_priv = build(
        scope_kw={"constraints": {"max:amount": 500}}
    )
    w_priv, w_pub = crypto.generate_keypair()
    worker = cp.register_agent("worker", w_pub)
    sub = cp.sub_delegate(
        issuer_private_key=a_priv, issuer_id=bot.id, subject_id=worker.id,
        parent_delegation_id=grant.id,
        scope=Scope.make(tools={"invoices.pay"}, actions={"write"}, max_risk=70,
                         constraints={"max:amount": 100}),
        purpose="pay approved supplier invoices", ttl_seconds=60,
    )
    v = cp.authorize(
        actor_private_key=w_priv, actor_id=worker.id, delegation_id=sub.id,
        tool="invoices.pay", args={"invoice_id": "INV-1", "amount": 200},
        risk=60, description="pay approved supplier invoice", session_id="s1",
    )
    assert not v.allowed   # 200 <= parent's 500 but > the sub-grant's 100


# ---- containment ----------------------------------------------------------


def test_containment_revokes_the_subtree_and_rolls_back_its_actions():
    cp, store, bot, a_priv, grant, _cfo, _h = build()
    w_priv, w_pub = crypto.generate_keypair()
    worker = cp.register_agent("worker", w_pub)
    sub = cp.sub_delegate(
        issuer_private_key=a_priv, issuer_id=bot.id, subject_id=worker.id,
        parent_delegation_id=grant.id,
        scope=Scope.make(tools={"vendors.update"}, actions={"write"}, max_risk=60),
        purpose="update supplier remittance details", ttl_seconds=60,
    )

    v1 = cp.authorize(
        actor_private_key=a_priv, actor_id=bot.id, delegation_id=grant.id,
        tool="invoices.pay", args={"invoice_id": "INV-1", "amount": 900},
        risk=60, description="pay approved supplier invoice", session_id="s1",
    )
    cp.confirm(v1, result=store.execute("invoices.pay", v1.effective_args))

    v2 = cp.authorize(
        actor_private_key=w_priv, actor_id=worker.id, delegation_id=sub.id,
        tool="vendors.update", args={"vendor_id": "V-1", "bank_account": "MULE-9999"},
        risk=55, description="update supplier remittance details", session_id="s2",
    )
    cp.confirm(v2, result=store.execute("vendors.update", v2.effective_args))

    assert store.vendors["V-1"]["bank_account"] == "MULE-9999"
    assert store.invoices["INV-1"]["status"] == "paid"

    report = cp.contain(grant.id, store.execute, reason="incident")

    # Both grants revoked, both actions rolled back — including the one taken
    # under the sub-delegation, which is the part a single-grant view would miss.
    assert set(report["revoked_delegations"]) == {grant.id, sub.id}
    assert report["rollback"]["reversed_ok"] == 2
    assert report["fully_contained"]
    assert store.vendors["V-1"]["bank_account"] == "REAL-1111"
    assert store.invoices["INV-1"]["status"] == "approved"
    assert cp.verify()


def test_containment_reports_residue_it_could_not_undo():
    cp, store, bot, a_priv, grant, _c, _h = build()
    v = cp.authorize(
        actor_private_key=a_priv, actor_id=bot.id, delegation_id=grant.id,
        tool="invoices.pay", args={"invoice_id": "INV-1", "amount": 900},
        risk=60, description="pay approved supplier invoice", session_id="s1",
    )
    cp.confirm(v, result=store.execute("invoices.pay", v.effective_args))
    report = cp.contain(grant.id, store.execute)
    assert any("remittance advice" in r for r in report["rollback"]["residues"])


def test_containment_does_not_stop_at_the_first_un_undoable_action():
    """One irreversible action must not prevent reverting the others."""
    cp, store, bot, a_priv, grant, _c, _h = build()
    v_wire = cp.authorize(
        actor_private_key=a_priv, actor_id=bot.id, delegation_id=grant.id,
        tool="payments.wire", args={"amount": 10}, risk=60,
        description="wire funds to supplier", session_id="s1",
    )
    cp.confirm(v_wire, result=store.execute("payments.wire", v_wire.effective_args))
    v_pay = cp.authorize(
        actor_private_key=a_priv, actor_id=bot.id, delegation_id=grant.id,
        tool="invoices.pay", args={"invoice_id": "INV-1", "amount": 900},
        risk=60, description="pay approved supplier invoice", session_id="s1",
    )
    cp.confirm(v_pay, result=store.execute("invoices.pay", v_pay.effective_args))

    report = cp.contain(grant.id, store.execute)
    assert report["rollback"]["reversed_ok"] == 1
    assert report["rollback"]["skipped"] == 1
    assert not report["fully_contained"]        # honest: the wire is gone
    assert store.invoices["INV-1"]["status"] == "approved"


def test_undoing_a_payment_returns_its_spend_to_the_session_budget():
    policy = {
        "name": "budgeted", "default_effect": "deny",
        "rules": [{"id": "pay", "effect": "allow", "tools": ["invoices.pay"],
                   "budget": {"key": "total", "field": "amount", "limit": 1000}}],
    }
    cp, store, bot, a_priv, grant, _c, _h = build(policy)
    v = cp.authorize(
        actor_private_key=a_priv, actor_id=bot.id, delegation_id=grant.id,
        tool="invoices.pay", args={"invoice_id": "INV-1", "amount": 900},
        risk=60, description="pay approved supplier invoice", session_id="s1",
    )
    cp.confirm(v, result=store.execute("invoices.pay", v.effective_args))
    assert cp.gate.store.get_total("s1", "total") == 900
    assert cp.undo(v.action_id, store.execute).ok
    assert cp.gate.store.get_total("s1", "total") == 0


# ---- detectors that need the merge ---------------------------------------


def test_phantom_rollback_is_flagged_when_the_snapshot_cannot_be_taken():
    """PRA02: believing you can undo something you cannot is the worst state."""
    cp = ControlPlane(
        policy=load_policy(PERMISSIVE),
        inverse_registry=ap_starter_registry(),
        state_reader=lambda t, a, f: {},        # returns nothing
    )
    h_priv, h_pub = crypto.generate_keypair()
    a_priv, a_pub = crypto.generate_keypair()
    cfo = cp.register_human("CFO", h_pub)
    bot = cp.register_agent("bot", a_pub)
    grant = cp.issue_root_delegation(
        human_private_key=h_priv, human_id=cfo.id, agent_id=bot.id,
        scope=Scope.make(tools={"vendors.update"}, actions={"write"}, max_risk=70),
        purpose="update supplier remittance details", ttl_seconds=60,
    )
    v = cp.authorize(
        actor_private_key=a_priv, actor_id=bot.id, delegation_id=grant.id,
        tool="vendors.update", args={"vendor_id": "V-1", "bank_account": "X"},
        risk=50, description="update supplier remittance details", session_id="s1",
    )
    assert "PRA02" in [f["code"] for f in v.findings]
    assert not v.allowed          # HIGH severity blocks


def test_irreversible_fanout_is_flagged():
    """PRA01: fan-out with no undo path is unbounded loss, not just fragility."""
    reg = InverseRegistry([InverseSpec(tool="oneway.go", kind=Reversibility.IRREVERSIBLE)])
    cp = ControlPlane(policy=load_policy(PERMISSIVE), inverse_registry=reg)
    h_priv, h_pub = crypto.generate_keypair()
    a_priv, a_pub = crypto.generate_keypair()
    cfo = cp.register_human("CFO", h_pub)
    bot = cp.register_agent("bot", a_pub)
    grant = cp.issue_root_delegation(
        human_private_key=h_priv, human_id=cfo.id, agent_id=bot.id,
        scope=Scope.make(tools={"oneway.go"}, actions={"write"}, max_risk=70),
        purpose="go one way", ttl_seconds=600,
    )
    codes: list[str] = []
    for _ in range(6):
        v = cp.authorize(
            actor_private_key=a_priv, actor_id=bot.id, delegation_id=grant.id,
            tool="oneway.go", args={}, risk=10, description="go one way",
            session_id="s1",
        )
        codes = [f["code"] for f in v.findings]
        if v.allowed:
            cp.confirm(v, result=None)
    assert "PRA01" in codes


# ---- evidence -------------------------------------------------------------


def test_evidence_pack_verifies_and_reports_honestly():
    cp, store, bot, a_priv, grant, _c, _h = build()
    v = cp.authorize(
        actor_private_key=a_priv, actor_id=bot.id, delegation_id=grant.id,
        tool="invoices.pay", args={"invoice_id": "INV-1", "amount": 900},
        risk=60, description="pay approved supplier invoice", session_id="s1",
    )
    cp.confirm(v, result=store.execute("invoices.pay", v.effective_args))

    pack = build_evidence_pack(
        cp.ledger, cp.reversal,
        policy_name=cp.gate.policy.name, policy_digest=cp.gate.policy.digest(),
    )
    d = pack.to_dict()
    assert d["integrity"]["chain_verified"] is True
    assert d["integrity"]["head_hash"] == cp.ledger.head_hash
    assert d["recoverability"]["actually_undoable"] == 1
    assert d["recoverability"]["phantom_rollbacks"] == 0
    assert d["pack_digest"]
    assert d["limitations"]                       # never claims completeness

    md = pack.to_markdown()
    assert "Agent Action Evidence Pack" in md
    assert "Limitations of this pack" in md


def test_evidence_pack_surfaces_a_broken_chain_prominently():
    cp, _store, _bot, _a, _g, _c, _h = build()
    cp.ledger.append("action", {"x": 1})
    entries = cp.ledger.entries()
    del entries[1]
    cp.ledger.load_entries(entries)
    pack = build_evidence_pack(cp.ledger, cp.reversal)
    d = pack.to_dict()
    assert d["integrity"]["chain_verified"] is False
    assert "failed integrity verification" in d["limitations"][0]


def test_readiness_report_names_the_unclassified_gap():
    cp, _store, _bot, _a, _g, _c, _h = build()
    r = readiness_report(cp.reversal, ["invoices.pay", "totally.unmapped"])
    assert r["verdict"] == "gaps present"
    assert "totally.unmapped" in r["unclassified_tools"]


def test_stats_expose_the_policy_digest_and_ledger_head():
    cp, _store, _bot, _a, _g, _c, _h = build()
    s = cp.stats()
    assert s["policy_digest"] == cp.gate.policy.digest()
    assert s["ledger_head"] == cp.ledger.head_hash


def test_fail_closed_blocks_on_an_internal_error():
    cp, _store, bot, a_priv, grant, _c, _h = build()

    def explode(*a, **kw):
        raise RuntimeError("boom")

    cp.reversal.classify = explode        # simulate an internal defect
    v = cp.authorize(
        actor_private_key=a_priv, actor_id=bot.id, delegation_id=grant.id,
        tool="invoices.pay", args={"invoice_id": "INV-1", "amount": 1},
        risk=10, description="pay", session_id="s1",
    )
    assert not v.allowed
    assert v.stage == "engine_failure"
    assert cp.verify()                    # the failure itself is on the ledger


# ---- strike accounting ----------------------------------------------------


def test_declining_an_approval_is_not_a_strike_against_the_agent():
    """A person saying no is the control working, not the agent misbehaving.

    The rogue-agent detector exists to catch an actor that keeps reaching for
    things it was never granted. A declined approval is the opposite: the
    policy deliberately handed the decision to a human, and the human used it.
    Counting those made the detector measure human caution, so an agent that
    proposed three risky-but-legitimate changes got quarantined for it.
    """
    cp, _store, bot, a_priv, grant, _cfo, _h = build(
        REVERSIBILITY_FIRST, approval=lambda *a, **k: False)

    for _ in range(5):
        v = cp.authorize(
            actor_private_key=a_priv, actor_id=bot.id, delegation_id=grant.id,
            tool="payments.wire", args={"amount": 10.0}, action="write",
            description="wire funds",
        )
        assert not v.allowed
        assert v.effect is Effect.REQUIRE_APPROVAL

    assert cp._actor_strikes.get(bot.id, 0) == 0, (
        "declined approvals accumulated strikes; the agent is being penalised "
        "for a human's decision")

    # And the agent is still able to work afterwards.
    ok = cp.authorize(
        actor_private_key=a_priv, actor_id=bot.id, delegation_id=grant.id,
        tool="invoices.read", args={"invoice_id": "INV-1"}, action="read",
        description="read an invoice",
    )
    assert ok.allowed, "a well-behaved agent was quarantined by human refusals"


def test_out_of_scope_attempts_still_accumulate_strikes():
    """The exemption above must not disarm the detector for real drift."""
    cp, _store, bot, a_priv, grant, _cfo, _h = build(PERMISSIVE)

    for _ in range(3):
        v = cp.authorize(
            actor_private_key=a_priv, actor_id=bot.id, delegation_id=grant.id,
            tool="admin.delete_everything", args={}, action="write",
            description="reach outside the grant",
        )
        assert not v.allowed
        assert v.effect is not Effect.REQUIRE_APPROVAL

    assert cp._actor_strikes.get(bot.id, 0) >= 3, (
        "an agent repeatedly reaching outside its grant stopped being tracked")
