"""Rebuilding a horizon from what a control plane persisted.

The console renders a horizon. Until now a horizon could only come from a live
in-process ControlPlane, which is not the situation an operator is ever in: the
process that held it has exited and the journal on disk is what is left.
"""

from __future__ import annotations

import pytest

from revoco import ControlPlane, Scope, crypto
from revoco.core.errors import ValidationError
from revoco.gate import load_policy
from revoco.reversal import InverseRegistry, InverseSpec, Reversibility
from revoco.reversal.horizon import build
from revoco.reversal.model import JournalEntry, JournalState, PlannedStep, ReversalPlan

PERMISSIVE = {"name": "t", "default_effect": "allow",
              "rules": [{"id": "a", "effect": "allow"}]}


def _plane(store=None):
    reg = InverseRegistry([
        InverseSpec(tool="payments.schedule", kind=Reversibility.REVERSIBLE,
                    inverse_tool="payments.cancel",
                    arg_map=(("payment_id", "args.payment_id"),),
                    window_seconds=1800.0),
        InverseSpec(tool="vendors.update", kind=Reversibility.REVERSIBLE,
                    inverse_tool="vendors.update",
                    arg_map=(("vendor_id", "args.vendor_id"),
                             ("bank_account", "snapshot.bank_account")),
                    snapshot_fields=("bank_account",)),
        InverseSpec(tool="payments.wire", kind=Reversibility.IRREVERSIBLE),
    ])
    cp = ControlPlane(policy=load_policy(PERMISSIVE), inverse_registry=reg,
                      state_reader=lambda t, a, f: {x: "prior" for x in f},
                      store=store)
    hp, hb = crypto.generate_keypair()
    ap, ab = crypto.generate_keypair()
    cfo = cp.register_human("CFO", hb)
    bot = cp.register_agent("bot", ab)
    g = cp.issue_root_delegation(
        human_private_key=hp, human_id=cfo.id, agent_id=bot.id,
        scope=Scope.make(tools={"*"}, actions={"read", "write"}, max_risk=90),
        purpose="p", ttl_seconds=7200)
    return cp, ap, bot, g


def _act(cp, ap, bot, g, tool, args, risk=10):
    v = cp.authorize(actor_private_key=ap, actor_id=bot.id, delegation_id=g.id,
                     tool=tool, args=args, action="write", risk=risk, session_id="s1")
    if v.allowed:
        cp.confirm(v, result={"payment_id": "PAY-1"})
    return v


def test_a_horizon_rebuilt_from_the_journal_matches_the_live_one(tmp_path):
    """The whole point. If the rebuilt view disagreed with the one the process
    held, the console would be showing a different estate from the one that ran."""
    from revoco.store.sqlite import SqliteStore

    store = SqliteStore(str(tmp_path / "s.db"))
    cp, ap, bot, g = _plane(store)
    _act(cp, ap, bot, g, "payments.schedule", {"payment_id": "PAY-1"})
    _act(cp, ap, bot, g, "vendors.update", {"vendor_id": "V-1"})
    _act(cp, ap, bot, g, "payments.wire", {"amount": 5000}, risk=80)

    live = cp.horizon()
    rebuilt = build([JournalEntry.from_dict(r) for r in store.load_journal()],
                    now=live.at)

    def shape(h):
        return {k: sorted(e.tool for e in getattr(h, k))
                for k in ("closing", "open_indefinitely", "expired",
                          "standing_exposure", "broken")}

    assert shape(rebuilt) == shape(live)
    assert rebuilt.undoable_count == live.undoable_count
    assert rebuilt.unrecoverable_count == live.unrecoverable_count
    assert rebuilt.recoverable_fraction == live.recoverable_fraction
    assert abs((rebuilt.time_to_first_close or 0)
               - (live.time_to_first_close or 0)) < 0.01


def test_a_plan_survives_the_round_trip_with_its_steps_and_gates():
    from revoco.reversal.model import ReversalGate

    plan = ReversalPlan(
        id="p1", tool="sap.pay", kind=Reversibility.COMPENSABLE,
        inverse_tool=None, inverse_args={"a": 1}, unresolved_args=("b",),
        snapshot={"prior": "x"}, window_seconds=60.0, residue="stays",
        created_at=1000.0, snapshot_error=None, deferred_args=("c",),
        steps=(PlannedStep(name="undo", tool="sap.reverse", args={"doc": 1},
                           unresolved=("d",), description="step"),),
        gates=(ReversalGate(name="period_open", description="must be open"),),
        one_shot=True,
    )
    back = ReversalPlan.from_dict(plan.to_dict())
    assert back.to_dict() == plan.to_dict()
    assert back.steps[0].unresolved == ("d",)
    assert back.gates[0].name == "period_open"
    assert back.one_shot is True


def test_a_derived_expiry_is_not_read_back_from_the_file():
    """`expires_at` is written for readers and derived from the plan's window and
    the commit time. Accepting the stored value would let a hand-edited file
    claim a window the plan does not support."""
    plan = ReversalPlan(id="p", tool="t", kind=Reversibility.REVERSIBLE,
                        inverse_tool="u", inverse_args={}, unresolved_args=(),
                        snapshot={}, window_seconds=60.0, residue="",
                        created_at=1000.0)
    entry = JournalEntry(id="j", plan=plan, state=JournalState.COMMITTED,
                         committed_at=1000.0)
    d = entry.to_dict()
    assert d["expires_at"] == 1060.0

    d["expires_at"] = 9_999_999_999.0          # a claim the plan cannot support
    assert JournalEntry.from_dict(d).expires_at == 1060.0


def test_a_malformed_entry_is_refused_rather_than_half_built():
    with pytest.raises(ValidationError):
        JournalEntry.from_dict({"id": "j", "state": "committed"})
    with pytest.raises(ValidationError):
        JournalEntry.from_dict({"id": "j", "state": "not-a-state",
                                "plan": {"id": "p", "tool": "t",
                                         "kind": "reversible", "created_at": 1.0}})
    with pytest.raises(ValidationError):
        ReversalPlan.from_dict({"id": "p", "tool": "t", "kind": "nonsense",
                                "created_at": 1.0})
