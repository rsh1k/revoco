"""Authority layer: capability attenuation, chain reconstruction, revocation."""

from __future__ import annotations

import time

import pytest

from praetor.authority import AuthorityEngine, Scope
from praetor.core import crypto
from praetor.core.errors import ExpiredGrant, ScopeViolation, ValidationError
from praetor.reversal.model import Reversibility


@pytest.fixture
def party():
    """A CFO, an orchestrator, and a worker, with keys."""
    eng = AuthorityEngine()
    h_priv, h_pub = crypto.generate_keypair()
    o_priv, o_pub = crypto.generate_keypair()
    w_priv, w_pub = crypto.generate_keypair()
    return {
        "eng": eng,
        "h_priv": h_priv,
        "o_priv": o_priv,
        "w_priv": w_priv,
        "cfo": eng.register_human("Alice (CFO)", h_pub),
        "orch": eng.register_agent("orchestrator", o_pub, roles={"ap-clerk"}),
        "work": eng.register_agent("worker", w_pub),
    }


# ---- scope attenuation ----------------------------------------------------


def test_scope_contains_rejects_tool_escalation():
    parent = Scope.make(tools={"a", "b"}, actions={"read"}, max_risk=50)
    assert parent.contains(Scope.make(tools={"a"}, actions={"read"}, max_risk=10))
    assert not parent.contains(Scope.make(tools={"a", "c"}, actions={"read"}, max_risk=10))


def test_scope_contains_rejects_wildcard_escalation():
    parent = Scope.make(tools={"a"}, actions={"read"}, max_risk=50)
    assert not parent.contains(Scope.make(tools={"*"}, actions={"read"}, max_risk=10))


def test_scope_contains_rejects_risk_escalation():
    parent = Scope.make(tools={"a"}, actions={"read"}, max_risk=20)
    assert not parent.contains(Scope.make(tools={"a"}, actions={"read"}, max_risk=21))


def test_child_omitting_a_cap_inherits_it_rather_than_escaping_it():
    parent = Scope.make(tools={"a"}, actions={"write"}, max_risk=50,
                        constraints={"max:amount": 100})
    child = Scope.make(tools={"a"}, actions={"write"}, max_risk=50)
    assert parent.contains(child)
    # ...and the cap still binds at the leaf.
    assert Scope.effective_constraints([child, parent])["max:amount"] == 100


def test_child_stating_a_looser_cap_is_escalation():
    parent = Scope.make(tools={"a"}, actions={"write"}, max_risk=50,
                        constraints={"max:amount": 100})
    child = Scope.make(tools={"a"}, actions={"write"}, max_risk=50,
                       constraints={"max:amount": 101})
    assert not parent.contains(child)


def test_effective_constraints_takes_the_tightest_cap_in_the_chain():
    scopes = [
        Scope.make(constraints={"max:amount": 50}),
        Scope.make(constraints={"max:amount": 500}),
        Scope.make(constraints={"max:amount": 200}),
    ]
    assert Scope.effective_constraints(scopes)["max:amount"] == 50


# ---- reversibility floor as a capability ---------------------------------


def test_reversibility_floor_cannot_be_relaxed_downward():
    parent = Scope.make(tools={"a"}, actions={"write"}, max_risk=50,
                        min_reversibility=Reversibility.REVERSIBLE)
    looser = Scope.make(tools={"a"}, actions={"write"}, max_risk=50,
                        min_reversibility=Reversibility.COMPENSABLE)
    assert not parent.contains(looser)
    stricter = Scope.make(tools={"a"}, actions={"write"}, max_risk=50,
                          min_reversibility=Reversibility.REVERSIBLE)
    assert parent.contains(stricter)


def test_child_dropping_the_floor_entirely_is_escalation():
    parent = Scope.make(tools={"a"}, actions={"write"},
                        min_reversibility=Reversibility.COMPENSABLE)
    silent = Scope.make(tools={"a"}, actions={"write"})
    assert not parent.contains(silent)


def test_unknown_floor_means_no_requirement():
    s = Scope.make(tools={"a"})
    assert s.permits_reversibility(Reversibility.IRREVERSIBLE)
    assert s.permits_reversibility(Reversibility.UNKNOWN)


def test_stated_floor_rejects_unknown_and_irreversible():
    s = Scope.make(tools={"a"}, min_reversibility=Reversibility.COMPENSABLE)
    assert not s.permits_reversibility(Reversibility.UNKNOWN)
    assert not s.permits_reversibility(Reversibility.IRREVERSIBLE)
    assert s.permits_reversibility(Reversibility.COMPENSABLE)
    assert s.permits_reversibility(Reversibility.REVERSIBLE)


def test_effective_floor_is_the_strictest_in_the_chain():
    scopes = [
        Scope.make(min_reversibility=Reversibility.COMPENSABLE),
        Scope.make(min_reversibility=Reversibility.REVERSIBLE),
        Scope.make(),
    ]
    assert Scope.effective_reversibility_floor(scopes) is Reversibility.REVERSIBLE


def test_scope_round_trips_through_dict():
    s = Scope.make(tools={"a"}, actions={"write"}, max_risk=33,
                   constraints={"max:amount": 7}, min_reversibility=Reversibility.COMPENSABLE)
    assert Scope.from_dict(s.to_dict()) == s


# ---- delegation ----------------------------------------------------------


def test_root_delegation_must_come_from_a_human(party):
    eng = party["eng"]
    with pytest.raises(ValidationError):
        eng.issue_root_delegation(
            human_private_key=party["o_priv"],
            human_id=party["orch"].id,       # an agent, not a human
            agent_id=party["work"].id,
            scope=Scope.make(tools={"a"}, actions={"read"}, max_risk=10),
            purpose="nope",
            ttl_seconds=60,
        )


def test_sub_delegation_cannot_escalate(party):
    eng = party["eng"]
    root = eng.issue_root_delegation(
        human_private_key=party["h_priv"], human_id=party["cfo"].id,
        agent_id=party["orch"].id,
        scope=Scope.make(tools={"invoices.read"}, actions={"read"}, max_risk=20),
        purpose="read invoices", ttl_seconds=600,
    )
    with pytest.raises(ScopeViolation):
        eng.sub_delegate(
            issuer_private_key=party["o_priv"], issuer_id=party["orch"].id,
            subject_id=party["work"].id, parent_delegation_id=root.id,
            scope=Scope.make(tools={"invoices.pay"}, actions={"write"}, max_risk=90),
            purpose="pay", ttl_seconds=600,
        )


def test_agent_cannot_delegate_authority_it_never_held(party):
    eng = party["eng"]
    root = eng.issue_root_delegation(
        human_private_key=party["h_priv"], human_id=party["cfo"].id,
        agent_id=party["orch"].id,
        scope=Scope.make(tools={"a"}, actions={"read"}, max_risk=20),
        purpose="p", ttl_seconds=600,
    )
    # The worker was never the subject of root, so it cannot sub-delegate from it.
    with pytest.raises(ScopeViolation):
        eng.sub_delegate(
            issuer_private_key=party["w_priv"], issuer_id=party["work"].id,
            subject_id=party["orch"].id, parent_delegation_id=root.id,
            scope=Scope.make(tools={"a"}, actions={"read"}, max_risk=10),
            purpose="p", ttl_seconds=60,
        )


def test_child_ttl_is_clamped_to_the_parent(party):
    eng = party["eng"]
    now = time.time()
    root = eng.issue_root_delegation(
        human_private_key=party["h_priv"], human_id=party["cfo"].id,
        agent_id=party["orch"].id,
        scope=Scope.make(tools={"a"}, actions={"read"}, max_risk=20),
        purpose="p", ttl_seconds=100, now=now,
    )
    sub = eng.sub_delegate(
        issuer_private_key=party["o_priv"], issuer_id=party["orch"].id,
        subject_id=party["work"].id, parent_delegation_id=root.id,
        scope=Scope.make(tools={"a"}, actions={"read"}, max_risk=10),
        purpose="p", ttl_seconds=99_999, now=now,
    )
    assert sub.expires_at <= root.expires_at


def test_expired_parent_cannot_delegate(party):
    eng = party["eng"]
    now = time.time()
    root = eng.issue_root_delegation(
        human_private_key=party["h_priv"], human_id=party["cfo"].id,
        agent_id=party["orch"].id,
        scope=Scope.make(tools={"a"}, actions={"read"}, max_risk=20),
        purpose="p", ttl_seconds=10, now=now,
    )
    with pytest.raises(ExpiredGrant):
        eng.sub_delegate(
            issuer_private_key=party["o_priv"], issuer_id=party["orch"].id,
            subject_id=party["work"].id, parent_delegation_id=root.id,
            scope=Scope.make(tools={"a"}, actions={"read"}, max_risk=10),
            purpose="p", ttl_seconds=5, now=now + 20,
        )


# ---- chain reconstruction -------------------------------------------------


def _two_hop(party):
    eng = party["eng"]
    root = eng.issue_root_delegation(
        human_private_key=party["h_priv"], human_id=party["cfo"].id,
        agent_id=party["orch"].id,
        scope=Scope.make(tools={"invoices.read", "invoices.pay"},
                         actions={"read", "write"}, max_risk=60,
                         constraints={"max:amount": 1000}),
        purpose="reconcile and pay invoices", ttl_seconds=600,
    )
    sub = eng.sub_delegate(
        issuer_private_key=party["o_priv"], issuer_id=party["orch"].id,
        subject_id=party["work"].id, parent_delegation_id=root.id,
        scope=Scope.make(tools={"invoices.read"}, actions={"read"}, max_risk=20,
                         constraints={"max:amount": 500}),
        purpose="read invoices", ttl_seconds=300,
    )
    return root, sub


def test_chain_reconstructs_to_the_human_root(party):
    eng = party["eng"]
    _root, sub = _two_hop(party)
    rec = eng.record_action(
        actor_private_key=party["w_priv"], actor_id=party["work"].id,
        delegation_id=sub.id, tool="invoices.read", action="read", risk=10,
        description="read invoice batch",
    )
    chain = eng.reconstruct_chain(rec.id)
    assert chain.ok
    assert chain.human_root_name == "Alice (CFO)"
    assert chain.hops == 2
    # Tightest cap across both hops wins.
    assert chain.effective_constraints["max:amount"] == 500


def test_revoking_a_grant_breaks_previously_recorded_actions(party):
    eng = party["eng"]
    _root, sub = _two_hop(party)
    rec = eng.record_action(
        actor_private_key=party["w_priv"], actor_id=party["work"].id,
        delegation_id=sub.id, tool="invoices.read", action="read", risk=10,
        description="read invoice batch",
    )
    assert eng.reconstruct_chain(rec.id).ok
    eng.revoke_delegation(sub.id, "key leak")
    after = eng.reconstruct_chain(rec.id)
    assert not after.ok
    assert any("revoked" in e for e in after.errors)


def test_revoking_the_human_invalidates_the_whole_chain(party):
    eng = party["eng"]
    _root, sub = _two_hop(party)
    rec = eng.record_action(
        actor_private_key=party["w_priv"], actor_id=party["work"].id,
        delegation_id=sub.id, tool="invoices.read", action="read", risk=10,
        description="read",
    )
    eng.revoke_principal(party["cfo"].id, "offboarded")
    assert not eng.reconstruct_chain(rec.id).ok


def test_tampered_action_signature_is_caught(party):
    from dataclasses import replace

    eng = party["eng"]
    _root, sub = _two_hop(party)
    rec = eng.record_action(
        actor_private_key=party["w_priv"], actor_id=party["work"].id,
        delegation_id=sub.id, tool="invoices.read", action="read", risk=10,
        description="read invoice batch",
    )
    # Rewrite the recorded action in place, as a database-level attacker would.
    eng._actions[rec.id] = replace(rec, tool="invoices.pay", risk=99)
    chain = eng.reconstruct_chain(rec.id)
    assert not chain.ok
    assert any("signature invalid" in e for e in chain.errors)


def test_descendant_delegations_returns_the_whole_subtree(party):
    eng = party["eng"]
    root, sub = _two_hop(party)
    subtree = eng.descendant_delegations(root.id)
    assert set(subtree) == {root.id, sub.id}
    assert eng.descendant_delegations(sub.id) == [sub.id]


def test_principal_cannot_be_re_registered_with_a_different_key(party):
    from praetor.authority.principals import Principal, PrincipalKind

    eng = party["eng"]
    _other_priv, other_pub = crypto.generate_keypair()
    impostor = Principal(
        id=party["work"].id, kind=PrincipalKind.AGENT, name="worker", public_key=other_pub
    )
    with pytest.raises(ValidationError):
        eng.registry.register(impostor)
