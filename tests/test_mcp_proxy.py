"""The MCP stdio proxy, exercised without spawning anything.

`run()` owns process management; every decision it makes lives in
`_on_client_line` and `_on_upstream_line`, so the tests drive those directly
against a real ControlPlane and a fake upstream pipe. A proxy tested against a
mocked control plane would prove only that the mock was called.
"""

from __future__ import annotations

import io
import json

import pytest

from revoco import ControlPlane, Scope, crypto
from revoco.gate import load_policy
from revoco.mcp import Caller, McpProxy
from revoco.reversal import ap_starter_registry

REVERSIBILITY_FIRST = {
    "name": "mcp-test",
    "default_effect": "deny",
    "rules": [
        {"id": "reads", "effect": "allow", "actions": ["read"]},
        {"id": "no-undo", "effect": "deny", "reversibility": ["irreversible", "unknown"]},
        {"id": "undoable", "effect": "allow", "min_reversibility": "compensable"},
    ],
}


class Upstream(io.RawIOBase):
    """Stands in for the real server's stdin. Records what was forwarded."""

    def __init__(self) -> None:
        self.lines: list[dict] = []

    def write(self, data) -> int:  # type: ignore[override]
        for line in bytes(data).decode().splitlines():
            if line.strip():
                self.lines.append(json.loads(line))
        return len(data)

    def flush(self) -> None:
        pass


def _read_state(tool, args, fields):
    """A stand-in system of record.

    Without one, `invoices.pay` cannot capture the prior state its inverse needs
    and revoco refuses the call outright as a phantom rollback — correctly, but
    it means the proxy would never be reached. The first version of this fixture
    omitted it and every gated test failed at the detect stage.
    """
    prior = {"status": "approved", "paid_amount": 0.0, "payment_id": None,
             "bank_account": "REAL-1111", "remit_to": "a@b.example"}
    return {f: prior.get(f) for f in fields}


def _proxy(monkeypatch, policy=None):
    cp = ControlPlane(
        policy=load_policy(policy or REVERSIBILITY_FIRST),
        inverse_registry=ap_starter_registry(),
        state_reader=_read_state,
    )
    h_priv, h_pub = crypto.generate_keypair()
    a_priv, a_pub = crypto.generate_keypair()
    cfo = cp.register_human("CFO", h_pub)
    bot = cp.register_agent("bot", a_pub, roles={"ap-clerk"})
    grant = cp.issue_root_delegation(
        human_private_key=h_priv, human_id=cfo.id, agent_id=bot.id,
        scope=Scope.make(
            tools={"invoices.read", "invoices.pay", "payments.wire", "vendors.update"},
            actions={"read", "write"}, max_risk=70),
        purpose="pay approved invoices", ttl_seconds=600,
    )
    caller = Caller(actor_id=bot.id, actor_private_key=a_priv,
                    delegation_id=grant.id, session_id="s")
    proxy = McpProxy(cp, caller, ["true"],
                     action_of=lambda t, a: "read" if t.endswith(".read") else "write")

    replies: list[dict] = []
    monkeypatch.setattr(proxy, "_reply", replies.append)
    return proxy, cp, Upstream(), replies


def _call(tool, args=None, request_id=1):
    return json.dumps({"jsonrpc": "2.0", "id": request_id, "method": "tools/call",
                       "params": {"name": tool, "arguments": args or {}}})


# ---- what is and is not gated ---------------------------------------------

def test_the_handshake_is_forwarded_untouched(monkeypatch):
    """Gating `initialize` would break the session and govern nothing: a
    handshake is not an action."""
    proxy, _cp, up, replies = _proxy(monkeypatch)
    proxy._on_client_line(json.dumps({"jsonrpc": "2.0", "id": 0, "method": "initialize"}), up)
    assert up.lines == [{"jsonrpc": "2.0", "id": 0, "method": "initialize"}]
    assert replies == []


def test_a_permitted_call_reaches_upstream(monkeypatch):
    proxy, _cp, up, replies = _proxy(monkeypatch)
    proxy._on_client_line(_call("invoices.read", {"invoice_id": "INV-1"}), up)
    assert len(up.lines) == 1
    assert up.lines[0]["params"]["name"] == "invoices.read"
    assert replies == []


def test_an_unrecoverable_call_is_refused_and_never_forwarded(monkeypatch):
    """The refusal has to name the posture. "Denied" alone tells the operator
    nothing about whether the policy or the tool is the thing to change."""
    proxy, _cp, up, replies = _proxy(monkeypatch)
    proxy._on_client_line(_call("payments.wire", {"amount": 10}), up)
    assert up.lines == []
    assert len(replies) == 1
    msg = replies[0]["error"]["message"]
    assert "payments.wire" in msg
    assert "reversibility=irreversible" in msg
    assert "stage=" in msg


def test_a_call_with_no_id_is_refused_rather_than_forwarded_unconfirmable(monkeypatch):
    """Without an id there is no response to correlate, so `confirm` could never
    run and the undo plan would never bind its result-derived arguments.
    Forwarding it would silently discard half of the design."""
    proxy, _cp, up, replies = _proxy(monkeypatch)
    proxy._on_client_line(json.dumps({
        "jsonrpc": "2.0", "method": "tools/call",
        "params": {"name": "invoices.read", "arguments": {}}}), up)
    assert up.lines == []
    assert "cannot be confirmed" in replies[0]["error"]["message"]


# ---- the half a forwarding proxy would throw away --------------------------

def test_a_successful_response_confirms_the_journalled_action(monkeypatch):
    """revoco journals the undo plan at authorize time and binds result-derived
    arguments at confirm. A proxy that only forwarded would never reach the
    second half, and the plan would stay pending forever."""
    proxy, cp, up, _replies = _proxy(monkeypatch)
    proxy._on_client_line(_call("invoices.pay", {"invoice_id": "INV-1", "amount": 900}), up)
    assert proxy._pending, "the verdict should be held until upstream answers"

    proxy._on_upstream_line(json.dumps(
        {"jsonrpc": "2.0", "id": 1, "result": {"payment_id": "PAY-77"}}))

    assert proxy._pending == {}, "the pending entry should be cleared on response"
    committed = [e for e in cp.reversal.entries() if e.state.value == "committed"]
    assert len(committed) == 1


def test_an_upstream_error_abandons_the_undo_plan(monkeypatch):
    """The action did not happen. Leaving the entry open would offer a rollback
    for a call that never landed."""
    proxy, cp, up, _replies = _proxy(monkeypatch)
    proxy._on_client_line(_call("invoices.pay", {"invoice_id": "INV-1", "amount": 900}), up)
    proxy._on_upstream_line(json.dumps(
        {"jsonrpc": "2.0", "id": 1, "error": {"code": -1, "message": "upstream exploded"}}))

    assert proxy._pending == {}
    states = {e.state.value for e in cp.reversal.entries()}
    assert "committed" not in states
    assert "abandoned" in states


def test_a_response_to_something_never_gated_is_ignored(monkeypatch):
    proxy, _cp, _up, _replies = _proxy(monkeypatch)
    proxy._on_upstream_line(json.dumps({"jsonrpc": "2.0", "id": 999, "result": {}}))
    assert proxy._pending == {}


def test_a_proxy_with_nowhere_to_forward_is_refused_at_construction():
    with pytest.raises(ValueError):
        McpProxy(None, None, [])  # type: ignore[arg-type]
