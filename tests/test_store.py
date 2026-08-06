"""Durable storage: the evidence chain, the journal, and drill history.

The properties tested here are the ones persistence exists to provide, plus the two
hazards it introduces. A restart that loses the chain is a different failure from
tampering, and the whole point is that afterwards you can tell which one happened.
"""

from __future__ import annotations

import sqlite3

import pytest

from revoco import ControlPlane, Scope, crypto
from revoco.core.errors import TamperDetected
from revoco.drills import DrillOutcome, DrillResult, RecoverabilityRegister
from revoco.gate.policy import load_policy
from revoco.ledger import Ledger
from revoco.reversal import InverseRegistry, InverseSpec, Reversibility
from revoco.store import SqliteStore, StoreError

_SPEC = InverseSpec(
    tool="vendor.update",
    kind=Reversibility.REVERSIBLE,
    inverse_tool="vendor.update",
    arg_map=(("id", "args.id"), ("value", "snapshot.value")),
    snapshot_fields=("value",),
)

POLICY = {
    "name": "store-test", "default_effect": "deny",
    "rules": [
        {"id": "reads", "effect": "allow", "actions": ["read"]},
        {"id": "undoable", "effect": "allow", "reversibility": ["reversible", "compensable"]},
    ],
}


@pytest.fixture
def db(tmp_path):
    return tmp_path / "revoco.db"


def _plane(db, **kw):
    cp = ControlPlane(
        policy=load_policy(POLICY),
        inverse_registry=InverseRegistry([_SPEC]),
        state_reader=lambda t, a, f: {"value": "original"},
        store=SqliteStore(db),
        **kw,
    )
    h_priv, h_pub = crypto.generate_keypair()
    a_priv, a_pub = crypto.generate_keypair()
    owner = cp.register_human("Owner", h_pub)
    bot = cp.register_agent("bot", a_pub)
    grant = cp.issue_root_delegation(
        human_private_key=h_priv, human_id=owner.id, agent_id=bot.id,
        scope=Scope.make(tools={"vendor.update"}, actions={"write"}, max_risk=80),
        purpose="maintain vendors", ttl_seconds=3600,
    )
    return cp, bot, a_priv, grant


# ---------------------------------------------------------------------------
# The chain survives a restart
# ---------------------------------------------------------------------------


def test_write_through_persists_and_reloads_the_chain(db):
    store = SqliteStore(db)
    led = Ledger()
    for i in range(6):
        entry = led.prepare("action", {"i": i})
        store.append_ledger(entry)
        led.append_prebuilt(entry)
    head = led.head_hash
    assert led.verify_integrity()
    store.close()

    reopened = SqliteStore(db)
    reloaded = Ledger()
    reloaded.load_entries(reopened.load_ledger())
    assert len(reloaded) == 6
    assert reloaded.head_hash == head
    assert reloaded.verify_integrity()
    reopened.close()


def test_prepare_does_not_extend_the_chain_until_it_is_durable(db):
    """Appending before persisting would let the in-memory head outrun the disk.

    A crash in that window leaves a head hash nothing on disk supports, which reads
    as truncation to whoever verifies it later.
    """
    led = Ledger()
    entry = led.prepare("action", {"x": 1})
    assert len(led) == 0                    # not in the chain yet
    assert led.head_hash != entry.entry_hash
    led.append_prebuilt(entry)
    assert len(led) == 1 and led.head_hash == entry.entry_hash


def test_tampering_with_a_persisted_row_is_still_detected_after_reload(db):
    """Triggers stop the honest path; verification catches the dishonest one."""
    store = SqliteStore(db)
    led = Ledger()
    for i in range(4):
        e = led.prepare("action", {"i": i})
        store.append_ledger(e)
        led.append_prebuilt(e)
    store.close()

    # Drop the triggers, then tamper — i.e. an attacker with file access, not an
    # application bug. Verification must still notice.
    raw = sqlite3.connect(db)
    raw.executescript(
        "DROP TRIGGER ledger_is_append_only_update;"
        "UPDATE ledger SET payload='{\"i\": 999}' WHERE seq=1;"
    )
    raw.commit()
    raw.close()

    reopened = SqliteStore(db)
    reloaded = Ledger()
    reloaded.load_entries(reopened.load_ledger())
    with pytest.raises(TamperDetected):
        reloaded.verify_integrity()
    reopened.close()


# ---------------------------------------------------------------------------
# Append-only, enforced where SQLite has no GRANT
# ---------------------------------------------------------------------------


def test_ledger_rows_cannot_be_updated_or_deleted(db):
    """SQLite has no GRANT, so triggers are the mechanism — and they bind any client."""
    store = SqliteStore(db)
    e = Ledger().prepare("action", {"i": 0})
    store.append_ledger(e)
    store.close()

    raw = sqlite3.connect(db)
    with pytest.raises(sqlite3.IntegrityError, match="append-only"):
        raw.execute("UPDATE ledger SET kind='forged' WHERE seq=0")
    with pytest.raises(sqlite3.IntegrityError, match="append-only"):
        raw.execute("DELETE FROM ledger WHERE seq=0")
    raw.close()


def test_a_duplicate_sequence_is_refused_rather_than_silently_overwriting(db):
    store = SqliteStore(db)
    e = Ledger().prepare("action", {"i": 0})
    store.append_ledger(e)
    with pytest.raises(StoreError, match="conflicts"):
        store.append_ledger(e)
    store.close()


# ---------------------------------------------------------------------------
# The transaction boundary — the reason this module exists
# ---------------------------------------------------------------------------


def test_ledger_and_journal_are_written_atomically(db):
    store = SqliteStore(db)
    led = Ledger()
    e = led.prepare("reversal_commit", {"id": "j1"})
    store.record_reversal(e, {"id": "j1", "state": "committed",
                              "plan": {"tool": "vendor.update"}, "committed_at": 1.0})
    assert store.ledger_count() == 1
    assert len(store.load_journal()) == 1
    store.close()


def test_a_failed_journal_write_rolls_back_the_ledger_append(db):
    """Both or neither.

    Written separately, a crash between them leaves the journal claiming a plan the
    ledger never recorded — and afterwards nothing can tell you which one is true.
    """
    store = SqliteStore(db)
    led = Ledger()
    good = led.prepare("reversal_commit", {"id": "j1"})
    store.record_reversal(good, {"id": "j1", "state": "committed", "plan": {"tool": "t"}})
    led.append_prebuilt(good)
    assert store.ledger_count() == 1

    # Force the journal half to fail: `state` is NOT NULL.
    bad = led.prepare("reversal_commit", {"id": "j2"})
    # StoreError, not sqlite3.IntegrityError: the store presents its own type so a
    # caller can handle storage failure without importing sqlite3.
    with pytest.raises(StoreError, match="atomic ledger"):
        store.record_reversal(bad, {"id": "j2", "state": None, "plan": {"tool": "t"}})

    # The ledger append must have rolled back with it.
    assert store.ledger_count() == 1, "ledger kept an entry whose journal write failed"
    assert len(store.load_journal()) == 1
    store.close()


def test_a_control_plane_with_a_store_writes_both_sides(db):
    cp, bot, a_priv, grant = _plane(db)
    v = cp.authorize(
        actor_private_key=a_priv, actor_id=bot.id, delegation_id=grant.id,
        tool="vendor.update", args={"id": "V1", "value": "new"},
        risk=50, description="maintain vendor", session_id="s1",
    )
    assert v.allowed
    cp.confirm(v, result={})
    assert cp.store.ledger_count() == len(cp.ledger)
    assert cp.store.open_journal_count() >= 1
    assert cp.verify()
    cp.store.close()


def test_a_restart_recovers_the_chain_and_the_open_undo_windows(db):
    cp, bot, a_priv, grant = _plane(db)
    v = cp.authorize(
        actor_private_key=a_priv, actor_id=bot.id, delegation_id=grant.id,
        tool="vendor.update", args={"id": "V1", "value": "new"},
        risk=50, description="maintain vendor", session_id="s1",
    )
    cp.confirm(v, result={})
    head, count = cp.ledger.head_hash, len(cp.ledger)
    cp.store.close()

    # A new process, same file.
    revived = ControlPlane(
        policy=load_policy(POLICY),
        inverse_registry=InverseRegistry([_SPEC]),
        store=SqliteStore(db),
    )
    assert len(revived.ledger) == count
    assert revived.ledger.head_hash == head
    assert revived.verify()
    report = revived.store.startup_report()
    assert report.ledger_verified
    assert report.open_journal_entries >= 1
    assert any("live undo paths" in n for n in report.notes)
    revived.store.close()


# ---------------------------------------------------------------------------
# Drill history and the honest startup report
# ---------------------------------------------------------------------------


def test_drill_history_survives_a_restart_so_freshness_means_something(db):
    store = SqliteStore(db)
    reg = RecoverabilityRegister(stale_after=3600.0, store=store)
    reg.record(DrillResult(id="d1", tool="vendor.update", outcome=DrillOutcome.PASSED,
                           declared_kind=Reversibility.REVERSIBLE, at=1000.0, duration_ms=5.0))
    assert reg.is_proven("vendor.update", now=1100.0)
    store.close()

    reopened = SqliteStore(db)
    revived = RecoverabilityRegister(stale_after=3600.0, store=reopened)
    assert revived.is_proven("vendor.update", now=1100.0)   # remembered
    assert not revived.is_proven("vendor.update", now=99_000.0)
    reopened.close()


def test_downtime_counts_against_proof_freshness_rather_than_being_forgiven(db):
    """The tempting fix is the wrong one.

    Not counting downtime would be comfortable and unsafe: an upgrade during the
    outage is exactly when a spec silently becomes a confident wrong rollback. So the
    proof goes stale, the report says so, and remediation is prioritised — rather
    than freshness being granted on a technicality.
    """
    store = SqliteStore(db)
    reg = RecoverabilityRegister(stale_after=3600.0, store=store)
    reg.record(DrillResult(id="d1", tool="vendor.update", outcome=DrillOutcome.PASSED,
                           declared_kind=Reversibility.REVERSIBLE, at=1000.0, duration_ms=1.0))
    store.heartbeat(now=1000.0)
    store.close()

    reopened = SqliteStore(db)
    report = reopened.startup_report(stale_after=3600.0, now=1000.0 + 50_000)
    assert report.downtime_seconds == pytest.approx(50_000, rel=0.01)
    assert "vendor.update" in report.stale_proof_tools
    assert any("unproven until re-drilled" in n for n in report.notes)
    assert report.needs_attention

    revived = RecoverabilityRegister(stale_after=3600.0, store=reopened)
    assert not revived.is_proven("vendor.update", now=1000.0 + 50_000)
    # And it is first in the remediation queue.
    due = revived.due(["vendor.update"], now=1000.0 + 50_000)
    assert due and due[0].urgency == "stale"
    reopened.close()


def test_a_fresh_database_says_so_rather_than_implying_a_crash(db):
    store = SqliteStore(db)
    report = store.startup_report()
    assert report.fresh_database
    assert report.downtime_seconds is None
    assert report.ledger_verified and report.ledger_entries == 0
    store.close()


def test_the_startup_report_distinguishes_a_broken_chain_from_a_restart(db):
    """A clean restart loses nothing, so verification failure is never an artefact."""
    store = SqliteStore(db)
    led = Ledger()
    for i in range(3):
        e = led.prepare("action", {"i": i})
        store.append_ledger(e)
        led.append_prebuilt(e)
    store.close()

    raw = sqlite3.connect(db)
    raw.executescript(
        "DROP TRIGGER ledger_is_append_only_delete; DELETE FROM ledger WHERE seq=1;"
    )
    raw.commit()
    raw.close()

    reopened = SqliteStore(db)
    report = reopened.startup_report()
    assert not report.ledger_verified
    assert any("not a restart artefact" in n for n in report.notes)
    reopened.close()


def test_stats_report_what_is_actually_stored(db):
    store = SqliteStore(db)
    led = Ledger()
    e = led.prepare("action", {"i": 0})
    store.record_reversal(e, {"id": "j1", "state": "committed", "plan": {"tool": "t"}})
    store.record_drill({"id": "d1", "tool": "t", "outcome": "passed", "at": 1.0,
                        "declared_kind": "reversible", "duration_ms": 1.0})
    s = store.stats()
    assert s["ledger_entries"] == 1
    assert s["open_journal_entries"] == 1
    assert s["drills"] == 1
    assert s["tools_with_a_pass"] == 1
    store.close()


def test_no_ledger_append_bypasses_the_store(db):
    """Regression guard on a bug this suite caught.

    Two call sites appended straight to the in-memory ledger, so the chain ran one
    entry ahead of the durable copy — precisely the divergence persistence exists to
    prevent, and invisible until you compare the counts.
    """
    cp, bot, a_priv, grant = _plane(db)
    for i in range(3):
        v = cp.authorize(
            actor_private_key=a_priv, actor_id=bot.id, delegation_id=grant.id,
            tool="vendor.update", args={"id": f"V{i}", "value": "new"},
            risk=50, description="maintain vendor", session_id="s1",
        )
        if v.allowed:
            cp.confirm(v, result={})
    cp.contain(grant.id, lambda t, a: {}, reason="drill")
    assert cp.store.ledger_count() == len(cp.ledger)
    assert cp.verify()
    cp.store.close()
