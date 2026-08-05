"""The unified hash-chained ledger."""

from __future__ import annotations

import pytest

from praetor.core.errors import TamperDetected
from praetor.ledger import GENESIS_PREV_HASH, Ledger, LedgerEntry


def _fill(n: int = 5) -> Ledger:
    led = Ledger()
    for i in range(n):
        led.append("action", {"i": i})
    return led


def test_empty_ledger_head_is_genesis():
    assert Ledger().head_hash == GENESIS_PREV_HASH
    assert Ledger().merkle_root() == GENESIS_PREV_HASH


def test_chain_verifies():
    assert _fill().verify_integrity() is True


def test_edited_payload_is_detected():
    led = _fill()
    entries = led.entries()
    entries[2] = LedgerEntry(
        seq=entries[2].seq,
        kind=entries[2].kind,
        payload={"i": 999},           # altered
        recorded_at=entries[2].recorded_at,
        prev_hash=entries[2].prev_hash,
        entry_hash=entries[2].entry_hash,   # stale hash
    )
    led.load_entries(entries)
    with pytest.raises(TamperDetected, match="altered payload"):
        led.verify_integrity()


def test_interior_deletion_is_detected():
    led = _fill()
    entries = led.entries()
    del entries[2]
    led.load_entries(entries)
    with pytest.raises(TamperDetected):
        led.verify_integrity()


def test_reorder_is_detected():
    led = _fill()
    entries = led.entries()
    entries[1], entries[3] = entries[3], entries[1]
    # load_entries sorts by seq, so rewrite the seqs to simulate a real reorder.
    swapped = [
        LedgerEntry(seq=i, kind=e.kind, payload=e.payload, recorded_at=e.recorded_at,
                    prev_hash=e.prev_hash, entry_hash=e.entry_hash)
        for i, e in enumerate(entries)
    ]
    led.load_entries(swapped)
    with pytest.raises(TamperDetected):
        led.verify_integrity()


def test_truncation_is_NOT_detected_by_the_chain_alone():
    """The documented limitation. The surviving prefix is internally valid."""
    led = _fill(5)
    led.load_entries(led.entries()[:3])
    assert led.verify_integrity() is True   # honest: this passes


def test_truncation_IS_detected_against_a_witnessed_head():
    led = _fill(5)
    witnessed = led.head_hash
    led.load_entries(led.entries()[:3])
    with pytest.raises(TamperDetected, match="witnessed"):
        led.verify_against_head(witnessed)


def test_merkle_root_changes_when_history_changes():
    led = _fill(4)
    before = led.merkle_root()
    led.append("action", {"i": 99})
    assert led.merkle_root() != before


def test_merkle_root_is_deterministic_for_the_same_history():
    led = _fill(4)
    assert led.merkle_root() == led.merkle_root()


def test_counts_by_kind():
    led = Ledger()
    led.append("action", {})
    led.append("action", {})
    led.append("verdict", {})
    assert led.counts_by_kind() == {"action": 2, "verdict": 1}


def test_write_through_hook_failure_does_not_corrupt_the_chain():
    def boom(entry):
        raise RuntimeError("disk full")

    led = Ledger(on_append=boom)
    led.append("action", {"i": 0})
    led.append("action", {"i": 1})
    assert len(led) == 2
    assert led.verify_integrity() is True


def test_checkpoint_exposes_anchorable_values():
    led = _fill(3)
    cp = led.checkpoint()
    assert cp["entries"] == 3
    assert cp["head_hash"] == led.head_hash
    assert cp["merkle_root"] == led.merkle_root()
