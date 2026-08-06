"""
revoco.ledger
==============
One append-only, hash-chained ledger — the black-box flight recorder for the
whole control plane.

Every entry stores the hash of the entry before it, so the log forms a chain
anchored in a genesis hash. Changing, removing, or reordering any past entry
changes its hash and breaks every subsequent link, so a single
:meth:`Ledger.verify_integrity` pass detects tampering anywhere in history —
the property auditors and incident responders need and that ordinary
application logs lack (NIST SP 800-92).

Why there is exactly one of these
---------------------------------
The three merged tools each carried their own hash-chained audit log. Three
chains cannot be verified as one history: an attacker who altered a policy
decision in one log and the corresponding action record in another would break
both chains independently, and nothing in the system could prove the two logs
described the same event. Worse, cross-referencing them during an incident meant
reconciling three clocks. A single chain over authority, enforcement, and
reversal events makes "what happened, in what order, under whose authority" a
single verifiable question.

The ledger stores opaque payload dicts; it neither signs nor interprets them.
Signing lives with the producers (delegations, actions); integrity of *history*
lives here. Separating the two keeps each concern auditable on its own.
"""

from __future__ import annotations

import threading
import time
from collections.abc import Callable, Iterable, Iterator
from dataclasses import dataclass
from typing import Any

from .core import crypto
from .core.errors import TamperDetected

GENESIS_PREV_HASH = "0" * 64

# ---------------------------------------------------------------------------
# Entry kinds. Enumerated in one place so an evidence pack can assert it covered
# every kind of event rather than every kind it happened to know about.
# ---------------------------------------------------------------------------
KIND_PRINCIPAL = "principal"
KIND_DELEGATION = "delegation"
KIND_REVOCATION = "revocation"
KIND_ACTION = "action"
KIND_VERDICT = "verdict"           # the control plane's combined decision
KIND_GATE_DECISION = "gate_decision"
KIND_REVERSAL_PLAN = "reversal_plan"
KIND_REVERSAL_COMMIT = "reversal_commit"
KIND_REVERSAL_ABANDON = "reversal_abandon"
KIND_REVERSAL_EXECUTED = "reversal_executed"
KIND_REVERSAL_EXPIRED = "reversal_expired"
KIND_CHECKPOINT = "checkpoint"

ALL_KINDS = (
    KIND_PRINCIPAL,
    KIND_DELEGATION,
    KIND_REVOCATION,
    KIND_ACTION,
    KIND_VERDICT,
    KIND_GATE_DECISION,
    KIND_REVERSAL_PLAN,
    KIND_REVERSAL_COMMIT,
    KIND_REVERSAL_ABANDON,
    KIND_REVERSAL_EXECUTED,
    KIND_REVERSAL_EXPIRED,
    KIND_CHECKPOINT,
)


@dataclass(frozen=True)
class LedgerEntry:
    seq: int
    kind: str
    payload: dict[str, Any]
    recorded_at: float
    prev_hash: str
    entry_hash: str

    def _hash_input(self) -> bytes:
        return crypto.canonical_bytes(
            {
                "seq": self.seq,
                "kind": self.kind,
                "payload": self.payload,
                "recorded_at": self.recorded_at,
                "prev_hash": self.prev_hash,
            }
        )

    def compute_hash(self) -> str:
        return crypto.sha256_hex(self._hash_input())

    def to_dict(self) -> dict[str, Any]:
        return {
            "seq": self.seq,
            "kind": self.kind,
            "payload": self.payload,
            "recorded_at": self.recorded_at,
            "prev_hash": self.prev_hash,
            "entry_hash": self.entry_hash,
        }

    @classmethod
    def from_dict(cls, d: dict[str, Any]) -> LedgerEntry:
        return cls(
            seq=int(d["seq"]),
            kind=d["kind"],
            payload=d["payload"],
            recorded_at=float(d["recorded_at"]),
            prev_hash=d["prev_hash"],
            entry_hash=d["entry_hash"],
        )


class Ledger:
    """Thread-safe append-only hash-chained ledger.

    ``on_append`` is a write-through hook for durable storage. It must not raise;
    the caller guards it, because a persistence failure must never corrupt the
    in-memory chain.

    # HARDENING: this in-memory implementation is correct for a single process.
    # For production, back it with a WORM store (append-only object storage, or
    # an RDBMS table with INSERT-only grants) and publish the head hash to an
    # external witness on a schedule — see verify_against_head() for why.
    """

    def __init__(self, on_append: Callable[[LedgerEntry], None] | None = None) -> None:
        self._entries: list[LedgerEntry] = []
        self._lock = threading.Lock()
        self._on_append = on_append

    # ---- writing ----------------------------------------------------------
    def prepare(self, kind: str, payload: dict[str, Any]) -> LedgerEntry:
        """Compute the next entry without adding it to the chain.

        For durable deployments: build the entry, persist it, and only then call
        :meth:`append_prebuilt`. Appending first and writing second would let an
        in-memory chain run ahead of the durable one, so a crash in between leaves a
        head hash nothing on disk supports — which is indistinguishable from
        truncation to anyone verifying later.
        """
        with self._lock:
            return self._build(kind, payload)

    def _build(self, kind: str, payload: dict[str, Any]) -> LedgerEntry:
        seq = len(self._entries)
        prev_hash = self._entries[-1].entry_hash if self._entries else GENESIS_PREV_HASH
        recorded_at = time.time()
        partial = LedgerEntry(
            seq=seq,
            kind=kind,
            payload=payload,
            recorded_at=recorded_at,
            prev_hash=prev_hash,
            entry_hash="",
        )
        return LedgerEntry(
            seq=seq,
            kind=kind,
            payload=payload,
            recorded_at=recorded_at,
            prev_hash=prev_hash,
            entry_hash=partial.compute_hash(),
        )

    def append(self, kind: str, payload: dict[str, Any]) -> LedgerEntry:
        with self._lock:
            entry = self._build(kind, payload)
            self._entries.append(entry)
            if self._on_append is not None:
                try:
                    self._on_append(entry)
                except Exception:
                    # Surfaced by the store's own health checks, never by
                    # corrupting the chain we just extended.
                    pass
            return entry

    def load_entries(self, entries: list[LedgerEntry]) -> None:
        """Rehydrate from persisted entries WITHOUT recomputing hashes.

        Persisted hashes are authoritative; call :meth:`verify_integrity`
        afterwards to confirm the loaded chain is intact.
        """
        with self._lock:
            self._entries = sorted(entries, key=lambda e: e.seq)

    def append_prebuilt(self, entry: LedgerEntry) -> None:
        """Mirror an entry whose seq/hashes were assigned elsewhere."""
        with self._lock:
            self._entries.append(entry)

    # ---- reading ----------------------------------------------------------
    @property
    def head_hash(self) -> str:
        return self._entries[-1].entry_hash if self._entries else GENESIS_PREV_HASH

    def __len__(self) -> int:
        return len(self._entries)

    def __iter__(self) -> Iterator[LedgerEntry]:
        return iter(list(self._entries))

    def get(self, seq: int) -> LedgerEntry:
        return self._entries[seq]

    def entries(self) -> list[LedgerEntry]:
        return list(self._entries)

    def find(self, kind: str | None = None) -> Iterable[LedgerEntry]:
        for e in self._entries:
            if kind is None or e.kind == kind:
                yield e

    def counts_by_kind(self) -> dict[str, int]:
        out: dict[str, int] = {}
        for e in self._entries:
            out[e.kind] = out.get(e.kind, 0) + 1
        return out

    # ---- integrity --------------------------------------------------------
    def verify_integrity(self) -> bool:
        """Recompute the whole chain. Raises :class:`TamperDetected` on any break.

        A self-contained hash chain detects edits, reorders, and interior
        deletions — but not truncation of the most recent entries, because the
        remaining prefix is still internally valid. Use
        :meth:`verify_against_head` with an externally-witnessed head hash to
        detect truncation and forks.
        """
        prev = GENESIS_PREV_HASH
        for i, e in enumerate(self._entries):
            if e.seq != i:
                raise TamperDetected(f"sequence gap/reorder at index {i} (seq={e.seq})")
            if e.prev_hash != prev:
                raise TamperDetected(f"broken link at seq {e.seq}: prev_hash mismatch")
            if e.compute_hash() != e.entry_hash:
                raise TamperDetected(f"altered payload at seq {e.seq}: hash mismatch")
            prev = e.entry_hash
        return True

    def verify_against_head(self, expected_head_hash: str) -> bool:
        """Verify the chain AND that its head matches an external witness.

        This closes the truncation gap: if recent entries were dropped, the
        internal chain still validates but the head no longer matches what a
        witness recorded.
        """
        self.verify_integrity()
        if self.head_hash != expected_head_hash:
            raise TamperDetected(
                "ledger head does not match the witnessed head — entries may have "
                "been truncated or the ledger forked"
            )
        return True

    def merkle_root(self) -> str:
        """A Merkle root over all entry hashes.

        A single checkpoint value to anchor externally (RFC 3161 timestamping
        authority, a transparency log, or a counterparty's own store) so
        non-repudiation does not rest on trusting the operator of this process.
        """
        if not self._entries:
            return GENESIS_PREV_HASH
        level = [e.entry_hash for e in self._entries]
        while len(level) > 1:
            nxt = []
            for i in range(0, len(level), 2):
                left = level[i]
                right = level[i + 1] if i + 1 < len(level) else left
                nxt.append(crypto.sha256_hex((left + right).encode("ascii")))
            level = nxt
        return level[0]

    def checkpoint(self) -> dict[str, Any]:
        """An anchorable summary of the chain as it stands right now."""
        return {
            "entries": len(self._entries),
            "head_hash": self.head_hash,
            "merkle_root": self.merkle_root(),
            "at": time.time(),
        }
