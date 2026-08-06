"""
revoco.store.sqlite
===================
Durable storage for the ledger, the reversal journal, and drill history.

Until this existed, everything reset on restart. Three consequences, and the third
is the one that matters: the horizon forgot undo windows that were still open, the
drill register's freshness window meant nothing across deploys, and **a restart lost
the evidence chain rather than breaking it** — which is a different failure from
tampering and was indistinguishable from it.

Four decisions, each with a reason
----------------------------------
**WAL with ``synchronous=FULL``.** SQLite's defaults are ambiguous enough that you
cannot rely on them, and ``NORMAL`` does not survive power loss. For an evidence
store that is not a trade-off: a ledger that silently drops its last entries on
power loss is precisely the truncation case a self-contained hash chain cannot
detect, because the remaining prefix still verifies.

**Append-only enforced by triggers, not permissions.** SQLite has no
``GRANT``/``REVOKE``, so an INSERT-only grant — the way you would do this in
Postgres — is not available. ``BEFORE UPDATE`` and ``BEFORE DELETE`` triggers that
``RAISE(ABORT)`` are the mechanism. Same guarantee, different lever, and worth
stating because the Postgres instinct silently produces no protection here.

**Ledger append and journal write in one transaction.** The correctness question
persistence actually raises. Written separately, a crash between them leaves the
journal claiming a plan the ledger never recorded, or a ledger entry with no journal
row — so ``horizon()`` and ``undo()`` disagree with the evidence, and there is no
way afterwards to tell which one is right. :meth:`record_reversal` does both or
neither.

**No fake freshness after downtime.** The tempting fix for "every proof is stale
after an outage" is to not count downtime against staleness. That is wrong: an ERP
upgrade during the outage is exactly when a spec silently becomes a confident wrong
rollback, and pretending the proof survived would be the phantom-rollback failure
with extra steps. So downtime *does* count, the startup report says how many proofs
went stale and for how long, that fact is written to the ledger, and
:meth:`~revoco.drills.RecoverabilityRegister.due` puts them at the front of the
queue. Visible and remediated fast beats invisible and assumed good.
"""

from __future__ import annotations

import json
import sqlite3
import threading
import time
from collections.abc import Iterator
from contextlib import contextmanager
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from ..core.errors import RevocoError
from ..ledger import GENESIS_PREV_HASH, LedgerEntry

SCHEMA_VERSION = 1

# Ledger rows are immutable. SQLite has no GRANT, so this is the only way to say so
# inside the database — which matters because it also blocks a mistake made through
# a sqlite3 shell, not just one made through this class.
_SCHEMA = """
CREATE TABLE IF NOT EXISTS ledger (
    seq         INTEGER PRIMARY KEY,
    kind        TEXT    NOT NULL,
    payload     TEXT    NOT NULL,
    recorded_at REAL    NOT NULL,
    prev_hash   TEXT    NOT NULL,
    entry_hash  TEXT    NOT NULL UNIQUE
);

CREATE TRIGGER IF NOT EXISTS ledger_is_append_only_update
BEFORE UPDATE ON ledger
BEGIN
    SELECT RAISE(ABORT, 'ledger is append-only: entries cannot be updated');
END;

CREATE TRIGGER IF NOT EXISTS ledger_is_append_only_delete
BEFORE DELETE ON ledger
BEGIN
    SELECT RAISE(ABORT, 'ledger is append-only: entries cannot be deleted');
END;

-- Working state, mutable by design: a journal entry's whole purpose is to change
-- state as an action is planned, committed and reversed. Its transitions are what
-- the ledger records immutably.
CREATE TABLE IF NOT EXISTS journal (
    id            TEXT PRIMARY KEY,
    action_id     TEXT,
    delegation_id TEXT,
    session_id    TEXT,
    state         TEXT NOT NULL,
    tool          TEXT NOT NULL,
    committed_at  REAL,
    resolved_at   REAL,
    ledger_seq    INTEGER,
    data          TEXT NOT NULL
);
CREATE INDEX IF NOT EXISTS journal_by_action     ON journal(action_id);
CREATE INDEX IF NOT EXISTS journal_by_delegation ON journal(delegation_id);
CREATE INDEX IF NOT EXISTS journal_by_state      ON journal(state);

CREATE TABLE IF NOT EXISTS drills (
    id      TEXT PRIMARY KEY,
    tool    TEXT NOT NULL,
    outcome TEXT NOT NULL,
    at      REAL NOT NULL,
    data    TEXT NOT NULL
);
CREATE INDEX IF NOT EXISTS drills_by_tool ON drills(tool, at);

CREATE TABLE IF NOT EXISTS meta (
    key   TEXT PRIMARY KEY,
    value TEXT NOT NULL
);
"""


class StoreError(RevocoError):
    """The durable store rejected an operation."""


@dataclass
class StartupReport:
    """What the store found when it opened, stated plainly.

    Exists because a restart has consequences somebody has to see. Returning this
    rather than silently reconciling is the difference between an operator knowing
    forty proofs went stale and an operator finding out when a rollback is refused.
    """

    fresh_database: bool
    downtime_seconds: float | None
    ledger_entries: int
    ledger_head: str
    ledger_verified: bool
    ledger_error: str | None
    open_journal_entries: int
    stale_proof_tools: list[str] = field(default_factory=list)
    notes: list[str] = field(default_factory=list)

    @property
    def needs_attention(self) -> bool:
        return bool(not self.ledger_verified or self.stale_proof_tools)

    def to_dict(self) -> dict[str, Any]:
        return {
            "fresh_database": self.fresh_database,
            "downtime_seconds": (
                round(self.downtime_seconds, 2) if self.downtime_seconds is not None else None
            ),
            "ledger_entries": self.ledger_entries,
            "ledger_head": self.ledger_head,
            "ledger_verified": self.ledger_verified,
            "ledger_error": self.ledger_error,
            "open_journal_entries": self.open_journal_entries,
            "stale_proof_tools": list(self.stale_proof_tools),
            "needs_attention": self.needs_attention,
            "notes": list(self.notes),
        }


class SqliteStore:
    """Durable ledger, journal, and drill history in one SQLite file.

    ``synchronous`` defaults to ``FULL``. Lowering it trades the durability of the
    most recent entries for write throughput, which for an evidence store is the
    wrong side of the trade — so it is possible and deliberately not the default.
    """

    def __init__(
        self,
        path: str | Path,
        *,
        synchronous: str = "FULL",
        timeout: float = 30.0,
    ) -> None:
        self.path = Path(path)
        self.path.parent.mkdir(parents=True, exist_ok=True)
        fresh = not self.path.exists()
        self._lock = threading.RLock()
        self._conn = sqlite3.connect(
            str(self.path), timeout=timeout, isolation_level=None, check_same_thread=False
        )
        self._conn.row_factory = sqlite3.Row
        self._conn.execute("PRAGMA journal_mode=WAL")
        self._conn.execute(f"PRAGMA synchronous={synchronous}")
        self._conn.execute("PRAGMA foreign_keys=ON")
        self._conn.executescript(_SCHEMA)
        self._fresh = fresh
        self._set_meta("schema_version", str(SCHEMA_VERSION))

    # ---- transactions -----------------------------------------------------
    @contextmanager
    def _tx(self) -> Iterator[sqlite3.Cursor]:
        """One all-or-nothing unit of work.

        BEGIN IMMEDIATE rather than deferred: these writes always mutate, so taking
        the write lock up front turns a mid-transaction contention failure into an
        honest wait at the start.
        """
        with self._lock:
            cur = self._conn.cursor()
            cur.execute("BEGIN IMMEDIATE")
            try:
                yield cur
            except Exception:
                cur.execute("ROLLBACK")
                raise
            cur.execute("COMMIT")

    def close(self) -> None:
        with self._lock:
            self._set_meta("closed_at", str(time.time()))
            self._conn.close()

    def __enter__(self) -> SqliteStore:
        return self

    def __exit__(self, *exc: Any) -> None:
        self.close()

    # ---- meta -------------------------------------------------------------
    def _set_meta(self, key: str, value: str) -> None:
        with self._lock:
            self._conn.execute(
                "INSERT INTO meta(key,value) VALUES(?,?) "
                "ON CONFLICT(key) DO UPDATE SET value=excluded.value",
                (key, value),
            )

    def _get_meta(self, key: str) -> str | None:
        row = self._conn.execute("SELECT value FROM meta WHERE key=?", (key,)).fetchone()
        return row["value"] if row else None

    def heartbeat(self, *, now: float | None = None) -> None:
        """Record liveness, so downtime can be measured rather than guessed."""
        self._set_meta("last_seen_at", str(now if now is not None else time.time()))

    # ---- ledger -----------------------------------------------------------
    def _insert_ledger(self, cur: sqlite3.Cursor, entry: LedgerEntry) -> None:
        cur.execute(
            "INSERT INTO ledger(seq,kind,payload,recorded_at,prev_hash,entry_hash) "
            "VALUES(?,?,?,?,?,?)",
            (
                entry.seq,
                entry.kind,
                json.dumps(entry.payload, sort_keys=True, separators=(",", ":"), default=str),
                entry.recorded_at,
                entry.prev_hash,
                entry.entry_hash,
            ),
        )

    def append_ledger(self, entry: LedgerEntry) -> None:
        """Persist one prepared ledger entry."""
        try:
            with self._tx() as cur:
                self._insert_ledger(cur, entry)
        except sqlite3.IntegrityError as exc:
            raise StoreError(
                f"ledger entry seq={entry.seq} conflicts with a row already stored: {exc}. "
                "Two writers sharing one file without coordination will do this; the "
                "hash chain is single-writer by construction."
            ) from exc

    def load_ledger(self) -> list[LedgerEntry]:
        rows = self._conn.execute(
            "SELECT seq,kind,payload,recorded_at,prev_hash,entry_hash FROM ledger ORDER BY seq"
        ).fetchall()
        return [
            LedgerEntry(
                seq=r["seq"],
                kind=r["kind"],
                payload=json.loads(r["payload"]),
                recorded_at=r["recorded_at"],
                prev_hash=r["prev_hash"],
                entry_hash=r["entry_hash"],
            )
            for r in rows
        ]

    def ledger_head(self) -> str:
        row = self._conn.execute(
            "SELECT entry_hash FROM ledger ORDER BY seq DESC LIMIT 1"
        ).fetchone()
        return row["entry_hash"] if row else GENESIS_PREV_HASH

    def ledger_count(self) -> int:
        return int(self._conn.execute("SELECT COUNT(*) AS n FROM ledger").fetchone()["n"])

    # ---- journal ----------------------------------------------------------
    def _upsert_journal(
        self, cur: sqlite3.Cursor, data: dict[str, Any], ledger_seq: int | None
    ) -> None:
        cur.execute(
            "INSERT INTO journal(id,action_id,delegation_id,session_id,state,tool,"
            "committed_at,resolved_at,ledger_seq,data) VALUES(?,?,?,?,?,?,?,?,?,?) "
            "ON CONFLICT(id) DO UPDATE SET "
            "action_id=excluded.action_id, delegation_id=excluded.delegation_id, "
            "session_id=excluded.session_id, state=excluded.state, "
            "committed_at=excluded.committed_at, resolved_at=excluded.resolved_at, "
            "ledger_seq=excluded.ledger_seq, data=excluded.data",
            (
                data.get("id"),
                data.get("action_id"),
                data.get("delegation_id"),
                data.get("session_id") or "",
                data.get("state"),
                (data.get("plan") or {}).get("tool") or "",
                data.get("committed_at"),
                data.get("resolved_at"),
                ledger_seq,
                json.dumps(data, sort_keys=True, separators=(",", ":"), default=str),
            ),
        )

    def record_reversal(self, entry: LedgerEntry, journal_data: dict[str, Any] | None) -> None:
        """Persist a ledger entry and the journal state it describes, atomically.

        The whole reason this class exists. Two separate writes leave a window where
        a crash produces a journal claiming a plan the ledger never recorded, or a
        ledger entry with no journal row — and afterwards there is no way to tell
        which of the two is the truth.
        """
        try:
            with self._tx() as cur:
                self._insert_ledger(cur, entry)
                if journal_data and journal_data.get("id"):
                    self._upsert_journal(cur, journal_data, entry.seq)
        except sqlite3.IntegrityError as exc:
            raise StoreError(f"atomic ledger+journal write failed: {exc}") from exc

    def load_journal(self) -> list[dict[str, Any]]:
        rows = self._conn.execute("SELECT data FROM journal ORDER BY rowid").fetchall()
        return [json.loads(r["data"]) for r in rows]

    def open_journal_count(self) -> int:
        return int(
            self._conn.execute(
                "SELECT COUNT(*) AS n FROM journal WHERE state='committed'"
            ).fetchone()["n"]
        )

    # ---- drills -----------------------------------------------------------
    def record_drill(self, data: dict[str, Any]) -> None:
        with self._tx() as cur:
            cur.execute(
                "INSERT INTO drills(id,tool,outcome,at,data) VALUES(?,?,?,?,?) "
                "ON CONFLICT(id) DO NOTHING",
                (
                    data.get("id"),
                    data.get("tool"),
                    data.get("outcome"),
                    data.get("at"),
                    json.dumps(data, sort_keys=True, separators=(",", ":"), default=str),
                ),
            )

    def load_drills(self) -> list[dict[str, Any]]:
        rows = self._conn.execute("SELECT data FROM drills ORDER BY at").fetchall()
        return [json.loads(r["data"]) for r in rows]

    def last_pass_per_tool(self) -> dict[str, float]:
        rows = self._conn.execute(
            "SELECT tool, MAX(at) AS at FROM drills WHERE outcome='passed' GROUP BY tool"
        ).fetchall()
        return {r["tool"]: r["at"] for r in rows}

    # ---- startup ----------------------------------------------------------
    def startup_report(
        self, *, stale_after: float = 86_400.0, now: float | None = None
    ) -> StartupReport:
        """What this restart means, computed rather than assumed.

        Downtime deliberately *does* count against proof freshness. Not counting it
        would be the comfortable choice and the wrong one — an upgrade during the
        outage is exactly when a spec silently becomes a confident wrong rollback,
        and a proof that survived on a technicality is a phantom rollback with a
        certificate.
        """
        when = now if now is not None else time.time()
        last_seen = self._get_meta("last_seen_at") or self._get_meta("closed_at")
        downtime = (when - float(last_seen)) if last_seen else None

        entries = self.load_ledger()
        verified, err = True, None
        prev = GENESIS_PREV_HASH
        for i, e in enumerate(entries):
            if e.seq != i or e.prev_hash != prev or e.compute_hash() != e.entry_hash:
                verified, err = False, f"chain breaks at seq {e.seq}"
                break
            prev = e.entry_hash

        passes = self.last_pass_per_tool()
        stale = sorted(t for t, at in passes.items() if (when - at) > stale_after)

        report = StartupReport(
            fresh_database=self._fresh,
            downtime_seconds=downtime,
            ledger_entries=len(entries),
            ledger_head=entries[-1].entry_hash if entries else GENESIS_PREV_HASH,
            ledger_verified=verified,
            ledger_error=err,
            open_journal_entries=self.open_journal_count(),
            stale_proof_tools=stale,
        )
        if downtime is not None and downtime > stale_after:
            report.notes.append(
                f"down for {downtime / 3600:.1f}h, longer than the {stale_after / 3600:.0f}h "
                "proof window — treat every rollback claim as unproven until re-drilled"
            )
        if stale:
            report.notes.append(
                f"{len(stale)} tool(s) have no fresh proof of recoverability. The proof "
                "gate is already treating them as irreversible; drill them first."
            )
        if not verified:
            report.notes.append(
                "LEDGER VERIFICATION FAILED. This is not a restart artefact — a clean "
                "restart loses nothing. Investigate before writing anything further."
            )
        if report.open_journal_entries:
            report.notes.append(
                f"{report.open_journal_entries} committed action(s) still have live undo "
                "paths; check the horizon for windows that closed during the outage."
            )
        self.heartbeat(now=when)
        return report

    def stats(self) -> dict[str, Any]:
        return {
            "path": str(self.path),
            "ledger_entries": self.ledger_count(),
            "ledger_head": self.ledger_head(),
            "journal_entries": int(
                self._conn.execute("SELECT COUNT(*) AS n FROM journal").fetchone()["n"]
            ),
            "open_journal_entries": self.open_journal_count(),
            "drills": int(
                self._conn.execute("SELECT COUNT(*) AS n FROM drills").fetchone()["n"]
            ),
            "tools_with_a_pass": len(self.last_pass_per_tool()),
        }


__all__ = ["SqliteStore", "StartupReport", "StoreError", "SCHEMA_VERSION"]
