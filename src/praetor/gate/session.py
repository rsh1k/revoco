"""
praetor.gate.session
====================
Session state: the memory that makes enforcement stateful.

Budgets ("no more than $2000 of refunds per session") require accumulating
values across calls. This holds those running totals, keyed by the budget key
from the matching rule.

# HARDENING: InMemorySessionStore is per-process and lost on restart. For
# multi-replica or durable enforcement, implement SessionStore against Redis or
# a database with atomic increment-and-compare. The interface is intentionally
# tiny so that swap stays localized — and note that `would_exceed` followed by
# `commit` is not atomic here, so two concurrent calls can both pass a check
# that only one should. A shared store must make that pair atomic.
"""

from __future__ import annotations

import threading
from typing import Protocol


class SessionStore(Protocol):
    def get_total(self, session_id: str, budget_key: str) -> float: ...
    def would_exceed(
        self, session_id: str, budget_key: str, add: float, limit: float
    ) -> bool: ...
    def commit(self, session_id: str, budget_key: str, add: float) -> None: ...


class InMemorySessionStore:
    """Thread-safe in-process store. Correct for a single instance."""

    def __init__(self) -> None:
        self._totals: dict[tuple[str, str], float] = {}
        self._lock = threading.Lock()

    def get_total(self, session_id: str, budget_key: str) -> float:
        with self._lock:
            return self._totals.get((session_id, budget_key), 0.0)

    def would_exceed(
        self, session_id: str, budget_key: str, add: float, limit: float
    ) -> bool:
        with self._lock:
            current = self._totals.get((session_id, budget_key), 0.0)
            return (current + add) > limit

    def commit(self, session_id: str, budget_key: str, add: float) -> None:
        # Called only AFTER a call is allowed and actually executed, so budgets
        # reflect real spend rather than attempted spend.
        with self._lock:
            key = (session_id, budget_key)
            self._totals[key] = self._totals.get(key, 0.0) + add

    def release(self, session_id: str, budget_key: str, amount: float) -> None:
        """Return spend to a budget after a successful reversal.

        Without this, undoing a $900 payment would leave the session's refund
        budget permanently consumed, so a legitimate retry would be blocked by a
        ceiling that no longer reflects reality. Floors at zero: a reversal can
        never create headroom that was never spent.
        """
        with self._lock:
            key = (session_id, budget_key)
            self._totals[key] = max(0.0, self._totals.get(key, 0.0) - amount)

    def totals_for(self, session_id: str) -> dict[str, float]:
        with self._lock:
            return {k[1]: v for k, v in self._totals.items() if k[0] == session_id}
