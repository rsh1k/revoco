"""
praetor.authority.revocation
============================
Revocation of delegations and principals.

A signature stays mathematically valid forever, so signature verification alone
can never express "this authority was withdrawn". Revocation is the separate,
explicitly-checked list that makes offboarding and key-leak response real: once
a grant or principal is revoked, every action whose chain runs through it stops
verifying — including actions recorded before the revocation, which is the
correct behavior for an evidence system (the record stands; the authorization
does not).
"""

from __future__ import annotations

import threading
import time
from dataclasses import dataclass
from typing import Any, Literal

from ..core import ids

TargetKind = Literal["delegation", "principal"]


@dataclass(frozen=True)
class Revocation:
    id: str
    target_id: str
    target_kind: TargetKind
    reason: str
    revoked_at: float
    revoked_by: str | None = None

    def to_dict(self) -> dict[str, Any]:
        return {
            "id": self.id,
            "target_id": self.target_id,
            "target_kind": self.target_kind,
            "reason": self.reason,
            "revoked_at": self.revoked_at,
            "revoked_by": self.revoked_by,
        }

    @classmethod
    def from_dict(cls, d: dict[str, Any]) -> Revocation:
        return cls(
            id=d["id"],
            target_id=d["target_id"],
            target_kind=d["target_kind"],
            reason=d.get("reason", ""),
            revoked_at=float(d["revoked_at"]),
            revoked_by=d.get("revoked_by"),
        )


class RevocationRegistry:
    """Thread-safe in-memory revocation list."""

    def __init__(self) -> None:
        self._by_target: dict[str, Revocation] = {}
        self._lock = threading.Lock()

    def revoke(
        self,
        target_id: str,
        target_kind: TargetKind,
        reason: str,
        *,
        revoked_by: str | None = None,
        now: float | None = None,
    ) -> Revocation:
        with self._lock:
            existing = self._by_target.get(target_id)
            if existing is not None:
                return existing  # revocation is idempotent and irreversible
            r = Revocation(
                id=ids.new_id(ids.REVOCATION),
                target_id=target_id,
                target_kind=target_kind,
                reason=reason,
                revoked_at=now if now is not None else time.time(),
                revoked_by=revoked_by,
            )
            self._by_target[target_id] = r
            return r

    def is_revoked(self, target_id: str) -> bool:
        return target_id in self._by_target

    def get(self, target_id: str) -> Revocation | None:
        return self._by_target.get(target_id)

    def all(self) -> list[Revocation]:
        return list(self._by_target.values())

    def load(self, revocations: list[Revocation]) -> None:
        with self._lock:
            for r in revocations:
                self._by_target.setdefault(r.target_id, r)
