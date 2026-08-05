"""
praetor.authority.delegation
============================
A :class:`Delegation` is a signed grant: "principal I gives principal S the
authority described by this scope, for this purpose, until this time."

Root delegations are issued by a human and are the only valid chain terminus.
Sub-delegations are issued by an agent to another agent and must attenuate.

The signature covers every field including the parent link, so an attacker
cannot re-point a validly-signed grant at a broader parent.
"""

from __future__ import annotations

import time
from dataclasses import dataclass
from typing import Any

from ..core import crypto, ids
from ..core.errors import ValidationError
from .scope import Scope

_PURPOSE_MAX = 1024


@dataclass(frozen=True)
class Delegation:
    id: str
    issuer_id: str
    subject_id: str
    scope: Scope
    purpose: str
    parent_id: str | None
    issued_at: float
    expires_at: float
    signature: str = ""

    def __post_init__(self) -> None:
        if not isinstance(self.purpose, str) or len(self.purpose) > _PURPOSE_MAX:
            raise ValidationError("purpose too long")
        if self.expires_at < self.issued_at:
            raise ValidationError("delegation expires before it is issued")
        if self.issuer_id == self.subject_id:
            raise ValidationError("a principal cannot delegate to itself")

    @property
    def is_root(self) -> bool:
        return self.parent_id is None

    def expired(self, *, now: float | None = None) -> bool:
        return (now if now is not None else time.time()) >= self.expires_at

    def _signing_payload(self) -> dict[str, Any]:
        return {
            "id": self.id,
            "issuer_id": self.issuer_id,
            "subject_id": self.subject_id,
            "scope": self.scope.to_dict(),
            "purpose": self.purpose,
            "parent_id": self.parent_id,
            "issued_at": self.issued_at,
            "expires_at": self.expires_at,
        }

    def signing_bytes(self) -> bytes:
        return crypto.canonical_bytes(self._signing_payload())

    def verify_signature(self, issuer_public_key: crypto.Ed25519PublicKey) -> bool:
        return crypto.verify(issuer_public_key, self.signing_bytes(), self.signature)

    def to_dict(self) -> dict[str, Any]:
        d = self._signing_payload()
        d["signature"] = self.signature
        return d

    @classmethod
    def from_dict(cls, d: dict[str, Any]) -> Delegation:
        if not isinstance(d, dict):
            raise ValidationError("delegation payload must be an object")
        try:
            return cls(
                id=d["id"],
                issuer_id=d["issuer_id"],
                subject_id=d["subject_id"],
                scope=Scope.from_dict(d["scope"]),
                purpose=d["purpose"],
                parent_id=d.get("parent_id"),
                issued_at=float(d["issued_at"]),
                expires_at=float(d["expires_at"]),
                signature=d.get("signature", ""),
            )
        except (KeyError, TypeError, ValueError) as exc:
            raise ValidationError(f"malformed delegation payload: {exc}") from None


def build_signed_delegation(
    *,
    issuer_private_key: crypto.Ed25519PrivateKey,
    issuer_id: str,
    subject_id: str,
    scope: Scope,
    purpose: str,
    parent_id: str | None,
    ttl_seconds: float,
    now: float | None = None,
) -> Delegation:
    """Construct and sign a delegation."""
    if ttl_seconds <= 0:
        raise ValidationError("ttl_seconds must be positive")
    issued = now if now is not None else time.time()
    d = Delegation(
        id=ids.new_id(ids.DELEGATION),
        issuer_id=issuer_id,
        subject_id=subject_id,
        scope=scope,
        purpose=purpose,
        parent_id=parent_id,
        issued_at=issued,
        expires_at=issued + ttl_seconds,
    )
    sig = crypto.sign(issuer_private_key, d.signing_bytes())
    return Delegation(
        id=d.id,
        issuer_id=d.issuer_id,
        subject_id=d.subject_id,
        scope=d.scope,
        purpose=d.purpose,
        parent_id=d.parent_id,
        issued_at=d.issued_at,
        expires_at=d.expires_at,
        signature=sig,
    )
