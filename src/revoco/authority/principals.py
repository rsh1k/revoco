"""
revoco.authority.principals
============================
Principals: the humans and agents that can hold authority.

A principal is a name, a kind, a public key, and a set of roles. Revoco holds
only **public** keys; private keys stay with the signer. That asymmetry is the
whole point — the control plane can verify everything and forge nothing, so its
own compromise does not let an attacker fabricate authority retroactively.

Merge note
----------
This type absorbs mcp-gate's ``AgentIdentity``. mcp-gate matched policy rules
against ``agent_id`` and ``roles``; veritrail verified signatures against a
``Principal``. Keeping those separate would have meant two identity registries
that could disagree about who an agent is — precisely the kind of seam an
attacker looks for. The ``roles`` field lives here now, and the gate matches
against the same object the signature verifies against.
"""

from __future__ import annotations

import enum
import threading
from dataclasses import dataclass, field
from typing import Any

from ..core import crypto, ids
from ..core.errors import UnknownPrincipal, ValidationError

_NAME_MAX = 256


class PrincipalKind(enum.Enum):
    HUMAN = "human"
    AGENT = "agent"


@dataclass(frozen=True)
class Principal:
    id: str
    kind: PrincipalKind
    name: str
    public_key: crypto.Ed25519PublicKey
    roles: frozenset[str] = field(default_factory=frozenset)
    claims: tuple[tuple[str, str], ...] = field(default_factory=tuple)

    def __post_init__(self) -> None:
        if not isinstance(self.name, str) or not (0 < len(self.name) <= _NAME_MAX):
            raise ValidationError("principal name invalid")
        if not isinstance(self.kind, PrincipalKind):
            raise ValidationError("principal kind invalid")

    def has_role(self, role: str) -> bool:
        return role in self.roles

    @property
    def claim_map(self) -> dict[str, str]:
        return dict(self.claims)

    @property
    def is_human(self) -> bool:
        return self.kind is PrincipalKind.HUMAN

    def to_dict(self) -> dict[str, Any]:
        return {
            "id": self.id,
            "kind": self.kind.value,
            "name": self.name,
            "public_key": crypto.public_key_to_b64(self.public_key),
            "roles": sorted(self.roles),
            "claims": dict(self.claims),
        }

    @classmethod
    def from_dict(cls, d: dict[str, Any]) -> Principal:
        try:
            return cls(
                id=d["id"],
                kind=PrincipalKind(d["kind"]),
                name=d["name"],
                public_key=crypto.public_key_from_b64(d["public_key"]),
                roles=frozenset(d.get("roles", [])),
                claims=tuple(sorted((d.get("claims") or {}).items())),
            )
        except (KeyError, TypeError, ValueError) as exc:
            raise ValidationError(f"malformed principal payload: {exc}") from None


class PrincipalRegistry:
    """Thread-safe in-memory registry of principals.

    Registration is idempotent by id but *rejects* a conflicting re-registration
    of the same id with a different key: silently accepting a new key for an
    existing id would let an attacker who can call ``register`` retroactively
    validate forged signatures.
    """

    def __init__(self) -> None:
        self._by_id: dict[str, Principal] = {}
        self._lock = threading.Lock()

    def register(self, principal: Principal) -> Principal:
        with self._lock:
            existing = self._by_id.get(principal.id)
            if existing is not None:
                if crypto.public_key_to_b64(existing.public_key) != crypto.public_key_to_b64(
                    principal.public_key
                ):
                    raise ValidationError(
                        f"principal {principal.id} already registered with a different key"
                    )
                return existing
            self._by_id[principal.id] = principal
            return principal

    def register_human(
        self,
        name: str,
        public_key: crypto.Ed25519PublicKey,
        *,
        id: str | None = None,
        roles: set[str] | None = None,
        claims: dict[str, str] | None = None,
    ) -> Principal:
        return self.register(
            Principal(
                id=id or ids.new_id(ids.PRINCIPAL),
                kind=PrincipalKind.HUMAN,
                name=name,
                public_key=public_key,
                roles=frozenset(roles or set()),
                claims=tuple(sorted((claims or {}).items())),
            )
        )

    def register_agent(
        self,
        name: str,
        public_key: crypto.Ed25519PublicKey,
        *,
        id: str | None = None,
        roles: set[str] | None = None,
        claims: dict[str, str] | None = None,
    ) -> Principal:
        return self.register(
            Principal(
                id=id or ids.new_id(ids.PRINCIPAL),
                kind=PrincipalKind.AGENT,
                name=name,
                public_key=public_key,
                roles=frozenset(roles or set()),
                claims=tuple(sorted((claims or {}).items())),
            )
        )

    def get(self, principal_id: str) -> Principal:
        try:
            return self._by_id[principal_id]
        except KeyError:
            raise UnknownPrincipal(f"unknown principal: {principal_id}") from None

    def __contains__(self, principal_id: object) -> bool:
        return principal_id in self._by_id

    def all(self) -> list[Principal]:
        return list(self._by_id.values())
