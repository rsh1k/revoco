"""
revoco.authority.engine
========================
The delegated-authority layer: issue grants, record actions, and reconstruct the
chain from any action back to the human who started it.

This is the ``veritrail`` engine with the detection logic lifted out. In the
merged design the authority layer answers exactly one question — *was there
valid authority for this, and whose?* — while behavioral judgement lives in
:mod:`revoco.detect` and orchestration in :mod:`revoco.controlplane`. The
original engine did all three, which made it the only place a change could be
made and therefore the place every change was made.
"""

from __future__ import annotations

import threading
import time
from dataclasses import dataclass, field
from typing import Any

from ..core import crypto
from ..core.errors import (
    ChainBroken,
    ExpiredGrant,
    ScopeViolation,
    SignatureError,
    UnknownPrincipal,
    ValidationError,
)
from .action import ActionRecord, build_signed_action
from .delegation import Delegation, build_signed_delegation
from .principals import Principal, PrincipalKind, PrincipalRegistry
from .revocation import Revocation, RevocationRegistry
from .scope import Scope

_MAX_CHAIN_DEPTH = 64  # defense against malicious or cyclic delegation graphs


@dataclass
class ChainResult:
    """The reconstructed authorization chain for one action."""

    ok: bool
    action_id: str
    human_root_id: str | None = None
    human_root_name: str | None = None
    chain: list[dict[str, Any]] = field(default_factory=list)  # leaf -> root
    hops: int = 0
    errors: list[str] = field(default_factory=list)
    effective_constraints: dict[str, Any] = field(default_factory=dict)
    reversibility_floor: str = "unknown"

    def to_dict(self) -> dict[str, Any]:
        return {
            "ok": self.ok,
            "action_id": self.action_id,
            "human_root_id": self.human_root_id,
            "human_root_name": self.human_root_name,
            "hops": self.hops,
            "errors": self.errors,
            "effective_constraints": self.effective_constraints,
            "reversibility_floor": self.reversibility_floor,
            "chain": self.chain,
        }


class AuthorityEngine:
    """Holds principals, delegations, actions, and revocations.

    ``on_event(kind, payload)`` is called for every state change so the control
    plane can mirror it into the single hash-chained ledger. The authority layer
    deliberately does not own a ledger of its own — that duplication is what the
    merge removes.
    """

    def __init__(
        self,
        *,
        registry: PrincipalRegistry | None = None,
        revocations: RevocationRegistry | None = None,
        on_event: Any | None = None,
    ) -> None:
        self.registry = registry or PrincipalRegistry()
        self.revocations = revocations or RevocationRegistry()
        self._on_event = on_event
        self._delegations: dict[str, Delegation] = {}
        self._actions: dict[str, ActionRecord] = {}
        self._lock = threading.RLock()

    def _emit(self, kind: str, payload: dict[str, Any]) -> None:
        if self._on_event is not None:
            try:
                self._on_event(kind, payload)
            except Exception:
                pass

    # ---- identity ---------------------------------------------------------
    def register_human(self, name: str, public_key, **kw: Any) -> Principal:
        p = self.registry.register_human(name, public_key, **kw)
        self._emit("principal", p.to_dict())
        return p

    def register_agent(self, name: str, public_key, **kw: Any) -> Principal:
        p = self.registry.register_agent(name, public_key, **kw)
        self._emit("principal", p.to_dict())
        return p

    def get_principal(self, principal_id: str) -> Principal:
        return self.registry.get(principal_id)

    # ---- revocation -------------------------------------------------------
    def revoke_delegation(self, delegation_id: str, reason: str, **kw: Any) -> Revocation:
        r = self.revocations.revoke(delegation_id, "delegation", reason, **kw)
        self._emit("revocation", r.to_dict())
        return r

    def revoke_principal(self, principal_id: str, reason: str, **kw: Any) -> Revocation:
        r = self.revocations.revoke(principal_id, "principal", reason, **kw)
        self._emit("revocation", r.to_dict())
        return r

    # ---- delegation -------------------------------------------------------
    def issue_root_delegation(
        self,
        *,
        human_private_key,
        human_id: str,
        agent_id: str,
        scope: Scope,
        purpose: str,
        ttl_seconds: float,
        now: float | None = None,
    ) -> Delegation:
        """A human grants authority to an agent. The only valid chain root."""
        human = self.registry.get(human_id)
        if human.kind is not PrincipalKind.HUMAN:
            raise ValidationError("root delegations must be issued by a HUMAN principal")
        self.registry.get(agent_id)  # ensure the subject exists
        d = build_signed_delegation(
            issuer_private_key=human_private_key,
            issuer_id=human_id,
            subject_id=agent_id,
            scope=scope,
            purpose=purpose,
            parent_id=None,
            ttl_seconds=ttl_seconds,
            now=now,
        )
        if not d.verify_signature(human.public_key):
            raise SignatureError("root delegation signature failed to verify")
        self._store_delegation(d)
        return d

    def sub_delegate(
        self,
        *,
        issuer_private_key,
        issuer_id: str,
        subject_id: str,
        parent_delegation_id: str,
        scope: Scope,
        purpose: str,
        ttl_seconds: float,
        now: float | None = None,
    ) -> Delegation:
        """An agent delegates a *subset* of its authority onward.

        Attenuation and expiry are enforced here so an invalid sub-delegation is
        rejected before it can ever enter the ledger.
        """
        parent = self._delegations.get(parent_delegation_id)
        if parent is None:
            raise ChainBroken(f"unknown parent delegation: {parent_delegation_id}")
        if parent.subject_id != issuer_id:
            raise ScopeViolation(
                "issuer is not the subject of the parent delegation — it cannot "
                "delegate authority it was never given"
            )
        when = now if now is not None else time.time()
        if parent.expired(now=when):
            raise ExpiredGrant("parent delegation has expired")
        if not parent.scope.contains(scope):
            raise ScopeViolation(
                "sub-delegation scope is not contained by parent scope (privilege escalation)"
            )
        # A child can never outlive its parent.
        effective_ttl = min(ttl_seconds, max(0.0, parent.expires_at - when))
        if effective_ttl <= 0:
            raise ExpiredGrant("no remaining lifetime on the parent to delegate")
        issuer = self.registry.get(issuer_id)
        self.registry.get(subject_id)
        d = build_signed_delegation(
            issuer_private_key=issuer_private_key,
            issuer_id=issuer_id,
            subject_id=subject_id,
            scope=scope,
            purpose=purpose,
            parent_id=parent_delegation_id,
            ttl_seconds=effective_ttl,
            now=when,
        )
        if not d.verify_signature(issuer.public_key):
            raise SignatureError("sub-delegation signature failed to verify")
        self._store_delegation(d)
        return d

    def _store_delegation(self, d: Delegation) -> None:
        with self._lock:
            self._delegations[d.id] = d
        self._emit("delegation", d.to_dict())

    def get_delegation(self, delegation_id: str) -> Delegation | None:
        return self._delegations.get(delegation_id)

    # ---- actions ----------------------------------------------------------
    def record_action(
        self,
        *,
        actor_private_key,
        actor_id: str,
        delegation_id: str,
        tool: str,
        action: str,
        risk: int,
        description: str,
        params: dict[str, Any] | None = None,
        session_id: str = "",
        reversal_plan_id: str | None = None,
        now: float | None = None,
    ) -> ActionRecord:
        """Sign and record an action.

        An action that fails verification is still recorded — you want forensic
        evidence of attempted abuse — and it is the caller's job to consult the
        verdict before allowing the side effect.
        """
        if delegation_id not in self._delegations:
            raise ChainBroken(f"unknown delegation: {delegation_id}")
        rec = build_signed_action(
            actor_private_key=actor_private_key,
            actor_id=actor_id,
            delegation_id=delegation_id,
            tool=tool,
            action=action,
            risk=risk,
            description=description,
            params=params,
            session_id=session_id,
            reversal_plan_id=reversal_plan_id,
            now=now,
        )
        with self._lock:
            self._actions[rec.id] = rec
        self._emit("action", rec.to_dict())
        return rec

    def get_action(self, action_id: str) -> ActionRecord | None:
        return self._actions.get(action_id)

    def actions_by_actor(self, actor_id: str, *, exclude: str | None = None) -> list[ActionRecord]:
        return [
            a for a in self._actions.values() if a.actor_id == actor_id and a.id != exclude
        ]

    def actions_under_delegation(self, delegation_id: str) -> list[ActionRecord]:
        return [a for a in self._actions.values() if a.delegation_id == delegation_id]

    def descendant_delegations(self, delegation_id: str) -> list[str]:
        """Every delegation at or below ``delegation_id`` in the grant tree.

        A leaked grant's blast radius includes everything sub-delegated from it,
        so containment and cascade rollback both need the subtree, not just the
        node. Computed breadth-first with a visited set because a corrupted store
        could contain a cycle.
        """
        out: list[str] = []
        frontier = [delegation_id]
        seen: set[str] = set()
        while frontier:
            current = frontier.pop()
            if current in seen:
                continue
            seen.add(current)
            out.append(current)
            frontier.extend(
                d.id for d in self._delegations.values() if d.parent_id == current
            )
        return out

    # ---- chain reconstruction ---------------------------------------------
    def reconstruct_chain(self, action_id: str) -> ChainResult:
        """Walk an action back to a human root, verifying every hop."""
        action = self._actions.get(action_id)
        if action is None:
            return ChainResult(ok=False, action_id=action_id, errors=["unknown action"])

        result = ChainResult(ok=True, action_id=action_id)

        # 1. The action's own signature.
        try:
            actor = self.registry.get(action.actor_id)
            if not action.verify_signature(actor.public_key):
                result.ok = False
                result.errors.append("action signature invalid")
        except UnknownPrincipal:
            result.ok = False
            result.errors.append("action actor is not a registered principal")
        if self.revocations.is_revoked(action.actor_id):
            result.ok = False
            result.errors.append(f"actor {action.actor_id} has been revoked")

        # 2. Walk the delegation chain leaf -> root.
        current = self._delegations.get(action.delegation_id)
        if current is None:
            result.ok = False
            result.errors.append("authorizing delegation not found")
            return result

        scopes: list[Scope] = []
        seen: set[str] = set()
        depth = 0
        while current is not None:
            depth += 1
            if depth > _MAX_CHAIN_DEPTH:
                result.ok = False
                result.errors.append("chain exceeds maximum depth (possible cycle)")
                break
            if current.id in seen:
                result.ok = False
                result.errors.append("cycle detected in delegation chain")
                break
            seen.add(current.id)

            # A still-valid signature on a revoked grant must not authorize.
            if self.revocations.is_revoked(current.id):
                result.ok = False
                result.errors.append(f"delegation {current.id} has been revoked")
            if self.revocations.is_revoked(current.issuer_id):
                result.ok = False
                result.errors.append(f"issuer {current.issuer_id} has been revoked")

            try:
                issuer = self.registry.get(current.issuer_id)
            except UnknownPrincipal:
                result.ok = False
                result.errors.append(f"issuer {current.issuer_id} not registered")
                break
            if not current.verify_signature(issuer.public_key):
                result.ok = False
                result.errors.append(f"delegation {current.id} signature invalid")

            result.chain.append(current.to_dict())
            scopes.append(current.scope)

            if current.is_root:
                if issuer.kind is not PrincipalKind.HUMAN:
                    result.ok = False
                    result.errors.append("root delegation not issued by a human")
                else:
                    result.human_root_id = issuer.id
                    result.human_root_name = issuer.name
                break

            parent = self._delegations.get(current.parent_id or "")
            if parent is None:
                result.ok = False
                result.errors.append(f"parent delegation {current.parent_id} missing")
                break
            if parent.subject_id != current.issuer_id:
                result.ok = False
                result.errors.append(
                    f"delegation {current.id} issued by {current.issuer_id} but parent "
                    f"granted authority to {parent.subject_id}"
                )
            if not parent.scope.contains(current.scope):
                result.ok = False
                result.errors.append(f"privilege escalation at delegation {current.id}")
            current = parent

        result.hops = len(result.chain)
        result.effective_constraints = Scope.effective_constraints(scopes)
        result.reversibility_floor = Scope.effective_reversibility_floor(scopes).value
        if result.human_root_id is None and not any("root" in e for e in result.errors):
            result.ok = False
            result.errors.append("chain did not terminate at a human root")
        return result

    def chain_scopes(self, action_id: str) -> list[Scope]:
        """The scopes along an action's chain, leaf first."""
        return [Scope.from_dict(d["scope"]) for d in self.reconstruct_chain(action_id).chain]

    # ---- stats ------------------------------------------------------------
    def stats(self) -> dict[str, Any]:
        return {
            "principals": len(self.registry.all()),
            "delegations": len(self._delegations),
            "actions": len(self._actions),
            "revocations": len(self.revocations.all()),
        }


__all__ = ["AuthorityEngine", "ChainResult", "crypto"]
