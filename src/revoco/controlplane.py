"""
revoco.controlplane
====================
The orchestrator: one pipeline from "an agent wants to do something" to "here is
the signed, verifiable, reversible record of whether it did".

    classify -> enforce -> plan undo -> record -> verify authority -> detect
             -> combined verdict -> [caller executes] -> confirm

Every stage can veto, and the verdict names which one did. That attribution
matters more than it looks: "blocked" is not an answer anyone can act on, while
"blocked at the authority stage because the grant was revoked at 14:02" is.

Why the stages run in this order
--------------------------------
Policy is evaluated *before* the state snapshot is taken. Snapshots cost a read
against the system of record, and taking one for a call that policy was always
going to deny would mean the control plane generates load — and touches
production data — on behalf of requests it is in the middle of refusing.

The snapshot is taken *before* the action executes, because that is the only
moment prior state still exists to be captured. This is the ordering constraint
the whole reversal design hangs on, and it is why a rollback layer cannot be
bolted onto an audit log after the fact.

The action is recorded *before* the verdict is known, and recorded even when the
verdict is a refusal. Evidence of an attempt is exactly what an investigation
needs, and a system that only logs successes cannot tell you that an agent tried
forty times.

Trust boundary on the state reader
----------------------------------
``state_reader`` is called by the control plane with the agent's own arguments,
before authorization completes. It must be read-only and it must not be the
agent's credential — otherwise a hostile argument set turns the snapshot into an
oracle the agent can query for data it was never granted. Give it its own
narrowly-scoped read access.
"""

from __future__ import annotations

import threading
import time
from collections.abc import Callable
from dataclasses import dataclass, field
from typing import Any

from . import ledger as ledger_mod
from .authority.action import ActionRecord
from .authority.delegation import Delegation
from .authority.engine import AuthorityEngine, ChainResult
from .authority.principals import Principal
from .authority.scope import Scope
from .core import crypto
from .core.errors import ChainBroken
from .detect import DetectionEngine, Finding, Severity, is_blocking, max_severity
from .gate.decision import Decision, Effect
from .gate.engine import PolicyEngine, redact_arguments
from .gate.policy import Policy, starter_policy
from .gate.session import InMemorySessionStore, SessionStore
from .gate.threats import ThreatScanner
from .ledger import Ledger
from .reversal.budget import Charge, IrreversibilityBudget
from .reversal.engine import ReversalEngine
from .reversal.model import (
    CascadeReport,
    GateEvaluator,
    InverseExecutor,
    JournalEntry,
    JournalState,
    ReversalPlan,
    ReversalReceipt,
    Reversibility,
    StateReader,
)
from .reversal.registry import InverseRegistry

# An approval hook plugs in human-in-the-loop. It receives the call context and
# returns True (approved) or False (rejected). The default rejects, because
# REQUIRE_APPROVAL with nobody wired up must fail safe rather than silently
# degrade to allow.
ApprovalHook = Callable[[str, dict[str, Any], Principal, Decision], bool]

STAGE_ENFORCE = "enforce"
STAGE_BUDGET = "budget"
STAGE_REVERSAL = "reversal"
STAGE_AUTHORITY = "authority"
STAGE_DETECT = "detect"
STAGE_ALLOWED = "allowed"


def _deny_by_default(tool: str, args: dict[str, Any], principal: Principal, decision: Decision) -> bool:
    return False


@dataclass
class Verdict:
    """The combined outcome of one authorization pass."""

    action_id: str
    allowed: bool
    stage: str                       # which stage decided
    effect: Effect
    reason: str
    tool: str
    action: str
    risk: int
    reversibility: Reversibility
    chain: ChainResult | None = None
    gate_decision: Decision | None = None
    plan: ReversalPlan | None = None
    journal_id: str | None = None
    findings: list[dict[str, Any]] = field(default_factory=list)
    max_severity: str = Severity.INFO.value
    effective_args: dict[str, Any] = field(default_factory=dict)
    ledger_seq: int | None = None
    approved_by_human: bool = False
    budget_charge: Charge | None = None

    @property
    def human_root(self) -> str | None:
        return self.chain.human_root_name if self.chain else None

    @property
    def undoable(self) -> bool:
        """Whether an undo path exists and has no unresolvable gap.

        Deferred (result-bound) arguments do not count against this: they bind on
        :meth:`ControlPlane.confirm`, so a payment whose void needs the payment id
        is still correctly reported as undoable at authorization time.
        """
        return bool(self.plan and self.plan.is_executable and not self.plan.unresolved_args)

    def to_dict(self) -> dict[str, Any]:
        return {
            "action_id": self.action_id,
            "allowed": self.allowed,
            "stage": self.stage,
            "effect": self.effect.value,
            "reason": self.reason,
            "tool": self.tool,
            "action": self.action,
            "risk": self.risk,
            "reversibility": self.reversibility.value,
            "undoable": self.undoable,
            "human_root": self.human_root,
            "approved_by_human": self.approved_by_human,
            "max_severity": self.max_severity,
            "budget_charge": self.budget_charge.to_dict() if self.budget_charge else None,
            "findings": self.findings,
            "chain": self.chain.to_dict() if self.chain else None,
            "gate_decision": self.gate_decision.to_dict() if self.gate_decision else None,
            "plan": self.plan.to_dict() if self.plan else None,
            "journal_id": self.journal_id,
            "ledger_seq": self.ledger_seq,
        }


class ControlPlane:
    """The single object an integration talks to.

    ``fail_closed`` decides what happens if a stage raises unexpectedly. It
    defaults to True: an internal error blocks the action. Setting it False
    prioritizes availability and is a legitimate choice for low-risk tool
    surfaces, but it means a bug in this package becomes an unguarded action, so
    it is opt-in and audited when it fires.
    """

    def __init__(
        self,
        *,
        policy: Policy | None = None,
        inverse_registry: InverseRegistry | None = None,
        state_reader: StateReader | None = None,
        gate_evaluator: GateEvaluator | None = None,
        irreversibility_budget: IrreversibilityBudget | None = None,
        recoverability_register: Any | None = None,
        store: Any | None = None,
        session_store: SessionStore | None = None,
        scanner: ThreatScanner | None = None,
        detector: DetectionEngine | None = None,
        approval_hook: ApprovalHook | None = None,
        fail_closed: bool = True,
    ) -> None:
        # Durable store, optional. Without one everything is in memory and a restart
        # loses the evidence chain rather than breaking it — a different failure from
        # tampering, and indistinguishable from it. See revoco.store.
        self.store = store
        self.ledger = Ledger()
        if store is not None:
            self.ledger.load_entries(store.load_ledger())
        self.authority = AuthorityEngine(on_event=self._on_authority_event)
        # When a register is supplied, a declared reversibility only survives while
        # a recent drill proves it. See revoco.drills.
        self.recoverability = recoverability_register
        self.reversal = ReversalEngine(
            inverse_registry or InverseRegistry(),
            state_reader=state_reader,
            gate_evaluator=gate_evaluator,
            classify_hook=(
                recoverability_register.classify_hook if recoverability_register else None
            ),
            on_event=self._on_reversal_event,
        )
        self.gate = PolicyEngine(
            policy or starter_policy(),
            store=session_store or InMemorySessionStore(),
            scanner=scanner,
        )
        self.detector = detector or DetectionEngine()
        self.approval_hook = approval_hook or _deny_by_default
        # Optional. Without one, unrecoverable exposure is detected after the fact
        # (PRA01) but never capped — which the containment benchmark showed lets
        # several one-way actions land before the pattern is visible.
        self.budget = irreversibility_budget
        self.fail_closed = fail_closed

        self._actor_strikes: dict[str, int] = {}
        self._verdicts: dict[str, Verdict] = {}
        self._args_by_action: dict[str, dict[str, Any]] = {}
        self._lock = threading.RLock()

    # ---- ledger plumbing --------------------------------------------------
    def _append(
        self, kind: str, payload: dict[str, Any], *, journal: dict[str, Any] | None = None
    ) -> Any:
        """Append to the ledger, durably when a store is configured.

        Order matters: prepare, persist, *then* extend the in-memory chain. Appending
        first would let the in-memory head run ahead of the durable one, so a crash in
        between leaves a head hash nothing on disk supports — indistinguishable from
        truncation to whoever verifies it later.

        When ``journal`` is supplied, the ledger entry and the journal state it
        describes are written in one transaction. Separately, a crash between the two
        leaves the journal claiming a plan the ledger never recorded, and afterwards
        there is no way to tell which is the truth.
        """
        if self.store is None:
            return self.ledger.append(kind, payload)
        entry = self.ledger.prepare(kind, payload)
        if journal is not None:
            self.store.record_reversal(entry, journal)
        else:
            self.store.append_ledger(entry)
        self.ledger.append_prebuilt(entry)
        return entry

    def _on_authority_event(self, kind: str, payload: dict[str, Any]) -> None:
        self._append(kind, payload)

    def _on_reversal_event(self, kind: str, payload: dict[str, Any]) -> None:
        # A reversal event whose payload *is* a journal entry gets the atomic path.
        journal = payload if ("plan" in payload and "state" in payload) else None
        self._append(kind, payload, journal=journal)

    # ---- identity & delegation (thin pass-through) ------------------------
    def register_human(self, name: str, public_key, **kw: Any) -> Principal:
        return self.authority.register_human(name, public_key, **kw)

    def register_agent(self, name: str, public_key, **kw: Any) -> Principal:
        return self.authority.register_agent(name, public_key, **kw)

    def issue_root_delegation(self, **kw: Any) -> Delegation:
        return self.authority.issue_root_delegation(**kw)

    def sub_delegate(self, **kw: Any) -> Delegation:
        return self.authority.sub_delegate(**kw)

    # ---- the pipeline -----------------------------------------------------
    def authorize(
        self,
        *,
        actor_private_key,
        actor_id: str,
        delegation_id: str,
        tool: str,
        args: dict[str, Any] | None = None,
        action: str = "write",
        risk: int = 0,
        description: str = "",
        session_id: str = "",
        now: float | None = None,
    ) -> Verdict:
        """Run all stages and return a verdict. Does NOT execute the action.

        The caller executes only if ``verdict.allowed``, then calls
        :meth:`confirm`. Splitting authorization from execution is what lets the
        undo plan be journaled against real prior state without this package
        needing to own the connection to the system of record.
        """
        try:
            return self._authorize_inner(
                actor_private_key=actor_private_key,
                actor_id=actor_id,
                delegation_id=delegation_id,
                tool=tool,
                args=dict(args or {}),
                action=action,
                risk=risk,
                description=description,
                session_id=session_id,
                now=now,
            )
        except ChainBroken:
            raise  # a caller error: the delegation does not exist
        except Exception as exc:
            if not self.fail_closed:
                # Availability-first. Audited so the gap is visible afterwards.
                v = Verdict(
                    action_id="",
                    allowed=True,
                    stage="engine_failure",
                    effect=Effect.ALLOW,
                    reason=f"control plane error, fail_closed=False: {type(exc).__name__}",
                    tool=tool,
                    action=action,
                    risk=risk,
                    reversibility=Reversibility.UNKNOWN,
                    effective_args=dict(args or {}),
                )
                v.ledger_seq = self._append(ledger_mod.KIND_VERDICT, v.to_dict()).seq
                return v
            v = Verdict(
                action_id="",
                allowed=False,
                stage="engine_failure",
                effect=Effect.DENY,
                reason=f"control plane error, blocked (fail-closed): {type(exc).__name__}: {exc}",
                tool=tool,
                action=action,
                risk=risk,
                reversibility=Reversibility.UNKNOWN,
                effective_args={},
            )
            v.ledger_seq = self._append(ledger_mod.KIND_VERDICT, v.to_dict()).seq
            return v

    def _authorize_inner(
        self,
        *,
        actor_private_key,
        actor_id: str,
        delegation_id: str,
        tool: str,
        args: dict[str, Any],
        action: str,
        risk: int,
        description: str,
        session_id: str,
        now: float | None,
    ) -> Verdict:
        when = now if now is not None else time.time()

        # -- stage 0: classify --------------------------------------------
        # Args are passed so authorize-phase gates can refine the answer for this
        # specific target: an S3 delete against a non-versioned bucket is not
        # "compensable like every other S3 delete", it is gone. Getting this right
        # before the write is the whole point — an escalation after the fact is
        # just a notification.
        reversibility = self.reversal.classify(tool, args)

        principal = self.authority.get_principal(actor_id)

        # -- stage 1: enforce ----------------------------------------------
        decision = self.gate.evaluate(
            tool=tool,
            args=args,
            principal=principal,
            session_id=session_id,
            action=action,
            reversibility=reversibility,
            risk=risk,
        )

        approved_by_human = False
        if decision.effect is Effect.REQUIRE_APPROVAL:
            approved_by_human = bool(self.approval_hook(tool, args, principal, decision))

        gate_blocks = decision.effect is Effect.DENY or (
            decision.effect is Effect.REQUIRE_APPROVAL and not approved_by_human
        )

        effective_args = (
            redact_arguments(args, decision.redact_fields)
            if decision.effect is Effect.REDACT
            else dict(args)
        )

        # A hard refusal short-circuits: no snapshot, no plan. We still record
        # the attempt, because an agent's blocked attempts are the signal that
        # something upstream is wrong.
        if gate_blocks:
            record = self.authority.record_action(
                actor_private_key=actor_private_key,
                actor_id=actor_id,
                delegation_id=delegation_id,
                tool=tool,
                action=action,
                risk=risk,
                description=description or f"{action} {tool}",
                params=args,
                session_id=session_id,
                reversal_plan_id=None,
                now=when,
            )
            verdict = Verdict(
                action_id=record.id,
                allowed=False,
                stage=STAGE_ENFORCE,
                effect=decision.effect,
                reason=decision.reason,
                tool=tool,
                action=action,
                risk=risk,
                reversibility=reversibility,
                gate_decision=decision,
                effective_args={},
                approved_by_human=approved_by_human,
            )
            return self._finalize(verdict, args)

        # -- stage 1b: irreversibility budget -------------------------------
        # Placed after the gate so a call the policy already refused does not
        # consume or refuse budget, and before planning so the refusal costs no
        # snapshot round-trip. Scoped to the delegation because that is the unit a
        # human authorized and therefore the unit they should be asked to renew.
        budget_charge: Charge | None = None
        if self.budget is not None:
            spec = self.reversal.registry.get(tool)
            ok, budget_charge, budget_reason = self.budget.check(
                delegation_id,
                tool=tool,
                kind=reversibility,
                risk=risk,
                has_residue=bool(spec and spec.residue),
            )
            if not ok:
                record = self.authority.record_action(
                    actor_private_key=actor_private_key,
                    actor_id=actor_id,
                    delegation_id=delegation_id,
                    tool=tool,
                    action=action,
                    risk=risk,
                    description=description or f"{action} {tool}",
                    params=args,
                    session_id=session_id,
                    reversal_plan_id=None,
                    now=when,
                )
                verdict = Verdict(
                    action_id=record.id,
                    allowed=False,
                    stage=STAGE_BUDGET,
                    effect=Effect.DENY,
                    reason=budget_reason,
                    tool=tool,
                    action=action,
                    risk=risk,
                    reversibility=reversibility,
                    gate_decision=decision,
                    effective_args={},
                    approved_by_human=approved_by_human,
                    budget_charge=budget_charge,
                )
                return self._finalize(verdict, args)

        # -- stage 2: plan the undo (before the action runs) ---------------
        plan = self.reversal.plan(tool, args, now=when)

        # -- stage 3: record the signed action ------------------------------
        record = self.authority.record_action(
            actor_private_key=actor_private_key,
            actor_id=actor_id,
            delegation_id=delegation_id,
            tool=tool,
            action=action,
            risk=risk,
            description=description or f"{action} {tool}",
            params=args,
            session_id=session_id,
            reversal_plan_id=plan.id,
            now=when,
        )

        # -- stage 4: verify authority -------------------------------------
        chain = self.authority.reconstruct_chain(record.id)

        # -- stage 5: detect ------------------------------------------------
        findings = self._run_detectors(record=record, chain=chain, plan=plan, args=args)
        sev = max_severity(findings)

        # -- stage 6: combine ----------------------------------------------
        floor = Reversibility(chain.reversibility_floor)
        authority_ok = chain.ok
        detect_ok = not is_blocking(sev)

        if not authority_ok:
            stage, allowed, reason = (
                STAGE_AUTHORITY,
                False,
                "; ".join(chain.errors) or "authority chain did not verify",
            )
        elif not detect_ok:
            stage, allowed, reason = (
                STAGE_DETECT,
                False,
                "; ".join(
                    f.title
                    for f in findings
                    if f.severity in (Severity.HIGH, Severity.CRITICAL)
                ),
            )
        else:
            stage, allowed, reason = STAGE_ALLOWED, True, decision.reason

        journal = self.reversal.open_journal(
            plan,
            actor_id=actor_id,
            delegation_id=delegation_id,
            session_id=session_id,
        )

        verdict = Verdict(
            action_id=record.id,
            allowed=allowed,
            budget_charge=budget_charge,
            stage=stage,
            effect=decision.effect if allowed else Effect.DENY,
            reason=reason,
            tool=tool,
            action=action,
            risk=risk,
            reversibility=reversibility,
            chain=chain,
            gate_decision=decision,
            plan=plan,
            journal_id=journal.id,
            findings=[f.to_dict() for f in findings],
            max_severity=sev.value,
            effective_args=effective_args if allowed else {},
            approved_by_human=approved_by_human,
        )
        if floor is not Reversibility.UNKNOWN:
            verdict.gate_decision = decision  # keep for evidence; floor is in chain

        if not allowed:
            self.reversal.abandon(journal.id, f"blocked at {stage}: {reason}")

        return self._finalize(verdict, args)

    def _finalize(self, verdict: Verdict, raw_args: dict[str, Any]) -> Verdict:
        """Strike accounting, ledger append, and bookkeeping.

        A strike means the agent tried something it was never permitted to do.
        A declined approval is not that: the policy *offered the decision to a
        person* and the person said no, which is the control working exactly as
        designed. Counting those was making the rogue-agent detector measure
        how often a human exercised judgment, and three sensible refusals in a
        row quarantined a perfectly well-behaved agent.

        The distinction was harmless while approval prompts were rare and only
        fired on genuinely irreversible actions. It stopped being harmless once
        callers began routing ordinary risky-looking work to a human — declining
        three suggested changes is normal use, not drift.
        """
        declined_by_human = verdict.effect is Effect.REQUIRE_APPROVAL
        with self._lock:
            if not verdict.allowed and verdict.action_id and not declined_by_human:
                record = self.authority.get_action(verdict.action_id)
                if record is not None:
                    self._actor_strikes[record.actor_id] = (
                        self._actor_strikes.get(record.actor_id, 0) + 1
                    )
            if verdict.action_id:
                self._verdicts[verdict.action_id] = verdict
                self._args_by_action[verdict.action_id] = raw_args
        entry = self._append(ledger_mod.KIND_VERDICT, verdict.to_dict())
        verdict.ledger_seq = entry.seq
        return verdict

    def _run_detectors(
        self,
        *,
        record: ActionRecord,
        chain: ChainResult,
        plan: ReversalPlan | None,
        args: dict[str, Any],
    ) -> list[Finding]:
        authorizing = self.authority.get_delegation(record.delegation_id)
        findings: list[Finding] = []
        if authorizing is None:
            return findings

        try:
            actor = self.authority.get_principal(record.actor_id)
            sig_valid = record.verify_signature(actor.public_key)
        except Exception:
            sig_valid = False

        chain_delegations = [Delegation.from_dict(d) for d in chain.chain]
        recent = self.authority.actions_by_actor(record.actor_id, exclude=record.id)

        findings.extend(
            self.detector.evaluate_action(
                action=record,
                authorizing_delegation=authorizing,
                chain=chain_delegations,
                actor_signature_valid=sig_valid,
                recent_actions=recent,
            )
        )
        findings.extend(
            self.detector.evaluate_chain(
                action=record,
                chain_errors=chain.errors,
                recent_actions=recent,
                actor_strikes=self._actor_strikes.get(record.actor_id, 0),
            )
        )
        findings.extend(
            self.detector.evaluate_constraints(
                action=record,
                args=args,
                effective_constraints=chain.effective_constraints,
            )
        )
        irreversible_under_grant = len(
            [
                e
                for e in self.reversal.entries(
                    state=JournalState.COMMITTED, delegation_id=record.delegation_id
                )
                if not e.plan.kind.is_undoable
            ]
        )
        findings.extend(
            self.detector.evaluate_reversibility(
                action=record,
                plan=plan,
                committed_irreversible_under_grant=irreversible_under_grant,
                reversibility_floor=Reversibility(chain.reversibility_floor),
            )
        )
        return findings

    # ---- post-execution ---------------------------------------------------
    def confirm(self, verdict: Verdict, *, result: Any = None, now: float | None = None) -> JournalEntry | None:
        """Record that the action actually executed.

        Binds result-derived inverse arguments (a payment id you only learn from
        the response) and commits any session budget. Called only on success, so
        budgets and the journal reflect completed work rather than attempts.
        """
        if not verdict.allowed or verdict.journal_id is None:
            return None
        entry = self.reversal.commit(
            verdict.journal_id, action_id=verdict.action_id, result=result, now=now
        )
        if verdict.gate_decision is not None:
            self.gate.commit_budget(
                verdict.tool,
                self._args_by_action.get(verdict.action_id, {}),
                verdict.gate_decision,
                self._session_of(verdict.action_id),
            )
        # Debit unrecoverable exposure only now. Charging at authorization time
        # would let a flapping integration exhaust the ceiling without ever having
        # changed anything.
        if self.budget is not None and verdict.budget_charge is not None:
            rec = self.authority.get_action(verdict.action_id)
            if rec is not None:
                self.budget.commit(rec.delegation_id, verdict.budget_charge)
        verdict.plan = entry.plan
        return entry

    def _session_of(self, action_id: str) -> str:
        rec = self.authority.get_action(action_id)
        return rec.session_id if rec else ""

    def horizon(self, **kw: Any) -> Any:
        """Remaining recovery options, soonest deadline first.

        Worth putting on a dashboard next to the retrospective numbers: an undo
        window that closes quietly is a capability the organization believes it has
        right up to the moment it reaches for one.
        """
        return self.reversal.horizon(**kw)

    # ---- undo -------------------------------------------------------------
    def undo(
        self, action_id: str, executor: InverseExecutor, *, now: float | None = None
    ) -> ReversalReceipt:
        """Undo one action and return the spend to its budget if it succeeded."""
        receipt = self.reversal.reverse(action_id, executor, now=now)
        if receipt.ok:
            verdict = self._verdicts.get(action_id)
            if verdict is not None and verdict.gate_decision is not None:
                self.gate.release_budget(
                    verdict.tool,
                    self._args_by_action.get(action_id, {}),
                    verdict.gate_decision,
                    self._session_of(action_id),
                )
            # Exposure that was actually undone is no longer exposure. Refunding it
            # is what makes the budget cooperate with the reversal layer rather than
            # compete with it: an agent that repairs its own mess recovers headroom,
            # so the incentive points at cleaning up instead of hoarding credit.
            if self.budget is not None and verdict is not None and verdict.budget_charge:
                rec = self.authority.get_action(action_id)
                if rec is not None:
                    self.budget.refund(rec.delegation_id, verdict.budget_charge)
        return receipt

    def undo_all(
        self,
        executor: InverseExecutor,
        *,
        session_id: str | None = None,
        delegation_id: str | None = None,
        include_subtree: bool = True,
        stop_on_error: bool = True,
        now: float | None = None,
    ) -> CascadeReport:
        """Undo a blast radius, newest action first.

        With ``delegation_id`` and ``include_subtree``, this covers every grant
        sub-delegated from that one. A compromised grant's damage is not confined
        to the agent that held it — that agent handed narrower slices to others,
        and those actions are part of the same incident.
        """
        if delegation_id is not None and include_subtree:
            ids = self.authority.descendant_delegations(delegation_id)
            action_ids: list[str] = []
            for did in ids:
                action_ids.extend(a.id for a in self.authority.actions_under_delegation(did))
            return self.reversal.reverse_cascade(
                executor=executor,
                action_ids=action_ids,
                stop_on_error=stop_on_error,
                now=now,
            )
        return self.reversal.reverse_cascade(
            executor=executor,
            session_id=session_id,
            delegation_id=delegation_id,
            stop_on_error=stop_on_error,
            now=now,
        )

    def contain(
        self,
        delegation_id: str,
        executor: InverseExecutor,
        *,
        reason: str = "incident containment",
        revoked_by: str | None = None,
        stop_on_error: bool = False,
        now: float | None = None,
    ) -> dict[str, Any]:
        """Revoke a grant and its whole subtree, then undo what it already did.

        This is the operation the merge exists to make possible. Revocation alone
        stops the bleeding but leaves the damage; undo alone leaves the attacker
        holding live authority. Doing them in this order — revoke first, so
        nothing new lands while the rollback runs — is the containment step an
        incident responder actually needs, and neither original tool could
        express it.

        ``stop_on_error`` defaults to False here, unlike :meth:`undo_all`: during
        containment, one un-undoable action should not prevent reverting the other
        forty.
        """
        subtree = self.authority.descendant_delegations(delegation_id)
        for did in subtree:
            self.authority.revoke_delegation(did, reason, revoked_by=revoked_by)

        action_ids: list[str] = []
        for did in subtree:
            action_ids.extend(a.id for a in self.authority.actions_under_delegation(did))

        report = self.reversal.reverse_cascade(
            executor=executor,
            action_ids=action_ids,
            stop_on_error=stop_on_error,
            now=now,
        )
        out = {
            "delegation_id": delegation_id,
            "revoked_delegations": subtree,
            "actions_in_radius": len(action_ids),
            "rollback": report.to_dict(),
            "fully_contained": report.ok and report.skipped == 0,
            # Split out because these two need different people. A closed gate is
            # a worklist item someone can often clear (reopen the period, get a
            # payroll partner); a missing inverse is a loss to be accounted for.
            "needs_human_to_unblock": list(report.blocked_by_gates),
        }
        self._append("containment", out)
        return out

    # ---- introspection ----------------------------------------------------
    def verify(self) -> bool:
        """Verify the ledger's hash chain end to end."""
        return self.ledger.verify_integrity()

    def stats(self) -> dict[str, Any]:
        return {
            **self.authority.stats(),
            **self.reversal.stats(),
            "ledger_entries": len(self.ledger),
            "ledger_head": self.ledger.head_hash,
            "merkle_root": self.ledger.merkle_root(),
            "policy": self.gate.policy.name,
            "policy_digest": self.gate.policy.digest(),
            "by_kind": self.ledger.counts_by_kind(),
        }

    def verdict_for(self, action_id: str) -> Verdict | None:
        return self._verdicts.get(action_id)


__all__ = [
    "ControlPlane",
    "Verdict",
    "ApprovalHook",
    "STAGE_ENFORCE",
    "STAGE_REVERSAL",
    "STAGE_AUTHORITY",
    "STAGE_DETECT",
    "STAGE_ALLOWED",
    "Scope",
    "crypto",
]
