"""
revoco.reversal.engine
=======================
The reversal engine: plan an undo before an action runs, commit it when the
action succeeds, and execute it — alone or as a cascade — when someone needs the
world put back.

Ordering guarantee
------------------
:meth:`ReversalEngine.plan` must be called *before* the forward action executes,
because that is the only moment prior state is still readable. Everything else in
this module follows from that constraint. A plan built after the fact can record
what changed but not what to restore, which is exactly the position an incident
responder is in today.

Sequenced undos
---------------
A plan is an ordered list of steps. Steps run in declaration order, each one able
to consume the results of those before it, and a failing *critical* step aborts
the remainder rather than pressing on. That abort behavior is the important part:
if voiding a payment medium fails, continuing to reset the clearing would leave
the ledger claiming the money was never paid while the bank statement says it
was — a worse state than the one we started in.

Cascade ordering
----------------
Cascades undo in reverse-chronological order (last action first). Compensating
transactions do not commute: if an agent created a vendor and then paid it,
voiding the payment before deactivating the vendor is fine, whereas the reverse
order leaves a payment attached to a dead vendor. LIFO is the only ordering that
is safe without a full dependency graph, and it matches how saga compensation is
specified everywhere it is specified.
"""

from __future__ import annotations

import threading
import time
from collections.abc import Callable, Iterable
from typing import Any

from ..core.errors import (
    AlreadyReversed,
    NotReversible,
    ReversalGateClosed,
    ReversalPlanMissing,
    ReversalWindowExpired,
)
from .model import (
    PHASE_AUTHORIZE,
    PHASE_UNDO,
    CascadeReport,
    GateContext,
    GateEvaluator,
    InverseExecutor,
    InverseSpec,
    JournalEntry,
    JournalState,
    PlannedStep,
    ReversalPlan,
    ReversalReceipt,
    Reversibility,
    StateReader,
    StepResult,
    new_journal_id,
    new_plan_id,
    new_reversal_id,
)
from .registry import InverseRegistry

EventSink = Callable[[str, dict[str, Any]], None]

# Ledger entry kinds this engine emits.
EVT_PLAN = "reversal_plan"
EVT_COMMIT = "reversal_commit"
EVT_ABANDON = "reversal_abandon"
EVT_EXECUTED = "reversal_executed"
EVT_EXPIRED = "reversal_expired"
EVT_GATE_BLOCKED = "reversal_gate_blocked"
EVT_DEGRADED = "reversal_kind_degraded"


def _noop_sink(kind: str, payload: dict[str, Any]) -> None:
    return None


class ReversalEngine:
    """Plans, journals, and executes undo paths.

    ``state_reader`` is optional. Without one, snapshots are empty and any spec
    that maps an inverse argument from ``snapshot.*`` produces a plan with that
    argument unresolved — which surfaces as a broken plan rather than one that
    quietly restores ``None`` over live data.

    ``gate_evaluator`` is optional too, but a spec that declares gates and runs
    without an evaluator will refuse to execute. That is deliberate: a declared
    precondition nobody can check is not a precondition, and pretending otherwise
    would let an undo fire into a closed accounting period.
    """

    def __init__(
        self,
        registry: InverseRegistry | None = None,
        *,
        state_reader: StateReader | None = None,
        gate_evaluator: GateEvaluator | None = None,
        classify_hook: Callable[[str, Reversibility], Reversibility] | None = None,
        command_classifier: Callable[[str, dict[str, Any]], InverseSpec | None]
        | None = None,
        on_event: EventSink | None = None,
    ) -> None:
        self.registry = registry or InverseRegistry()
        self.state_reader = state_reader
        self.gate_evaluator = gate_evaluator
        # Applied after gate resolution. Lets a recoverability register demote a
        # declared posture that has no fresh drill evidence behind it — see
        # revoco.drills. Only ever downgrades.
        self.classify_hook = classify_hook
        # Consulted only where the registry has no spec, so it fills the UNKNOWN
        # hole and can never contradict a declared one. That bound is what makes
        # it safe to let it *raise* a posture, which `classify_hook` deliberately
        # cannot: a hook runs at decision time and downgrades on missing proof,
        # while this is a declaration of what a tool does, at the trust level of
        # the registry itself.
        #
        # It returns an InverseSpec rather than a bare posture, and that is the
        # whole guarantee. An earlier version returned a Reversibility, which let
        # a classifier answer REVERSIBLE for a tool with no undo path — a plan the
        # horizon counted as recoverable while `reverse()` refused it. InverseSpec
        # will not construct in that shape: "kind=reversible requires an
        # inverse_tool or steps". The bug is now unrepresentable rather than
        # merely tested for.
        self.command_classifier = command_classifier
        self._emit = on_event or _noop_sink
        self._journal: dict[str, JournalEntry] = {}
        self._by_action: dict[str, str] = {}
        self._lock = threading.RLock()

    # ---- classification ---------------------------------------------------
    def classify(self, tool: str, args: dict[str, Any] | None = None) -> Reversibility:
        """The reversal posture of ``tool`` for *this* call.

        Reversibility is a property of the target, not only of the tool. An S3
        delete is recoverable if the bucket has versioning enabled and gone
        forever if it does not; the tool name is identical either way. Specs
        express that with authorize-phase gates, and this is where they are
        evaluated — before the forward action, which is the only moment an
        escalation is worth anything.

        Passing no ``args`` skips authorize-phase evaluation and returns the
        spec's optimistic kind. Callers that gate on the answer should pass args.
        """
        spec = self._spec_for(tool, args)
        if spec is None:
            return Reversibility.UNKNOWN
        if args is None or not spec.authorize_gates:
            return self._apply_hook(tool, spec.kind)
        closed = self._closed_gates(
            spec.authorize_gates, tool=tool, args=args, entry=None, phase=PHASE_AUTHORIZE
        )
        if closed:
            self._emit(
                EVT_DEGRADED,
                {"tool": tool, "declared_kind": spec.kind.value,
                 "effective_kind": spec.degraded_kind.value, "closed_gates": closed},
            )
            return self._apply_hook(tool, spec.degraded_kind)
        return self._apply_hook(tool, spec.kind)

    def _spec_for(
        self, tool: str, args: dict[str, Any] | None
    ) -> InverseSpec | None:
        """The spec governing this call: declared, or derived for this one call.

        A shell command is the case the classifier exists for. It is a string
        rather than a name and arguments, so no spec can be written for it ahead
        of time, and without this every one is UNKNOWN — which ranks below
        IRREVERSIBLE, so an agent cannot run `ls` without failing every floor a
        policy states.

        A derived spec then travels the ordinary path: snapshot capture, gate
        evaluation, plan construction. It is not a second kind of thing.
        """
        spec = self.registry.get(tool)
        if spec is not None:
            return spec
        if self.command_classifier is None or args is None:
            return None
        try:
            proposed = self.command_classifier(tool, args)
        except Exception:
            return None
        return proposed if isinstance(proposed, InverseSpec) else None

    def _apply_hook(self, tool: str, kind: Reversibility) -> Reversibility:
        """Run the classify hook, refusing any result that would upgrade.

        Guarded rather than trusted: a hook that could raise a posture would let a
        buggy or hostile integration manufacture recoverability the specs never
        claimed, which is the one direction this system must never move in.
        """
        if self.classify_hook is None:
            return kind
        try:
            proposed = self.classify_hook(tool, kind)
        except Exception:
            return kind
        if not isinstance(proposed, Reversibility) or proposed.rank > kind.rank:
            return kind
        if proposed is not kind:
            self._emit(
                EVT_DEGRADED,
                {"tool": tool, "declared_kind": kind.value,
                 "effective_kind": proposed.value,
                 "closed_gates": ["classify_hook: no fresh proof of recoverability"]},
            )
        return proposed

    def _closed_gates(
        self,
        gates: tuple[Any, ...],
        *,
        tool: str,
        args: dict[str, Any],
        entry: JournalEntry | None,
        phase: str,
    ) -> list[str]:
        """Evaluate gates; return a reason string per closed gate."""
        closed: list[str] = []
        for gate in gates:
            if self.gate_evaluator is None:
                closed.append(
                    f"{gate.name}: no gate evaluator configured, so this precondition "
                    f"cannot be verified ({gate.description})"
                )
                continue
            ctx = GateContext(gate=gate, tool=tool, phase=phase, args=dict(args), entry=entry)
            try:
                verdict = self.gate_evaluator(ctx)
            except Exception as exc:
                closed.append(f"{gate.name}: evaluator raised {type(exc).__name__}: {exc}")
                continue
            if verdict is True:
                continue
            detail = verdict if isinstance(verdict, str) else gate.description
            if gate.remediation:
                detail = f"{detail} — {gate.remediation}"
            closed.append(f"{gate.name}: {detail}")
        return closed

    # ---- planning ---------------------------------------------------------
    def plan(self, tool: str, args: dict[str, Any], *, now: float | None = None) -> ReversalPlan:
        """Compute the undo path for a *pending* action.

        Never raises on an unknown tool — an unclassified tool yields an UNKNOWN
        plan, and it is policy's job to decide whether that is acceptable.
        """
        spec = self._spec_for(tool, args)
        created = now if now is not None else time.time()

        if spec is None:
            return ReversalPlan(
                id=new_plan_id(),
                tool=tool,
                kind=Reversibility.UNKNOWN,
                inverse_tool=None,
                inverse_args={},
                unresolved_args=(),
                snapshot={},
                window_seconds=None,
                residue="",
                created_at=created,
            )

        snapshot: dict[str, Any] = {}
        snapshot_error: str | None = None
        if spec.snapshot_fields:
            if self.state_reader is None:
                snapshot_error = (
                    "no state_reader configured; prior-state fields "
                    f"{list(spec.snapshot_fields)} could not be captured"
                )
            else:
                try:
                    snapshot = dict(self.state_reader(tool, args, spec.snapshot_fields) or {})
                except Exception as exc:  # a broken reader must not block the caller
                    snapshot_error = f"state_reader failed: {exc!r}"

        # An authorize-phase gate can make this call less recoverable than the
        # spec optimistically claims. Use the degraded kind for the plan so the
        # policy layer and the detectors see the truth for THIS target.
        effective_kind = self.classify(tool, args)
        if not effective_kind.is_undoable and spec.kind.is_undoable:
            return ReversalPlan(
                id=new_plan_id(),
                tool=tool,
                kind=effective_kind,
                inverse_tool=None,
                inverse_args={},
                unresolved_args=(),
                snapshot=snapshot,
                window_seconds=None,
                residue=spec.residue,
                created_at=created,
                snapshot_error=snapshot_error,
                gates=spec.gates,
                one_shot=spec.one_shot,
            )

        planned: list[PlannedStep] = []
        all_unresolved: list[str] = []
        all_deferred: list[str] = []
        for step in spec.effective_steps:
            resolved, unresolved, deferred, from_step = step.resolve(
                forward_args=args, snapshot=snapshot, include_result=False, include_steps=False
            )
            planned.append(
                PlannedStep(
                    name=step.name,
                    tool=step.tool,
                    args=resolved,
                    unresolved=unresolved,
                    deferred=deferred,
                    from_prior_step=from_step,
                    description=step.description,
                    critical=step.critical,
                )
            )
            all_unresolved.extend(unresolved)
            all_deferred.extend(deferred)

        head = planned[0] if planned else None
        plan = ReversalPlan(
            id=new_plan_id(),
            tool=tool,
            kind=spec.kind,
            inverse_tool=head.tool if head else None,
            inverse_args=dict(head.args) if head else {},
            unresolved_args=tuple(dict.fromkeys(all_unresolved)),
            deferred_args=tuple(dict.fromkeys(all_deferred)),
            snapshot=snapshot,
            window_seconds=spec.window_seconds,
            residue=spec.residue,
            created_at=created,
            snapshot_error=snapshot_error,
            steps=tuple(planned),
            gates=spec.gates,
            one_shot=spec.one_shot,
        )
        self._emit(EVT_PLAN, plan.to_dict())
        return plan

    def open_journal(
        self,
        plan: ReversalPlan,
        *,
        actor_id: str | None = None,
        delegation_id: str | None = None,
        session_id: str = "",
    ) -> JournalEntry:
        """Record a plan in the journal in the PLANNED state."""
        entry = JournalEntry(
            id=new_journal_id(),
            plan=plan,
            state=JournalState.PLANNED,
            actor_id=actor_id,
            delegation_id=delegation_id,
            session_id=session_id,
        )
        with self._lock:
            self._journal[entry.id] = entry
        return entry

    # ---- lifecycle --------------------------------------------------------
    def commit(
        self,
        journal_id: str,
        *,
        action_id: str,
        result: Any = None,
        now: float | None = None,
    ) -> JournalEntry:
        """Mark the forward action as executed and bind result-derived args.

        Called only after the forward action actually succeeded, so the journal
        reflects real state changes rather than attempted ones.
        """
        with self._lock:
            entry = self._require(journal_id)
            spec = self.registry.get(entry.plan.tool)
            if spec is not None and entry.plan.kind.is_undoable:
                by_name = {s.name: s for s in spec.effective_steps}
                rebound: list[PlannedStep] = []
                all_unresolved: list[str] = []
                for ps in entry.plan.steps:
                    step = by_name.get(ps.name)
                    if step is None:
                        rebound.append(ps)
                        all_unresolved.extend(ps.unresolved)
                        continue
                    resolved, _unres, _def, _from_step = step.resolve(
                        forward_args={},
                        snapshot=entry.plan.snapshot,
                        result=result,
                        include_result=True,
                        include_steps=False,
                    )
                    # Plan-time values stay authoritative: they were captured
                    # pre-execution and the world has since changed. Only
                    # result-derived keys are (re)bound here.
                    merged = dict(ps.args)
                    for name in step.needs_result:
                        if name in resolved:
                            merged[name] = resolved[name]
                    # A deferred argument the response did not supply is now a
                    # real hole, not a pending one — promote it so the
                    # phantom-rollback detector and journal_health can see it.
                    still_deferred = tuple(n for n in ps.deferred if n not in merged)
                    unresolved = tuple(
                        dict.fromkeys(
                            tuple(n for n in ps.unresolved if n not in merged) + still_deferred
                        )
                    )
                    rebound.append(
                        PlannedStep(
                            name=ps.name,
                            tool=ps.tool,
                            args=merged,
                            unresolved=unresolved,
                            deferred=(),
                            from_prior_step=ps.from_prior_step,
                            description=ps.description,
                            critical=ps.critical,
                        )
                    )
                    all_unresolved.extend(unresolved)

                head = rebound[0] if rebound else None
                entry.plan = ReversalPlan(
                    id=entry.plan.id,
                    tool=entry.plan.tool,
                    kind=entry.plan.kind,
                    inverse_tool=head.tool if head else None,
                    inverse_args=dict(head.args) if head else {},
                    unresolved_args=tuple(dict.fromkeys(all_unresolved)),
                    deferred_args=(),
                    snapshot=entry.plan.snapshot,
                    window_seconds=entry.plan.window_seconds,
                    residue=entry.plan.residue,
                    created_at=entry.plan.created_at,
                    snapshot_error=entry.plan.snapshot_error,
                    steps=tuple(rebound),
                    gates=entry.plan.gates,
                    one_shot=entry.plan.one_shot,
                )
            entry.action_id = action_id
            entry.transition(JournalState.COMMITTED, now=now)
            self._by_action[action_id] = entry.id
            self._emit(EVT_COMMIT, entry.to_dict())
            return entry

    def abandon(self, journal_id: str, reason: str, *, now: float | None = None) -> JournalEntry:
        """Discard a plan whose forward action was blocked or never ran."""
        with self._lock:
            entry = self._require(journal_id)
            entry.transition(JournalState.ABANDONED, note=reason, now=now)
            self._emit(EVT_ABANDON, entry.to_dict())
            return entry

    # ---- gates ------------------------------------------------------------
    def check_gates(self, entry: JournalEntry) -> list[str]:
        """Evaluate an entry's undo-phase preconditions. Returns closure reasons.

        An empty list means every gate is open. A declared gate with no evaluator
        configured counts as closed, because an unverifiable precondition is not a
        precondition. Authorize-phase-only gates are not re-checked here — their
        job was done before the forward action ran.
        """
        undo_gates = tuple(g for g in entry.plan.gates if g.checked_at_undo)
        return self._closed_gates(
            undo_gates,
            tool=entry.plan.tool,
            args=dict(entry.plan.inverse_args),
            entry=entry,
            phase=PHASE_UNDO,
        )

    # ---- execution --------------------------------------------------------
    def reverse(
        self,
        ref: str,
        executor: InverseExecutor,
        *,
        now: float | None = None,
        force_expired: bool = False,
    ) -> ReversalReceipt:
        """Undo one action, running its steps in order.

        ``ref`` may be a journal id or an action id. Raises rather than returning
        a failed receipt when the *request itself* is invalid (unknown ref, not
        reversible, already reversed, window closed, gate closed) — those are
        caller errors and must not be mistaken for "the undo ran and failed". A
        failure inside the executor does produce a receipt with ``ok=False``,
        because that is a real outcome someone has to act on.
        """
        with self._lock:
            entry = self._resolve_ref(ref)
            when = now if now is not None else time.time()

            if entry.state is JournalState.REVERSED:
                raise AlreadyReversed(
                    f"{entry.id} was already reversed at {entry.resolved_at}; "
                    "repeating the inverse would apply it twice"
                )
            if entry.state is JournalState.PLANNED:
                raise ReversalPlanMissing(
                    f"{entry.id} is still PLANNED — the forward action never committed, "
                    "so there is nothing to undo"
                )
            if entry.state in (JournalState.ABANDONED, JournalState.EXPIRED):
                raise ReversalPlanMissing(f"{entry.id} is {entry.state.value}; no live undo path")
            if not entry.plan.is_executable:
                raise NotReversible(
                    f"{entry.plan.tool} is {entry.plan.kind.value}; no inverse operation exists"
                )
            if entry.plan.unresolved_args:
                raise NotReversible(
                    f"{entry.plan.tool}: inverse arguments {list(entry.plan.unresolved_args)} "
                    "were never resolved, so the undo cannot be executed safely"
                )
            if entry.is_expired(now=when) and not force_expired:
                entry.transition(JournalState.EXPIRED, note="window closed", now=when)
                self._emit(EVT_EXPIRED, entry.to_dict())
                raise ReversalWindowExpired(
                    f"{entry.plan.tool}: undo window closed at {entry.expires_at}"
                )

            closed = self.check_gates(entry)
            if closed:
                # The entry stays COMMITTED, not EXPIRED: a gate can reopen, and
                # marking this terminal would tell a responder the rollback is
                # gone when it is merely blocked.
                self._emit(
                    EVT_GATE_BLOCKED,
                    {"journal_id": entry.id, "action_id": entry.action_id,
                     "tool": entry.plan.tool, "closed_gates": closed, "at": when},
                )
                raise ReversalGateClosed(
                    f"{entry.plan.tool}: undo blocked by {len(closed)} precondition(s): "
                    + "; ".join(closed)
                )

            step_results: dict[str, Any] = {}
            outcomes: list[StepResult] = []
            spec = self.registry.get(entry.plan.tool)
            by_name = {s.name: s for s in (spec.effective_steps if spec else ())}
            ok = True
            error: str | None = None
            aborted = False

            for ps in entry.plan.steps:
                if aborted:
                    outcomes.append(
                        StepResult(name=ps.name, tool=ps.tool, args={}, ok=False,
                                   skipped=True,
                                   error="not attempted: an earlier critical step failed")
                    )
                    continue

                args = dict(ps.args)
                if ps.from_prior_step:
                    step = by_name.get(ps.name)
                    if step is not None:
                        late, _unres, _def, still_pending = step.resolve(
                            forward_args={},
                            snapshot=entry.plan.snapshot,
                            step_results=step_results,
                            include_result=True,
                            include_steps=True,
                        )
                        for name in ps.from_prior_step:
                            if name in late:
                                args[name] = late[name]
                        if still_pending:
                            ok = False
                            error = (
                                f"step {ps.name!r}: arguments {list(still_pending)} could not "
                                "be resolved from earlier step results"
                            )
                            outcomes.append(
                                StepResult(name=ps.name, tool=ps.tool, args=args, ok=False,
                                           error=error)
                            )
                            if ps.critical:
                                aborted = True
                            continue

                try:
                    res = executor(ps.tool, args)
                    step_results[ps.name] = res if isinstance(res, dict) else {"value": res}
                    outcomes.append(
                        StepResult(name=ps.name, tool=ps.tool, args=args, ok=True, result=res)
                    )
                except Exception as exc:
                    ok = False
                    step_error = f"{type(exc).__name__}: {exc}"
                    error = f"step {ps.name!r} failed: {step_error}"
                    outcomes.append(
                        StepResult(name=ps.name, tool=ps.tool, args=args, ok=False,
                                   error=step_error)
                    )
                    if ps.critical:
                        aborted = True

            entry.reversal_result = step_results
            entry.error = error
            entry.transition(
                JournalState.REVERSED if ok else JournalState.FAILED,
                note=error or "",
                now=when,
            )

            head = entry.plan.steps[0] if entry.plan.steps else None
            receipt = ReversalReceipt(
                id=new_reversal_id(),
                journal_id=entry.id,
                action_id=entry.action_id,
                tool=entry.plan.tool,
                inverse_tool=head.tool if head else None,
                kind=entry.plan.kind,
                ok=ok,
                state=entry.state,
                residue=entry.plan.residue,
                error=error,
                executed_args=dict(head.args) if head else {},
                result=step_results,
                at=when,
                steps=tuple(outcomes),
                one_shot=entry.plan.one_shot,
            )
            self._emit(EVT_EXECUTED, receipt.to_dict())
            return receipt

    def reverse_cascade(
        self,
        *,
        executor: InverseExecutor,
        session_id: str | None = None,
        delegation_id: str | None = None,
        action_ids: Iterable[str] | None = None,
        stop_on_error: bool = True,
        now: float | None = None,
    ) -> CascadeReport:
        """Undo a whole blast radius as one unit, newest action first.

        Exactly one of ``session_id``, ``delegation_id``, or ``action_ids``
        selects the set. Scoping by delegation is the one that matters most in an
        incident: a leaked grant is the unit of compromise, so "undo everything
        that happened under this authority" is the question actually being asked,
        and the delegation graph is what makes it answerable.
        """
        selectors = [x is not None for x in (session_id, delegation_id, action_ids)]
        if sum(selectors) != 1:
            raise ValueError("pass exactly one of session_id, delegation_id, action_ids")

        with self._lock:
            if action_ids is not None:
                wanted = list(action_ids)
                entries = [
                    self._journal[self._by_action[a]] for a in wanted if a in self._by_action
                ]
                scope_kind, scope_id = "explicit", f"{len(wanted)} actions"
            elif session_id is not None:
                entries = [e for e in self._journal.values() if e.session_id == session_id]
                scope_kind, scope_id = "session", session_id
            else:
                entries = [e for e in self._journal.values() if e.delegation_id == delegation_id]
                scope_kind, scope_id = "delegation", delegation_id or ""

        live = [e for e in entries if e.state is JournalState.COMMITTED]
        # LIFO: newest committed action is undone first.
        live.sort(key=lambda e: (e.committed_at or 0.0), reverse=True)

        receipts: list[ReversalReceipt] = []
        residues: list[str] = []
        gate_blocks: list[str] = []
        failed = skipped = ok_count = 0
        stopped_early = False

        for entry in live:
            try:
                r = self.reverse(entry.id, executor, now=now)
            except ReversalGateClosed as exc:
                # Reported separately from "no undo exists": a blocked gate is
                # something a human can often clear, so it belongs on a worklist
                # rather than in a loss column.
                skipped += 1
                gate_blocks.append(str(exc))
                if entry.plan.residue:
                    residues.append(entry.plan.residue)
                continue
            except (NotReversible, ReversalWindowExpired, ReversalPlanMissing, AlreadyReversed):
                # Not a failure of the undo — there was no undo to run. Counted
                # separately so a cascade report never overstates its success.
                skipped += 1
                if entry.plan.residue:
                    residues.append(entry.plan.residue)
                continue
            receipts.append(r)
            if r.residue:
                residues.append(r.residue)
            if r.ok:
                ok_count += 1
            else:
                failed += 1
                if stop_on_error:
                    stopped_early = True
                    break

        return CascadeReport(
            scope_kind=scope_kind,
            scope_id=scope_id,
            attempted=len(live),
            reversed_ok=ok_count,
            failed=failed,
            skipped=skipped,
            receipts=tuple(receipts),
            residues=tuple(dict.fromkeys(residues)),
            stopped_early=stopped_early,
            blocked_by_gates=tuple(gate_blocks),
        )

    # ---- maintenance ------------------------------------------------------
    def expire_stale(self, *, now: float | None = None) -> list[str]:
        """Transition committed entries whose undo window has closed.

        Worth running on a schedule: an entry silently past its window is a
        rollback capability the organization believes it has and does not.
        """
        when = now if now is not None else time.time()
        expired: list[str] = []
        with self._lock:
            for entry in self._journal.values():
                if entry.state is JournalState.COMMITTED and entry.is_expired(now=when):
                    entry.transition(JournalState.EXPIRED, note="window closed", now=when)
                    self._emit(EVT_EXPIRED, entry.to_dict())
                    expired.append(entry.id)
        return expired

    # ---- lookups ----------------------------------------------------------
    def get(self, journal_id: str) -> JournalEntry | None:
        return self._journal.get(journal_id)

    def for_action(self, action_id: str) -> JournalEntry | None:
        jid = self._by_action.get(action_id)
        return self._journal.get(jid) if jid else None

    def entries(
        self,
        *,
        state: JournalState | None = None,
        session_id: str | None = None,
        delegation_id: str | None = None,
    ) -> list[JournalEntry]:
        out = list(self._journal.values())
        if state is not None:
            out = [e for e in out if e.state is state]
        if session_id is not None:
            out = [e for e in out if e.session_id == session_id]
        if delegation_id is not None:
            out = [e for e in out if e.delegation_id == delegation_id]
        return sorted(out, key=lambda e: (e.committed_at or e.plan.created_at))

    def undoable(self, **kw: Any) -> list[JournalEntry]:
        """Committed entries that could still actually be undone right now.

        Gates are *not* evaluated here — that would mean a round trip to the
        system of record per entry. Use :meth:`check_gates` on the ones you are
        about to touch.
        """
        return [
            e
            for e in self.entries(state=JournalState.COMMITTED, **kw)
            if e.plan.is_complete and not e.is_expired()
        ]

    def horizon(
        self,
        *,
        now: float | None = None,
        warn_within: float = 3600.0,
        session_id: str | None = None,
        delegation_id: str | None = None,
    ) -> Any:
        """Which undo options are still open, and when each one closes.

        The only forward-looking view in this package — everything else describes
        what already happened. See :mod:`revoco.reversal.horizon`.
        """
        from .horizon import build as _build

        entries = list(self._journal.values())
        if session_id is not None:
            entries = [x for x in entries if x.session_id == session_id]
        if delegation_id is not None:
            entries = [x for x in entries if x.delegation_id == delegation_id]
        return _build(entries, now=now, warn_within=warn_within)

    def stats(self) -> dict[str, Any]:
        counts: dict[str, int] = {s.value: 0 for s in JournalState}
        for e in self._journal.values():
            counts[e.state.value] += 1
        return {
            "journal_entries": len(self._journal),
            "by_state": counts,
            "undoable_now": len(self.undoable()),
            "registered_inverses": len(self.registry.all()),
        }

    # ---- internals --------------------------------------------------------
    def _require(self, journal_id: str) -> JournalEntry:
        entry = self._journal.get(journal_id)
        if entry is None:
            raise ReversalPlanMissing(f"unknown journal entry: {journal_id}")
        return entry

    def _resolve_ref(self, ref: str) -> JournalEntry:
        if ref in self._journal:
            return self._journal[ref]
        jid = self._by_action.get(ref)
        if jid is not None:
            return self._journal[jid]
        raise ReversalPlanMissing(f"no journal entry for reference: {ref}")
