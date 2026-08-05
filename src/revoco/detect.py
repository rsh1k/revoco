"""
revoco.detect
==============
Behavioral detectors that flag when an authorization chain has been corrupted
between the human's intent and the action taken. Findings are mapped to the
OWASP Top 10 for Agentic Applications (ASI 2026) so security teams triage in a
familiar taxonomy.

Per-action detectors:

* ASI01 / ASI02  Goal hijack / tool misuse   -> action exceeds delegated scope
* ASI03          Identity & privilege abuse  -> actor mismatch, bad signature,
                                                action under lapsed authority
* ASI06          Memory & context poisoning  -> stated intent diverges from the
                                                delegated purpose
* ASI09          Human-agent trust abuse     -> consent fatigue

Chain-level detectors (needing cross-action context):

* ASI07          Forged inter-agent grant
* ASI08          Cascading-failure fan-out
* ASI10          Rogue-agent drift

Detectors new to the merged control plane
-----------------------------------------
Two findings exist only because authority and reversibility are now in the same
system, and both describe a failure mode that neither original tool could see:

* ``PRA01`` **Unrecoverable blast radius** — a burst of *irreversible* actions
  under a single grant. Ordinary fan-out is a resilience concern; fan-out with no
  undo path is an unbounded loss, and the distinction is invisible unless you
  know both the grant and the reversal posture.
* ``PRA02`` **Phantom rollback** — an action committed with a reversal plan that
  cannot actually execute (unresolved inverse arguments, or a snapshot that
  failed to capture). This is the most dangerous state in the system, because the
  organization believes it holds a rollback capability it does not hold. Silence
  here would be worse than having no reversal layer at all.
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from enum import Enum
from typing import Any

from .authority.action import ActionRecord
from .authority.delegation import Delegation
from .reversal.model import JournalEntry, ReversalPlan, Reversibility


class Severity(str, Enum):
    INFO = "info"
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"


_SEV_ORDER = {
    s: i
    for i, s in enumerate(
        [Severity.INFO, Severity.LOW, Severity.MEDIUM, Severity.HIGH, Severity.CRITICAL]
    )
}


@dataclass(frozen=True)
class Finding:
    code: str                # OWASP ASI code, or PRA* for revoco-specific
    title: str
    severity: Severity
    message: str
    evidence: dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> dict[str, Any]:
        return {
            "code": self.code,
            "title": self.title,
            "severity": self.severity.value,
            "message": self.message,
            "evidence": self.evidence,
        }


def max_severity(findings: list[Finding]) -> Severity:
    if not findings:
        return Severity.INFO
    return max((f.severity for f in findings), key=lambda s: _SEV_ORDER[s])


def is_blocking(severity: Severity) -> bool:
    return severity in (Severity.HIGH, Severity.CRITICAL)


_WORD_RE = re.compile(r"[a-z0-9]+")


def _tokens(text: str) -> set[str]:
    return set(_WORD_RE.findall(text.lower()))


def _jaccard(a: set[str], b: set[str]) -> float:
    if not a and not b:
        return 1.0
    if not a or not b:
        return 0.0
    return len(a & b) / len(a | b)


def _resolve_arg(path: str, args: dict[str, Any]) -> tuple[bool, Any]:
    cur: Any = args
    for part in path.split("."):
        if isinstance(cur, dict) and part in cur:
            cur = cur[part]
        else:
            return False, None
    return True, cur


class DetectionEngine:
    """Runs explainable, deterministic detectors over an action's full context.

    Every threshold is a constructor argument because the right value is a
    property of the deployment, not of the detector. Defaults are a starting
    point to tune against a corpus, not calibrated values.
    """

    def __init__(
        self,
        *,
        intent_drift_threshold: float = 0.05,
        fatigue_window_seconds: float = 300.0,
        fatigue_low_risk_max: int = 25,
        fatigue_high_risk_min: int = 70,
        fatigue_burst_count: int = 5,
        cascade_window_seconds: float = 60.0,
        cascade_fanout_threshold: int = 25,
        irreversible_fanout_threshold: int = 5,
        rogue_strike_threshold: int = 3,
    ) -> None:
        self.intent_drift_threshold = intent_drift_threshold
        self.fatigue_window_seconds = fatigue_window_seconds
        self.fatigue_low_risk_max = fatigue_low_risk_max
        self.fatigue_high_risk_min = fatigue_high_risk_min
        self.fatigue_burst_count = fatigue_burst_count
        self.cascade_window_seconds = cascade_window_seconds
        self.cascade_fanout_threshold = cascade_fanout_threshold
        self.irreversible_fanout_threshold = irreversible_fanout_threshold
        self.rogue_strike_threshold = rogue_strike_threshold

    # ---- per-action -------------------------------------------------------
    def evaluate_action(
        self,
        *,
        action: ActionRecord,
        authorizing_delegation: Delegation,
        chain: list[Delegation],
        actor_signature_valid: bool,
        recent_actions: list[ActionRecord] | None = None,
    ) -> list[Finding]:
        findings: list[Finding] = []
        recent_actions = recent_actions or []

        # --- ASI03: identity abuse ----------------------------------------
        if not actor_signature_valid:
            findings.append(
                Finding(
                    code="ASI03",
                    title="Identity Abuse: invalid actor signature",
                    severity=Severity.CRITICAL,
                    message="Action signature did not verify against the actor's registered key.",
                    evidence={"action_id": action.id, "actor_id": action.actor_id},
                )
            )
        if action.actor_id != authorizing_delegation.subject_id:
            findings.append(
                Finding(
                    code="ASI03",
                    title="Identity Abuse: actor is not the delegation subject",
                    severity=Severity.CRITICAL,
                    message="The acting principal was not the subject the delegation was issued to.",
                    evidence={
                        "action_actor": action.actor_id,
                        "delegation_subject": authorizing_delegation.subject_id,
                    },
                )
            )

        # --- ASI01/ASI02: goal hijack / tool misuse (scope) ---------------
        scope = authorizing_delegation.scope
        if not scope.permits_action(action.tool, action.action, action.risk):
            findings.append(
                Finding(
                    code="ASI02",
                    title="Tool Misuse / Goal Hijack: action outside delegated scope",
                    severity=Severity.HIGH,
                    message=(
                        f"Action {action.action} on tool '{action.tool}' at risk "
                        f"{action.risk} is not within the delegated scope."
                    ),
                    evidence={
                        "tool": action.tool,
                        "action": action.action,
                        "risk": action.risk,
                        "allowed_tools": sorted(scope.allowed_tools),
                        "allowed_actions": sorted(scope.allowed_actions),
                        "max_risk": scope.max_risk,
                    },
                )
            )

        # --- ASI03: acting on lapsed authority ----------------------------
        if authorizing_delegation.expired(now=action.occurred_at):
            findings.append(
                Finding(
                    code="ASI03",
                    title="Privilege Abuse: action under expired authority",
                    severity=Severity.HIGH,
                    message="Action occurred after its authorizing delegation expired.",
                    evidence={
                        "occurred_at": action.occurred_at,
                        "expires_at": authorizing_delegation.expires_at,
                    },
                )
            )

        # --- ASI06: intent drift / memory poisoning -----------------------
        chain_purpose_tokens: set[str] = set()
        for d in chain:
            chain_purpose_tokens |= _tokens(d.purpose)
        action_tokens = (
            _tokens(action.description) | _tokens(action.tool) | _tokens(action.action)
        )
        similarity = _jaccard(action_tokens, chain_purpose_tokens)
        if similarity < self.intent_drift_threshold and action.risk >= 40:
            findings.append(
                Finding(
                    code="ASI06",
                    title="Intent Drift: action diverges from delegated purpose",
                    severity=Severity.MEDIUM,
                    message=(
                        "The action's stated intent has low overlap with the purpose it "
                        "was delegated for — possible goal redirection or memory poisoning."
                    ),
                    evidence={
                        "similarity": round(similarity, 3),
                        "threshold": self.intent_drift_threshold,
                        "action_description": action.description[:200],
                    },
                )
            )

        # --- ASI09: consent fatigue ---------------------------------------
        if action.risk >= self.fatigue_high_risk_min:
            window_start = action.occurred_at - self.fatigue_window_seconds
            low_risk_burst = [
                a
                for a in recent_actions
                if window_start <= a.occurred_at < action.occurred_at
                and a.risk <= self.fatigue_low_risk_max
            ]
            if len(low_risk_burst) >= self.fatigue_burst_count:
                findings.append(
                    Finding(
                        code="ASI09",
                        title="Human-Agent Trust Exploitation: consent fatigue",
                        severity=Severity.HIGH,
                        message=(
                            "A high-risk action was approved immediately after a burst of "
                            "low-risk approvals — a classic human-in-the-loop bypass."
                        ),
                        evidence={
                            "high_risk": action.risk,
                            "preceding_low_risk_count": len(low_risk_burst),
                            "window_seconds": self.fatigue_window_seconds,
                        },
                    )
                )

        return findings

    # ---- chain-level ------------------------------------------------------
    def evaluate_chain(
        self,
        *,
        action: ActionRecord,
        chain_errors: list[str],
        recent_actions: list[ActionRecord],
        actor_strikes: int = 0,
    ) -> list[Finding]:
        out: list[Finding] = []

        for msg in (e for e in chain_errors if "revoked" in e):
            out.append(
                Finding(
                    code="ASI03",
                    title="Privilege Abuse: revoked authority used",
                    severity=Severity.CRITICAL,
                    message=msg,
                    evidence={"action_id": action.id},
                )
            )

        for err in chain_errors:
            if "signature invalid" in err and "delegation" in err:
                out.append(
                    Finding(
                        code="ASI07",
                        title="Insecure Inter-Agent Communication: forged delegation in chain",
                        severity=Severity.CRITICAL,
                        message="A delegation passed between agents failed signature verification.",
                        evidence={"detail": err},
                    )
                )

        window_start = action.occurred_at - self.cascade_window_seconds
        burst = [
            a
            for a in recent_actions
            if a.delegation_id == action.delegation_id and a.occurred_at >= window_start
        ]
        if len(burst) + 1 >= self.cascade_fanout_threshold:
            out.append(
                Finding(
                    code="ASI08",
                    title="Cascading Failure risk: high action fan-out",
                    severity=Severity.MEDIUM,
                    message=(
                        "An unusually large number of actions fired under a single grant in "
                        "a short window — a fault here would cascade across the workflow."
                    ),
                    evidence={
                        "fanout": len(burst) + 1,
                        "window_seconds": self.cascade_window_seconds,
                        "threshold": self.cascade_fanout_threshold,
                    },
                )
            )

        if actor_strikes >= self.rogue_strike_threshold:
            out.append(
                Finding(
                    code="ASI10",
                    title="Rogue Agent: repeated authorization violations",
                    severity=Severity.HIGH,
                    message=(
                        "This actor has accumulated multiple blocking findings — its behavior "
                        "has drifted from authorized bounds and it should be quarantined."
                    ),
                    evidence={"strikes": actor_strikes, "threshold": self.rogue_strike_threshold},
                )
            )

        return out

    # ---- chain constraint caps --------------------------------------------
    def evaluate_constraints(
        self,
        *,
        action: ActionRecord,
        args: dict[str, Any],
        effective_constraints: dict[str, Any],
    ) -> list[Finding]:
        """Enforce numeric caps carried by the delegation chain.

        A constraint key of the form ``max:<dotted.arg.path>`` is an upper bound
        on that argument, and the bound in force is the tightest one anywhere in
        the chain (see :meth:`Scope.effective_constraints`).

        This closes a gap in the original design: ``effective_constraints`` was
        computed and attenuated correctly but nothing ever compared it against a
        real argument, so ``max_amount_usd=50000`` on a grant read like a spending
        limit and enforced nothing. A cap that looks like a control and is not one
        is worse than no cap, because people delegate more freely on the strength
        of it. The explicit ``max:`` prefix keeps the binding unambiguous — other
        constraint keys remain free-form metadata for policy to consume.
        """
        out: list[Finding] = []
        for key, cap in effective_constraints.items():
            if not key.startswith("max:"):
                continue
            if not isinstance(cap, (int, float)) or isinstance(cap, bool):
                continue
            path = key[len("max:") :]
            found, value = _resolve_arg(path, args)
            if not found:
                continue
            try:
                numeric = float(value)
            except (TypeError, ValueError):
                out.append(
                    Finding(
                        code="ASI02",
                        title="Tool Misuse: capped argument is not numeric",
                        severity=Severity.HIGH,
                        message=(
                            f"The chain caps '{path}' at {cap}, but the supplied value is "
                            f"not a number, so the cap cannot be enforced."
                        ),
                        evidence={"constraint": key, "cap": cap, "value": repr(value)},
                    )
                )
                continue
            if numeric > cap:
                out.append(
                    Finding(
                        code="ASI02",
                        title="Tool Misuse: action exceeds a delegated cap",
                        severity=Severity.HIGH,
                        message=(
                            f"'{path}' is {numeric}, above the {cap} ceiling the "
                            "authorizing chain permits."
                        ),
                        evidence={
                            "constraint": key,
                            "cap": cap,
                            "value": numeric,
                            "tool": action.tool,
                        },
                    )
                )
        return out

    # ---- reversibility-aware (new) ----------------------------------------
    def evaluate_reversibility(
        self,
        *,
        action: ActionRecord,
        plan: ReversalPlan | None,
        committed_irreversible_under_grant: int = 0,
        reversibility_floor: Reversibility = Reversibility.UNKNOWN,
    ) -> list[Finding]:
        """Findings that depend on knowing both the grant and the undo path."""
        out: list[Finding] = []

        if plan is None:
            return out

        # PRA01 — unrecoverable blast radius.
        if (
            not plan.kind.is_undoable
            and committed_irreversible_under_grant + 1 >= self.irreversible_fanout_threshold
        ):
            out.append(
                Finding(
                    code="PRA01",
                    title="Unrecoverable blast radius: irreversible fan-out under one grant",
                    severity=Severity.HIGH,
                    message=(
                        "Multiple irreversible actions have executed under a single "
                        "delegation. Revoking the grant stops further damage but cannot "
                        "undo what has already happened, so the exposure is now bounded "
                        "only by what the agent already did."
                    ),
                    evidence={
                        "delegation_id": action.delegation_id,
                        "irreversible_count": committed_irreversible_under_grant + 1,
                        "threshold": self.irreversible_fanout_threshold,
                        "tool": action.tool,
                    },
                )
            )

        # PRA02 — phantom rollback: a plan that exists but has a real hole.
        # Deliberately excludes deferred (result-bound) arguments, which are
        # expected to be outstanding until the forward call returns.
        if plan.is_broken:
            out.append(
                Finding(
                    code="PRA02",
                    title="Phantom rollback: undo path recorded but not executable",
                    severity=Severity.HIGH,
                    message=(
                        f"'{plan.tool}' is classified {plan.kind.value}, but its reversal "
                        "plan cannot execute as recorded. The rollback capability this "
                        "organization believes it has for this action does not exist."
                    ),
                    evidence={
                        "plan_id": plan.id,
                        "unresolved_args": list(plan.unresolved_args),
                        "deferred_args": list(plan.deferred_args),
                        "snapshot_error": plan.snapshot_error,
                    },
                )
            )

        # A grant that demanded undoability is being used for something else.
        if reversibility_floor is not Reversibility.UNKNOWN:
            if plan.kind.rank < reversibility_floor.rank:
                out.append(
                    Finding(
                        code="ASI02",
                        title="Tool Misuse: action below the chain's reversibility floor",
                        severity=Severity.HIGH,
                        message=(
                            f"The authorizing chain requires at least "
                            f"'{reversibility_floor.value}' reversibility; this action is "
                            f"'{plan.kind.value}'."
                        ),
                        evidence={
                            "required": reversibility_floor.value,
                            "actual": plan.kind.value,
                            "tool": plan.tool,
                        },
                    )
                )

        return out


def journal_health(entries: list[JournalEntry]) -> dict[str, Any]:
    """Summarize whether the rollback capability is real.

    Distinguishes entries that *could* be undone right now from entries that are
    merely classified as undoable. The gap between those two numbers is the
    honest measure of recovery readiness, and it is the number worth putting in
    front of a risk committee.
    """
    committed = [e for e in entries if e.state.value == "committed"]
    executable = [e for e in committed if e.plan.is_complete and not e.is_expired()]
    phantom = [
        e
        for e in committed
        if e.plan.kind.is_undoable and (not e.plan.is_complete or e.is_expired())
    ]
    return {
        "committed": len(committed),
        "actually_undoable": len(executable),
        "phantom_rollbacks": len(phantom),
        "irreversible": len([e for e in committed if not e.plan.kind.is_undoable]),
        "phantom_details": [
            {
                "journal_id": e.id,
                "tool": e.plan.tool,
                "unresolved_args": list(e.plan.unresolved_args) + list(e.plan.deferred_args),
                "snapshot_error": e.plan.snapshot_error,
                "expired": e.is_expired(),
            }
            for e in phantom
        ],
    }


__all__ = [
    "Severity",
    "Finding",
    "DetectionEngine",
    "max_severity",
    "is_blocking",
    "journal_health",
]
