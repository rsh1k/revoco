"""
praetor.gate.engine
===================
The Policy Decision Point.

Given a tool call, the calling principal, the action's reversal posture, and a
session id, the engine returns exactly one :class:`Decision`. It is pure and
synchronous: no I/O, no network, no forwarding. That separation is what makes
the engine the part you can test exhaustively and reason about, while messy
transport lives at the edges.

Evaluation order (first match wins, like a firewall)::

    for each rule in policy order:
        if rule matches (tool, action, agent, roles, reversibility,
                         threat score, risk, condition, budget):
            return that rule's decision
    return policy.default_effect
"""

from __future__ import annotations

import fnmatch
from typing import Any

from ..authority.principals import Principal
from ..reversal.model import Reversibility
from .decision import Decision, Effect
from .policy import Policy, Rule
from .session import InMemorySessionStore, SessionStore
from .threats import ScanResult, ThreatScanner


class PolicyEngine:
    def __init__(
        self,
        policy: Policy,
        store: SessionStore | None = None,
        scanner: ThreatScanner | None = None,
    ) -> None:
        self.policy = policy
        self.store = store or InMemorySessionStore()
        # Always available so rules can reference threat scores without the
        # caller having to remember to wire a scanner up.
        self.scanner = scanner or ThreatScanner()

    # -- matching helpers ---------------------------------------------------
    @staticmethod
    def _matches_any_glob(value: str, globs: tuple[str, ...]) -> bool:
        return any(fnmatch.fnmatchcase(value, g) for g in globs)

    def _rule_matches(
        self,
        rule: Rule,
        *,
        tool: str,
        action: str,
        args: dict[str, Any],
        principal: Principal,
        session_id: str,
        scan: ScanResult,
        reversibility: Reversibility,
        risk: int,
    ) -> bool:
        if not self._matches_any_glob(tool, rule.tools):
            return False
        if not self._matches_any_glob(action, rule.actions):
            return False
        if not self._matches_any_glob(principal.id, rule.agents):
            return False
        if rule.require_roles and not all(principal.has_role(r) for r in rule.require_roles):
            return False
        if rule.reversibility and reversibility not in rule.reversibility:
            return False
        if rule.min_threat_score is not None and scan.score < rule.min_threat_score:
            return False
        if rule.max_risk is not None and risk > rule.max_risk:
            return False
        if not rule.condition.evaluate(args):
            return False
        if rule.budget is not None:
            # Budget participates in MATCHING: once the running total would be
            # exceeded by this call, the rule stops matching, so evaluation falls
            # through to whatever rule or default handles the over-limit case.
            # This keeps budget logic declarative instead of special-cased.
            found, raw_val = _resolve(rule.budget.field, args)
            add = _safe_float(raw_val) if found else 0.0
            if self.store.would_exceed(session_id, rule.budget.key, add, rule.budget.limit):
                return False
        return True

    # -- public API ---------------------------------------------------------
    def evaluate(
        self,
        *,
        tool: str,
        args: dict[str, Any],
        principal: Principal,
        session_id: str,
        action: str = "write",
        reversibility: Reversibility = Reversibility.UNKNOWN,
        risk: int = 0,
    ) -> Decision:
        args = args or {}
        scan = self.scanner.scan(args)
        for rule in self.policy.rules:
            if self._rule_matches(
                rule,
                tool=tool,
                action=action,
                args=args,
                principal=principal,
                session_id=session_id,
                scan=scan,
                reversibility=reversibility,
                risk=risk,
            ):
                obligations = dict(rule.obligations)
                if not scan.clean:
                    # Surface threat findings in the audit trail even on an
                    # allow, so analysts can review what got through.
                    obligations["threat_scan"] = scan.to_dict()
                obligations["reversibility"] = reversibility.value
                return Decision(
                    effect=rule.effect,
                    rule_id=rule.id,
                    reason=rule.reason or f"matched rule {rule.id}",
                    redact_fields=rule.redact_fields,
                    obligations=obligations,
                )

        default_obligations: dict[str, Any] = {"reversibility": reversibility.value}
        if not scan.clean:
            default_obligations["threat_scan"] = scan.to_dict()
        return Decision(
            effect=self.policy.default_effect,
            rule_id="__default__",
            reason=f"no rule matched; default {self.policy.default_effect.value}",
            obligations=default_obligations,
        )

    def commit_budget(
        self, tool: str, args: dict[str, Any], decision: Decision, session_id: str
    ) -> None:
        """Record spend against a budget AFTER a call actually executed."""
        rule = self._rule_for(decision)
        if rule is None or rule.budget is None:
            return
        found, raw_val = _resolve(rule.budget.field, args or {})
        if found:
            self.store.commit(session_id, rule.budget.key, _safe_float(raw_val))

    def release_budget(
        self, tool: str, args: dict[str, Any], decision: Decision, session_id: str
    ) -> None:
        """Return spend to a budget after the action was successfully reversed.

        Without this the ledger and the budget disagree: the money is back but
        the session still believes it was spent, so the next legitimate attempt
        hits a ceiling that no longer exists.
        """
        rule = self._rule_for(decision)
        if rule is None or rule.budget is None:
            return
        release = getattr(self.store, "release", None)
        if release is None:
            return
        found, raw_val = _resolve(rule.budget.field, args or {})
        if found:
            release(session_id, rule.budget.key, _safe_float(raw_val))

    def _rule_for(self, decision: Decision) -> Rule | None:
        if decision.rule_id in ("__default__", "__engine_failure__"):
            return None
        return next((r for r in self.policy.rules if r.id == decision.rule_id), None)


def _resolve(path: str, args: dict[str, Any]) -> tuple[bool, Any]:
    cur: Any = args
    for part in path.split("."):
        if isinstance(cur, dict) and part in cur:
            cur = cur[part]
        else:
            return False, None
    return True, cur


def _safe_float(x: Any) -> float:
    try:
        if isinstance(x, bool):
            return 0.0
        return float(x)
    except (TypeError, ValueError):
        return 0.0


def redact_arguments(args: dict[str, Any], fields: tuple[str, ...]) -> dict[str, Any]:
    """Return a copy of ``args`` with dotted-path ``fields`` masked.

    Redaction replaces rather than removes, so the downstream tool still sees a
    well-formed payload and the shape of the call is preserved in evidence.
    """
    import copy

    out = copy.deepcopy(args or {})
    for path in fields:
        parts = path.split(".")
        cur: Any = out
        for p in parts[:-1]:
            if isinstance(cur, dict) and p in cur:
                cur = cur[p]
            else:
                cur = None
                break
        if isinstance(cur, dict) and parts[-1] in cur:
            cur[parts[-1]] = "[REDACTED]"
    return out


__all__ = ["PolicyEngine", "redact_arguments", "Effect"]
