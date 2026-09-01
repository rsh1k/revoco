"""Generating the golden files that hold the two runtimes together.

The fixtures are produced by *running* revoco, never by writing down what revoco
ought to do. That distinction is the whole value: a hand-authored expectation
encodes the author's belief about the engine, so when Go disagrees with it you
have learned that Go disagrees with the author. Fixtures taken from execution
mean a mismatch is a real divergence between two implementations of one rule.

There is a second trap this module is built to avoid. The bundle evaluator in
`bundle.py` is itself a reimplementation — a third one, in Python — and if the
fixtures came only from it, Go would be conformed to a model of revoco rather
than to revoco. So every case is run through **both** revoco's real
`PolicyEngine` and the bundle evaluator, and generation fails outright if they
ever differ. Only then is the verdict frozen.
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

from .bundle import Call, classify, compile_bundle, evaluate

# The matrix is deliberately small and deliberately awkward. It is not trying to
# be representative traffic; it is trying to hit the places where two glob or
# comparison implementations diverge.
_TOOLS = [
    "invoices.read", "invoices.pay", "vendors.update", "payments.wire",
    "unregistered.tool", "invoices", "invoices.read.extra",
    # Cases that separate Python's fnmatch from Go's path.Match: `*` in Go's
    # path.Match does not cross `/`, and character-class handling differs.
    "a/b", "a.b", "file[1]", "UPPER.case",
]
_ACTIONS = ["read", "write", "admin"]
_AGENTS = ["ap-bot", "other-bot"]
_ROLES: list[tuple[str, ...]] = [(), ("ap-clerk",), ("ap-clerk", "approver")]


def _boundaries(policy: Any, attrs: tuple[str, ...]) -> list[int]:
    """Every threshold in the policy, plus the values either side of it.

    Hand-picked numbers were the first version of this and they were quietly
    useless. The matrix ran 0, 1, 39, 40, 41, 70, 100 against a policy whose only
    threshold was 25, so `risk >= 25` and `risk > 25` produced identical verdicts
    on every single case — a one-character comparison bug survived 8,316 fixtures
    untouched, which was proved by introducing it deliberately.

    Comparison bugs live exactly on the boundary, so the boundary has to come
    from the policy rather than from taste. Deriving it means a new rule brings
    its own coverage with it instead of relying on someone remembering.
    """
    seen = {0}
    for rule in policy.rules:
        for attr in attrs:
            t = getattr(rule, attr, None)
            if t is None:
                continue
            seen.update({t - 1, t, t + 1})
    return sorted(v for v in seen if v >= 0)


def _principal(agent_id: str, roles: tuple[str, ...]) -> Any:
    from revoco import crypto
    from revoco.authority import Principal, PrincipalKind

    _, pub = crypto.generate_keypair()
    return Principal(id=agent_id, kind=PrincipalKind.AGENT, name=agent_id,
                     public_key=pub, roles=frozenset(roles))


def _cases(policy: Any) -> list[Call]:
    risks = _boundaries(policy, ("min_risk", "max_risk"))
    threats = _boundaries(policy, ("min_threat_score",))
    out: list[Call] = []
    for tool in _TOOLS:
        for action in _ACTIONS:
            for agent in _AGENTS:
                for roles in _ROLES:
                    for risk in risks:
                        for threat in threats:
                            out.append(Call(tool=tool, action=action, agent_id=agent,
                                            roles=roles, risk=risk, threat_score=threat))
    return out


class _FixedScanner:
    """A scanner with a dialable score.

    revoco's real scanner derives a threat score from argument text. Reproducing
    that in Go is a separate problem with its own conformance surface, so schema
    1 takes the score as an input to the decision rather than computing it. This
    stands in for the scorer so the *rule matching* on `min_threat_score` is
    still exercised.
    """

    def __init__(self, score: int) -> None:
        self.score = score

    def scan(self, args: Any) -> Any:
        from revoco.gate.threats import ScanResult

        return ScanResult(score=self.score, hits=())


def generate(policy: Any, registry: Any, name: str) -> dict[str, Any]:
    """Run every case through both engines, agree, and freeze."""
    from revoco.gate.engine import PolicyEngine

    bundle = compile_bundle(policy, registry)
    rows: list[dict[str, Any]] = []
    disagreements: list[str] = []

    for call in _cases(policy):
        rev = classify(bundle, call.tool)
        principal = _principal(call.agent_id, call.roles)

        engine = PolicyEngine(policy, scanner=_FixedScanner(call.threat_score))
        from revoco.reversal import Reversibility

        real = engine.evaluate(
            tool=call.tool, args={}, principal=principal, session_id="fixtures",
            action=call.action, reversibility=Reversibility(rev), risk=call.risk,
        )
        mine = evaluate(bundle, call)

        if (real.effect.value, real.rule_id) != (mine.effect, mine.rule_id):
            disagreements.append(
                f"{call.tool}/{call.action}/{call.agent_id}/roles={call.roles}"
                f"/risk={call.risk}/threat={call.threat_score}: "
                f"revoco={real.effect.value}:{real.rule_id} "
                f"bundle={mine.effect}:{mine.rule_id}")
            continue

        rows.append({
            "tool": call.tool, "action": call.action, "agent_id": call.agent_id,
            "roles": list(call.roles), "risk": call.risk,
            "threat_score": call.threat_score,
            "expect": {
                "effect": mine.effect,
                "rule_id": mine.rule_id,
                "reversibility": mine.reversibility,
                "allowed": mine.allowed,
            },
        })

    if disagreements:
        raise AssertionError(
            f"{len(disagreements)} case(s) where the bundle evaluator and revoco's "
            f"PolicyEngine disagree. The fixtures are not trustworthy until this is "
            f"zero, because Go would be conformed to the wrong oracle.\n  " +
            "\n  ".join(disagreements[:10]))

    return {"name": name, "bundle": bundle, "cases": rows}


def write(out_dir: Path, suites: list[dict[str, Any]]) -> list[Path]:
    out_dir.mkdir(parents=True, exist_ok=True)
    written = []
    for suite in suites:
        p = out_dir / f"{suite['name']}.json"
        p.write_text(json.dumps(suite, indent=2, sort_keys=True) + "\n", encoding="utf-8")
        written.append(p)
    return written
