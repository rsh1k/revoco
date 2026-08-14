#!/usr/bin/env python3
"""Does the analysis actually say something true about the traffic?

These check the properties that make the feature safe to act on rather than the
shape of the output. A `suggest` that silently blessed an irreversible action, or
a `simulate` that reported no change when a policy really would break work, would
be worse than not having the feature: both fail in the direction of false
confidence, and both would be believed.
"""

from __future__ import annotations

import json
import sys
import tempfile
from pathlib import Path

from recoup.analyse import Observation, inventory, read, simulate, suggest
from recoup.bundle import compile_bundle

BOLD, DIM, GREEN, RED, RESET = "\033[1m", "\033[2m", "\033[32m", "\033[31m", "\033[0m"

failures = 0


def check(label: str, ok: bool, detail: str = "") -> None:
    global failures
    if not ok:
        failures += 1
    mark = f"{GREEN}pass{RESET}" if ok else f"{RED}FAIL{RESET}"
    print(f"  {mark}  {label}")
    if detail:
        print(f"        {DIM}{detail}{RESET}")


def obs(tool, action="write", agent="bot", rev="reversible", allowed=True, risk=0):
    return Observation(tool=tool, action=action, agent_id=agent, reversibility=rev,
                       effect="allow" if allowed else "require_approval",
                       allowed=allowed, risk=risk)


def main() -> int:
    print(f"\n{BOLD}reading a journal{RESET}\n")

    with tempfile.TemporaryDirectory() as d:
        p = Path(d) / "j.jsonl"
        p.write_text(
            json.dumps({"tool": "a.read", "action": "read", "agent_id": "x",
                        "reversibility": "reversible", "effect": "allow",
                        "allowed": True, "risk": 0}) + "\n"
            + "{not json\n"                      # a torn line
            + json.dumps({"tool": "b.pay", "action": "write", "agent_id": "y",
                          "reversibility": "irreversible", "effect": "require_approval",
                          "allowed": False, "risk": 30}) + "\n",
            encoding="utf-8")
        got = list(read(p))
        check("a torn line is skipped, not fatal", len(got) == 2,
              "a journal is written by a process that can be killed mid-line")

    print(f"\n{BOLD}inventory{RESET}\n")

    inv = inventory(iter([obs("i.read", "read", "reader", "reversible")] * 10
                         + [obs("p.wire", "write", "payer", "irreversible", False)] * 5))
    check("agents are separated", len(inv["agents"]) == 2)
    check("irreversible tools are named", inv["irreversible_tools"] == ["p.wire"])
    payer = next(a for a in inv["agents"] if a["agent_id"] == "payer")
    check("share of unrecoverable work is reported per agent",
          payer["irreversible_share"] == 1.0, f"payer: {payer['irreversible_share']}")

    print(f"\n{BOLD}suggest{RESET}\n")

    stream = ([obs("i.read", "read", "reader")] * 50
              + [obs("v.update", "write", "reader")] * 2          # thin
              + [obs("p.wire", "write", "payer", "irreversible", False)] * 20)
    out = suggest(iter(stream))
    rules = {r["id"]: r for r in out["policy"]["rules"]}

    check("an irreversible tool is never rolled into an allow rule",
          all("p.wire" not in r.get("tools", []) for r in out["policy"]["rules"]
              if r["effect"] == "allow"),
          "it happened; that is not evidence it should have")
    check("it gets its own approval clause",
          rules["irreversible-needs-a-human"]["tools"] == ["p.wire"])
    # First match wins, so an approval clause placed after the allows would be
    # unreachable — a generated policy must not ship that bug.
    ids = [r["id"] for r in out["policy"]["rules"]]
    check("the approval clause is ordered before the allows",
          ids.index("irreversible-needs-a-human") == 0, " -> ".join(ids))
    check("the default stays deny", out["policy"]["default_effect"] == "deny")
    check("thinly-evidenced tools are flagged",
          any("v.update" in n for n in out["notes"]),
          "2 observations is a coincidence, not a duty")
    check("the output says it is a draft", "Review every clause" in out["warning"])

    print(f"\n{BOLD}simulate{RESET}\n")

    # Traffic where the reader wrote to vendors, and a policy that stops it.
    traffic = [obs("i.read", "read", "reader")] * 100 + [obs("v.update", "write", "reader")] * 4
    tight = {
        "schema": 1, "policy_id": "tight@1", "default_effect": "deny",
        "reversibility": {"i.read": "reversible", "v.update": "reversible"},
        "reversibility_globs": [], "unknown_tool_reversibility": "unknown",
        "rules": [{"id": "reads", "effect": "allow", "tools": ["i.read"],
                   "actions": ["read"], "agents": ["*"], "require_roles": [],
                   "reversibility": [], "min_risk": None, "max_risk": None,
                   "min_threat_score": None, "redact_fields": [], "reason": "r"}],
    }
    r = simulate(iter(traffic), tight)
    check("work that would newly break is counted", r["newly_blocked_calls"] == 4,
          f"{r['newly_blocked_calls']} calls, {r['would_break_pct']}% of traffic")
    check("and attributed to a tool and an agent",
          r["newly_blocked"][0]["tool"] == "v.update"
          and r["newly_blocked"][0]["agent_id"] == "reader")
    check("the blast radius is a percentage someone can decide on",
          abs(r["would_break_pct"] - 3.846) < 0.01, f"{r['would_break_pct']}%")

    # The comparison must be against the policy's verdict, not the shadowed
    # outcome. Getting this backwards would report every shadow deployment as
    # "nothing changes", which is the exact opposite of the truth.
    shadowed = [Observation(tool="p.wire", action="write", agent_id="payer",
                            reversibility="irreversible", effect="require_approval",
                            allowed=False)] * 10
    permissive = dict(tight, policy_id="open@1", default_effect="allow", rules=[])
    r2 = simulate(iter(shadowed), permissive)
    check("a policy that would newly allow blocked work is detected",
          r2["newly_allowed_calls"] == 10,
          "compares against the recorded verdict, not the shadowed outcome")

    print(f"\n{BOLD}dependencies{RESET}\n")

    from recoup.analyse import consequence_budget, dependencies

    mixed = ([obs("shared.read", "read", "a")] * 10
             + [obs("shared.read", "read", "b")] * 10
             + [obs("solo.write", "write", "b")] * 5
             + [obs("p.wire", "write", "c", "irreversible", False)] * 3)
    d = dependencies(iter(mixed))
    check("a tool used by two agents is flagged as shared",
          d["shared_tools"] == ["shared.read"],
          "removing it breaks more than one thing")
    check("a tool used by one agent is not", "solo.write" in d["single_agent_tools"])
    shared = next(t for t in d["tools"] if t["tool"] == "shared.read")
    check("dependents are named, not just counted",
          shared["agents"] == ["a", "b"])

    print(f"\n{BOLD}exposure{RESET}\n")

    b = consequence_budget(iter(mixed))
    rows = {r["agent_id"]: r for r in b["agents"]}
    check("an irreversible call weighs more than a reversible one",
          rows["c"]["consequence"] == 24 and rows["a"]["consequence"] == 10,
          f"c: 3 irreversible = {rows['c']['consequence']}, "
          f"a: 10 reversible = {rows['a']['consequence']}")
    check("so a low-volume agent can still dominate exposure",
          rows["c"]["consequence"] > rows["a"]["consequence"],
          "3 calls out-weigh 10, which is the entire point of weighting")
    check("shares sum to a whole",
          abs(sum(r["share_pct"] for r in b["agents"]) - 100.0) < 0.2)
    check("exposure concentration is attributed to tools",
          rows["c"]["top_by_consequence"][0][0] == "p.wire")

    test_finality_and_intel()
    test_prove()

    print(f"\n{'all checks passed' if not failures else str(failures) + ' FAILED'}\n")
    return 1 if failures else 0




def test_finality_and_intel() -> None:
    """On-chain finality and behavioural intel."""
    global failures
    from recoup import finality as F
    from recoup.intel import analyse as intel_analyse

    print(f"\n{BOLD}on-chain finality{RESET}\n")

    draft = F.OnChainAction(chain="solana", value=50_000, asset="USDC")
    check("an unsigned transaction is fully reversible",
          F.reversibility(draft) == "reversible",
          "stopping it costs nothing, which is the only moment that is true")

    # Solana has no replacement mechanism and carries most agentic payment
    # volume, so a pending transaction there is genuinely beyond recall.
    pending_solana = F.OnChainAction(chain="solana", confirmations=0, signed=True)
    check("pending on a chain with no replacement is irreversible, not compensable",
          F.reversibility(pending_solana) == "irreversible",
          "naming a remedy that does not exist is the phantom rollback again")

    pending_eth = F.OnChainAction(chain="ethereum", confirmations=0, signed=True)
    check("pending where replacement exists is compensable",
          F.reversibility(pending_eth) == "compensable")

    confirming = F.OnChainAction(chain="bitcoin", confirmations=2, signed=True)
    check("below finality depth is compensable", F.reversibility(confirming) == "compensable")
    final = F.OnChainAction(chain="bitcoin", confirmations=6, signed=True)
    check("at finality depth it is irreversible", F.reversibility(final) == "irreversible")

    ttl = F.time_to_irreversibility(confirming)
    check("time to irreversibility counts down with confirmations",
          ttl is not None and abs(ttl - 2400.0) < 1, f"{ttl}s remaining at 2 of 6")
    check("and is None once final", F.time_to_irreversibility(final) is None)

    h = F.holdback_for(draft, threshold=10_000)
    check("a large draft payment is held back", h.hold and h.can_still_stop,
          h.reason[:70])
    h2 = F.holdback_for(F.OnChainAction(chain="solana", value=5, asset="USDC"),
                        threshold=10_000)
    check("a small one is not", not h2.hold)
    h3 = F.holdback_for(pending_solana, threshold=1)
    check("a holdback after broadcast is refused rather than pretended",
          not h3.hold and not h3.can_still_stop,
          "holding something already in the mempool changes nothing")

    a = F.anchor(final)
    check("the anchor records finality convention honestly",
          "convention" in a.get("finality_note", ""),
          "bitcoin's six confirmations is not a protocol guarantee")

    print(f"\n{BOLD}threat intel{RESET}\n")

    base = ([obs("i.read", "read", "reader")] * 60
            + [obs("i.read", "read", "payer")] * 40)
    window = ([obs("i.read", "read", "reader")] * 20
              + [obs("p.wire", "write", "reader", "irreversible", False)] * 3
              + [obs("x.tool", "write", "ghost")] * 5)
    r = intel_analyse(iter(base), iter(window))
    rules = {f.rule for f in r["findings"]}

    check("a tool never seen before is flagged as drift", "privilege-drift" in rules)
    drift = next(f for f in r["findings"] if f.rule == "privilege-drift")
    check("and irreversible drift is high severity", drift.severity == "high",
          drift.summary[:70])
    check("it carries an ATLAS technique for interoperability",
          drift.atlas.startswith("AML."), drift.atlas)
    check("newly irreversible work is its own finding",
          "new-irreversible-work" in rules)
    check("an agent absent from baseline is surfaced", "unknown-agent" in rules,
          "a new agent nobody mentioned is agent sprawl arriving in person")
    check("the baseline hazard is stated in the output",
          "the compromise is the norm" in r["caveat"])

    # An agent with almost no history must not generate drift findings, or the
    # first day of any deployment is nothing but noise.
    r2 = intel_analyse(iter([obs("a.read", "read", "newbie")] * 3),
                       iter([obs("z.write", "write", "newbie")] * 5))
    check("an agent with too little baseline is excluded, not alerted on",
          "newbie" in r2["insufficient_baseline"]
          and not any(f.rule == "privilege-drift" for f in r2["findings"]))


def test_prove() -> None:
    """Static analysis of a policy."""
    global failures
    from recoup.prove import analyse

    print(f"\n{BOLD}proving policy properties{RESET}\n")

    def rule(rid, effect, **kw):
        base = {"id": rid, "effect": effect, "tools": ["*"], "actions": ["*"],
                "agents": ["*"], "require_roles": [], "reversibility": [],
                "min_risk": None, "max_risk": None, "min_threat_score": None,
                "redact_fields": [], "reason": rid}
        base.update(kw)
        return base

    def bundle(*rules, default="deny", rev=None):
        return {"schema": 1, "policy_id": "t@1", "default_effect": default,
                "reversibility": rev or {}, "reversibility_globs": [],
                "unknown_tool_reversibility": "unknown", "rules": list(rules)}

    # A correct policy: irreversible work is caught before anything allows it.
    good = bundle(
        rule("no-undo", "require_approval", reversibility=["irreversible", "unknown"]),
        rule("ok", "allow", reversibility=["reversible", "compensable"]))
    r = analyse(good)
    check("a correct policy reports no holes", not r.holes, f"{r.witnesses_checked} calls")
    check("and no unreachable rules", not r.unreachable)
    check("and the search is complete", r.complete)

    # The ordering bug: a broad allow ahead of the irreversible catch.
    bad = bundle(
        rule("reads-are-free", "allow", actions=["read"]),
        rule("no-undo", "require_approval", reversibility=["irreversible", "unknown"]))
    r = analyse(bad)
    check("an allow ahead of the irreversible catch is a hole",
          any(h["rule_id"] == "reads-are-free" for h in r.holes),
          "this is the bug the prover exists to find")
    hole = next(h for h in r.holes if h["rule_id"] == "reads-are-free")
    check("with a concrete witness, not just an assertion",
          "read" in hole["witness"] and hole["directly_reachable"],
          hole["witness"])

    # An unreachable rule: fully shadowed by a catch-all ahead of it.
    shadowed = bundle(
        rule("catch-all", "require_approval"),
        rule("never-fires", "allow", tools=["invoices.read"]))
    r = analyse(shadowed)
    check("a rule shadowed by a catch-all is reported unreachable",
          any(u["rule_id"] == "never-fires" for u in r.unreachable))
    check("naming what shadows it",
          r.unreachable[0]["shadowed_by"] == ["catch-all"])

    # A permissive default is a hole in its own right.
    r = analyse(bundle(rule("reads", "allow", actions=["read"]), default="allow"))
    check("an allow-by-default policy is flagged",
          any(h["rule_id"] == "__default__" for h in r.holes),
          "unclassified irreversible work would be permitted")

    # Explicitly blessing a rule silences it, so the exception is recorded in
    # the command rather than by weakening the check.
    r = analyse(bad, allow_irreversible=frozenset({"reads-are-free"}))
    check("an explicitly permitted rule stops being a hole", not r.holes)

    # Soundness in the right direction: an unanalysable glob must make the
    # report say so rather than quietly claim safety.
    weird = bundle(rule("odd", "allow", tools=["a*b*c"]))
    r = analyse(weird)
    check("an unsynthesisable pattern marks the search incomplete",
          not r.complete and r.incompleteness,
          r.incompleteness[0][:60] if r.incompleteness else "")
    check("and no unreachable claim is made over an incomplete search",
          not r.unreachable,
          "deleting a live control on a partial analysis is the worse error")


if __name__ == "__main__":
    sys.exit(main())
