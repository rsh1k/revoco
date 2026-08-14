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

    print(f"\n{'all checks passed' if not failures else str(failures) + ' FAILED'}\n")
    return 1 if failures else 0


if __name__ == "__main__":
    sys.exit(main())
