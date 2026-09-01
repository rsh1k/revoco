"""The control-plane side of the boundary: turn a policy into a bundle.

This is the command that actually connects the two halves. A policy is authored
and tested in Python, where the corpus and the drills live; `recoup compile`
turns it into the portable document the Go enforcer loads. Nothing else crosses.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import sys
from pathlib import Path

from .bundle import BundleError, compile_bundle, dumps


def _load_registry(name: str):
    from revoco.reversal import InverseRegistry, ap_starter_registry

    if name == "ap-starter":
        return ap_starter_registry()
    if name == "empty":
        return InverseRegistry()
    path = Path(name)
    if not path.is_file():
        raise SystemExit(
            f"--registry {name!r} is neither a known preset (ap-starter, empty) "
            f"nor a readable file")
    reg = InverseRegistry()
    reg.load(json.loads(path.read_text(encoding="utf-8")))
    return reg


def cmd_compile(args: argparse.Namespace) -> int:
    from revoco.gate import load_policy

    raw = json.loads(Path(args.policy).read_text(encoding="utf-8"))
    policy = load_policy(raw)
    registry = _load_registry(args.registry)

    try:
        bundle = compile_bundle(policy, registry)
    except BundleError as exc:
        # Refusing beats emitting a bundle that means something weaker than the
        # policy it came from.
        print(f"cannot compile: {exc}", file=sys.stderr)
        return 1

    body = dumps(bundle)
    digest = hashlib.sha256(body.encode("utf-8")).hexdigest()

    if args.out:
        Path(args.out).write_text(json.dumps(bundle, indent=2, sort_keys=True) + "\n",
                                  encoding="utf-8")
        print(f"wrote {args.out}")
        print(f"  policy      {bundle['policy_id']}")
        print(f"  rules       {len(bundle['rules'])}")
        print(f"  tools known {len(bundle['reversibility'])} exact, "
              f"{len(bundle['reversibility_globs'])} glob")
        # The digest is what ties a verdict in the ledger back to the exact
        # policy that produced it. Print it so it can be recorded at deploy time.
        print(f"  sha256      {digest[:16]}")
    else:
        print(body)
    return 0


def cmd_digest(args: argparse.Namespace) -> int:
    bundle = json.loads(Path(args.bundle).read_text(encoding="utf-8"))
    print(hashlib.sha256(dumps(bundle).encode("utf-8")).hexdigest())
    return 0


def _fmt_pct(x: float) -> str:
    return f"{x:.2f}%"


def cmd_inventory(args: argparse.Namespace) -> int:
    from .analyse import inventory, read

    inv = inventory(read(args.journal))
    if args.json:
        print(json.dumps(inv, indent=2))
        return 0

    print(f"{inv['calls']:,} decisions | {len(inv['agents'])} agent(s) | "
          f"{len(inv['tools'])} tool(s)\n")
    print(f"  {'agent':<22} {'calls':>8} {'tools':>6} {'irreversible':>13}  top tools")
    print(f"  {'-'*22} {'-'*8} {'-'*6} {'-'*13}  {'-'*36}")
    for a in inv["agents"]:
        top = ", ".join(f"{t}" for t, _ in a["top_tools"][:3])
        print(f"  {(a['agent_id'] or '(unattributed)'):<22} {a['calls']:>8,} "
              f"{a['tools']:>6} {_fmt_pct(a['irreversible_share']*100):>13}  {top[:36]}")
    if inv["irreversible_tools"]:
        print(f"\n  no undo exists for: {', '.join(inv['irreversible_tools'])}")
    return 0


def cmd_suggest(args: argparse.Namespace) -> int:
    from .analyse import read, suggest

    out = suggest(read(args.journal), name=args.name)
    if args.out:
        Path(args.out).write_text(json.dumps(out["policy"], indent=2) + "\n",
                                  encoding="utf-8")
        print(f"wrote {args.out}")
    else:
        print(json.dumps(out["policy"], indent=2))

    ev = out["evidence"]
    print(f"\nfrom {ev['observations']:,} observations across {ev['agents']} agent(s)",
          file=sys.stderr)
    for n in out["notes"]:
        print(f"  · {n}", file=sys.stderr)
    print(f"\n{out['warning']}", file=sys.stderr)
    return 0


def cmd_simulate(args: argparse.Namespace) -> int:
    from .analyse import read, simulate

    bundle = json.loads(Path(args.bundle).read_text(encoding="utf-8"))
    r = simulate(read(args.journal), bundle)
    if args.json:
        print(json.dumps(r, indent=2))
        return 0

    print(f"replayed {r['observations']:,} recorded decisions against "
          f"{bundle.get('policy_id', args.bundle)}\n")
    print(f"  unchanged        {r['unchanged']:>9,}")
    print(f"  newly blocked    {r['newly_blocked_calls']:>9,}   "
          f"({_fmt_pct(r['would_break_pct'])} of traffic)")
    print(f"  newly allowed    {r['newly_allowed_calls']:>9,}")

    if r["newly_blocked"]:
        print(f"\n  would start blocking:")
        for c in r["newly_blocked"][:15]:
            print(f"    {c['calls']:>7,}  {c['tool']}/{c['action']} "
                  f"[{c['agent_id'] or '*'}]  {c['was']} -> {c['now']}")
    if r["newly_allowed"]:
        print(f"\n  would start allowing:")
        for c in r["newly_allowed"][:15]:
            print(f"    {c['calls']:>7,}  {c['tool']}/{c['action']} "
                  f"[{c['agent_id'] or '*'}]  {c['was']} -> {c['now']}")
    # A simulation that reports zero change is usually a mistake in the inputs
    # rather than a perfect policy, so say so instead of looking like success.
    if not r["newly_blocked"] and not r["newly_allowed"]:
        print("\n  nothing changes. Check the journal and the bundle are the pair "
              "you meant — identical verdicts across real traffic is unusual.")
    return 0


def cmd_depends(args: argparse.Namespace) -> int:
    from .analyse import dependencies, read

    d = dependencies(read(args.journal))
    if args.json:
        print(json.dumps(d, indent=2))
        return 0
    print(f"{len(d['tools'])} tool(s) across {len(d['agents'])} agent(s)\n")
    print(f"  {'tool':<24} {'agents':>7} {'calls':>8}  depends")
    print(f"  {'-'*24} {'-'*7} {'-'*8}  {'-'*40}")
    for t in d["tools"]:
        flag = " !" if t["reversibility"] in ("irreversible", "unknown") else "  "
        print(f"  {t['tool']:<24} {t['agent_count']:>7} {t['calls']:>8,}{flag}"
              f"{', '.join(t['agents'])[:40]}")
    if d["shared_tools"]:
        print(f"\n  removing any of these breaks more than one agent: "
              f"{', '.join(d['shared_tools'])}")
    print("  ! = nothing can undo this")
    return 0


def cmd_exposure(args: argparse.Namespace) -> int:
    from .analyse import consequence_budget, read

    b = consequence_budget(read(args.journal))
    if args.json:
        print(json.dumps(b, indent=2))
        return 0
    print(f"consequence weights: {b['weights']}")
    print(f"total exposure: {b['total_consequence']:,}\n")
    print(f"  {'agent':<22} {'calls':>8} {'exposure':>9} {'share':>7} {'no undo':>8}  concentrated in")
    print(f"  {'-'*22} {'-'*8} {'-'*9} {'-'*7} {'-'*8}  {'-'*28}")
    for a in b["agents"]:
        top = ", ".join(f"{t}" for t, _ in a["top_by_consequence"][:2])
        print(f"  {(a['agent_id'] or '(none)'):<22} {a['calls']:>8,} "
              f"{a['consequence']:>9,} {a['share_pct']:>6.1f}% "
              f"{a['irreversible_calls']:>8,}  {top[:28]}")
    print("\n  Exposure counts calls weighted by how hard they are to take back, "
          "not money.")
    return 0


def cmd_intel(args: argparse.Namespace) -> int:
    from .analyse import read
    from .intel import analyse as intel_analyse, summarise

    rows = list(read(args.journal))
    if not rows:
        print("journal is empty", file=sys.stderr)
        return 1
    # Split by position rather than by clock: journals are appended in order, and
    # a caller who knows the estate changed on a date can pass --split instead.
    cut = args.split if args.split is not None else int(len(rows) * args.baseline)
    cut = max(1, min(cut, len(rows) - 1))
    r = intel_analyse(iter(rows[:cut]), iter(rows[cut:]))

    if args.json:
        print(json.dumps({
            "findings": [f.__dict__ for f in r["findings"]],
            "baseline_calls": r["baseline_calls"],
            "window_calls": r["window_calls"],
            "insufficient_baseline": r["insufficient_baseline"],
            "caveat": r["caveat"]}, indent=2))
        return 0

    print(f"baseline {r['baseline_calls']:,} calls | window {r['window_calls']:,} calls")
    print(f"{summarise(r)}\n")
    for f in r["findings"]:
        print(f"  {f}")
        for k, v in f.evidence.items():
            print(f"        {k}: {v}")
    if r["insufficient_baseline"]:
        print(f"\n  too little baseline to judge: {', '.join(r['insufficient_baseline'])}")
    print(f"\n  {r['caveat']}")
    return 0


def cmd_finality(args: argparse.Namespace) -> int:
    from .finality import CHAINS, OnChainAction, describe, holdback_for

    if args.chain not in CHAINS:
        print(f"unknown chain {args.chain!r}; known: {', '.join(sorted(CHAINS))}",
              file=sys.stderr)
        return 2
    a = OnChainAction(chain=args.chain, confirmations=args.confirmations,
                      signed=args.confirmations >= 0 or args.signed,
                      value=args.value, asset=args.asset)
    print(describe(a))
    h = holdback_for(a, threshold=args.threshold, window_seconds=args.window)
    verb = "HOLD" if h.hold else "proceed"
    print(f"  {verb}: {h.reason}")
    if h.hold:
        print(f"  challenge window {h.seconds:,.0f}s — a second party can still veto")
    elif not h.can_still_stop:
        print("  nothing can stop this now")
    ch = CHAINS[args.chain]
    if not ch.absolute:
        print(f"\n  note: {ch.note}")
    return 0


def cmd_prove(args: argparse.Namespace) -> int:
    from .prove import analyse, render

    bundle = json.loads(Path(args.bundle).read_text(encoding="utf-8"))
    r = analyse(bundle, allow_irreversible=frozenset(args.allow_irreversible or ()))
    print(f"{bundle.get('policy_id', args.bundle)}\n")
    print(render(r))
    # Non-zero on a hole so this can gate a deploy. Unreachable rules are a
    # correctness smell rather than a danger, so they do not fail the build
    # unless asked.
    if r.holes:
        return 1
    if args.strict and (r.unreachable or not r.complete):
        return 1
    return 0


def main(argv: list[str] | None = None) -> int:
    p = argparse.ArgumentParser(
        prog="recoup",
        description="Compile agent policy for the recoup enforcer.")
    sub = p.add_subparsers(dest="cmd", required=True)

    c = sub.add_parser("compile", help="policy JSON -> enforcer bundle")
    c.add_argument("policy", help="path to a revoco policy document")
    c.add_argument("-o", "--out", help="write here instead of stdout")
    c.add_argument("--registry", default="ap-starter",
                   help="inverse registry: ap-starter, empty, or a JSON file")
    c.set_defaults(func=cmd_compile)

    i = sub.add_parser("inventory", help="what the agents actually do")
    i.add_argument("journal", help="path to an enforcer journal")
    i.add_argument("--json", action="store_true")
    i.set_defaults(func=cmd_inventory)

    g = sub.add_parser("suggest", help="draft the tightest policy that fits observed traffic")
    g.add_argument("journal")
    g.add_argument("-o", "--out")
    g.add_argument("--name", default="suggested")
    g.set_defaults(func=cmd_suggest)

    m = sub.add_parser("simulate", help="replay traffic against a candidate bundle")
    m.add_argument("journal")
    m.add_argument("bundle")
    m.add_argument("--json", action="store_true")
    m.set_defaults(func=cmd_simulate)

    dp = sub.add_parser("depends", help="which agents depend on which tools")
    dp.add_argument("journal")
    dp.add_argument("--json", action="store_true")
    dp.set_defaults(func=cmd_depends)

    e = sub.add_parser("exposure", help="per-agent exposure weighted by reversibility")
    e.add_argument("journal")
    e.add_argument("--json", action="store_true")
    e.set_defaults(func=cmd_exposure)

    it = sub.add_parser("intel", help="behavioural findings against a baseline")
    it.add_argument("journal")
    it.add_argument("--baseline", type=float, default=0.7,
                    help="fraction of the journal treated as baseline (default 0.7)")
    it.add_argument("--split", type=int, default=None,
                    help="split at this entry instead of a fraction")
    it.add_argument("--json", action="store_true")
    it.set_defaults(func=cmd_intel)

    fn = sub.add_parser("finality", help="how reversible an on-chain action is right now")
    fn.add_argument("chain")
    fn.add_argument("--confirmations", type=int, default=-1,
                    help="-1 for not yet broadcast")
    fn.add_argument("--signed", action="store_true")
    fn.add_argument("--value", type=float, default=0.0)
    fn.add_argument("--asset", default="")
    fn.add_argument("--threshold", type=float, default=10_000.0)
    fn.add_argument("--window", type=float, default=300.0)
    fn.set_defaults(func=cmd_finality)

    pv = sub.add_parser("prove", help="prove properties about a compiled policy")
    pv.add_argument("bundle")
    pv.add_argument("--allow-irreversible", nargs="*", metavar="RULE_ID",
                    help="rule ids permitted to allow work nothing can undo")
    pv.add_argument("--strict", action="store_true",
                    help="also fail on unreachable rules or an incomplete search")
    pv.set_defaults(func=cmd_prove)

    d = sub.add_parser("digest", help="canonical sha256 of a bundle")
    d.add_argument("bundle")
    d.set_defaults(func=cmd_digest)

    args = p.parse_args(argv)
    return args.func(args)


if __name__ == "__main__":
    sys.exit(main())
