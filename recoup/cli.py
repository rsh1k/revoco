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

    d = sub.add_parser("digest", help="canonical sha256 of a bundle")
    d.add_argument("bundle")
    d.set_defaults(func=cmd_digest)

    args = p.parse_args(argv)
    return args.func(args)


if __name__ == "__main__":
    sys.exit(main())
