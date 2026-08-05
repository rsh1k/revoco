"""
praetor.cli
===========
Command-line surface, aimed at the two people who need answers without writing
Python: the engineer checking a policy before it ships, and the auditor asking
what this thing can actually prove.

Commands::

    praetor policy-check   <file>          validate a policy document
    praetor inverses-check <file>          validate an inverse-operation registry
    praetor coverage       <file> --tools  rollback readiness for a tool surface
    praetor controls                       print the control mapping
    praetor demo                           run the end-to-end AP scenario
"""

from __future__ import annotations

import argparse
import json
import sys
from typing import Any

from .core.errors import PolicyError
from .evidence import CONTROL_MAP
from .gate.policy import load_policy
from .reversal.model import Reversibility
from .reversal.registry import InverseRegistry


def _cmd_policy_check(args: argparse.Namespace) -> int:
    try:
        policy = load_policy(args.file)
    except PolicyError as exc:
        print(f"INVALID: {exc}", file=sys.stderr)
        return 1
    print(f"OK: '{policy.name}' v{policy.version}")
    print(f"  rules:          {len(policy.rules)}")
    print(f"  default effect: {policy.default_effect.value}")
    print(f"  digest:         {policy.digest()}")
    if policy.default_effect.value == "allow":
        print(
            "\nWARNING: default_effect is 'allow'. Any call not matched by a rule will be "
            "permitted. A locked-down posture uses 'deny' and allows explicitly.",
            file=sys.stderr,
        )
    rev_rules = [r for r in policy.rules if r.reversibility]
    if not rev_rules:
        print(
            "\nNOTE: no rule matches on reversibility. Consider adding one so actions with "
            "no rollback path escalate to a human:\n"
            "  - id: no-undo-needs-a-human\n"
            "    effect: require_approval\n"
            "    reversibility: [irreversible, unknown]"
        )
    return 0


def _cmd_inverses_check(args: argparse.Namespace) -> int:
    try:
        registry = InverseRegistry.load(args.file)
    except PolicyError as exc:
        print(f"INVALID: {exc}", file=sys.stderr)
        return 1
    specs = registry.all()
    print(f"OK: {len(specs)} inverse specs")
    for kind in Reversibility:
        matching = [s.tool for s in specs if s.kind is kind]
        if matching:
            print(f"  {kind.value:14s} {', '.join(sorted(matching))}")

    sequenced = [s for s in specs if len(s.effective_steps) > 1]
    if sequenced:
        print("\nSequenced undos (order is load-bearing):")
        for s in sorted(sequenced, key=lambda x: x.tool):
            chain = " -> ".join(st.tool for st in s.effective_steps)
            print(f"  {s.tool}\n      {chain}")

    one_shot = sorted(s.tool for s in specs if s.one_shot)
    if one_shot:
        print("\nOne-shot undos (cannot be retried; a wrong firing is unrecoverable):")
        for t in one_shot:
            print(f"  {t}")

    # The gate list is the integrator's to-do list: every name here needs a
    # branch in their GateEvaluator, and an unhandled gate fails closed.
    gates: dict[str, str] = {}
    for s in specs:
        for g in s.gates:
            gates[g.name] = g.description
    if gates:
        print("\nGates your GateEvaluator must answer (unhandled ones fail closed):")
        for name, desc in sorted(gates.items()):
            print(f"  {name}\n      {desc}")

    problems = 0
    missing_residue = [
        s.tool for s in specs if s.kind is Reversibility.COMPENSABLE and not s.residue
    ]
    if missing_residue:
        print(f"\nWARNING: compensable specs with no residue named: {missing_residue}")
        problems += 1

    # A spec that reads snapshot.X without declaring X in snapshot_fields will
    # never have X captured, so the undo silently restores nothing. This is the
    # single easiest way to author a phantom rollback, so it is checked here
    # rather than discovered during an incident.
    for s in specs:
        referenced = {
            expr.split(".", 1)[1].split(".")[0]
            for st in s.effective_steps
            for _name, expr in st.arg_map
            if expr.startswith("snapshot.")
        }
        undeclared = sorted(referenced - set(s.snapshot_fields))
        if undeclared:
            print(
                f"\nWARNING: {s.tool} reads snapshot.{{{','.join(undeclared)}}} but does not "
                "declare those in snapshot_fields — they will never be captured, so the "
                "undo would restore nothing for them"
            )
            problems += 1
    return 1 if problems else 0


def _cmd_coverage(args: argparse.Namespace) -> int:
    registry = InverseRegistry.load(args.file)
    tools = [t.strip() for t in args.tools.split(",") if t.strip()]
    report = registry.coverage(tools)
    print(json.dumps(report, indent=2))
    unknown = report["by_kind"][Reversibility.UNKNOWN.value]
    if unknown:
        print(
            f"\n{len(unknown)} of {len(tools)} tools have no declared inverse. Under the "
            "starter policy these escalate to human approval.",
            file=sys.stderr,
        )
        return 1
    return 0


def _cmd_controls(args: argparse.Namespace) -> int:
    if args.json:
        print(json.dumps(CONTROL_MAP, indent=2))
        return 0
    for framework, clauses in CONTROL_MAP.items():
        print(f"\n{framework}")
        print("-" * len(framework))
        for clause, evidence in clauses.items():
            print(f"  {clause}")
            print(f"      {evidence}")
    print(
        "\nThese mappings indicate which requirement a piece of technical evidence speaks "
        "to. They are a self-assessment aid, not a certification."
    )
    return 0


def _cmd_surfaces(args: argparse.Namespace) -> int:
    from .adapters import SURFACES, all_specs, gate_catalog, summary

    if args.json:
        print(json.dumps({"summary": summary(), "gates": gate_catalog()}, indent=2))
        return 0

    s = summary()
    print(f"{s['specs']} inverse specs across {len(SURFACES)} surfaces\n")
    print(f"  {'surface':14s} {'specs':>5s}  {'rev':>4s} {'comp':>4s} {'irr':>4s} {'unk':>4s}")
    for name in SURFACES:
        specs = all_specs(name)
        counts = {k.value: 0 for k in Reversibility}
        for sp in specs:
            counts[sp.kind.value] += 1
        print(
            f"  {name:14s} {len(specs):5d}  "
            f"{counts['reversible']:4d} {counts['compensable']:4d} "
            f"{counts['irreversible']:4d} {counts['unknown']:4d}"
        )
    print()
    print(f"  sequenced undos (>1 step)          {s['sequenced']}")
    print(f"  one-shot undos                     {s['one_shot']}")
    print(f"  gated specs                        {s['gated']}")
    print(f"  recoverable ONLY via snapshot      {s['snapshot_dependent']}")
    print(f"  may degrade for a given target     {s['degradable']}")
    print(f"  distinct gates to implement        {s['gates']}")
    print()
    print(
        "  'recoverable ONLY via snapshot' is the share of the undo surface this\n"
        "  control plane creates rather than merely records — those operations have\n"
        "  no native undo. 'may degrade' is the share whose recoverability depends on\n"
        "  the target's configuration, so an unchecked authorize-phase gate there is a\n"
        "  phantom rollback waiting to happen."
    )

    if args.gates:
        cat = gate_catalog(*(args.surface or ()))
        print(f"\nGates to implement in your GateEvaluator ({len(cat)}):\n")
        for name, info in sorted(cat.items(), key=lambda kv: (kv[1]["phase"], kv[0])):
            print(f"  [{info['phase']:9s}] {name}  ({info['surface']})")
            print(f"      {info['description']}")
            if info["remediation"]:
                print(f"      fix: {info['remediation']}")
    return 0


def _cmd_demo(args: argparse.Namespace) -> int:
    from .demo import run_demo

    run_demo()
    return 0


def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        prog="praetor",
        description="Action control plane for AI agents: authority, enforcement, reversibility, evidence.",
    )
    sub = p.add_subparsers(dest="command", required=True)

    pc = sub.add_parser("policy-check", help="validate a policy document")
    pc.add_argument("file")
    pc.set_defaults(func=_cmd_policy_check)

    ic = sub.add_parser("inverses-check", help="validate an inverse-operation registry")
    ic.add_argument("file")
    ic.set_defaults(func=_cmd_inverses_check)

    cv = sub.add_parser("coverage", help="rollback readiness for a tool surface")
    cv.add_argument("file", help="inverse registry file")
    cv.add_argument("--tools", required=True, help="comma-separated tool names")
    cv.set_defaults(func=_cmd_coverage)

    sf = sub.add_parser("surfaces", help="what the bundled adapters cover")
    sf.add_argument("--gates", action="store_true", help="list every gate to implement")
    sf.add_argument("--surface", action="append", help="restrict --gates to a surface")
    sf.add_argument("--json", action="store_true")
    sf.set_defaults(func=_cmd_surfaces)

    ct = sub.add_parser("controls", help="print the control mapping")
    ct.add_argument("--json", action="store_true")
    ct.set_defaults(func=_cmd_controls)

    dm = sub.add_parser("demo", help="run the end-to-end accounts-payable scenario")
    dm.set_defaults(func=_cmd_demo)

    return p


def main(argv: list[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)
    fn: Any = args.func
    return int(fn(args) or 0)


if __name__ == "__main__":  # pragma: no cover
    raise SystemExit(main())
