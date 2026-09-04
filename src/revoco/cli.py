"""
revoco.cli
===========
Command-line surface, aimed at the two people who need answers without writing
Python: the engineer checking a policy before it ships, and the auditor asking
what this thing can actually prove.

Commands::

    revoco policy-check   <file>          validate a policy document
    revoco inverses-check <file>          validate an inverse-operation registry
    revoco coverage       <file> --tools  rollback readiness for a tool surface
    revoco controls                       print the control mapping
    revoco demo                           run the end-to-end AP scenario
"""

from __future__ import annotations

import argparse
import json
import sys
from typing import Any

from .core.errors import PolicyError, RevocoError
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


# Below this many attack samples, a "noisy pattern" verdict reflects which attacks
# happen to be in the corpus rather than a property of the pattern.
GATE_MIN_ATTACKS = 30


def _cmd_calibrate(args: argparse.Namespace) -> int:
    from .gate.calibrate import compare_splits, corpus_samples, evaluate, render

    samples = corpus_samples(
        include_external=not args.no_external, content_only=not args.all_attacks
    )
    if not samples:
        print("no samples", file=sys.stderr)
        return 2
    cal = evaluate(samples)
    splits = compare_splits(samples)
    if args.json:
        print(json.dumps({"calibration": cal.to_dict(), "splits": splits}, indent=2))
    else:
        print(render(cal, splits=splits))
    # Non-zero on a weighted pattern that favours benign traffic — but only when there
    # are enough attack samples for that verdict to be evidence.
    #
    # CI taught this within minutes of the gate being switched on. Without an ATBench
    # snapshot the corpus holds three content attacks, none containing `../`, while a
    # benign scenario deliberately does — so `dot-dot-slash` read as noisy and failed
    # the build. The gate was measuring corpus size, not a defect. Same discipline as
    # compare_splits refusing to report an inflation figure from a fold with no
    # positives: below the threshold, report and do not fail.
    if cal.noisy and cal.n_malicious < GATE_MIN_ATTACKS:
        print(
            f"\nnote: {len(cal.noisy)} pattern(s) look noisy, but {cal.n_malicious} "
            f"attack sample(s) is below the {GATE_MIN_ATTACKS} needed for that to be "
            "evidence — not failing. Point ATBENCH_PATH at a snapshot to enforce it.",
            file=sys.stderr,
        )
        return 0
    return 1 if cal.noisy else 0


def _cmd_bench(args: argparse.Namespace) -> int:
    from .bench import Harness, all_scenarios, benign, malicious, render, to_dict

    if args.malicious_only:
        scenarios = malicious()
    elif args.benign_only:
        scenarios = benign()
    else:
        scenarios = all_scenarios()
    if args.technique:
        scenarios = [s for s in scenarios if s.technique in set(args.technique)]
    if not scenarios:
        print("no scenarios matched", file=sys.stderr)
        return 2

    if args.external:
        from .bench.external import provenance, ras_eval_scenarios

        prov = provenance()
        extra = ras_eval_scenarios()
        if not extra:
            print(f"no external scenarios: {prov.get('note','')}", file=sys.stderr)
        scenarios = scenarios + extra

    results = Harness().run_all(scenarios)
    if args.json:
        print(json.dumps(to_dict(results, include_scenarios=args.verbose), indent=2))
    else:
        print(render(results, verbose=args.verbose))

    # Exit non-zero on an *unexpected* loss or any false positive, so this can gate
    # CI. A scenario whose designed outcome is loss does not fail the build; a
    # regression that starts losing something new does.
    from .bench.scenario import Outcome

    bad = [
        r for r in results
        if r.outcome in (Outcome.UNCONTAINED, Outcome.FALSE_POSITIVE, Outcome.ERROR)
        and r.scenario.expect_outcome is not r.outcome
    ]
    return 1 if bad else 0


# Column labels for the posture table. Anything not named here still gets a column
# from its own value, because a hard-coded set of columns is how a posture added to
# the taxonomy silently stops being counted and the rows quietly stop adding up.
_POSTURE_ABBR = {
    Reversibility.IDEMPOTENT: "idem",
    Reversibility.REVERSIBLE: "rev",
    Reversibility.COMPENSABLE: "comp",
    Reversibility.IRREVERSIBLE: "irr",
    Reversibility.UNKNOWN: "unk",
}


def _cmd_surfaces(args: argparse.Namespace) -> int:
    from .adapters import EQUIVALENCES, SURFACES, all_specs, gate_catalog, summary

    if args.json:
        print(json.dumps({
            "summary": summary(),
            "gates": gate_catalog(),
            "equivalences": {
                name: (
                    {
                        "name": eq.name,
                        "exempt": [
                            {"field": e.field, "reason": e.reason} for e in eq.exempt
                        ],
                    }
                    if eq else None
                )
                for name, eq in EQUIVALENCES.items()
            },
        }, indent=2))
        return 0

    s = summary()
    postures = sorted(Reversibility, key=lambda k: -k.rank)
    head = "".join(f"{_POSTURE_ABBR.get(k, k.value[:4]):>5s}" for k in postures)
    print(f"{s['specs']} inverse specs across {len(SURFACES)} surfaces\n")
    print(f"  {'surface':14s} {'specs':>5s} {head}  {'equivalence':>11s}")
    for name in SURFACES:
        specs = all_specs(name)
        counts = {k: 0 for k in Reversibility}
        for sp in specs:
            counts[sp.kind] += 1
        row = "".join(f"{counts[k]:5d}" for k in postures)
        eq = EQUIVALENCES.get(name)
        print(
            f"  {name:14s} {len(specs):5d} {row}  "
            f"{(eq.name if eq else '—'):>11s}"
        )
    print()
    print(f"  sequenced undos (>1 step)          {s['sequenced']}")
    print(f"  one-shot undos                     {s['one_shot']}")
    print(f"  gated specs                        {s['gated']}")
    print(f"  recoverable ONLY via snapshot      {s['snapshot_dependent']}")
    print(f"  may degrade for a given target     {s['degradable']}")
    print(f"  distinct gates to implement        {s['gates']}")
    declared = [n for n, eq in EQUIVALENCES.items() if eq is not None]
    print(f"  surfaces with a declared equivalence {len(declared)}/{len(SURFACES)}")
    print()
    print(
        "  'recoverable ONLY via snapshot' is the share of the undo surface this\n"
        "  control plane creates rather than merely records — those operations have\n"
        "  no native undo. 'may degrade' is the share whose recoverability depends on\n"
        "  the target's configuration, so an unchecked authorize-phase gate there is a\n"
        "  phantom rollback waiting to happen."
    )

    if len(declared) < len(SURFACES):
        print()
        missing = [n for n in SURFACES if EQUIVALENCES.get(n) is None]
        print(
            "  No equivalence relation is declared for: "
            + ", ".join(missing)
            + ".\n"
            "  Until one exists a drill on those surfaces requires every reported\n"
            "  field to match exactly, which no real system survives — so whoever\n"
            "  runs the first drill decides at the call site what 'restored' means,\n"
            "  and the result cannot be argued with afterwards. Write the relation\n"
            "  before the drill, not after seeing what fails."
        )

    if args.equivalence:
        print("\nDeclared state-equivalence relations:\n")
        for name in args.surface or SURFACES:
            eq = EQUIVALENCES.get(name)
            if eq is None:
                print(f"  {name}: none declared")
                continue
            for line in eq.describe().splitlines():
                print(f"  {line}")
            print()

    if args.gates:
        cat = gate_catalog(*(args.surface or ()))
        print(f"\nGates to implement in your GateEvaluator ({len(cat)}):\n")
        for name, info in sorted(cat.items(), key=lambda kv: (kv[1]["phase"], kv[0])):
            print(f"  [{info['phase']:9s}] {name}  ({info['surface']})")
            print(f"      {info['description']}")
            if info["remediation"]:
                print(f"      fix: {info['remediation']}")
    return 0


def _cmd_validation_report(args: argparse.Namespace) -> int:
    """Compare a validation run against a baseline and report what moved."""
    from pathlib import Path

    from .core import crypto
    from .validation import ValidationRun, render, report

    def _load(path: str) -> ValidationRun:
        return ValidationRun.from_dict(json.loads(Path(path).read_text()))

    # Three outcomes, not two. A scheduler that cannot tell "a control regressed"
    # from "the comparison never happened" reads a broken runner as a healthy
    # estate the moment someone stops reading the log — which is the same
    # absence-looking-like-success this whole module exists to refuse.
    try:
        current = _load(args.run)
        previous = _load(args.previous) if args.previous else None
    except (RevocoError, OSError, json.JSONDecodeError) as exc:
        print(f"cannot compare: {exc}", file=sys.stderr)
        return 2

    if args.signing_key:
        signer_key = crypto.private_key_from_b64(
            Path(args.signing_key).read_text().strip())
        signer_id = args.signer or "unnamed-signer"
    else:
        # An ephemeral key would produce a signature nobody can check against a
        # known signer, which is decoration rather than evidence. Say it is
        # unsigned instead.
        signer_key, _ = crypto.generate_keypair()
        signer_id = "UNSIGNED"

    try:
        rep = report(current, previous=previous,
                     signer_private_key=signer_key, signer_id=signer_id)
    except RevocoError as exc:
        print(f"cannot compare: {exc}", file=sys.stderr)
        return 2

    if args.json:
        print(json.dumps(rep.to_dict(), indent=2, sort_keys=True))
    else:
        print(render(rep))
        if signer_id == "UNSIGNED":
            print("\nNOT SIGNED — pass --signing-key to produce evidence a third "
                  "party can verify.")

    # 0 nothing got worse · 1 something did · 2 the check could not be made.
    # A standing failure that has not moved is not a new incident and does not
    # fail the run.
    return 1 if not rep.clean else 0


def _cmd_demo(args: argparse.Namespace) -> int:
    from .demo import run_demo

    run_demo()
    return 0


def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        prog="revoco",
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

    bn = sub.add_parser("bench", help="run the containment benchmark")
    bn.add_argument("--verbose", "-v", action="store_true", help="per-step detail")
    bn.add_argument("--json", action="store_true")
    bn.add_argument("--technique", action="append", help="restrict to technique code(s)")
    bn.add_argument("--external", action="store_true",
                    help="also include benign scenarios imported from a RAS-Eval clone "
                         "(set RAS_EVAL_PATH; nothing is vendored)")
    bn.add_argument("--malicious-only", action="store_true")
    bn.add_argument("--benign-only", action="store_true")
    bn.set_defaults(func=_cmd_bench)

    cb = sub.add_parser("calibrate", help="measure the threat scanner against the corpus")
    cb.add_argument("--json", action="store_true")
    cb.add_argument("--no-external", action="store_true",
                    help="exclude imported RAS-Eval traffic")
    cb.add_argument("--all-attacks", action="store_true",
                    help="include semantic attacks, which a content scanner cannot see "
                         "and which make the numbers meaningless")
    cb.set_defaults(func=_cmd_calibrate)

    sf = sub.add_parser("surfaces", help="what the bundled adapters cover")
    sf.add_argument("--gates", action="store_true", help="list every gate to implement")
    sf.add_argument("--equivalence", action="store_true",
                    help="print each surface's declared state-equivalence relation")
    sf.add_argument("--surface", action="append", help="restrict --gates to a surface")
    sf.add_argument("--json", action="store_true")
    sf.set_defaults(func=_cmd_surfaces)

    vr = sub.add_parser(
        "validation-report",
        help="compare a validation run against a baseline and report what moved")
    vr.add_argument("run", help="the run to report on (JSON)")
    vr.add_argument("--previous", metavar="PATH",
                    help="the baseline to compare against; without one this is a "
                         "baseline and cannot show a regression")
    vr.add_argument("--signing-key", metavar="PATH",
                    help="base64 Ed25519 private key; unsigned without it")
    vr.add_argument("--signer", metavar="ID", help="who the signature belongs to")
    vr.add_argument("--json", action="store_true")
    vr.set_defaults(func=_cmd_validation_report)

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
