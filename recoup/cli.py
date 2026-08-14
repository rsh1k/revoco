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

    d = sub.add_parser("digest", help="canonical sha256 of a bundle")
    d.add_argument("bundle")
    d.set_defaults(func=cmd_digest)

    args = p.parse_args(argv)
    return args.func(args)


if __name__ == "__main__":
    sys.exit(main())
