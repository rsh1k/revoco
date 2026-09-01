# Contributing to revoco

Revoco decides whether an agent's action can be undone, and enforces policy on
the answer. That makes a wrong "yes" worse than a wrong "no", and it shapes what
review here cares about.

## Setup

```bash
uv sync --extra dev --extra yaml
uv run ruff check src tests scripts
uv run mypy src/revoco --ignore-missing-imports
uv run pytest tests -q
uv run python scripts/validate_workstation.py
```

Those are the same commands CI runs, in the same order, so a green local run
means a green CI run.

That last one drills the `workstation` inverse specs against a real filesystem
and a real `git init` repo in a temporary directory. It is safe to run anywhere
and it is the fastest way to see what this project means by evidence.

## Invariants that are load-bearing

A few things here look like ordinary code and are not. Changing them without
noticing is the main way to break revoco quietly.

**A drill reads state three times, not two.** Before the forward action, after
it, and after the inverse. Drop the middle read and a forward action that
silently changed nothing makes every inverse "restore" a state that never moved
— a green drill proving nothing. `FORWARD_NO_OP` exists for exactly that.

**`is_undoable` and `is_one_way` are different questions.** One asks whether an
undo path exists to execute, the other whether the action left damage nothing
can take back. They coincide for four postures and split on `IDEMPOTENT`. A risk
check that asks the structural question starts counting reads as irreversible
fan-out.

**Anything that enumerates the reversibility postures will rot.** Three separate
bugs came from code listing the classes by name instead of deriving them from
the enum: a policy allow-rule, a CLI table, and a risk predicate. Prefer
`min_reversibility` over a set, and build tables from `Reversibility` itself.

**An exemption needs a reason, and a residue needs naming.** `StateEquivalence`
is the one knob that can tune any comparison until it passes, so every exempt
field carries prose justifying it. Same reason `COMPENSABLE` refuses to be
constructed without a `residue`. An unexplained exclusion is an unowned risk.

**Reversibility expires.** A proof has a freshness window and lapses back to
irreversible. Anything that makes a claim permanent has broken the thesis.

## Inverse specifications

`src/revoco/adapters/` holds per-system inverse specs. One surface — `workstation`
— is validated against real systems. The rest are **written from vendor
documentation and have never been executed against a live tenant**, which is
stated plainly in [docs/ADAPTERS.md](docs/ADAPTERS.md).

If you have access to a real SAP, Workday, Salesforce, Entra or AWS tenant and
are willing to drill a surface against it, that is the single most valuable
contribution available. It needs a `StateEquivalence` for the surface — a
declared relation saying which differences do not count and why — written
*before* the drill, not after seeing what fails.

Please do not add equivalence relations reasoned out from documentation. A wrong
inverse spec produces a confident wrong rollback; a wrong exemption produces a
drill that cannot fail, which is worse.

## Pull requests

- One concern per PR. Tests with the change, not after it.
- A test should fail if you revert the change. Several bugs here were found by
  tests that passed without exercising anything.
- Prose in this codebase carries reasoning, not decoration. If you change
  behaviour a comment explains, change the comment.
- Say what you did not do and why. A stated gap is worth more than a silent one.

## Reporting security issues

See [SECURITY.md](SECURITY.md). Do not open a public issue for anything
exploitable.
