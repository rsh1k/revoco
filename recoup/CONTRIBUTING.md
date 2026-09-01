# Contributing

Read this before the code. Most of what's here is ordinary, but a handful of
decisions are load-bearing in ways that aren't obvious from reading a single
file, and undoing one by accident is easy.

## Get set up

```bash
python3 -m venv .venv && .venv/bin/pip install -e .
make all          # fmt, vet, both test suites, mutation check
```

Go lives in `~/.local/go/bin/go` on the original dev machine; override with
`make GO=/path/to/go`. CI uses whatever `setup-go` provides.

## The invariants

These aren't style preferences. Breaking one produces a system that looks like
it works.

**1. Go and Python must agree, exactly.**

Two implementations of one decision will drift, and a gate that says *allow* in
Go and *require approval* in Python is worse than no gate — the record it leaves
can't be trusted either way.

`conformance/fixtures/` holds verdicts revoco's engine actually produced. Both
runtimes reproduce every one, enforced in CI. If you change decision logic in
either language, `make conform` fails until they agree again. That's the system
working.

**2. The fixtures must be able to fail.**

A green conformance suite proves nothing on its own. The first version passed
8,316 cases with a `<` changed to `<=` in the Go evaluator, because the
hand-picked risk values never landed on the policy's only threshold.

`make mutate` introduces single-character bugs on purpose and fails if any
survives. **If you add a comparison or a match condition, add a mutation for
it.** A mutation that stops applying is reported as `STALE` and counts as a
failure, so moving code without updating the anchor won't pass silently.

**3. Never regenerate fixtures to make a test pass.**

`make fixtures` exists, but it's a deliberate act. The fixtures are the oracle;
an oracle that regenerates itself whenever behaviour changes just records
whatever the code currently does. CI has a job asserting they regenerate
byte-identically, so a change here needs a human to look at the diff and say
why.

**4. Errors run in the direction that fails safe.**

Not uniformly — it depends on what's being answered:

| Question | Wrong answer to avoid | So it errs toward |
|---|---|---|
| Does this rule match? | matching when it shouldn't | not matching |
| Is this rule unreachable? | deleting a live control | staying quiet |
| Is there a hole? | a clean report that isn't | saying "incomplete" |
| Is this undo real? | claiming one that isn't | refusing the action |

When you add analysis, decide which column you're in and say so in the
docstring.

**5. Don't invent a default the other runtime has to guess.**

The bundle compiler writes every rule field explicitly, and the Go loader
rejects a rule that omits one. Relying on two languages to agree about an absent
field is the exact bug the contract exists to prevent.

**6. Refuse rather than approximate.**

A rule the schema can't express doesn't compile. Dropping the part you can't
represent produces a rule matching strictly more calls than its author wrote,
which is a silent widening of a security policy. Failing the build is the only
honest option.

## What goes where

```
cmd/recoup-enforcer   request path. Go. Fast, small, no dependencies.
cmd/recoup-verify     offline proof checker. Standard library only, on purpose.
internal/decision     the evaluator both runtimes must agree on
internal/translog     RFC 6962 Merkle log
internal/journal      append-only record of decisions
recoup/               control plane. Python. Anything needing to read the world.
conformance/          the oracle, and the mutation check that keeps it honest
```

The split isn't "Go is fast, Python is slow". The enforcer answers *which rule
matches*; the control plane decides *what the rules should be* and everything
that needs live state. If you're reaching for a filesystem or a model inside
`internal/`, it's in the wrong half.

## Things that will get a review comment

- **A model producing something that reaches the ledger.** Classifier output is
  advisory and labelled as a prediction. The forensics literature is clear that
  hallucination rates fine for triage aren't acceptable for evidence under
  adversarial challenge, and mixing the two makes the whole record challengeable.
- **Tool arguments in the journal.** That's where payment amounts and customer
  records live. The entire deployment argument is that regulated data doesn't
  leave the customer's VPC.
- **`path.Match` instead of the `FnMatch` in `internal/decision`.** Go's `*`
  stops at `/`; policies are authored against Python's `fnmatch`. A rule would
  quietly stop catching what it was written for.
- **Claiming a capability the code doesn't have.** The enforcer doesn't detect
  phantom rollbacks and says so. A control documented as wider than it is gets
  believed exactly once.
- **A finality number you didn't check.** `finality.py` records whether a
  confirmation depth is a protocol guarantee or a convention. Getting that
  backwards means a control treating a convention as a proof.

## Prose

Write documentation the way a developer writes about their own project. Plain,
contractions fine, and no aphorism at the end of every paragraph. State the fact
and move on. Accuracy is never traded for brevity — measured figures, caveats
and limitations stay in.

## Commits

Explain *why*, and include what you tried that didn't work. Several of the
sharper decisions here came from something failing first, and a commit that
records only the final state loses the reason.

Commit as `rsh1k <128124382+rsh1k@users.noreply.github.com>`. No
`Co-Authored-By` trailers.

## Before you open a PR

```bash
make all
```

That's fmt, vet, the Go conformance suite, the Python suite, and the mutation
check. CI runs the same plus fixture reproducibility. If `make all` is green and
CI isn't, the difference is worth understanding rather than working around.
