# recoup

Decide whether an AI agent's action can actually be undone — before it happens.

Two processes. A small Go binary sits in the request path and answers one
question per tool call. A Python control plane behind it decides what the answers
should be, drills the undos to check they still work, and keeps the evidence.

```bash
recoup compile policy.json -o bundle.json     # Python: author and compile
recoup-enforcer --bundle bundle.json          # Go: enforce (shadow by default)
```

## Why it's built this way

Backup vendors already sell agent rollback. It works for anything that lives in
storage: file edits, config changes, database rows. It does nothing for a
captured payment, a sent email, a webhook a partner has already received. The
common failure isn't that rollback is missing, it's that someone assumed it
covered an action it never could.

So the useful question isn't "can we restore this later" but "does an undo for
this exist at all, right now". That gets asked before the action, not after.

## Who decides what

| | Enforcer (Go) | Control plane (Python) |
|---|---|---|
| Runs | in the request path | out of band |
| Needs | a bundle and the call | filesystem, snapshots, model, corpus |
| Decides | which rule matches | what the rules should be |
| Reversibility | looks it up | works it out from live state |
| Phantom rollback | **no** | yes |

That last row matters. A *phantom rollback* is an action claiming an undo that
can't actually run — the snapshot was never taken, the inverse was never wired
up. Catching it means reading the world, so it stays in the control plane. The
enforcer is told the reversibility; it doesn't discover it.

Worth being blunt about, because a sidecar that looked like it verified
recoverability but only read a lookup table would be believed exactly once.

## Shadow mode is the default

Nobody installs something that blocks their agents because a vendor said it was
safe. So the enforcer starts in shadow mode: every call is allowed, and the
verdict that *would* have applied is recorded.

```
$ curl -s localhost:842/v1/stats
{"decisions": 41208, "would_have_blocked": 1174, "mode": "shadow",
 "by_effect": {"allow": 40034, "require_approval": 1103, "deny": 71}}
```

Run it for a month and you get a number instead of an argument: how much of your
agent estate is doing work nothing can undo. Then decide what to enforce. It also
clears security review as a monitoring tool rather than a new control in the
payment path, which is a different conversation entirely.

## What the estate actually does

The enforcer sees every tool call every agent makes. With `--journal` it writes
one line per decision, and three commands turn that into something useful.

**`recoup inventory`** — who is doing what, and how much of it can't be taken back.

```
778 decisions | 3 agent(s) | 4 tool(s)

  agent                     calls  tools  irreversible  top tools
  invoice-reader              403      2         0.00%  invoices.read, vendors.update
  reconciler                  310      2         0.00%  invoices.read, invoices.pay
  payments-bot                 65      2        38.50%  vendors.update, payments.wire

  no undo exists for: payments.wire
```

**`recoup suggest`** — the tightest policy that would have allowed what actually
happened. Writing agent policy by hand is the main reason people run everything
wide open, so this removes the blank page.

It flags what it isn't sure about. On the traffic above it noticed that
`invoice-reader` wrote to `vendors.update` three times, which is thin evidence
for a clause — and a read-only bot mutating vendor records is worth a look on its
own merits.

Irreversible tools are never rolled into an allow rule. They get their own
approval clause, ordered first so it isn't unreachable, because the fact that
something happened during the window isn't evidence it should have.

**`recoup simulate`** — replay recorded traffic against a candidate policy and
see exactly what changes before turning it on.

```
replayed 778 recorded decisions against tightened@1

  unchanged              775
  newly blocked            3   (0.39% of traffic)
  newly allowed            0

  would start blocking:
          3  vendors.update/write [invoice-reader]  allow -> deny
```

It uses the same evaluator the enforcer does, so that's the answer the gate would
really give.

### The hazard, stated plainly

Generating policy from observation bakes in whatever the observation contained.
If an agent misbehaved during the window, the suggestion blesses it; if the window
was too short, the policy breaks work that hadn't happened yet. AWS learned this
publicly with IAM policy generation from CloudTrail.

So `suggest` reports how much evidence sits behind each clause, flags anything
thin, and prints a warning that it's a draft. It never emits a policy on its own
authority.

The journal records tool, action, agent and verdict — **never arguments**. Those
are where the payment amounts and customer records live, and the whole deployment
argument is that regulated data stays in your VPC. A journal capturing arguments
would be a second copy of exactly the data nobody wants copied.

## The conformance suite is the point

Two implementations of one decision will drift. A gate that says *allow* in Go
and *require approval* in Python is worse than no gate, because the record it
produces can't be trusted either way.

So the golden files in `conformance/fixtures/` are verdicts revoco's engine
actually produced, generated by running it rather than by writing down what it
ought to do. Both runtimes have to reproduce every one.

```bash
make conform     # Go must match every frozen verdict
make mutate      # ...and the fixtures must be capable of noticing
```

The second target exists because of a real failure. The first version of the
fixtures passed 8,316 cases with a `<` changed to `<=` in the Go evaluator: the
hand-picked risk values never landed on the policy's only threshold, so the bug
was invisible. Green and worthless.

The fix was to derive probe values from the policy's own thresholds, so every
rule brings its boundary coverage with it. `make mutate` then introduces
single-character bugs on purpose and fails if any of them survives. All nine
mutations are caught, including the one that swaps Python's glob semantics for
Go's.

## Globs, and why not `path.Match`

Policies are authored against Python's `fnmatch`. Go's `path.Match` looks
equivalent and isn't: its `*` stops at a `/`, so `svc*` wouldn't match
`svc/delete`. A rule meant to catch a tool would quietly stop catching it, which
is the worst direction for a security rule to move in. The enforcer implements
Python's semantics directly, and the fixtures include cases that separate the
two.

## Compiling a policy

The bundle spells out every field. revoco defaults an unspecified `tools` to
`["*"]`, and relying on two languages to agree about an absent field is exactly
the bug this design exists to prevent — so the compiler writes them all and the
enforcer rejects a rule that's missing one.

Anything the schema can't express is refused rather than approximated. A rule
carrying an argument condition or a spend budget doesn't compile. Dropping the
condition and emitting the rest would produce a rule matching strictly more calls
than its author wrote, which is a silent widening of a security policy.

## Agent identity is a claim, not a fact

The enforcer reads `agent_id` out of the request body. Nothing authenticates it,
so any caller that can reach the port can say it's any agent.

That costs nothing while every rule matches `*` — the answer is the same whoever
asks. It matters the moment a rule narrows by agent, because then an
unauthenticated caller gets to pick which rule applies to it. A control the
constrained party can select isn't a control.

So the enforcer checks at startup and refuses to run rather than serve a policy
whose agent conditions only look enforced:

```
refusing to start: 1 rule(s) decide on which agent is calling (named-agent),
but --agent-identity=unverified means that id is taken from the request
body and never checked. Any caller could select its own rule.
```

Pass `--agent-identity=trusted-network` when something upstream already
authenticates the caller — a mesh doing mTLS, for instance. It's opt-in so that
choosing it is a decision rather than an inherited default.

The real fix is SPIFFE SVIDs with mTLS, which is on the list.

## Container

The final stage is `scratch`. No shell, no package manager, no libc — one static
binary and nothing to pivot with. The build fails if the binary turns out to be
dynamically linked, because finding that out at runtime means finding out in a
CrashLoopBackOff.

```bash
make image
```

Not yet built in CI, and not yet size-measured on a real registry. The stripped
binary is about 5.9 MB.

## Status

Early. What works today:

- Policy compiles to a bundle, with a digest that ties a verdict back to the
  exact policy that produced it
- The Go enforcer evaluates it, in shadow or enforce mode, over HTTP
- 3,960 frozen verdicts, matched by both runtimes
- 9 of 9 mutations caught

Not built yet: drills, the ledger, containment, evidence packs. Those live in
[revoco](https://github.com/rsh1k/revoco) and aren't wired in here.

## Built on

[revoco](https://github.com/rsh1k/revoco) supplies the reversibility model, the
gate, the reversal engine, the delegation chain and the ledger. This repo is the
deployment shape around it: something you can run as a sidecar in your own VPC,
where regulated data never has to leave.

Apache-2.0.
