# Revoco — undo for AI agent actions

[![ci](https://github.com/rsh1k/revoco/actions/workflows/ci.yml/badge.svg)](https://github.com/rsh1k/revoco/actions/workflows/ci.yml)
[![PyPI](https://img.shields.io/pypi/v/revoco)](https://pypi.org/project/revoco/)
[![Python](https://img.shields.io/pypi/pyversions/revoco)](https://pypi.org/project/revoco/)
[![License](https://img.shields.io/badge/license-Apache--2.0-blue)](LICENSE)

Agent governance is crowded with tools that answer *was this allowed* and *was this logged*. Almost none answer **can we take it back** — and that's the question that decides whether an incident costs an afternoon or a quarter.

When an agent repoints a supplier's bank account or deletes a production Deployment, knowing exactly what happened is necessary and not sufficient. Somebody still has to put it back, by hand, under time pressure, while the auditors watch.

Revoco does four things:

- **Plans the rollback before the action runs** — the only moment prior state still exists. A plan built afterwards can record what changed but not what to restore.
- **Rolls back a whole compromised grant in one call** — revoke the authority *and* its sub-delegated subtree, then undo everything done under it, newest first.
- **Proves the rollback still works** — drills each inverse against a disposable canary and compares state, because a backup nobody has restored is a hypothesis.
- **Produces evidence someone who distrusts you can verify** — one hash-chained ledger over authority, enforcement and reversal.

*Revoco* is Latin for "I call it back."

```bash
pip install revoco
```

Revoco merges three earlier tools and adds the layer none of them had:

| Merged from | Contributes |
|---|---|
| [`veritrail`](https://github.com/rsh1k/veritrail) | Ed25519 attenuating delegation chains, provenance back to a named human, hash-chained ledger, OWASP ASI detectors |
| [`mcp-gate`](https://github.com/rsh1k/mcp-gate) | Per-action policy decision point — allow / deny / require\_approval / redact, argument-aware conditions, stateful session budgets |
| [`mnemosyne`](https://github.com/rsh1k/mnemosyne) | Obfuscation and injection detection over untrusted content |
| **new here** | **The reversal layer: plan an undo *before* the action, execute it after, cascade it across a compromised grant's whole subtree** |

---

## Reversibility as an authorization input

Reversibility isn't a recovery procedure you write afterwards — by then the prior state is gone. So Revoco treats it as a property of the action, declared before the action runs, which makes it available to the thing that decides whether the action happens at all:

```yaml
- id: no-undo-needs-a-human
  effect: require_approval
  reversibility: [irreversible, unknown]
  reason: "No rollback path exists, so a person must own this decision."
```

Enforcement stops being only *"may this agent do it?"* and becomes also *"and can we take it back if it was wrong?"*

---

## Quick start

Installed above, or from source:

```bash
git clone https://github.com/rsh1k/revoco.git
cd revoco && uv venv && uv pip install -e ".[dev]"
```

```python
from revoco import ControlPlane, Scope, crypto
from revoco.reversal import ap_starter_registry, Reversibility

cp = ControlPlane(inverse_registry=ap_starter_registry(), state_reader=my_erp.read_state)

cfo_priv, cfo_pub = crypto.generate_keypair()
bot_priv, bot_pub = crypto.generate_keypair()
cfo = cp.register_human("Alice (CFO)", cfo_pub)
bot = cp.register_agent("ap-bot", bot_pub, roles={"ap-clerk"})

# A grant that says: only do things we can take back.
grant = cp.issue_root_delegation(
    human_private_key=cfo_priv, human_id=cfo.id, agent_id=bot.id,
    scope=Scope.make(
        tools={"invoices.pay", "vendors.update"}, actions={"write"}, max_risk=70,
        constraints={"max_amount_usd": 50_000},
        min_reversibility=Reversibility.COMPENSABLE,
    ),
    purpose="pay approved supplier invoices", ttl_seconds=3600,
)

verdict = cp.authorize(
    actor_private_key=bot_priv, actor_id=bot.id, delegation_id=grant.id,
    tool="invoices.pay", args={"invoice_id": "INV-7781", "amount": 48_500},
    risk=65, description="pay approved invoice", session_id="sess-1",
)

if verdict.allowed:
    result = my_erp.pay(**verdict.effective_args)   # your code does the real work
    cp.confirm(verdict, result=result)              # binds the undo path to the real payment id

# Later — one action, or a whole compromised grant:
cp.undo(verdict.action_id, my_erp.execute)
cp.contain(grant.id, my_erp.execute)   # revoke grant + subtree, then roll back everything under it
```

See the whole thing work on a vendor-payment-fraud scenario:

```bash
revoco demo
```

---

## The pipeline

```
classify → enforce → plan undo → record → verify authority → detect → verdict
                                                                        ↓
                                                        caller executes, then confirm()
```

Every stage can veto, and the verdict names which one did. `stage="authority"` and `stage="enforce"` are different incidents with different owners; "blocked" alone is not something anyone can act on.

**Why this order.** Policy is evaluated *before* the state snapshot, so the control plane does not touch production data on behalf of requests it is in the middle of refusing. The snapshot is taken *before* the action executes, because that is the only moment prior state still exists. The action is recorded *before* the verdict is known, and recorded even on refusal — a system that only logs successes cannot tell you an agent tried forty times.

---

## What the merge made possible

Three capabilities exist only because authority, enforcement, and reversal are in one system:

**`cp.contain(delegation_id, executor)`** — revoke a grant *and its whole sub-delegated subtree*, then roll back everything done under it, newest action first. Revocation alone stops the bleeding and leaves the damage. Undo alone leaves the attacker holding live authority. Neither original tool could express the pair.

**`PRA01` unrecoverable blast radius** — a burst of *irreversible* actions under one grant. Ordinary fan-out is a resilience concern; fan-out with no undo path is unbounded loss. The distinction is invisible unless you know both the grant and the reversal posture.

**`PRA02` phantom rollback** — an action committed with a reversal plan that cannot actually execute (unresolved inverse arguments, or a snapshot that failed). This is the most dangerous state in the system, because the organization believes it holds a rollback capability it does not hold. `journal_health()` reports the gap between rollback *claimed* and rollback *held*, and that gap is the honest measure of recovery readiness.

---

## Reversibility as a perishable asset

Everything above treats recoverability as a fact asserted at design time: a spec says `REVERSIBLE` and that claim is believed forever. Three additions treat it as what it actually is — an asset that decays, has to be capped, and has to be re-proven.

### Recovery drills — `revoco.drills`

Backup teams settled this decades ago: *a backup that has never been restored is a hypothesis; a restore drill is the experiment.* Agent rollback has the same silent failure mode and none of the discipline. (The existing agent-rollback-drill writing is about redeploying agent *versions* — a different thing entirely from proving `sap.supplier.bank.update`'s inverse still works after last week's ERP upgrade.)

A drill runs the real forward action against a disposable canary, runs the real inverse, then **compares state**. An inverse that returns 200 and restores nothing passes every check except this one.

```python
runner.drill_due(register, canaries, max_batch=10)   # point a cron at this
```

`register.due(tools)` orders work by urgency — a *failing* drill outranks a never-drilled tool, because a proven capability that broke is a live regression against something in use — and refreshes proof at 80% of its freshness window rather than after expiry, like renewing a certificate.

**Proof-gated classification** is the inversion worth having: a spec claiming `REVERSIBLE` whose drill is failing or stale **stops being treated as reversible**. The hook can only ever downgrade — guarded, not trusted, because manufacturing recoverability is the one direction this system must never move in.

Plus signed **proof-of-recoverability attestations**. Every comparable system signs *what happened*; this signs *that it could be undone, and when the inverse was last proven working*. That's the artifact an SR 11-7 or AI-Act auditor asks for and cannot get elsewhere.

### Irreversibility budget — `IrreversibilityBudget`

A ceiling on unrecoverable exposure per grant. The benchmark measured why detection isn't enough: `PRA01` is a threshold detector, so **four one-way wires had already left** before the pattern was visible. Detection needs evidence, and the evidence is the damage.

| Control | Wires that landed (same scenario, same rubber-stamping human) |
|---|---|
| Detection only | 4 of 6 |
| Budget ceiling 1.5 | 2 of 6 |
| Budget ceiling 0.8 | 1 of 6 |

The concept is published ([arXiv 2603.03515](https://arxiv.org/pdf/2603.03515), military AI governance). This differs in one way that matters: **that framework scores per tool; this scores per resolved action.** `aws.s3.delete_object` has no single irreversibility score — recoverable against a versioned bucket, final against an unversioned one. A tool-keyed budget would either bankrupt safe cleanup or hand out free credit for permanent deletion.

Reversible work is free, so it is not a rate limiter. Cost scales with risk. Named residue carries a surcharge, so "compensable" isn't a loophole. A successful undo refunds headroom. Replenishment is manual, because forcing a human back into the loop is the entire point.

### Reversibility horizon — `cp.horizon()`

Every other number here is retrospective. MTTD and MTTR are industry standards and both are measured after the fact; so is a containment rate. Nothing measures **how long you still can recover** — and undo windows expire quietly.

```
time to first close   4.0 min  (b.window)
recoverable now       3 of 5  (60%)
  standing exposure      1   never undoable
  broken                 1   claims an undo it cannot run
```

`time_to_first_close` is the headline: how long until the soonest undo option disappears. **MTTR asks how fast you recover; this asks how long you still have the choice.**

It keeps five states apart, and the distinctions carry the value: a window that *closed* is a different problem from one that *never existed* (`standing_exposure`), and both differ from a plan that claims an undo it cannot run (`broken`) — which reads as recoverable in every report except this one.

---

## The containment benchmark

```bash
revoco bench
```

The closest public comparison is Uber's [ADR-Bench](https://github.com/uber/ADR), which scores **detection**: 302 tasks (42 malicious, 260 benign) across 133 MCP servers, reporting 67% detection at zero false positives ([arXiv 2605.17380](https://arxiv.org/abs/2605.17380)). That's the right question for a detection-and-response system, and their prevention layer isn't open-sourced.

It's the wrong ceiling for anything claiming actions can be undone. **A system that detects every attack and reverses nothing scores 100% and has prevented no loss.** So the headline here is containment:

```
containment = prevented + verifiably recovered
```

Current: **57 scenarios (18 malicious, 39 benign) across 17 techniques — 83.3% containment, 0% false positives, 100% precision.**

The load-bearing design choice: `recovered` is established by **comparing world state against a pre-attack baseline, never by reading a reversal receipt.** A phantom rollback produces a receipt indistinguishable from a real one, so a receipt-based benchmark would certify the exact failure mode this package exists to prevent. There's a test that proves it — an inverse reporting success while changing nothing scores `UNCONTAINED`.

Every malicious technique has a **benign twin on the same tools**, so a policy that blocks the tool outright scores badly. Several benign scenarios exist purely to probe detector false-positive risk: legitimate `../` paths, SQL in a config, high-entropy certificate fingerprints, localised non-ASCII strings, a 12-write reversible burst, and a legitimate action taken *after* the same agent was refused once.

Because it runs a real `ControlPlane` against a simulated world, it doubles as a regression suite for the 91 adapter specs — and it earned that keep immediately, finding six real defects including an inverse that relied on implicit convention and a `Rule` that couldn't express "escalate irreversible work only when consequential".

**Honest about the comparison:** ADR-Bench is ~5× larger, drawn from real enterprise telemetry, and far more imbalanced (6:1 benign vs 2.2:1 here). Detection coverage is their strength; verified recoverability is this one's. Complementary instruments, not competing ones.

One gap is left visible rather than tuned away: `T09` irreversible fan-out. `PRA01` is a threshold detector, so four one-way wires land before the pattern is visible. The controlled pair `M10`/`M18` measures detection versus the budget on the identical attack, and both stay in the corpus so the difference is attributable.

---

## System-of-record adapters

`revoco.adapters` ships **specification-grade** inverse registries for 91 operations across eight surfaces. Full semantics, citations, and a validation checklist are in [docs/ADAPTERS.md](docs/ADAPTERS.md).

```bash
revoco surfaces --gates    # what's covered, and every gate you must implement
```

```python
from revoco.adapters import registry_for
registry = registry_for("cloud", "devops", "workstation")   # load only what you govern
```

| Surface | Specs | Covers |
|---|---|---|
| `sap` | 11 | S/4HANA journal entries, supplier master, payments |
| `workday` | 9 | HCM business processes — compensation, staffing, payroll |
| `cloud` | 14 | AWS — S3, IAM, EC2/networking, RDS, Route 53, KMS |
| `identity` | 11 | Microsoft Entra ID, Okta |
| `devops` | 12 | GitHub refs and protection, Kubernetes, feature flags |
| `database` | 8 | Row writes, arbitrary SQL, schema migrations |
| `saas` | 12 | Salesforce records, Slack messages, Stripe payments |
| `workstation` | 14 | Filesystem, git, shell — what coding agents actually touch |

**39 of the 91 specs are recoverable *only* because prior state is captured before the write.** A deleted Kubernetes object, a deleted git branch, a force-pushed ref, an overwritten file, a revoked security-group rule, a repointed vendor bank account — none has a native undo. That fraction is the clearest statement of what this architecture buys.

Specifying these changed the core model rather than just filling in a table — all four original assumptions about what an undo *is* turned out to be wrong:

| Assumption | Reality | Model change |
|---|---|---|
| An undo is one call | Reversing a cleared SAP payment is: void the payment medium → reset clearing (`FBRA`) → post reversal (`FB08`), **in that order** | `InverseStep` — ordered sequences, per-step criticality |
| Undo windows are durations | A Workday process is rescindable *until payroll runs*; an SAP document is reversible *while its period is open* | `ReversalGate` — event-bounded preconditions |
| Undos can be retried | An SAP reversal document cannot be reversed; a Workday rescind cannot be un-rescinded | `InverseSpec.one_shot` |
| Reversibility is a property of the tool | `aws.s3.delete_object` is recoverable against a versioned bucket and **final** against an unversioned one, same arguments. `entra.group.delete` soft-deletes a security group and hard-deletes a distribution group | authorize-phase gates + `degraded_kind` |

That last one changes how the control plane behaves. An authorize-phase gate is evaluated **before** the write, and a closed gate degrades the classification — so a reversibility-first policy escalates to a human while escalation still means something. Degrading afterwards would just be a notification that something unrecoverable had happened.

Findings worth pulling out:

**SAP reverses, it does not delete.** A posting plus its reversal leaves *two* documents. So no financial posting is ever `REVERSIBLE` here — the best available is `COMPENSABLE`, and a test enforces it. Anyone modeling an FI reversal as an exact inverse has misunderstood the ledger.

**SAP's own change log may not preserve the value you need.** Where supplier bank fields are configured as sensitive, the change log can show the new value as `*** Deleted ***` ([KBA 3475932](https://userapps.support.sap.com/sap/support/knowledge/en/3475932)), `FK08` may omit sensitive-field changes ([KBA 2518672](https://userapps.support.sap.com/sap/support/knowledge/en/2518672)), and vendor bank updates have been reported missing from change logs entirely ([KBA 2518878](https://userapps.support.sap.com/sap/support/knowledge/en/2518878)). If the prior bank account cannot be reliably read back out of `CDHDR`/`CDPOS` after the fact, capturing it *before* the write is not a nice-to-have — it is the only place the value exists.

**The cheapest win in the whole document:** `sap.journalentry.park` is genuinely reversible, because a parked document has not posted. Routing agent postings through park-then-human-post converts an irreversible surface into a reversible one for free.

**Enabling S3 versioning on agent-writable buckets is the cloud equivalent** — it converts every object delete and overwrite from irreversible to recoverable, for free.

**Identity is the one surface where the undo is more dangerous than the action.** Restoring a deleted account restores access; if it was deleted because it was compromised, a cascade rollback hands the attacker their session back. Nothing here can tell those apart, so every identity restore carries a gate requiring a human to confirm intent — and containment on that surface means *disable*, not delete.

**`shell.exec` and `db.execute_sql` are `UNKNOWN` by design.** An arbitrary command's effects cannot be known in advance, so under the starter policy every invocation escalates. That is the correct answer, not a gap — and the argument for giving agents specific tools rather than a shell.

Workday's `Correct` is deliberately modeled as `COMPENSABLE`, never `REVERSIBLE`, even though it restores the value exactly — a correction rewrites the record rather than reversing it, so the effective-dated history reads as though the corrected value was always intended. The number comes back; the record of what happened does not, and for an evidence system that is the part that counts. Compare `stripe.subscription.update` (schedule cancellation — reversible) with `stripe.subscription.cancel` (immediate — irreversible): nearly identical in a tool list, opposite in recoverability.

```bash
revoco inverses-check examples/inverses_sap.json
```

lists the sequenced undos, the one-shot specs, and every gate your `GateEvaluator` must answer. It exits non-zero if a spec reads `snapshot.X` without declaring `X` in `snapshot_fields` — the easiest way to author a phantom rollback.

---

## Honest scope — read this first

This is a **working foundation**, published so it can be read, run, and extended. It is not a finished or certified product.

- **One adapter surface is validated; seven are specifications.** `workstation` (14 specs) is drilled against a real filesystem and a real git repo by `scripts/validate_workstation.py`, in CI — 11 of 11 drillable inverses restore state, 10 prose claims probed. **The other seven have never been executed against a live system.** They were written from vendor documentation and KBAs; argument names differ across S/4HANA Cloud, on-premise releases and your middleware, and Workday business process configuration is per-tenant. **A tool mapped to the wrong inverse produces a confident, wrong rollback** — worse than none. Work through the checklist in [docs/ADAPTERS.md](docs/ADAPTERS.md) first, and re-validate after every ERP upgrade. Validating the one cheap surface found five defects that would all have recurred elsewhere, which is the argument for doing it before you touch a vendor sandbox — and a scheduled drill is the only thing that catches a spec going stale after an upgrade.
- **`ap_starter_registry()` is illustrative**, not a starting point for production. It exists so the demo and the quick start have something to run against.
- **A `const:` value in a spec is a placeholder.** The SAP specs default `ReversalReason` to `01`, which as delivered permits only the original posting date. Use the reason your finance team configured.
- **Compensating actions are not inverses.** You can void a payment; you cannot recall the remittance advice already sent. `Reversibility.COMPENSABLE` requires you to name the `residue` — what survives the undo — because an unnamed side effect is an unowned risk.
- **A policy engine's false-positive rate is a property of the policies you write**, not of the engine. A flawless engine still blocks a legitimate call if a rule is too broad. The goal is an engine you can reason about and test exhaustively.
- **The threat scanner is a heuristic, not a calibrated classifier.** It is meant to feed `require_approval`, so a false hit costs a review click rather than a broken workflow. Absence of a finding is not evidence that no injection occurred.
- **Intent-drift detection is lexical overlap.** It flags divergence; it does not establish intent.
- **A hash chain does not detect truncation.** Edits, reorders, and interior deletions break verification; dropping the most recent entries leaves a valid prefix. Anchor the head hash externally — `Ledger.checkpoint()` gives you the value to publish.
- **In-memory stores are single-process.** `InMemorySessionStore.would_exceed` followed by `commit` is not atomic, so two concurrent calls can both pass a check only one should. A shared store must make that pair atomic.
- **Nothing persists yet.** The ledger, the reversal journal, and the drill register are all in memory, so they reset on restart. Three consequences worth knowing: the horizon forgets undo windows that are still open, `RecoverabilityRegister`'s freshness window means nothing across deploys, and a restart loses the evidence chain rather than breaking it — which is a different failure from tampering and currently indistinguishable from it. Persisting the ledger needs WAL with `synchronous=FULL` and append-only enforced by triggers (SQLite has no `GRANT`), the ledger append and journal write in one transaction, and a startup grace period so a long outage does not mass-degrade every proof to `IRREVERSIBLE` and block legitimate work.
- **Control mappings are a self-assessment aid, not a certification** or a legal opinion. NIST AI RMF is voluntary; EU AI Act conformity is assessed against a quality-management system of which logging is one clause.

Every place needing production hardening is marked `# HARDENING:` in the source. Search for it before deploying.

---

## Standards alignment

`revoco controls` prints the full mapping. Summary:

| Framework | Covered |
|---|---|
| **EU AI Act** | Art. 12 automatic record-keeping · Art. 12(2) lifetime traceability · Art. 14 human oversight · Art. 19 logs under deployer control |
| **NIST AI RMF 1.0** | GOVERN 1.5 accountability · MEASURE 2.7 security tracked · MANAGE 2.3 supersede/deactivate |
| **OWASP Agentic Top 10 (ASI 2026)** | ASI01, ASI02, ASI03, ASI06, ASI07, ASI08, ASI09, ASI10 |
| **SR 11-7 / OCC** | III.B process verification · V governance & controls |
| **SOX / ICFR** | Change authorization over financial records · reversal of unauthorized entries |

On **Article 19** specifically: providers must keep logs "to the extent such logs are under their control." Revoco's ledger is held by the deployer and independently verifiable from its head hash and Merkle root. Evidence that lives only in a vendor's cloud is evidence whose control is, at minimum, arguable.

ASI04 (supply chain) and ASI05 (unexpected code execution) are deliberately left to complementary controls — manifest signing and execution sandboxing — because they belong at a different layer.

---

## CLI

```bash
revoco bench                                    # the containment benchmark
revoco surfaces --gates                         # what the adapters cover, and every gate to implement
revoco policy-check   policy.yaml               # validate a policy, warn on risky defaults
revoco inverses-check inverses.yaml             # validate an inverse registry
revoco coverage       inverses.yaml --tools a,b # rollback readiness for a tool surface
revoco controls                                 # print the control mapping
revoco demo                                     # end-to-end AP fraud scenario
```

Plus one script, because it needs a real filesystem rather than a package entry point:

```bash
python scripts/validate_workstation.py          # drill the workstation adapter for real
```

**Three of these are CI gates**, and each encodes a rule the package makes about itself:

- `bench` exits non-zero on an unexpected loss or any false positive. A scenario whose designed outcome is loss doesn't fail the build; a regression that starts losing something new does.
- `coverage` exits non-zero when a tool has no declared inverse — so adding a write operation without classifying its undo path fails the build.
- `inverses-check` exits non-zero when a spec reads `snapshot.X` without declaring `X`, which is the easiest way to author a phantom rollback.

---

## Layout

```
src/revoco/
  core/            crypto (Ed25519, SHA-256, RFC-8785 canonical JSON), ids, errors
  authority/       principals · scope · delegation · revocation · chain reconstruction
  gate/            policy · conditions · threat scanner · session budgets · PDP
  reversal/        model · registry · engine · budget · horizon
  adapters/        91 inverse specs across 8 surfaces (docs/ADAPTERS.md)
  bench/           containment benchmark: world · scenarios · harness · corpus · report
  drills.py        recovery drills, proof-gated classification, attestations
  ledger.py        one append-only hash-chained ledger
  detect.py        OWASP ASI + PRA01/PRA02 detectors
  controlplane.py  the orchestrator
  evidence.py      evidence packs + readiness reports
  demo.py          runnable AP-fraud scenario

scripts/
  validate_workstation.py   drills the workstation adapter against real fs + git
  bump_version.py           used by the release workflow

docs/
  ADAPTERS.md      per-spec semantics, citations, validation checklist
  RELEASING.md     the release path, and how to schedule drills
```

**One ledger, not three.** Each merged tool had its own hash-chained log. Three chains cannot be verified as one history: an attacker who altered a policy decision in one and the matching action record in another breaks both independently, and nothing could prove the two logs described the same event. A single chain over authority, enforcement, and reversal makes "what happened, in what order, under whose authority" one verifiable question.

**One identity model.** `Principal` absorbed mcp-gate's separate `AgentIdentity`. Two identity registries that can disagree about who an agent is are exactly the seam an attacker looks for; the gate now matches policy against the same object whose signature the authority layer verifies.

---

## Development

```bash
uv venv && uv pip install -e ".[dev]"
.venv/bin/pytest -q
.venv/bin/ruff check src tests
```

## License

Apache-2.0
