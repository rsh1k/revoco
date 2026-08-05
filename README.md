# Praetor

**An action control plane for AI agents.** Delegated authority, per-action policy enforcement, **reversible execution**, and evidence a regulator can verify.

A Roman *praetor* held delegated *imperium*, issued *edicta*, and could stop an act in progress by *interdictum*. That is the shape of this package: authority that attenuates as it is delegated, policy as reviewable data, and interception at the moment an action becomes real.

Praetor merges three earlier tools and adds the layer none of them had:

| Merged from | Contributes |
|---|---|
| [`veritrail`](https://github.com/rsh1k/veritrail) | Ed25519 attenuating delegation chains, provenance back to a named human, hash-chained ledger, OWASP ASI detectors |
| [`mcp-gate`](https://github.com/rsh1k/mcp-gate) | Per-action policy decision point — allow / deny / require\_approval / redact, argument-aware conditions, stateful session budgets |
| [`mnemosyne`](https://github.com/rsh1k/mnemosyne) | Obfuscation and injection detection over untrusted content |
| **new here** | **The reversal layer: plan an undo *before* the action, execute it after, cascade it across a compromised grant's whole subtree** |

---

## The gap this closes

Agent governance tooling is overwhelmingly about detection: was this call allowed, was it logged, was it anomalous. That leaves the expensive half of an incident untouched.

When an agent has already repointed a supplier's bank account and paid an invoice into it, knowing exactly what happened is necessary and not sufficient. Somebody still has to put it back — by hand, under time pressure, while the auditors watch. Reversibility is not a recovery procedure you write afterwards. By then the prior state is gone.

So Praetor treats reversibility as **a property of the action, declared and planned before the action runs**, and as a **first-class authorization input**:

```yaml
- id: no-undo-needs-a-human
  effect: require_approval
  reversibility: [irreversible, unknown]
  reason: "No rollback path exists, so a person must own this decision."
```

Enforcement stops being only *"may this agent do it?"* and becomes also *"and can we take it back if it was wrong?"*

---

## Quick start

Not on PyPI yet — install from source:

```bash
git clone https://github.com/rsh1k/praetor.git
cd praetor && uv venv && uv pip install -e ".[dev]"
```

```python
from praetor import ControlPlane, Scope, crypto
from praetor.reversal import ap_starter_registry, Reversibility

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
praetor demo
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

## System-of-record adapters

`praetor.adapters` ships **specification-grade** inverse registries for 91 operations across eight surfaces. Full semantics, citations, and a validation checklist are in [docs/ADAPTERS.md](docs/ADAPTERS.md).

```bash
praetor surfaces --gates    # what's covered, and every gate you must implement
```

```python
from praetor.adapters import registry_for
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
praetor inverses-check examples/inverses_sap.json
```

lists the sequenced undos, the one-shot specs, and every gate your `GateEvaluator` must answer. It exits non-zero if a spec reads `snapshot.X` without declaring `X` in `snapshot_fields` — the easiest way to author a phantom rollback.

---

## Honest scope — read this first

This is a **working foundation**, published so it can be read, run, and extended. It is not a finished or certified product.

- **The inverse registries are specifications, not validated integrations.** `ap_starter_registry()` is illustrative; the SAP and Workday registries were written from vendor documentation and KBAs and have **never been executed against a live system**. Argument names differ across S/4HANA Cloud, on-premise releases, and your middleware; Workday business process configuration is per-tenant. **A tool mapped to the wrong inverse will produce a confident, wrong rollback** — worse than no rollback. Work through the validation checklist in [docs/ADAPTERS.md](docs/ADAPTERS.md) before any of it governs a real write, and re-validate after every ERP upgrade: a changed API contract turns a correct spec into a wrong one and nothing here can detect that for you.
- **A `const:` value in a spec is a placeholder.** The SAP specs default `ReversalReason` to `01`, which as delivered permits only the original posting date. Use the reason your finance team configured.
- **Compensating actions are not inverses.** You can void a payment; you cannot recall the remittance advice already sent. `Reversibility.COMPENSABLE` requires you to name the `residue` — what survives the undo — because an unnamed side effect is an unowned risk.
- **A policy engine's false-positive rate is a property of the policies you write**, not of the engine. A flawless engine still blocks a legitimate call if a rule is too broad. The goal is an engine you can reason about and test exhaustively.
- **The threat scanner is a heuristic, not a calibrated classifier.** It is meant to feed `require_approval`, so a false hit costs a review click rather than a broken workflow. Absence of a finding is not evidence that no injection occurred.
- **Intent-drift detection is lexical overlap.** It flags divergence; it does not establish intent.
- **A hash chain does not detect truncation.** Edits, reorders, and interior deletions break verification; dropping the most recent entries leaves a valid prefix. Anchor the head hash externally — `Ledger.checkpoint()` gives you the value to publish.
- **In-memory stores are single-process.** `InMemorySessionStore.would_exceed` followed by `commit` is not atomic, so two concurrent calls can both pass a check only one should. A shared store must make that pair atomic.
- **Control mappings are a self-assessment aid, not a certification** or a legal opinion. NIST AI RMF is voluntary; EU AI Act conformity is assessed against a quality-management system of which logging is one clause.

Every place needing production hardening is marked `# HARDENING:` in the source. Search for it before deploying.

---

## Standards alignment

`praetor controls` prints the full mapping. Summary:

| Framework | Covered |
|---|---|
| **EU AI Act** | Art. 12 automatic record-keeping · Art. 12(2) lifetime traceability · Art. 14 human oversight · Art. 19 logs under deployer control |
| **NIST AI RMF 1.0** | GOVERN 1.5 accountability · MEASURE 2.7 security tracked · MANAGE 2.3 supersede/deactivate |
| **OWASP Agentic Top 10 (ASI 2026)** | ASI01, ASI02, ASI03, ASI06, ASI07, ASI08, ASI09, ASI10 |
| **SR 11-7 / OCC** | III.B process verification · V governance & controls |
| **SOX / ICFR** | Change authorization over financial records · reversal of unauthorized entries |

On **Article 19** specifically: providers must keep logs "to the extent such logs are under their control." Praetor's ledger is held by the deployer and independently verifiable from its head hash and Merkle root. Evidence that lives only in a vendor's cloud is evidence whose control is, at minimum, arguable.

ASI04 (supply chain) and ASI05 (unexpected code execution) are deliberately left to complementary controls — manifest signing and execution sandboxing — because they belong at a different layer.

---

## CLI

```bash
praetor policy-check   policy.yaml               # validate a policy, warn on risky defaults
praetor inverses-check inverses.yaml             # validate an inverse registry
praetor coverage       inverses.yaml --tools a,b # rollback readiness for a tool surface
praetor controls                                 # print the control mapping
praetor demo                                     # end-to-end AP fraud scenario
```

`coverage` exits non-zero when tools have no declared inverse, so it works as a CI gate: adding a write operation without classifying its undo path fails the build.

---

## Layout

```
src/praetor/
  core/            crypto (Ed25519, SHA-256, RFC-8785 canonical JSON), ids, errors
  authority/       principals · scope · delegation · revocation · chain reconstruction
  gate/            policy · conditions · threat scanner · session budgets · PDP
  reversal/        model · inverse registry · reversal engine        <- new
  adapters/        SAP + Workday inverse specs (see docs/ADAPTERS.md) <- new
  ledger.py        one append-only hash-chained ledger
  detect.py        OWASP ASI + PRA01/PRA02 detectors
  controlplane.py  the orchestrator
  evidence.py      evidence packs + readiness reports
  demo.py          runnable AP-fraud scenario
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
