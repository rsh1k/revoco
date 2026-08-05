# System-of-record adapters

**Status: specification, not a validated integration.**

Everything else in Revoco is transferable across customers. This is not. Knowing that an SAP payment reversal is a three-step ordered sequence, that a Workday rescind dies the moment payroll runs, or that an S3 delete is recoverable only if someone enabled versioning first, is per-system knowledge that has to be built once and maintained forever. It is also the moat — capital cannot shortcut it, and a horizontal identity vendor will not do it.

These specs were written from vendor documentation, Knowledge Base Articles, and customer-published administration guides. **They have not been executed against a live system.** Work through the validation checklist at the end before any of this governs a real write. A tool mapped to the wrong inverse produces a confident, wrong rollback — worse than having no rollback at all.

```bash
revoco surfaces --gates     # what is covered, and every gate you must implement
```

## Coverage

91 specs across eight surfaces:

| Surface | Specs | What it covers |
|---|---|---|
| `sap` | 11 | S/4HANA journal entries, supplier master, payments |
| `workday` | 9 | HCM business processes — compensation, staffing, payroll |
| `cloud` | 14 | AWS — S3, IAM, EC2/networking, RDS, Route 53, KMS |
| `identity` | 11 | Microsoft Entra ID, Okta |
| `devops` | 12 | GitHub refs and protection, Kubernetes, feature flags |
| `database` | 8 | Row writes, arbitrary SQL, schema migrations |
| `saas` | 12 | Salesforce records, Slack messages, Stripe payments |
| `workstation` | 14 | Filesystem, git, shell — what coding agents actually touch |

Two numbers from `revoco surfaces` are worth reporting upward:

- **39 of 91 specs are recoverable *only* because prior state is captured before the write.** That is the share of the undo surface this architecture creates rather than merely records. A deleted Kubernetes object, a deleted git branch, a force-pushed ref, an overwritten file, a revoked security-group rule, a repointed vendor bank account — none has a native undo.
- **12 specs can turn out irreversible for a particular target** despite an optimistic classification. An unchecked authorize-phase gate on any of them is a phantom rollback waiting to happen.

---

## What specifying these adapters changed in the core model

The research did not fill in a table. It invalidated four assumptions in the original reversal model, and the model was extended to fit reality rather than the reverse.

| Assumption | Reality | Model change |
|---|---|---|
| An undo is one call | Reversing a cleared SAP payment is: void the payment medium → reset the clearing (`FBRA`) → post the reversal (`FB08`), in that order | `InverseStep`, ordered sequences with per-step criticality |
| Undo windows are durations | A Workday process is rescindable *until payroll runs*; an SAP document is reversible *while its period is open*. Neither is a clock | `ReversalGate`, event-bounded preconditions |
| Undos can be retried | An SAP reversal document cannot be reversed; a Workday rescind cannot be un-rescinded | `InverseSpec.one_shot` |
| Reversibility is a property of the tool | `aws.s3.delete_object` is recoverable against a versioned bucket and final against an unversioned one, with identical arguments. `entra.group.delete` soft-deletes a security group and hard-deletes a distribution group | `check_at: authorize` gates, plus `degraded_kind` |

The third deserves emphasis: the undo is a single cartridge, and firing it at the wrong document is not recoverable by firing it again.

The fourth is the one that changes how the control plane behaves. An authorize-phase gate is evaluated **before the forward action**, and a closed gate degrades the classification — so a reversibility-first policy escalates to a human while escalation still means something. Degrading afterwards would just be a notification that something unrecoverable had happened.

---

## SAP S/4HANA

### The governing insight: SAP reverses, it does not delete

Posting a document and then reversing it leaves **two** documents. The original posting remains permanently in the ledger and in every report already run against it. Consequently **no financial posting in this adapter is `REVERSIBLE`** — the best available classification is `COMPENSABLE`, with the residue stated explicitly. Anyone modeling an FI reversal as an exact inverse has misunderstood the ledger, and the test suite enforces this.

### Spec table

| Forward tool | Kind | Undo path | Gates | One-shot |
|---|---|---|---|---|
| `sap.journalentry.post` | compensable | `sap.journalentry.reverse` | period open, items not cleared | yes |
| `sap.journalentry.park` | **reversible** | `sap.journalentry.delete_parked` | — | no |
| `sap.journalentry.reverse` | irreversible | — | — | — |
| `sap.supplier.bank.update` | **reversible** | `sap.supplier.bank.update` with captured prior values | dual control confirmable | no |
| `sap.supplier.bank.create` | compensable | `sap.supplier.bank.delete` | dual control confirmable | no |
| `sap.supplier.block` | **reversible** | `sap.supplier.set_block` with prior flags | — | no |
| `sap.payment.post` | compensable | void medium → reset clearing → reverse | payment not settled, period open | yes |
| `sap.paymentrun.execute` | irreversible | — | — | — |
| `sap.paymentfile.transmit` | irreversible | — | — | — |

### Why the vendor-bank spec matters most

Vendor-master bank tampering followed by a payment run is *the* canonical agent-assisted payment fraud. A fraudster changes a genuine supplier's bank account, and the next payment run sends money to their account instead ([Learn to SAP — audit trail scenario](https://www.learntosap.com/SAP-Audit-Trail-Real-Scenario.html)).

It is also the case where SAP's own audit trail may not be enough to recover from:

- Where bank fields are configured as sensitive, the change log can display the new value as `*** Deleted ***` — [KBA 3475932](https://userapps.support.sap.com/sap/support/knowledge/en/3475932)
- `FK08` may not display every change to sensitive fields — [KBA 2518672](https://userapps.support.sap.com/sap/support/knowledge/en/2518672)
- Updates to vendor master bank data have been reported missing from change logs entirely — [KBA 2518878](https://userapps.support.sap.com/sap/support/knowledge/en/2518878)
- Sensitive fields configured for dual control have been reported not displaying supplier bank account changes — [KBA 3716628](https://userapps.support.sap.com/sap/support/knowledge/en/3716628)

**This is the strongest available argument for the whole architecture.** If the prior bank account cannot be reliably read back out of `CDHDR`/`CDPOS` after the fact, then capturing it before the write is not a nice-to-have — it is the only place the value exists. Revoco's snapshot happens pre-write by construction.

Normally the prior value would come from `CDHDR`/`CDPOS`: query `CDHDR` where `OBJECTCLAS = 'BUPA_BUP'`, `OBJECTID` = the supplier, `CHANGE_IND = 'U'`, then `CDPOS` on the change number for `VALUE_OLD`/`VALUE_NEW` ([SAP Community](https://community.sap.com/t5/enterprise-resource-planning-q-a/dates-when-vendor-bank-details-updated/qaq-p/12023580), [KBA 3683201](https://userapps.support.sap.com/sap/support/knowledge/en/3683201)). Relevant fields are `LFBK-BANKS` (country), `LFBK-BANKL` (bank key), `LFBK-BANKN` (account). Treat that path as a cross-check, not the source of truth.

**IDoc caveat:** `DEBMAS`/`CREMAS` do not delete bank details ([KBA 3344959](https://userapps.support.sap.com/sap/support/knowledge/en/3344959)), so an IDoc-driven "undo" of `sap.supplier.bank.create` silently leaves the account in place. Verify removal; do not assume it.

### Why payment reversal is a sequence

- A reversal cannot be posted against already-cleared items. The error "Document includes already cleared items – reversal not possible" appears because a reverse posting must clear all line items managed as open items ([SAP Community](https://community.sap.com/t5/enterprise-resource-planning-q-a/document-includes-already-cleared-items-reversal-not-possible/qaq-p/7840284)).
- Therefore clearing must be reset first with `FBRA` ([Guru99](https://www.guru99.com/how-to-reset-ar-cleared-items.html), [SAP Community](https://community.sap.com/t5/financial-management-blog-posts-by-members/reversing-a-cleared-invoice-fbra-and-fb08/ba-p/13473411)). `FBRA` offers reset-only or reset-and-reverse; the specs keep the operations separate so a partial failure names the step it stopped at.
- **If a payment medium or cheque was issued, void it before resetting the clearing**, otherwise the ledger and the bank statement disagree ([SAP Community, FBRA discussion](https://community.sap.com/t5/enterprise-resource-planning-q-a/t-code-fbra/qaq-p/4224616)). This is why `void_medium` runs first and is marked `critical=True`: aborting on its failure is safer than proceeding.

### Posting-date rules — read before setting `ReversalReason`

The reversal's posting date is governed by the reversal reason's configuration. As delivered, reason `01` permits only the original document's posting date ([SAP Community](https://community.sap.com/t5/enterprise-resource-planning-q-a/reversal-reason-01-only-permits-posting-date-01-09-2010-in-fb08/qaq-p/7724285)). The period of the original document must be open; if it is closed, you must post the reversal into an open period, which means **both periods' figures move** ([SAP Community](https://community.sap.com/t5/enterprise-resource-planning-q-a/reversing-document-fb08-from-closed-period/qaq-p/12547904)). A posted document's posting date can never be changed afterwards.

The `const:01` in the specs is a **placeholder, not a recommendation.** Use the reason your finance team configured.

### And the reversal cannot be reversed

A reversal document cannot be reversed again; correcting a mistaken reversal needs a fresh manual posting (`F-02`) ([SAP Community](https://community.sap.com/t5/enterprise-resource-planning-q-a/reverse-document/qaq-p/5906707)). `sap.journalentry.reverse` is therefore registered as `IRREVERSIBLE`, so an agent calling it directly escalates to a human under the starter policy rather than inheriting the illusion that reversal is always safe.

### API surface

- **Journal entries:** `Journal Entry – Reverse` inbound service ([SAP Help Portal](https://help.sap.com/docs/SAP_S4HANA_CLOUD/b978f98fc5884ff2aeb10c8fdeb8a43b/57b40036b71f4825adad70a0a5b91573.html)); posting via synchronous/asynchronous SOAP services; `I_JournalEntryTP` exposes Post/Validate/Reverse/Change ([APIs for Journal Entries collection](https://community.sap.com/t5/technology-blog-posts-by-sap/apis-for-journal-entries-the-collection-updated-july-2025/ba-p/13565258)).
- **Supplier master:** `API_BUSINESS_PARTNER` OData, full CRUD plus deep insert, with `A_SupplierBank` for bank details ([KBA 3569467](https://userapps.support.sap.com/sap/support/knowledge/en/3569467), [SAP Help Portal](https://help.sap.com/docs/SAP_S4HANA_ON-PREMISE/44e06f22436c43e582db6ccd5250e29b/85043858ea0f9244e10000000a4450e5.html)).

Note that reads of bank and identification data through `API_BUSINESS_PARTNER` are subject to Read Access Logging. Revoco's `state_reader` will generate RAL entries — expected, but tell whoever owns that log before you turn it on.

### The cheapest win in this whole document

`sap.journalentry.park` is the one genuinely `REVERSIBLE` posting-adjacent operation: a parked document has not posted, so deleting it leaves no ledger trace. **Routing agent postings through park-then-human-post converts an irreversible surface into a reversible one for free.** If you take one design decision from this file, take that one.

---

## Workday HCM

### The governing insight: three corrective actions, only one is an inverse

| Action | Available when | Effect |
|---|---|---|
| **Cancel** | process is *In Progress* | reverses all data changes |
| **Rescind** | process is *Successfully Completed* | reverses all data changes; **cannot itself be undone** |
| **Correct** | process is completed | edits values; does **not** reverse |

Sources: [Texas A&M — Correct, Cancel and Rescind](https://it.tamus.edu/workdayservices/training/reference_guide/correct-cancel-and-rescind/), [UT Austin — Cancel or Rescind?](https://workday.utexas.edu/help/mistakes-happen), [Workday Finance blog](https://americasworkdayfinance.blogspot.com/2020/04/business-process-rescind-vs-cancel.html).

Because Revoco commits a journal entry only after the forward action has completed, **Rescind is the inverse that matters.** Cancel applies to a window this package does not model — a process still awaiting approval has not yet changed anything to undo. Rescind requires a security group with permission, typically Business Process Administrator, and the action cannot be undone.

### Spec table

| Forward tool | Kind | Undo path | One-shot |
|---|---|---|---|
| `workday.compensation.request_change` | compensable | `workday.bp.rescind` | yes |
| `workday.job.change_job` | compensable | `workday.bp.rescind` | yes |
| `workday.staffing.hire` | compensable | `workday.bp.rescind` | yes |
| `workday.staffing.terminate` | compensable | `workday.bp.rescind` | yes |
| `workday.compensation.correct` | compensable | `workday.compensation.correct` with prior values | no |
| `workday.bp.rescind` | irreversible | — | — |
| `workday.payroll.complete` | irreversible | — | — |
| `workday.payment.settle` | irreversible | — | — |

API surface: `Rescind_Business_Process` in Workday Web Services ([operation reference](https://community.workday.com/sites/default/files/file-hosting/productionapi/Integrations/v10/Rescind_Business_Process.html)).

### The gate that time cannot express

If payroll has completed since a business process was processed, that process **cannot be rescinded** ([UT Austin rescind guidance](https://workday.utexas.edu/support/rescind-guidance), [rescind request matrix](https://workday.utexas.edu/support/rescind-request-matrix)). This is not a duration. A `window_seconds` of any value would be wrong: too short and you refuse valid rollbacks, too long and you promise one that vanished the moment payroll ran.

Four gates, all of which your `GateEvaluator` must answer:

| Gate | Question |
|---|---|
| `workday_bp_rescindable` | Is the process Successfully Completed, and does the caller hold Rescind permission? |
| `workday_payroll_not_run` | Has payroll completed over the affected period? |
| `workday_no_dependent_process` | Does a later completed process depend on this one? |
| `workday_integrations_not_consumed` | Have outbound integrations already published this change downstream? |

That last one is the honest one. Rescinding in Workday does not retract what a payroll provider, benefits carrier, or provisioning system already received — and a rescind is reported as not updating the Future Full State Object in at least one integration context ([NetIQ Workday driver notes](https://www.netiq.com/documentation/identity-manager-48-drivers/workday/data/t4fjkgz3jowk.html)). Connectors have to handle rescinded and corrected records explicitly ([SailPoint](https://documentation.sailpoint.com/connectors/workday/help/integrating_workday/rescinded_and_corrected_.html)).

### Why `Correct` is not modeled as a cheap inverse

It is tempting: read the old value, correct it back, done. The specs mark correction-based flows `COMPENSABLE`, never `REVERSIBLE`, because a correction **rewrites** the record rather than reversing it. The effective-dated history ends up reading as though the corrected value was always intended, with no visible reversal. That is a materially weaker audit position than a rescind, and in a dispute that difference is the whole argument.

The numeric value is restored exactly. What is not restored is the record of what happened, and for an evidence system that is the part that counts.

### `workday.payroll.complete` is the most consequential action on this surface

Not because it resists undo, but because **it destroys other actions' undo paths.** Completing a payroll closes the rescind window on everything it covers. Any policy governing a Workday agent surface should treat payroll completion as an approval-required action for that reason alone, independent of its own reversibility.

---

## AWS (`cloud`)

**The governing insight: reversibility is a property of the target's configuration.** `DeleteObject` against a versioning-enabled bucket inserts a delete marker you can remove ([Working with delete markers](https://docs.aws.amazon.com/AmazonS3/latest/userguide/DeleteMarker.html), [Managing delete markers](https://docs.aws.amazon.com/AmazonS3/latest/userguide/ManagingDelMarkers.html)); the identical call against a non-versioned bucket destroys the object. Undeleting means deleting the delete marker, which requires its version id — and MFA Delete blocks version-specific deletes without an MFA code an automated undo cannot supply.

**Enabling versioning on every agent-writable bucket is the highest-leverage change available on this surface.** It converts every object delete and overwrite from irreversible to recoverable, for free.

- **IAM policy versioning is a genuine built-in undo.** IAM keeps up to five versions of a customer managed policy; rolling back means making a previous version default again with nothing deleted or recreated ([Versioning IAM policies](https://docs.aws.amazon.com/IAM/latest/UserGuide/access_policies_managed-versioning.html), [rollback example](https://docs.aws.amazon.com/IAM/latest/UserGuide/iam_example_iam_Scenario_RollbackPolicyVersion_section.html)). The five-version ceiling is the catch — capture the document too, so you can rebuild if the version was pruned.
- **`aws.iam.delete_role` is irreversible in the way that matters.** Recreating a role with the same name produces a different principal id, so every trust and resource policy referencing the old id must be rewritten. That is a migration, not an undo.
- **Route 53 changes are restorable; the outage is not.** The authoritative record reverts immediately, but resolvers keep serving the wrong answer until the previous TTL expires. Recorded as residue rather than glossed over — pair it with a policy rule capping TTL on agent-writable zones, which has to be set *before* the mistake.
- **`aws.s3.put_bucket_policy`** is a sequenced undo for the same reason as the SAP payment: re-block public access *first*, then restore the policy. The other order leaves a window in which the bucket is reachable, which is what the undo was meant to close.

---

## Entra ID and Okta (`identity`)

**Identity is the one surface where the undo is more dangerous than the original action.** Restoring a deleted account restores access. If the account was deleted because it was compromised, a well-meaning cascade hands the attacker their session back — and nothing in this package can tell the two cases apart. Hence the `identity_restore_is_intended` gate on every restore, and the rule to take away: **containment on an identity surface means disable, not delete.**

- **Entra soft-deletes on a fixed 30-day clock.** Users, Microsoft 365 groups, cloud security groups, and app registrations become restorable for 30 days, then are hard deleted and unrecoverable by anyone including Microsoft Support. The window is not customizable ([restore deleted groups](https://learn.microsoft.com/en-us/entra/identity/users/groups-restore-deleted), [restore deleted users](https://learn.microsoft.com/en-us/entra/fundamentals/users-restore), [recover from deletions](https://docs.azure.cn/en-us/entra/architecture/recover-from-deletions)). This is the rare case where `window_seconds` is exactly right.
- **But only certain object types soft-delete.** Distribution groups, among others, are hard deleted immediately. Same API verb, and one of them has no undo — which is why `entra_object_type_soft_deletes` is an authorize-phase gate.
- **Okta separates deactivate from delete, and only one is reversible.** Deactivation is undoable ([deactivate and delete accounts](https://help.okta.com/en-us/content/topics/users-groups-profiles/usgp-deactivate-user-account.htm)); deletion is not.
- **The Okta trap:** deactivating a user does **not** re-evaluate group rules, so the account keeps its memberships while inactive ([Okta support](https://support.okta.com/help/s/article/Deactivated-Users-not-Removed-From-Okta-Groups-Automatically?language=en_US)). An undo that only reactivates is correct; one that also "restores" memberships would grant access that was never removed. An inverse written from intuition rather than the docs gets this wrong in the direction of *more* access.

---

## GitHub and Kubernetes (`devops`)

**This is where snapshot-before-write earns its keep**, because it turns natively unrecoverable operations into recoverable ones.

- **A deleted branch.** GitHub offers a restore button only for branches attached to a pull request ([deleting and restoring branches](https://docs.github.com/en/repositories/configuring-branches-and-merges-in-your-repository/managing-branches-in-your-repository/deleting-and-restoring-branches-in-a-pull-request)); one deleted from the branches list has no UI path ([community discussion](https://github.com/orgs/community/discussions/55884)). Git's reflog does not help — **reflogs are local, cannot be fetched from a remote, and expire** ([reflog recovery](https://rewind.com/blog/how-to-restore-deleted-branch-commit-git-reflog/)). But a branch is a pointer: capture the tip SHA and recreating the ref is an exact inverse. Better than what GitHub itself offers.
- **A force push.** Same logic ([force-push recovery](https://github.com/orgs/community/discussions/146637)). Capturing `prior_sha` server-side removes the dependency on someone's local reflog entirely.
- **A merged PR is compensable, not reversible.** A revert adds a commit; history shows both, and any deployment the merge triggered stands.
- **`github.repo.delete` is marked irreversible conservatively.** Organization repos may be restorable within a retention window depending on plan and settings, but that was not verified — and classifying it optimistically is the exact mistake this file exists to prevent.
- **A deleted Kubernetes object.** `kubectl delete` has no undo. Capture the manifest first and re-applying it is a compensating action: the object returns with a fresh UID and recreated pods, so not perfect — but "we lost four minutes of uptime" beats "we lost the Deployment spec."
- **`kubectl rollout undo` has a hard cliff.** It works by pointing back at an old ReplicaSet, and `revisionHistoryLimit` (default 10) prunes them; once pruned, `unable to find specified revision` is final, because the configuration is stored nowhere else ([revision limits](https://oneuptime.com/blog/post/2026-02-09-deployment-rollback-history-revision-limits/view), [safe rollback](https://www.plural.sh/blog/kubectl-rollout-undo-deployment/)). A rollback capability that *looks* built-in silently evaporates under a burst of deploys — the phantom-rollback condition, exactly.
- **PersistentVolumeClaims.** With a `Delete` reclaim policy the volume goes with the claim, so re-applying restores the workload and not its data. Gated separately, because "the pods are running again" reads like success.

---

## Salesforce, Slack, Stripe (`saas`)

Three different shapes of "no".

**Salesforce says no on a clock, and sometimes early.** Deleted records sit in the Recycle Bin for 15 days by default — 30 in Classic if Support has enabled Extended Recycle Bin Retention — then hard delete ([retention limits](https://www.grax.com/blog/salesforce-recycle-bin-limits/), [Salesforce Help](https://help.salesforce.com/s/articleView?id=000387160&language=en_US&type=1)). But the bin holds at most **25× the org's storage allocation**, so records can purge *before* the window elapses under volume. A clock alone would over-promise, hence both a window and a gate.

**Slack says no because the message already arrived.** Deleting removes it from the channel and nothing else: the notification fired, people read it, and retention/export/DLP tooling likely holds a copy. The clearest case in the whole adapter set for separating "the record is reversed" from "the effect is reversed" — treat an agent posting to a channel with outsiders in it as effectively irreversible in policy, whatever the spec says.

**Stripe says no because the money moved.** A refund can be cancelled only while its status is `requires_action`, which only happens for payment methods needing customer action; in any other state it cannot be cancelled, and a fully-refunded charge cannot be refunded again ([cancel a refund](https://docs.stripe.com/api/refunds/cancel), [refunds guide](https://docs.stripe.com/refunds)). Classified compensable *only* because that narrow state exists, with the gate degrading it to irreversible in the ordinary case.

Note the pair `stripe.subscription.update` (schedule cancellation at period end — reversible) versus `stripe.subscription.cancel` (immediate — irreversible). Nearly identical in an agent's tool list, opposite in recoverability. That pair is worth showing to anyone who thinks reversibility is obvious from a tool name.

---

## Filesystem, git, shell (`workstation`)

The surface an MCP-governed coding agent actually touches, and where the documented 2025–26 losses happened: agents deleting production databases, wiping home directories, destroying business-critical data through single tool calls. **This is also the easiest surface to validate** — a temp directory and a scratch repo will do.

Three honest hard edges:

- **`git reset --hard` destroys work that was never in the object store.** Committed history is recoverable from the captured SHA, but uncommitted modifications to tracked files were never hashed into an object, so no reflog entry and no gc setting brings them back. The spec captures a `dirty` flag so the evidence pack can say whether this instance destroyed work or not, rather than stating a generic caveat.
- **`git clean` removes untracked files git never had a copy of.** Unambiguously irreversible, registered explicitly so it escalates rather than falling into `UNKNOWN` by accident.
- **`shell.exec` cannot be classified at all**, so it is `UNKNOWN` — which escalates to a human on every invocation. That is not a gap in the adapter; it is the correct answer, and the argument for giving agents specific tools instead of a shell. Where shell access is unavoidable, the *enforcement* layer's threat scanner and argument conditions are the control, not the reversal layer.

Two details worth copying: `fs.write_file` captures `existed`, because the correct undo for a file that did not exist is deletion rather than writing empty content; and `fs.delete_file` is compensable rather than reversible because the restored file has a new inode, breaking any hard links.

---

## Databases (`database`)

**Most database writes an agent makes are not recoverable by this control plane, and the specs say so.** `DROP TABLE` and `TRUNCATE` are irreversible; point-in-time recovery may exist at the infrastructure layer, but restoring a whole database to undo one statement is a DBA decision under an incident process, not an automated inverse. Arbitrary SQL is `UNKNOWN` for the same reason arbitrary shell is.

The useful control here is the **enforcement** layer, not the reversal layer: require a `WHERE` clause, cap affected rows, deny DDL. The reversal layer's honest contribution is making the unrecoverability visible at authorize time so policy escalates before the statement runs.

Two subtleties:

- **A row update is reversible only if nobody else touched the row.** Writing captured values back over a concurrent edit is data loss dressed as recovery, so `db.update_row` captures a `row_version` and gates on it. Without that, the undo is a blind overwrite — how a recovery becomes a second incident.
- **Migrations are the one designed inverse on this surface**, and still gated. A `down` step that drops the column the `up` added is technically an inverse and loses every value in it. Requiring down migrations in review and running them in CI is what makes the spec true; the spec cannot make it true on its own.

---

## Validation checklist

Do not skip this. The specs are a starting shape, not verified truth.

**Per spec:**
1. Execute the forward operation in a sandbox and capture the real response shape. Confirm every `result.*` path in the `arg_map` actually exists in it.
2. Execute the undo. Confirm it succeeds and that the resulting state matches what the `kind` claims — exact for `REVERSIBLE`, offsetting-with-named-residue for `COMPENSABLE`.
3. Attempt the undo **twice**. If the second attempt succeeds where the spec says `one_shot`, the spec is wrong. If it corrupts state, that is exactly what `one_shot` exists to prevent.
4. Verify each declared gate by forcing it closed (close the period; run payroll) and confirming your `GateEvaluator` reports it.
5. Confirm every `snapshot_fields` entry is actually readable by the credential your `state_reader` uses — and that this credential is **not** the agent's.

**Per landscape:**
6. Argument names differ between S/4HANA Cloud, on-premise releases, and whatever your middleware renames them to. Diff the specs against your own API contract.
7. Confirm which reversal reasons your finance team has configured and what posting-date rule each carries. Replace the `const:01` placeholders.
8. Confirm which Workday business processes expose Rescind **in your tenant**, and to which security groups. Business process configuration is per-tenant.
9. Run `revoco coverage <registry> --tools <your real tool list>` and drive the unclassified count to zero. It exits non-zero, so wire it into CI: adding a write operation without classifying its undo path should fail the build.

**Ongoing:**
10. Re-validate after every ERP upgrade. A changed API contract turns a correct spec into a confident, wrong rollback, and nothing in this package can detect that for you.

---

## Using them

```python
from revoco import ControlPlane
from revoco.adapters import registry_for

def gate_evaluator(ctx):
    # ctx.phase is "authorize" (before the write, ctx.entry is None) or "undo".
    # ctx.gate, ctx.tool, ctx.args are always present.
    if ctx.gate.name == "aws_s3_versioning_enabled":
        return my_aws.bucket_versioning_on(ctx.args["Bucket"])
    if ctx.gate.name == "sap_period_open":
        return my_erp.is_period_open(ctx.args.get("FiscalYear"))
    if ctx.gate.name == "workday_payroll_not_run":
        return not my_workday.payroll_completed_for(ctx.entry.plan.snapshot)
    return False   # unknown gate: fail closed

cp = ControlPlane(
    inverse_registry=registry_for("cloud", "devops", "workstation"),
    state_reader=my_reader,          # read-only, NOT the agent's credential
    gate_evaluator=gate_evaluator,
)
```

Load only the surfaces you actually govern — a registry claiming to classify SAP postings in a shop with no SAP is noise in every coverage report.

Return `True` to open a gate, `False` to close it, or a **string** to close it with an explanation that reaches the incident responder. Raising is treated as closed.

A spec that declares gates and runs without an evaluator refuses to execute, and an authorize-phase gate with no evaluator degrades the classification to irreversible. Both are deliberate: an unverifiable precondition is not a precondition, and at authorize time "assume the worst" is what makes the escalation trustworthy.
