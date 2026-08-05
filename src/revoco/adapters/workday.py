"""
revoco.adapters.workday
========================
Inverse-operation specs for Workday HCM writes.

Status: **specification, not a validated integration.** Semantics gathered from
Workday Web Services documentation and customer-published administration guides
(cited in ``docs/ADAPTERS.md``). Not executed against a live tenant. Business
process configuration is per-tenant, so which processes are even rescindable in
*your* tenant is a question only your tenant can answer.

Workday's model, and why it maps cleanly
----------------------------------------
Workday distinguishes three corrective actions, and the distinction is exactly the
one this package cares about:

* **Cancel** — available only while a business process is *In Progress*. Reverses
  all data changes.
* **Rescind** — available only once a business process is *Successfully
  Completed*. Reverses all data changes. **Cannot itself be undone.**
* **Correct** — edits values on a completed process. Does *not* reverse; the new
  value replaces the old in the record's effective history.

Because the control plane commits a journal entry only after the forward action
has actually completed, **Rescind is the inverse that matters**. Cancel applies to
a window this package does not model — a process still awaiting approval has not
yet changed anything to undo.

The gate that time cannot express
---------------------------------
Rescind availability is bounded by *downstream events*, not elapsed time. Once
payroll has completed over a compensation change, that change is no longer
rescindable — at any age. A ``window_seconds`` of any value would be wrong: too
short and you refuse valid rollbacks, too long and you promise one that vanished
the moment payroll ran. This is what :class:`ReversalGate` is for.

Correct is not an undo
----------------------
It is tempting to model *Correct* as a cheap inverse: read the old value, correct
it back. The specs below that do this are marked ``COMPENSABLE``, never
``REVERSIBLE``, because a correction rewrites the record rather than reversing it.
The effective-dated history ends up showing the corrected value as though it had
always been intended, which is a materially different audit position from a
visible rescind — and in a dispute, that difference is the whole argument.
"""

from __future__ import annotations

from ..reversal.model import InverseSpec, ReversalGate, Reversibility
from ..reversal.registry import InverseRegistry

# ---------------------------------------------------------------------------
# Gates
# ---------------------------------------------------------------------------

GATE_BP_RESCINDABLE = ReversalGate(
    name="workday_bp_rescindable",
    description=(
        "The business process must be in Successfully Completed status and must "
        "expose the Rescind action to the caller's security groups."
    ),
    remediation=(
        "Check the process status and that the actor holds a role with Rescind "
        "permission (typically Business Process Administrator) for this process type."
    ),
)

GATE_PAYROLL_NOT_RUN = ReversalGate(
    name="workday_payroll_not_run",
    description=(
        "Payroll must not have completed over the period this change affects. Once it "
        "has, the change is no longer rescindable regardless of how recent it is."
    ),
    remediation=(
        "If payroll has run, this is a payroll-correction matter (retro processing / "
        "off-cycle adjustment), not a rollback. Escalate to a payroll partner."
    ),
)

GATE_NO_DOWNSTREAM_BP = ReversalGate(
    name="workday_no_dependent_process",
    description=(
        "No later business process may depend on this one. Workday blocks a rescind "
        "whose effects a subsequent completed process relies on."
    ),
    remediation=(
        "Rescind the dependent processes first, newest to oldest. A cascade over the "
        "delegation subtree already runs in that order."
    ),
)

GATE_INTEGRATIONS_NOT_CONSUMED = ReversalGate(
    name="workday_integrations_not_consumed",
    description=(
        "Outbound integrations must not have already published this change to "
        "downstream systems (payroll provider, badge system, benefits carrier). "
        "Rescinding in Workday does not retract what those systems received."
    ),
    remediation=(
        "Check integration event history for the period. If published, the downstream "
        "systems need their own correction — treat this as compensable, not reversed."
    ),
)

WORKDAY_GATES = (
    GATE_BP_RESCINDABLE,
    GATE_PAYROLL_NOT_RUN,
    GATE_NO_DOWNSTREAM_BP,
    GATE_INTEGRATIONS_NOT_CONSUMED,
)


# A rescind's residue is the same wherever it is used, so it is stated once. The
# integration-visibility clause is the one people forget: Workday's own record is
# clean afterwards, and every system downstream of it is not.
_RESCIND_RESIDUE = (
    "Rescinding reverses the data in Workday but does not retract what outbound "
    "integrations already published, so downstream systems (payroll provider, "
    "benefits carriers, provisioning) may still hold the change. The rescinded "
    "transaction remains visible in the worker's process history, and the rescind "
    "itself cannot be undone."
)


WORKDAY_SPECS: list[InverseSpec] = [
    # -- reads --------------------------------------------------------------
    InverseSpec(
        tool="workday.worker.read",
        kind=Reversibility.REVERSIBLE,
        inverse_tool="workday.noop",
        notes="A read changes nothing.",
    ),
    # -- the rescind family -------------------------------------------------
    InverseSpec(
        tool="workday.compensation.request_change",
        kind=Reversibility.COMPENSABLE,
        inverse_tool="workday.bp.rescind",
        arg_map=(
            ("Business_Process_Reference", "result.Business_Process_Reference"),
            ("Comment", "const:rescinded by revoco control plane"),
        ),
        snapshot_fields=("Total_Base_Pay", "Pay_Rate", "Currency", "Frequency"),
        gates=(
            GATE_BP_RESCINDABLE,
            GATE_PAYROLL_NOT_RUN,
            GATE_NO_DOWNSTREAM_BP,
            GATE_INTEGRATIONS_NOT_CONSUMED,
        ),
        one_shot=True,
        residue=_RESCIND_RESIDUE,
        notes=(
            "The snapshot is captured even though rescind does not need it, for two "
            "reasons: it lets an evidence pack state what the compensation actually "
            "was before the change, and it leaves a manual restore path if the rescind "
            "gate is closed and someone has to put the value back by hand."
        ),
    ),
    InverseSpec(
        tool="workday.job.change_job",
        kind=Reversibility.COMPENSABLE,
        inverse_tool="workday.bp.rescind",
        arg_map=(
            ("Business_Process_Reference", "result.Business_Process_Reference"),
            ("Comment", "const:rescinded by revoco control plane"),
        ),
        snapshot_fields=("Position_ID", "Job_Profile", "Supervisory_Organization", "Location"),
        gates=(GATE_BP_RESCINDABLE, GATE_PAYROLL_NOT_RUN, GATE_NO_DOWNSTREAM_BP),
        one_shot=True,
        residue=_RESCIND_RESIDUE,
    ),
    InverseSpec(
        tool="workday.staffing.hire",
        kind=Reversibility.COMPENSABLE,
        inverse_tool="workday.bp.rescind",
        arg_map=(
            ("Business_Process_Reference", "result.Business_Process_Reference"),
            ("Comment", "const:rescinded by revoco control plane"),
        ),
        gates=(
            GATE_BP_RESCINDABLE,
            GATE_PAYROLL_NOT_RUN,
            GATE_NO_DOWNSTREAM_BP,
            GATE_INTEGRATIONS_NOT_CONSUMED,
        ),
        one_shot=True,
        residue=(
            _RESCIND_RESIDUE
            + " A rescinded hire also consumes the employee ID, and any account "
            "provisioned by an integration during the window needs separate "
            "deprovisioning."
        ),
    ),
    InverseSpec(
        tool="workday.staffing.terminate",
        kind=Reversibility.COMPENSABLE,
        inverse_tool="workday.bp.rescind",
        arg_map=(
            ("Business_Process_Reference", "result.Business_Process_Reference"),
            ("Comment", "const:rescinded by revoco control plane"),
        ),
        gates=(
            GATE_BP_RESCINDABLE,
            GATE_PAYROLL_NOT_RUN,
            GATE_NO_DOWNSTREAM_BP,
            GATE_INTEGRATIONS_NOT_CONSUMED,
        ),
        one_shot=True,
        residue=(
            _RESCIND_RESIDUE
            + " Access revoked by downstream provisioning during the window is not "
            "automatically restored, and benefits events already triggered may need "
            "manual reversal."
        ),
        notes=(
            "An agent-initiated termination is the highest-consequence write on this "
            "surface. Even though it is technically rescindable, treat it as an "
            "approval-required action in policy rather than relying on the undo."
        ),
    ),
    # -- correct is not an undo ---------------------------------------------
    InverseSpec(
        tool="workday.compensation.correct",
        kind=Reversibility.COMPENSABLE,
        inverse_tool="workday.compensation.correct",
        arg_map=(
            ("Worker_Reference", "args.Worker_Reference"),
            ("Total_Base_Pay", "snapshot.Total_Base_Pay"),
            ("Currency", "snapshot.Currency"),
            ("Frequency", "snapshot.Frequency"),
            ("Comment", "const:corrected back by revoco control plane"),
        ),
        snapshot_fields=("Total_Base_Pay", "Currency", "Frequency"),
        gates=(GATE_PAYROLL_NOT_RUN,),
        residue=(
            "Correct rewrites the record rather than reversing it. After correcting "
            "back, the effective-dated history reads as though the corrected value was "
            "always intended, with no visible reversal — a materially weaker audit "
            "position than a rescind, and the difference that matters in a dispute."
        ),
        notes=(
            "Deliberately COMPENSABLE, not REVERSIBLE, even though the numeric value "
            "is restored exactly. What is not restored is the record of what happened, "
            "and for an evidence system that is the part that counts."
        ),
    ),
    # -- irreversible -------------------------------------------------------
    InverseSpec(
        tool="workday.bp.rescind",
        kind=Reversibility.IRREVERSIBLE,
        notes=(
            "Registered deliberately. A rescind cannot be un-rescinded. If an agent "
            "can call rescind directly, that call needs a human on it — the undo "
            "button is itself a one-way door."
        ),
    ),
    InverseSpec(
        tool="workday.payroll.complete",
        kind=Reversibility.IRREVERSIBLE,
        notes=(
            "Completing a payroll closes the rescind window on everything it covers, "
            "which makes it the single most consequential action on this surface: it "
            "does not just resist undo, it destroys other actions' undo paths."
        ),
    ),
    InverseSpec(
        tool="workday.payment.settle",
        kind=Reversibility.IRREVERSIBLE,
        notes="Funds disbursed. No inverse exists inside Workday.",
    ),
]


def workday_registry() -> InverseRegistry:
    """An :class:`InverseRegistry` preloaded with the Workday specs.

    Unvalidated. Business process configuration is per-tenant: confirm which
    processes expose Rescind in your tenant, and to which security groups, before
    relying on any of this.
    """
    return InverseRegistry(list(WORKDAY_SPECS))


__all__ = [
    "WORKDAY_SPECS",
    "WORKDAY_GATES",
    "workday_registry",
    "GATE_BP_RESCINDABLE",
    "GATE_PAYROLL_NOT_RUN",
    "GATE_NO_DOWNSTREAM_BP",
    "GATE_INTEGRATIONS_NOT_CONSUMED",
]
