"""
revoco.adapters.saas
=====================
Inverse-operation specs for Salesforce, Slack, and Stripe.

Status: **specification, not a validated integration.** See ``docs/ADAPTERS.md``
for citations and the validation checklist.

Three different shapes of "no"
------------------------------
**Salesforce says no on a clock, and sometimes early.** Deleted records sit in the
Recycle Bin for 15 days by default (30 in Classic, if Support has enabled Extended
Recycle Bin Retention), then hard delete. But the bin also holds at most 25× the
org's storage allocation, so records can be purged *before* the window elapses
under volume. A time window alone would therefore over-promise — hence a gate on
the record still being in the bin, alongside the clock.

**Slack says no because the message already arrived.** Deleting a message removes
it from the channel and from nothing else. The notification fired, people read it,
and DLP and export tooling likely retained it. The API call succeeds and the
disclosure is permanent, which makes this the clearest case in the whole adapter
set for the distinction between "the record is reversed" and "the effect is
reversed".

**Stripe says no because the money moved.** A refund can be cancelled only while
its status is ``requires_action``; in any other state it cannot be cancelled at
all, and a fully-refunded charge cannot be refunded again. This is the canonical
irreversible action and it is classified as such rather than dressed up with a
compensating transfer, because "send the money back the other way" is a new
payment with its own risk, not an undo.
"""

from __future__ import annotations

from ..reversal.model import InverseSpec, ReversalGate, Reversibility
from ..reversal.registry import InverseRegistry

_SF_RECYCLE_BIN_WINDOW = 15 * 24 * 3600.0  # default; 30d possible in Classic

# ---------------------------------------------------------------------------
# Gates
# ---------------------------------------------------------------------------

GATE_SF_IN_RECYCLE_BIN = ReversalGate(
    name="salesforce_record_still_in_recycle_bin",
    description=(
        "The record must still be in the Recycle Bin. Beyond the retention window it "
        "is hard deleted — and the bin holds only 25x the org's storage allocation, so "
        "records can be purged early under volume regardless of age."
    ),
    remediation=(
        "Recover from a backup or an archival store. The storage cap means the clock "
        "alone is not a guarantee, which is why this is checked rather than assumed."
    ),
)

GATE_STRIPE_REFUND_CANCELLABLE = ReversalGate(
    name="stripe_refund_requires_action",
    description=(
        "A refund can be cancelled only while its status is requires_action, which "
        "only happens for payment methods needing customer action. In any other state "
        "it cannot be cancelled."
    ),
    remediation=(
        "There is no undo. If the refund was wrong, collecting the funds again is a "
        "new payment with its own authorization and dispute risk."
    ),
)

SAAS_GATES = (GATE_SF_IN_RECYCLE_BIN, GATE_STRIPE_REFUND_CANCELLABLE)


SAAS_SPECS: list[InverseSpec] = [
    # -- Salesforce ---------------------------------------------------------
    InverseSpec(
        tool="salesforce.record.delete",
        kind=Reversibility.COMPENSABLE,
        inverse_tool="salesforce.record.undelete",
        arg_map=(("Id", "args.Id"),),
        snapshot_fields=("Id", "Name", "OwnerId"),
        window_seconds=_SF_RECYCLE_BIN_WINDOW,
        gates=(GATE_SF_IN_RECYCLE_BIN,),
        residue=(
            "Undelete restores the record and most relationships, but automation that "
            "fired on the delete — workflow, flows, roll-up recalculation, outbound "
            "integrations — already ran, and reports produced while it was absent were "
            "wrong."
        ),
        notes=(
            "Both a clock and a gate, because the 15-day window is not the only way to "
            "lose the record: the Recycle Bin is capped at 25x storage allocation and "
            "purges early under volume. Trusting the clock alone would over-promise."
        ),
    ),
    InverseSpec(
        tool="salesforce.record.hard_delete",
        kind=Reversibility.IRREVERSIBLE,
        notes=(
            "Bypasses the Recycle Bin entirely. Registered separately from the normal "
            "delete precisely so policy can treat them differently — the same-looking "
            "operation with the safety net removed."
        ),
    ),
    InverseSpec(
        tool="salesforce.record.update",
        kind=Reversibility.REVERSIBLE,
        inverse_tool="salesforce.record.update",
        arg_map=(
            ("Id", "args.Id"),
            ("fields", "snapshot.fields"),
        ),
        snapshot_fields=("fields",),
        notes=(
            "Capture exactly the fields the forward call intends to write, not the "
            "whole record: a blind full-record restore would clobber concurrent edits "
            "made by other users in between."
        ),
    ),
    # -- Slack --------------------------------------------------------------
    InverseSpec(
        tool="slack.chat.post_message",
        kind=Reversibility.COMPENSABLE,
        inverse_tool="slack.chat.delete",
        arg_map=(("channel", "args.channel"), ("ts", "result.ts")),
        residue=(
            "The message disappears from the channel and from nowhere else. Push and "
            "email notifications already went out, anyone watching has read it, and "
            "retention, export, and DLP tooling likely holds a copy. If it contained "
            "something confidential, deletion does not undo the disclosure."
        ),
        notes=(
            "The clearest case in this whole adapter set for separating 'the record is "
            "reversed' from 'the effect is reversed'. Treat an agent posting to a "
            "channel with outsiders in it as effectively irreversible in policy, "
            "whatever this spec says."
        ),
    ),
    InverseSpec(
        tool="slack.chat.update",
        kind=Reversibility.COMPENSABLE,
        inverse_tool="slack.chat.update",
        arg_map=(
            ("channel", "args.channel"),
            ("ts", "args.ts"),
            ("text", "snapshot.text"),
        ),
        snapshot_fields=("text",),
        residue=(
            "The text reverts but the message shows as edited, and anyone who read the "
            "intermediate version read it."
        ),
    ),
    InverseSpec(
        tool="slack.chat.delete",
        kind=Reversibility.IRREVERSIBLE,
        notes=(
            "There is no undelete. An agent tidying a channel destroys the record, "
            "which on a surface people treat as a business record is a retention issue "
            "as much as an availability one."
        ),
    ),
    InverseSpec(
        tool="slack.conversations.archive",
        kind=Reversibility.REVERSIBLE,
        inverse_tool="slack.conversations.unarchive",
        arg_map=(("channel", "args.channel"),),
    ),
    # -- Stripe -------------------------------------------------------------
    InverseSpec(
        tool="stripe.refund.create",
        kind=Reversibility.COMPENSABLE,
        inverse_tool="stripe.refund.cancel",
        arg_map=(("refund", "result.id"),),
        gates=(GATE_STRIPE_REFUND_CANCELLABLE,),
        degraded_kind=Reversibility.IRREVERSIBLE,
        residue=(
            "Cancellation is possible only in the narrow requires_action state. In "
            "every other case the money has moved and the only remedy is a fresh "
            "charge, which is a new payment with its own authorization and dispute "
            "risk rather than a reversal."
        ),
        notes=(
            "Classified compensable only because that narrow cancellable state exists. "
            "The gate degrades it to irreversible in the ordinary case, which is the "
            "honest default — and the reason policy should require approval on agent "
            "refunds rather than leaning on this spec."
        ),
    ),
    InverseSpec(
        tool="stripe.payment_intent.cancel",
        kind=Reversibility.IRREVERSIBLE,
        notes=(
            "Cancelling an authorized-but-uncaptured PaymentIntent is not a refund and "
            "has no inverse: the authorization is released and a new PaymentIntent must "
            "be created, which means re-obtaining customer consent."
        ),
    ),
    InverseSpec(
        tool="stripe.subscription.update",
        kind=Reversibility.REVERSIBLE,
        inverse_tool="stripe.subscription.update",
        arg_map=(
            ("subscription", "args.subscription"),
            ("cancel_at_period_end", "snapshot.cancel_at_period_end"),
        ),
        snapshot_fields=("cancel_at_period_end",),
        notes=(
            "Scheduling a cancellation at period end is reversible by unscheduling it. "
            "Registered separately from immediate cancellation below, because the two "
            "differ entirely in recoverability while looking almost identical in an "
            "agent's tool list."
        ),
    ),
    InverseSpec(
        tool="stripe.subscription.cancel",
        kind=Reversibility.IRREVERSIBLE,
        notes=(
            "Immediate cancellation cannot be undone; a new subscription is a new "
            "object with new billing anchors, not a restoration. Contrast with the "
            "update above — this is the pair worth putting in front of anyone who "
            "thinks reversibility is obvious from a tool name."
        ),
    ),
    InverseSpec(
        tool="stripe.customer.delete",
        kind=Reversibility.IRREVERSIBLE,
        notes="Permanent, and it detaches payment methods and cancels subscriptions with it.",
    ),
]


def saas_registry() -> InverseRegistry:
    """An :class:`InverseRegistry` preloaded with the SaaS specs (unvalidated)."""
    return InverseRegistry(list(SAAS_SPECS))


__all__ = ["SAAS_SPECS", "SAAS_GATES", "saas_registry"]
