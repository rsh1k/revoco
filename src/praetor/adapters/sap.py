"""
praetor.adapters.sap
====================
Inverse-operation specs for SAP S/4HANA financial writes.

Status: **specification, not a validated integration.** These specs encode
reversal semantics gathered from SAP documentation, KBAs, and practitioner
sources (cited per spec in ``docs/ADAPTERS.md``). They have not been executed
against a live system. Argument names in particular follow the S/4HANA Cloud
OData/SOAP surface and will need adjusting for on-premise releases, custom
fields, and your own middleware naming. Validate every spec against a sandbox
before trusting it — a tool mapped to the wrong inverse produces a confident,
wrong rollback, which is worse than having none.

The three things SAP gets right that most models get wrong
---------------------------------------------------------
**1. Nothing is deleted; things are reversed.** Posting a document and then
reversing it leaves *two* documents. So no financial posting is ever
``REVERSIBLE`` here — the best available is ``COMPENSABLE``, and the residue is
that the original posting remains permanently visible. Anyone modeling an FI
reversal as an exact inverse has misunderstood the ledger.

**2. A reversal cannot be posted against cleared items.** Reversing a payment is
a *sequence*: void the payment medium, reset the clearing (``FBRA``), then post
the reversal (``FB08``). Order is load-bearing. Resetting clearing before voiding
the cheque leaves the ledger saying the money was never paid while the bank says
it was.

**3. The undo is single-use.** A reversal document cannot itself be reversed;
correcting a mistaken reversal requires a fresh manual posting. Hence
``one_shot=True`` on every reversal spec.

Why the vendor-bank spec matters most
-------------------------------------
Vendor-master bank tampering followed by a payment run is *the* canonical
agent-assisted payment fraud. It is also the case where SAP's own audit trail may
not be enough to recover: where bank fields are configured as sensitive, the
change log can display the new value as ``*** Deleted ***`` (KBA 3475932),
``FK08`` may not show every sensitive-field change (KBA 2518672), and vendor bank
updates have been reported missing from change logs entirely (KBA 2518878).

That is the strongest argument for this whole architecture. If the prior bank
account cannot be reliably read back out of SAP's change documents *after* the
fact, then capturing it before the write is not a nice-to-have — it is the only
place the value exists.
"""

from __future__ import annotations

from ..reversal.model import InverseSpec, InverseStep, ReversalGate, Reversibility
from ..reversal.registry import InverseRegistry

# ---------------------------------------------------------------------------
# Gates. Your GateEvaluator must recognize these names. Each is an *event*
# condition, not a duration — which is precisely why window_seconds cannot
# express them.
# ---------------------------------------------------------------------------

GATE_PERIOD_OPEN = ReversalGate(
    name="sap_period_open",
    description=(
        "The accounting period of the document being reversed must be open. A "
        "reversal posted into a closed period is rejected."
    ),
    remediation=(
        "Either reopen the period (OB52 / Manage Posting Periods), or post the "
        "reversal to the current open period and accept that the reversal lands in "
        "a different period from the original."
    ),
)

GATE_NOT_CLEARED = ReversalGate(
    name="sap_items_not_cleared",
    description=(
        "The document must have no already-cleared line items, or the clearing must "
        "have been reset first. SAP refuses a reversal that would need to clear an "
        "item another process already cleared."
    ),
    remediation="Reset the clearing with FBRA before attempting the reversal.",
)

GATE_PAYMENT_NOT_SETTLED = ReversalGate(
    name="sap_payment_not_settled",
    description=(
        "The outbound payment must not have settled at the bank. Once funds have "
        "left, voiding the payment medium changes the ledger but not reality."
    ),
    remediation=(
        "Confirm against the bank statement / payment status before reversing. If "
        "settled, this is a recovery matter for treasury, not a rollback."
    ),
)

GATE_DUAL_CONTROL_CLEAR = ReversalGate(
    name="sap_bank_dual_control_confirmable",
    description=(
        "Where supplier bank fields are configured as sensitive, restoring them "
        "re-triggers dual-control confirmation. Until a second person confirms, the "
        "supplier is blocked for payment."
    ),
    remediation=(
        "Ensure a confirmer is available (FK08 / Confirm Supplier List), or accept "
        "that the supplier stays payment-blocked until they are."
    ),
)

SAP_GATES = (
    GATE_PERIOD_OPEN,
    GATE_NOT_CLEARED,
    GATE_PAYMENT_NOT_SETTLED,
    GATE_DUAL_CONTROL_CLEAR,
)


# ---------------------------------------------------------------------------
# Specs
# ---------------------------------------------------------------------------

SAP_SPECS: list[InverseSpec] = [
    # -- reads --------------------------------------------------------------
    InverseSpec(
        tool="sap.journalentry.read",
        kind=Reversibility.REVERSIBLE,
        inverse_tool="sap.noop",
        notes="A read changes nothing, so its undo is trivially complete.",
    ),
    InverseSpec(
        tool="sap.supplier.read",
        kind=Reversibility.REVERSIBLE,
        inverse_tool="sap.noop",
        notes=(
            "Reading supplier bank data triggers SAP Read Access Logging where "
            "configured. The read is free to undo but not free to perform."
        ),
    ),
    # -- journal entries ----------------------------------------------------
    InverseSpec(
        tool="sap.journalentry.post",
        kind=Reversibility.COMPENSABLE,
        inverse_tool="sap.journalentry.reverse",
        arg_map=(
            ("AccountingDocument", "result.AccountingDocument"),
            ("CompanyCode", "args.CompanyCode"),
            ("FiscalYear", "result.FiscalYear"),
            ("ReversalReason", "const:01"),
        ),
        gates=(GATE_PERIOD_OPEN, GATE_NOT_CLEARED),
        one_shot=True,
        residue=(
            "Reversal creates a second, offsetting document; the original posting "
            "remains permanently in the ledger and in every report already run "
            "against it. If the original period has closed, the reversal posts to a "
            "later period, so both periods' figures move. The reversal document "
            "cannot itself be reversed."
        ),
        notes=(
            "ReversalReason drives the posting date rule: reason 01 as delivered "
            "permits only the original posting date, so a reversal in a closed "
            "period requires a reason configured to allow an alternative date. Pick "
            "the reason your finance team has configured — this default is a "
            "placeholder, not a recommendation."
        ),
    ),
    InverseSpec(
        tool="sap.journalentry.reverse",
        kind=Reversibility.IRREVERSIBLE,
        notes=(
            "Registered deliberately. A reversal document cannot be reversed; "
            "correcting a mistaken reversal needs a fresh manual posting (F-02). "
            "Classifying it as irreversible means an agent calling reverse directly "
            "escalates to a human under the starter policy, instead of inheriting "
            "the illusion that reversal is always safe."
        ),
    ),
    InverseSpec(
        tool="sap.journalentry.park",
        kind=Reversibility.REVERSIBLE,
        inverse_tool="sap.journalentry.delete_parked",
        arg_map=(
            ("AccountingDocument", "result.AccountingDocument"),
            ("CompanyCode", "args.CompanyCode"),
            ("FiscalYear", "result.FiscalYear"),
        ),
        notes=(
            "The useful contrast: a *parked* document has not posted, so deleting it "
            "is a true inverse with no ledger trace. Routing agent postings through "
            "park-then-human-post is the cheapest way to convert an irreversible "
            "surface into a reversible one."
        ),
    ),
    # -- supplier master: the fraud-critical path ---------------------------
    InverseSpec(
        tool="sap.supplier.bank.update",
        kind=Reversibility.REVERSIBLE,
        inverse_tool="sap.supplier.bank.update",
        arg_map=(
            ("BusinessPartner", "args.BusinessPartner"),
            ("BankIdentification", "args.BankIdentification"),
            ("BankCountryKey", "snapshot.BankCountryKey"),
            ("BankNumber", "snapshot.BankNumber"),
            ("BankAccount", "snapshot.BankAccount"),
            ("BankControlKey", "snapshot.BankControlKey"),
            ("IBAN", "snapshot.IBAN"),
        ),
        static_args=(("_praetor_reason", "restore prior banking details"),),
        snapshot_fields=(
            "BankCountryKey",
            "BankNumber",
            "BankAccount",
            "BankControlKey",
            "IBAN",
        ),
        gates=(GATE_DUAL_CONTROL_CLEAR,),
        notes=(
            "THE spec to get right. Writing back the captured prior values restores "
            "state exactly, which is why this fraud pattern is recoverable at all — "
            "but only if the prior values were captured before the write. SAP's own "
            "change log is not a dependable fallback here: sensitive bank fields can "
            "log as '*** Deleted ***' (KBA 3475932), FK08 may omit sensitive-field "
            "changes (KBA 2518672), and vendor bank updates have been reported "
            "missing from change logs entirely (KBA 2518878). Restoring also writes "
            "a new CDHDR/CDPOS record, so the audit trail shows two changes rather "
            "than none."
        ),
    ),
    InverseSpec(
        tool="sap.supplier.bank.create",
        kind=Reversibility.COMPENSABLE,
        inverse_tool="sap.supplier.bank.delete",
        arg_map=(
            ("BusinessPartner", "args.BusinessPartner"),
            ("BankIdentification", "args.BankIdentification"),
        ),
        gates=(GATE_DUAL_CONTROL_CLEAR,),
        residue=(
            "The bank-details record is removed but the change history retains "
            "evidence that the account existed. Any payment proposal built while it "
            "existed must be re-checked separately."
        ),
        notes=(
            "Note for IDoc-based landscapes: DEBMAS/CREMAS do not delete bank "
            "details (KBA 3344959), so an IDoc-driven 'undo' silently leaves the "
            "account in place. Use the API or a direct maintenance path, and verify "
            "removal rather than assuming it."
        ),
    ),
    InverseSpec(
        tool="sap.supplier.block",
        kind=Reversibility.REVERSIBLE,
        inverse_tool="sap.supplier.set_block",
        arg_map=(
            ("BusinessPartner", "args.BusinessPartner"),
            ("PostingBlock", "snapshot.PostingBlock"),
            ("PaymentBlock", "snapshot.PaymentBlock"),
        ),
        snapshot_fields=("PostingBlock", "PaymentBlock"),
        notes=(
            "Blocking is reversible and cheap, which makes it the right *containment* "
            "action for an agent-driven incident: block first, then work out what to "
            "reverse."
        ),
    ),
    # -- payments: the multi-step case --------------------------------------
    InverseSpec(
        tool="sap.payment.post",
        kind=Reversibility.COMPENSABLE,
        steps=(
            InverseStep(
                name="void_medium",
                tool="sap.paymentmedium.void",
                arg_map=(
                    ("PaymentDocument", "result.PaymentDocument"),
                    ("CompanyCode", "args.CompanyCode"),
                    ("FiscalYear", "result.FiscalYear"),
                ),
                description=(
                    "Void the cheque or payment medium FIRST. If a medium was issued "
                    "and this is skipped, the ledger and the bank statement disagree "
                    "the moment clearing is reset."
                ),
                critical=True,
            ),
            InverseStep(
                name="reset_clearing",
                tool="sap.clearing.reset",
                arg_map=(
                    ("ClearingDocument", "result.PaymentDocument"),
                    ("CompanyCode", "args.CompanyCode"),
                    ("FiscalYear", "result.FiscalYear"),
                ),
                description=(
                    "FBRA. A reversal cannot be posted against cleared items, so the "
                    "clearing must be reset before FB08 will accept the document. "
                    "FBRA can also reset-and-reverse in one action; these are kept "
                    "separate so a partial failure names the step it stopped at."
                ),
                critical=True,
            ),
            InverseStep(
                name="reverse_document",
                tool="sap.journalentry.reverse",
                arg_map=(
                    ("AccountingDocument", "result.PaymentDocument"),
                    ("CompanyCode", "args.CompanyCode"),
                    ("FiscalYear", "result.FiscalYear"),
                    ("ReversalReason", "const:01"),
                ),
                description="FB08. Posts the offsetting document.",
                critical=True,
            ),
        ),
        gates=(GATE_PAYMENT_NOT_SETTLED, GATE_PERIOD_OPEN),
        one_shot=True,
        residue=(
            "The remittance advice already sent to the supplier is not recalled. The "
            "payment appears as a void rather than an absence on the bank statement, "
            "and the cheque number is consumed. If the funds already settled, none of "
            "this returns the money — it only corrects the books."
        ),
        notes=(
            "The canonical sequenced undo, and the reason InverseStep exists. If your "
            "landscape issues no payment media, drop the void step; if it issues them "
            "asynchronously, the void may need its own gate."
        ),
    ),
    InverseSpec(
        tool="sap.paymentrun.execute",
        kind=Reversibility.IRREVERSIBLE,
        notes=(
            "F110 in anger. A payment run can produce hundreds of payment documents "
            "and a transmitted payment file in one action, so there is no single "
            "inverse — recovery means reversing each resulting document individually, "
            "assuming the file has not gone to the bank. Classified irreversible so "
            "policy forces a human onto the run itself, which is where the control "
            "belongs."
        ),
    ),
    InverseSpec(
        tool="sap.paymentfile.transmit",
        kind=Reversibility.IRREVERSIBLE,
        notes="Once the file is with the bank, this system has no inverse to offer.",
    ),
]


def sap_registry() -> InverseRegistry:
    """An :class:`InverseRegistry` preloaded with the SAP specs.

    Remember these are unvalidated. Run ``praetor inverses-check`` on the YAML
    equivalent, then test each spec against a sandbox company code before any of
    it governs a real posting.
    """
    return InverseRegistry(list(SAP_SPECS))


__all__ = ["SAP_SPECS", "SAP_GATES", "sap_registry",
           "GATE_PERIOD_OPEN", "GATE_NOT_CLEARED",
           "GATE_PAYMENT_NOT_SETTLED", "GATE_DUAL_CONTROL_CLEAR"]
