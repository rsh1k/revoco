"""
revoco.demo
============
An end-to-end scenario: agent-assisted vendor-payment fraud, caught and undone.

The scenario is chosen because it is the most common real shape of agentic
financial loss, and because it exercises every stage. An agent with legitimate
accounts-payable authority is induced — via injected content in an invoice
document — to repoint a supplier's banking details and then pay an invoice into
the attacker's account.

Each of the three merged tools would have handled part of this and left the rest:

* provenance alone proves who authorized the change, after the money has gone
* enforcement alone blocks the call if a rule anticipated it, and logs nothing
  usable about prior state if it did not
* neither restores the vendor's real bank account

The control plane does all of it, and then answers the question an auditor will
actually ask: prove it.

Run with ``revoco demo`` or ``python -m revoco.demo``.
"""

from __future__ import annotations

import copy
from typing import Any

from .authority.scope import Scope
from .controlplane import ControlPlane
from .core import crypto
from .evidence import build_evidence_pack
from .gate.policy import load_policy
from .reversal.model import Reversibility
from .reversal.registry import ap_starter_registry


# ---------------------------------------------------------------------------
# A stand-in system of record. Real integrations replace this with an ERP client.
# ---------------------------------------------------------------------------
class FakeERP:
    def __init__(self) -> None:
        self.vendors: dict[str, dict[str, Any]] = {
            "V-100": {
                "name": "Northwind Components",
                "bank_account": "GB29-REAL-8888-1234",
                "remit_to": "accounts@northwind.example",
            }
        }
        self.invoices: dict[str, dict[str, Any]] = {
            "INV-7781": {
                "vendor_id": "V-100",
                "amount": 48_500.0,
                "status": "approved",
                "paid_amount": 0.0,
                "payment_id": None,
            }
        }
        self.emails_sent: list[dict[str, Any]] = []
        self._payment_seq = 0
        self.call_log: list[tuple[str, dict[str, Any]]] = []

    # -- the executor the control plane hands allowed calls to -------------
    def execute(self, tool: str, args: dict[str, Any]) -> Any:
        self.call_log.append((tool, copy.deepcopy(args)))
        if tool == "invoices.read":
            return self.invoices.get(args["invoice_id"])
        if tool == "vendors.update":
            v = self.vendors[args["vendor_id"]]
            for field in ("bank_account", "remit_to"):
                if field in args and args[field] is not None:
                    v[field] = args[field]
            return dict(v)
        if tool == "invoices.pay":
            inv = self.invoices[args["invoice_id"]]
            self._payment_seq += 1
            pid = f"PAY-{self._payment_seq:04d}"
            inv["status"] = "paid"
            inv["paid_amount"] = float(args["amount"])
            inv["payment_id"] = pid
            return {"payment_id": pid, "paid_to": self.vendors[inv["vendor_id"]]["bank_account"]}
        if tool == "invoices.void_payment":
            inv = self.invoices[args["invoice_id"]]
            inv["status"] = "approved"
            inv["paid_amount"] = 0.0
            inv["payment_id"] = None
            return {"voided": args.get("payment_id")}
        if tool == "invoices.approve":
            inv = self.invoices[args["invoice_id"]]
            inv["status"] = "approved"
            return dict(inv)
        if tool == "invoices.set_status":
            inv = self.invoices[args["invoice_id"]]
            inv["status"] = args["status"]
            return dict(inv)
        if tool == "payments.wire":
            return {"wire_id": "WIRE-0001", "settled": True}
        if tool == "email.send":
            self.emails_sent.append(dict(args))
            return {"sent": True}
        if tool == "noop.none":
            return None
        raise KeyError(f"FakeERP has no tool {tool!r}")

    # -- the read-only snapshot reader -------------------------------------
    def read_state(
        self, tool: str, args: dict[str, Any], fields: tuple[str, ...]
    ) -> dict[str, Any]:
        if tool.startswith("vendors.") and "vendor_id" in args:
            src = self.vendors.get(args["vendor_id"], {})
        elif tool.startswith("invoices.") and "invoice_id" in args:
            src = self.invoices.get(args["invoice_id"], {})
        else:
            src = {}
        return {f: src[f] for f in fields if f in src}


DEMO_POLICY = {
    "name": "ap-demo",
    "version": "1",
    "default_effect": "deny",
    "rules": [
        {"id": "reads-ok", "effect": "allow", "actions": ["read"],
         "reason": "Reads change nothing."},
        {"id": "no-undo-needs-a-human", "effect": "require_approval",
         "reversibility": ["irreversible", "unknown"],
         "reason": "No rollback path exists, so a person must own this decision."},
        {"id": "vendor-bank-changes-reviewed", "effect": "require_approval",
         "tools": ["vendors.update"],
         "reason": "Vendor banking changes are the standard payment-fraud vector."},
        {"id": "bounded-payments", "effect": "allow",
         "tools": ["invoices.pay", "invoices.approve"],
         "reversibility": ["reversible", "compensable"],
         "budget": {"key": "payments_total", "field": "amount", "limit": 100_000},
         "reason": "Undoable payment inside the session ceiling."},
    ],
}


def _hr(title: str) -> None:
    print()
    print("=" * 74)
    print(title)
    print("=" * 74)


def run_demo() -> dict[str, Any]:  # noqa: C901 - a narrative script reads better flat
    erp = FakeERP()

    # A rubber-stamp approver, standing in for a distracted human. Returning True
    # unconditionally is exactly the consent-fatigue failure the ASI09 detector
    # exists to catch, and modeling it here keeps the demo honest: the control
    # plane's value cannot depend on humans reviewing carefully.
    approvals: list[str] = []

    def rubber_stamp(tool: str, args: dict[str, Any], principal: Any, decision: Any) -> bool:
        approvals.append(tool)
        return True

    cp = ControlPlane(
        policy=load_policy(DEMO_POLICY),
        inverse_registry=ap_starter_registry(),
        state_reader=erp.read_state,
        approval_hook=rubber_stamp,
    )

    # ---- identities and authority ----------------------------------------
    cfo_priv, cfo_pub = crypto.generate_keypair()
    orch_priv, orch_pub = crypto.generate_keypair()
    work_priv, work_pub = crypto.generate_keypair()

    cfo = cp.register_human("Alice (CFO)", cfo_pub, roles={"approver"})
    orchestrator = cp.register_agent("ap-orchestrator", orch_pub, roles={"ap-clerk"})
    worker = cp.register_agent("ap-worker", work_pub, roles={"ap-clerk"})

    _hr("1. A human delegates authority, requiring that everything be undoable")
    root = cp.issue_root_delegation(
        human_private_key=cfo_priv,
        human_id=cfo.id,
        agent_id=orchestrator.id,
        scope=Scope.make(
            # payments.wire IS granted here, on purpose. The point of step 6 is
            # that permission alone is no longer sufficient.
            tools={
                "invoices.read", "invoices.pay", "invoices.approve",
                "vendors.update", "payments.wire",
            },
            actions={"read", "write"},
            max_risk=70,
            constraints={"max:amount": 50_000},
            min_reversibility=Reversibility.COMPENSABLE,
        ),
        purpose="reconcile and pay approved supplier invoices",
        ttl_seconds=3600,
    )
    print(f"  root grant  : {root.id}")
    print(f"  granted by  : {cfo.name}")
    print(f"  reversibility floor: {root.scope.min_reversibility.value}")
    print("  -> the grant itself says: only do things we can take back.")

    sub = cp.sub_delegate(
        issuer_private_key=orch_priv,
        issuer_id=orchestrator.id,
        subject_id=worker.id,
        parent_delegation_id=root.id,
        scope=Scope.make(
            tools={"invoices.read"},
            actions={"read"},
            max_risk=20,
            min_reversibility=Reversibility.COMPENSABLE,
        ),
        purpose="read invoice batches",
        ttl_seconds=1800,
    )
    print(f"  sub-grant   : {sub.id} (read-only, narrower)")

    _hr("2. Legitimate read — allowed, traced to the human")
    v = cp.authorize(
        actor_private_key=work_priv,
        actor_id=worker.id,
        delegation_id=sub.id,
        tool="invoices.read",
        action="read",
        args={"invoice_id": "INV-7781"},
        risk=10,
        description="read invoice batch for reconciliation",
        session_id="sess-1",
    )
    print(f"  allowed={v.allowed}  stage={v.stage}  traced to: {v.human_root}")
    if v.allowed:
        cp.confirm(v, result=erp.execute("invoices.read", v.effective_args))

    _hr("3. The worker tries to pay — outside its scope, blocked")
    v = cp.authorize(
        actor_private_key=work_priv,
        actor_id=worker.id,
        delegation_id=sub.id,
        tool="invoices.pay",
        args={"invoice_id": "INV-7781", "amount": 48_500},
        risk=80,
        description="wire funds out",
        session_id="sess-1",
    )
    print(f"  allowed={v.allowed}  stage={v.stage}")
    print(f"  findings: {[f['code'] for f in v.findings]}")
    print(f"  reason  : {v.reason[:100]}")

    _hr("4. The orchestrator is injected: repoint the vendor's bank account")
    print(f"  bank account BEFORE : {erp.vendors['V-100']['bank_account']}")
    v_vendor = cp.authorize(
        actor_private_key=orch_priv,
        actor_id=orchestrator.id,
        delegation_id=root.id,
        tool="vendors.update",
        args={"vendor_id": "V-100", "bank_account": "LT77-MULE-0000-9999"},
        risk=60,
        description="update supplier remittance details per invoice instructions",
        session_id="sess-1",
    )
    print(f"  allowed={v_vendor.allowed}  stage={v_vendor.stage}")
    print(f"  human approved? {v_vendor.approved_by_human}  (rubber-stamped)")
    print(f"  reversal posture: {v_vendor.reversibility.value}  undoable: {v_vendor.undoable}")
    print(f"  prior state captured: {v_vendor.plan.snapshot if v_vendor.plan else {}}")
    if v_vendor.allowed:
        cp.confirm(v_vendor, result=erp.execute("vendors.update", v_vendor.effective_args))
    print(f"  bank account AFTER  : {erp.vendors['V-100']['bank_account']}")
    print("  -> the change went through. Note what was captured BEFORE it did.")

    _hr("5. And now pay the invoice into the attacker's account")
    v_pay = cp.authorize(
        actor_private_key=orch_priv,
        actor_id=orchestrator.id,
        delegation_id=root.id,
        tool="invoices.pay",
        args={"invoice_id": "INV-7781", "amount": 48_500},
        risk=65,
        description="pay approved supplier invoice INV-7781",
        session_id="sess-1",
    )
    rule = v_pay.gate_decision.rule_id if v_pay.gate_decision else "—"
    print(f"  allowed={v_pay.allowed}  stage={v_pay.stage}  rule={rule}")
    if v_pay.allowed:
        result = erp.execute("invoices.pay", v_pay.effective_args)
        cp.confirm(v_pay, result=result)
        print(f"  paid: {result}")
        print(f"  invoice status: {erp.invoices['INV-7781']['status']}")

    _hr("6. An irreversible wire — permitted by scope, stopped by reversibility")
    v_wire = cp.authorize(
        actor_private_key=orch_priv,
        actor_id=orchestrator.id,
        delegation_id=root.id,
        tool="payments.wire",
        # Inside every classic limit: the tool is granted, the amount is under the
        # cap, the risk is under the ceiling. Only recoverability is missing.
        args={"beneficiary": "LT77-MULE-0000-9999", "amount": 25_000},
        risk=65,
        description="wire funds to supplier per remittance instructions",
        session_id="sess-1",
    )
    print("  tool granted by scope?  yes ('payments.wire' is in the grant)")
    print("  amount within cap?      yes (25,000 <= 50,000)")
    print("  risk within ceiling?    yes (65 <= 70)")
    print(f"  reversal posture:       {v_wire.reversibility.value}")
    print()
    print(f"  allowed={v_wire.allowed}  stage={v_wire.stage}")
    print(f"  findings: {[f['code'] for f in v_wire.findings]}")
    print(f"  reason: {v_wire.reason[:140]}")
    print()
    print("  -> Every permission check passed. It was blocked purely because the grant")
    print("     required recoverability and a settled wire has none. That check did not")
    print("     exist in any of the three tools this package merges.")

    _hr("7. Containment: revoke the grant and roll back everything under it")
    print(f"  bank account BEFORE containment: {erp.vendors['V-100']['bank_account']}")
    print(f"  invoice status BEFORE          : {erp.invoices['INV-7781']['status']}")
    report = cp.contain(root.id, erp.execute, reason="injected-content incident")
    print()
    print(f"  revoked delegations : {len(report['revoked_delegations'])}")
    print(f"  actions in radius   : {report['actions_in_radius']}")
    rb = report["rollback"]
    print(f"  reversed            : {rb['reversed_ok']}")
    print(f"  failed              : {rb['failed']}")
    print(f"  skipped (no undo)   : {rb['skipped']}")
    print(f"  fully contained     : {report['fully_contained']}")
    print()
    print(f"  bank account AFTER containment : {erp.vendors['V-100']['bank_account']}")
    print(f"  invoice status AFTER           : {erp.invoices['INV-7781']['status']}")
    if rb["residues"]:
        print()
        print("  Residue — what the undo could NOT restore:")
        for r in rb["residues"]:
            print(f"    - {r}")

    _hr("8. Evidence")
    pack = build_evidence_pack(
        cp.ledger,
        cp.reversal,
        policy_name=cp.gate.policy.name,
        policy_digest=cp.gate.policy.digest(),
    )
    d = pack.to_dict()
    print(f"  ledger entries    : {d['integrity']['entries']}")
    print(f"  chain verified    : {d['integrity']['chain_verified']}")
    print(f"  head hash         : {d['integrity']['head_hash'][:32]}...")
    print(f"  merkle root       : {d['integrity']['merkle_root'][:32]}...")
    print(f"  policy digest     : {d['integrity']['policy_digest'][:32]}...")
    print(f"  verdicts          : {d['activity']['verdicts']}")
    print(f"  blocked           : {d['activity']['blocked']}")
    print(f"  findings by code  : { {k: v['count'] for k, v in d['findings']['by_code'].items()} }")
    print(f"  recoverability    : {d['recoverability']['actually_undoable']} undoable, "
          f"{d['recoverability']['phantom_rollbacks']} phantom")

    _hr("What just happened")
    print(
        "  The vendor's real bank account is back, the fraudulent payment is voided, the\n"
        "  grant and everything sub-delegated from it are revoked, and the whole sequence\n"
        "  is one hash-chained history that verifies.\n\n"
        "  The rubber-stamp approver approved both fraudulent steps. The recovery did not\n"
        "  depend on the human catching it — which is the point, because in a real incident\n"
        "  the human does not catch it."
    )
    print()

    return {
        "erp": erp,
        "control_plane": cp,
        "containment": report,
        "evidence": d,
        "approvals": approvals,
    }


if __name__ == "__main__":  # pragma: no cover
    run_demo()
