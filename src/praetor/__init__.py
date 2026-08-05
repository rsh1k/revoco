"""
Praetor — an action control plane for AI agents.

Four questions, one pipeline, one verifiable record:

1. **Authority** — is there valid authority for this, traceable to a human?
2. **Enforcement** — does policy permit this specific action, with these
   arguments, under this session's accumulated spend?
3. **Reversibility** — if this turns out to be wrong, can we take it back?
4. **Evidence** — can we prove all of the above to someone who does not trust us?

Question 3 is the one most agent-governance tooling leaves out, and it is the one
that decides whether an incident costs an afternoon or a quarter.

Quick start::

    from praetor import ControlPlane, Scope, crypto
    from praetor.reversal import ap_starter_registry

    cp = ControlPlane(inverse_registry=ap_starter_registry())

    h_priv, h_pub = crypto.generate_keypair()
    a_priv, a_pub = crypto.generate_keypair()
    cfo = cp.register_human("Alice (CFO)", h_pub)
    bot = cp.register_agent("ap-bot", a_pub, roles={"ap-clerk"})

    grant = cp.issue_root_delegation(
        human_private_key=h_priv, human_id=cfo.id, agent_id=bot.id,
        scope=Scope.make(tools={"invoices.pay"}, actions={"write"}, max_risk=60),
        purpose="pay approved invoices", ttl_seconds=3600,
    )

    v = cp.authorize(
        actor_private_key=a_priv, actor_id=bot.id, delegation_id=grant.id,
        tool="invoices.pay", args={"invoice_id": "INV-1", "amount": 900},
        risk=50, description="pay approved invoice INV-1",
    )
    if v.allowed:
        result = pay(...)          # your code does the real work
        cp.confirm(v, result=result)

    cp.undo(v.action_id, my_executor)          # one action
    cp.contain(grant.id, my_executor)          # revoke the grant, roll back its subtree

This package merges three earlier tools — ``veritrail`` (provenance and signed
delegation), ``mcp-gate`` (per-call policy enforcement), and ``mnemosyne``
(memory/context integrity) — and adds the reversal layer that none of them had.
"""

from .authority import (
    ActionRecord,
    AuthorityEngine,
    ChainResult,
    Delegation,
    Principal,
    PrincipalKind,
    Scope,
)
from .controlplane import ControlPlane, Verdict
from .core import crypto, ids
from .core.errors import PraetorError
from .detect import DetectionEngine, Finding, Severity, journal_health
from .evidence import EvidencePack, build_evidence_pack, readiness_report
from .gate import Decision, Effect, Policy, PolicyEngine, load_policy, starter_policy
from .ledger import Ledger, LedgerEntry
from .reversal import (
    CascadeReport,
    InverseRegistry,
    InverseSpec,
    InverseStep,
    JournalEntry,
    JournalState,
    ReversalEngine,
    ReversalGate,
    ReversalPlan,
    ReversalReceipt,
    Reversibility,
    ap_starter_registry,
)

__version__ = "0.1.0"

__all__ = [
    "__version__",
    # control plane
    "ControlPlane",
    "Verdict",
    # authority
    "Scope",
    "Principal",
    "PrincipalKind",
    "Delegation",
    "ActionRecord",
    "AuthorityEngine",
    "ChainResult",
    # enforcement
    "Policy",
    "PolicyEngine",
    "Decision",
    "Effect",
    "load_policy",
    "starter_policy",
    # reversal
    "Reversibility",
    "InverseSpec",
    "InverseStep",
    "ReversalGate",
    "InverseRegistry",
    "ap_starter_registry",
    "ReversalEngine",
    "ReversalPlan",
    "ReversalReceipt",
    "JournalEntry",
    "JournalState",
    "CascadeReport",
    # detection
    "DetectionEngine",
    "Finding",
    "Severity",
    "journal_health",
    # evidence
    "EvidencePack",
    "build_evidence_pack",
    "readiness_report",
    # infrastructure
    "Ledger",
    "LedgerEntry",
    "crypto",
    "ids",
    "PraetorError",
]
