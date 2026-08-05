"""
revoco.evidence
================
Turns the ledger into an evidence pack: a self-contained artifact someone can
hand to an auditor, a regulator, or opposing counsel.

What makes this different from a log export
-------------------------------------------
An exported log asserts. An evidence pack *proves*, and states the limits of what
it proves. Each pack carries the chain's head hash and Merkle root so a recipient
can verify the history independently, records the digest of the exact policy that
produced each decision, and — the part most tooling omits — reports the gap
between rollback capability claimed and rollback capability actually held.

On control-mapping claims
-------------------------
The mappings below say which regulatory requirement a given piece of technical
evidence *speaks to*. That is not the same as compliance, and this module does
not claim otherwise. NIST AI RMF is voluntary. EU AI Act conformity is assessed
against a quality-management system, of which logging is one clause. SOX
assertions rest on management's judgement, not on a vendor's report. Treat this
as a self-assessment aid that shortens an auditor's fieldwork by making the
technical record legible — not as a certification.

One design point worth flagging for a buyer
-------------------------------------------
EU AI Act Article 19 obliges providers to keep logs "to the extent such logs are
under their control". A pack generated here is built from a ledger the deployer
holds, and can be written to storage the deployer owns. That is a deliberate
architectural choice: evidence that lives only in a vendor's cloud is evidence
whose control is, at minimum, arguable.
"""

from __future__ import annotations

import time
from dataclasses import dataclass
from typing import Any

from . import ledger as ledger_mod
from .core import crypto
from .detect import journal_health
from .ledger import Ledger
from .reversal.engine import ReversalEngine
from .reversal.model import Reversibility

# ---------------------------------------------------------------------------
# Control mappings. Each entry: framework -> clause -> what evidence answers it.
# ---------------------------------------------------------------------------

CONTROL_MAP: dict[str, dict[str, str]] = {
    "EU AI Act": {
        "Art. 12 (record-keeping)": (
            "Every authority grant, policy decision, action, and reversal transition is "
            "recorded automatically by the control plane at the moment it occurs. No "
            "manual entry is possible, which is the article's operative requirement."
        ),
        "Art. 12(2) (traceability over lifetime)": (
            "The hash-chained ledger spans the deployment's whole life; entries cannot be "
            "removed or reordered without breaking verification."
        ),
        "Art. 14 (human oversight)": (
            "REQUIRE_APPROVAL decisions record whether a human approved, and the "
            "reversibility rule escalates un-undoable actions to a person by policy."
        ),
        "Art. 19 (log retention under provider control)": (
            "The ledger is held by the deployer. Head hash and Merkle root allow "
            "independent verification without relying on the vendor."
        ),
    },
    "NIST AI RMF 1.0": {
        "MANAGE 2.3 (mechanisms to supersede/deactivate)": (
            "Grant revocation plus cascade rollback provide both deactivation of "
            "authority and reversal of its effects."
        ),
        "MEASURE 2.7 (security & resilience tracked)": (
            "Threat-scan results and OWASP ASI findings are recorded per action."
        ),
        "GOVERN 1.5 (accountability structures)": (
            "Every action reconstructs to a named human root via signed delegations."
        ),
    },
    "OWASP Agentic Top 10 (ASI 2026)": {
        "ASI01/ASI02 Goal hijack, tool misuse": "Scope enforcement and per-action policy.",
        "ASI03 Identity & privilege abuse": "Signature verification, expiry, revocation checks.",
        "ASI06 Memory & context poisoning": "Intent-drift detection against delegated purpose.",
        "ASI07 Insecure inter-agent comms": "Signature verification on each delegation hop.",
        "ASI08 Cascading failures": "Fan-out detection plus bounded cascade rollback.",
        "ASI09 Human-agent trust abuse": "Consent-fatigue detection.",
        "ASI10 Rogue agents": "Repeat-violation strike accounting.",
    },
    "SR 11-7 / OCC model risk": {
        "III.B (process verification)": (
            "Decisions are reproducible: the policy digest and the inputs are recorded, "
            "so a validator can re-run the decision and compare."
        ),
        "V (governance & controls)": (
            "Policy is version-controlled data with a content digest bound to every "
            "decision it produced."
        ),
    },
    "SOX / ICFR": {
        "Change authorization over financial records": (
            "Agent-initiated writes to systems of record carry a signed authorization "
            "chain terminating at a named human."
        ),
        "Reversal of unauthorized entries": (
            "Reversal receipts evidence what was undone, when, by which inverse "
            "operation, and what residue remained."
        ),
    },
}


@dataclass
class EvidencePack:
    generated_at: float
    integrity: dict[str, Any]
    coverage: dict[str, Any]
    recoverability: dict[str, Any]
    activity: dict[str, Any]
    findings: dict[str, Any]
    control_map: dict[str, dict[str, str]]
    limitations: list[str]

    def to_dict(self) -> dict[str, Any]:
        d = {
            "generated_at": self.generated_at,
            "integrity": self.integrity,
            "coverage": self.coverage,
            "recoverability": self.recoverability,
            "activity": self.activity,
            "findings": self.findings,
            "control_map": self.control_map,
            "limitations": self.limitations,
        }
        # The pack's own digest, so a recipient can tell whether the document they
        # are holding is the document that was generated.
        d["pack_digest"] = crypto.digest_of(d)
        return d

    def to_markdown(self) -> str:
        d = self.to_dict()
        out: list[str] = []
        ts = time.strftime("%Y-%m-%d %H:%M:%S UTC", time.gmtime(self.generated_at))
        out.append("# Agent Action Evidence Pack")
        out.append("")
        out.append(f"Generated: **{ts}**  ")
        out.append(f"Pack digest: `{d['pack_digest']}`")
        out.append("")

        out.append("## 1. Ledger integrity")
        out.append("")
        for k, v in self.integrity.items():
            out.append(f"- **{k}**: `{v}`" if isinstance(v, str) else f"- **{k}**: {v}")
        out.append("")
        out.append(
            "> Verify independently by recomputing the chain and comparing the head hash "
            "against your witnessed value. A matching head proves no entry was altered, "
            "reordered, or removed."
        )
        out.append("")

        out.append("## 2. Activity")
        out.append("")
        out.append("| Entry kind | Count |")
        out.append("|---|---|")
        for kind, n in sorted(self.activity.get("by_kind", {}).items()):
            out.append(f"| `{kind}` | {n} |")
        out.append("")
        for k, v in self.activity.items():
            if k != "by_kind":
                out.append(f"- **{k}**: {v}")
        out.append("")

        out.append("## 3. Recoverability")
        out.append("")
        r = self.recoverability
        out.append(f"- Committed actions with an undo path recorded: **{r.get('committed', 0)}**")
        out.append(f"- Actually undoable right now: **{r.get('actually_undoable', 0)}**")
        out.append(f"- Phantom rollbacks (claimed but not executable): **{r.get('phantom_rollbacks', 0)}**")
        out.append(f"- Irreversible by nature: **{r.get('irreversible', 0)}**")
        out.append("")
        if r.get("phantom_rollbacks"):
            out.append(
                "> **Attention.** A phantom rollback is an action the organization believes "
                "it can reverse and cannot. These are listed below and should be treated as "
                "open risk items, not as recoverable positions."
            )
            out.append("")
            out.append("| Tool | Unresolved inverse args | Snapshot error | Expired |")
            out.append("|---|---|---|---|")
            for p in r.get("phantom_details", []):
                out.append(
                    f"| `{p['tool']}` | {', '.join(p['unresolved_args']) or '—'} "
                    f"| {p['snapshot_error'] or '—'} | {p['expired']} |"
                )
            out.append("")

        out.append("## 4. Inverse-operation coverage")
        out.append("")
        c = self.coverage
        out.append(f"- Tools observed: **{c.get('total_tools', 0)}**")
        out.append(f"- Classified: **{c.get('classified', 0)}** ({c.get('classified_pct', 0)}%)")
        out.append(f"- With a usable undo path: **{c.get('undoable', 0)}**")
        out.append("")
        for kind, tools in (c.get("by_kind") or {}).items():
            if tools:
                out.append(f"- `{kind}`: {', '.join(sorted(tools))}")
        out.append("")

        out.append("## 5. Findings")
        out.append("")
        if not self.findings.get("by_code"):
            out.append("No findings recorded in this period.")
        else:
            out.append("| Code | Count | Highest severity |")
            out.append("|---|---|---|")
            for code, info in sorted(self.findings["by_code"].items()):
                out.append(f"| `{code}` | {info['count']} | {info['max_severity']} |")
        out.append("")

        out.append("## 6. Control mapping")
        out.append("")
        for framework, clauses in self.control_map.items():
            out.append(f"### {framework}")
            out.append("")
            out.append("| Clause | Evidence in this pack |")
            out.append("|---|---|")
            for clause, evidence in clauses.items():
                out.append(f"| {clause} | {evidence} |")
            out.append("")

        out.append("## 7. Limitations of this pack")
        out.append("")
        for lim in self.limitations:
            out.append(f"- {lim}")
        out.append("")
        return "\n".join(out)


def build_evidence_pack(
    ledger: Ledger,
    reversal: ReversalEngine,
    *,
    policy_name: str = "",
    policy_digest: str = "",
    witnessed_head: str | None = None,
) -> EvidencePack:
    """Assemble an evidence pack from a ledger and reversal journal."""
    try:
        ledger.verify_integrity()
        integrity_ok: Any = True
        integrity_error = None
    except Exception as exc:
        integrity_ok = False
        integrity_error = str(exc)

    integrity: dict[str, Any] = {
        "chain_verified": integrity_ok,
        "entries": len(ledger),
        "head_hash": ledger.head_hash,
        "merkle_root": ledger.merkle_root(),
        "policy_name": policy_name,
        "policy_digest": policy_digest,
    }
    if integrity_error:
        integrity["error"] = integrity_error
    if witnessed_head is not None:
        integrity["witnessed_head"] = witnessed_head
        integrity["matches_witness"] = witnessed_head == ledger.head_hash

    # Findings rolled up from recorded verdicts.
    by_code: dict[str, dict[str, Any]] = {}
    sev_rank = {"info": 0, "low": 1, "medium": 2, "high": 3, "critical": 4}
    verdict_count = 0
    blocked = 0
    approvals = 0
    for entry in ledger.find(ledger_mod.KIND_VERDICT):
        verdict_count += 1
        payload = entry.payload
        if not payload.get("allowed"):
            blocked += 1
        if payload.get("approved_by_human"):
            approvals += 1
        for f in payload.get("findings") or []:
            code = f.get("code", "?")
            slot = by_code.setdefault(code, {"count": 0, "max_severity": "info"})
            slot["count"] += 1
            if sev_rank.get(f.get("severity", "info"), 0) > sev_rank.get(slot["max_severity"], 0):
                slot["max_severity"] = f.get("severity", "info")

    entries = reversal.entries()
    tools_seen = sorted({e.plan.tool for e in entries})
    coverage = reversal.registry.coverage(tools_seen)

    activity = {
        "by_kind": ledger.counts_by_kind(),
        "verdicts": verdict_count,
        "blocked": blocked,
        "human_approvals": approvals,
        "reversals_executed": len(
            [e for e in entries if e.state.value in ("reversed", "reversal_failed")]
        ),
    }

    limitations = [
        "A self-contained hash chain detects edits, reorders, and interior deletions. "
        "It does NOT detect truncation of the most recent entries — the surviving prefix "
        "still verifies. Anchor the head hash with an external witness to close that gap.",
        "Threat scanning is heuristic pattern matching, not a calibrated classifier. "
        "Absence of a threat finding is not evidence that no injection occurred.",
        "Intent-drift detection is a lexical overlap heuristic. It flags divergence; it "
        "does not establish intent.",
        "Reversal classifications are only as accurate as the inverse-operation registry. "
        "A tool mapped to the wrong inverse will produce a confident, wrong rollback — "
        "the registry is the part that needs per-system validation before production.",
        "Control mappings indicate which requirement a piece of evidence speaks to. They "
        "are a self-assessment aid, not a certification or a legal opinion.",
    ]
    if not integrity_ok:
        limitations.insert(
            0,
            "**The ledger failed integrity verification.** Nothing in this pack should be "
            "relied on until that is explained.",
        )

    return EvidencePack(
        generated_at=time.time(),
        integrity=integrity,
        coverage=coverage,
        recoverability=journal_health(entries),
        activity=activity,
        findings={"by_code": by_code},
        control_map=CONTROL_MAP,
        limitations=limitations,
    )


def readiness_report(reversal: ReversalEngine, tools: list[str]) -> dict[str, Any]:
    """A standalone rollback-readiness snapshot for a given tool surface.

    Answers the question a risk committee should be asking and usually cannot:
    of everything our agents can do, how much can we take back?
    """
    coverage = reversal.registry.coverage(tools)
    health = journal_health(reversal.entries())
    unclassified = coverage["by_kind"][Reversibility.UNKNOWN.value]
    return {
        "tool_surface": len(tools),
        "coverage": coverage,
        "journal": health,
        "unclassified_tools": unclassified,
        "verdict": (
            "ready"
            if not unclassified and not health["phantom_rollbacks"]
            else "gaps present"
        ),
    }


__all__ = ["EvidencePack", "build_evidence_pack", "readiness_report", "CONTROL_MAP"]
