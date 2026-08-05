"""
praetor.reversal.registry
=========================
The inverse-operation registry: which tools can be undone, and how.

This registry is the asset that does not generalize. A policy engine is
transferable across every customer; knowing that the inverse of an SAP journal
entry posting is a reversal document with a specific posting-date rule, and that
the inverse of a Workday compensation change is a rescind-not-correct operation,
is per-system knowledge that has to be built once and maintained forever.

Two consequences shape the API:

1. Specs are **data**, loadable from YAML, so domain experts who are not Python
   programmers can own the mapping for their system of record.
2. An unregistered tool classifies as ``UNKNOWN``, never as reversible. Silence
   is never taken as reassurance — the default must be the one that makes policy
   escalate rather than proceed.
"""

from __future__ import annotations

import fnmatch
import json
import threading
from pathlib import Path
from typing import Any

from ..core.errors import PolicyError, ValidationError
from .model import InverseSpec, Reversibility


class InverseRegistry:
    """Maps tool names to :class:`InverseSpec`.

    Lookup is exact-match first, then glob patterns in registration order. Exact
    beats glob so a broad family rule (``"invoices.*"``) can be overridden for
    one member without reordering anything.
    """

    def __init__(self, specs: list[InverseSpec] | None = None) -> None:
        self._exact: dict[str, InverseSpec] = {}
        self._globs: list[InverseSpec] = []
        self._lock = threading.Lock()
        for s in specs or []:
            self.register(s)

    def register(self, spec: InverseSpec) -> InverseSpec:
        with self._lock:
            if any(ch in spec.tool for ch in "*?["):
                self._globs = [g for g in self._globs if g.tool != spec.tool]
                self._globs.append(spec)
            else:
                self._exact[spec.tool] = spec
            return spec

    def register_many(self, specs: list[InverseSpec]) -> None:
        for s in specs:
            self.register(s)

    def get(self, tool: str) -> InverseSpec | None:
        spec = self._exact.get(tool)
        if spec is not None:
            return spec
        for g in self._globs:
            if fnmatch.fnmatchcase(tool, g.tool):
                return g
        return None

    def classify(self, tool: str) -> Reversibility:
        """The reversal posture of ``tool``. Unregistered means UNKNOWN."""
        spec = self.get(tool)
        return spec.kind if spec is not None else Reversibility.UNKNOWN

    def coverage(self, tools: list[str]) -> dict[str, Any]:
        """Report how much of a tool surface has a declared undo path.

        Useful as a readiness metric: "we govern 340 write operations and 61 of
        them have no classified inverse" is a concrete gap statement, which is
        what a risk committee can actually act on.
        """
        by_kind: dict[str, list[str]] = {k.value: [] for k in Reversibility}
        for t in tools:
            by_kind[self.classify(t).value].append(t)
        total = len(tools) or 1
        classified = total - len(by_kind[Reversibility.UNKNOWN.value])
        return {
            "total_tools": len(tools),
            "classified": classified,
            "classified_pct": round(100.0 * classified / total, 1),
            "undoable": len(by_kind[Reversibility.REVERSIBLE.value])
            + len(by_kind[Reversibility.COMPENSABLE.value]),
            "by_kind": by_kind,
        }

    def all(self) -> list[InverseSpec]:
        return list(self._exact.values()) + list(self._globs)

    def to_dict(self) -> dict[str, Any]:
        return {"specs": [s.to_dict() for s in self.all()]}

    # ---- loading ----------------------------------------------------------
    @classmethod
    def load(cls, source: str | Path | dict[str, Any]) -> InverseRegistry:
        """Load a registry from a YAML/JSON file path or a parsed dict."""
        if isinstance(source, dict):
            data = source
        else:
            path = Path(source)
            text = path.read_text()
            if path.suffix in (".yaml", ".yml"):
                try:
                    import yaml
                except ImportError as exc:
                    raise PolicyError(
                        "PyYAML not installed; use JSON or `pip install praetor-controlplane[yaml]`"
                    ) from exc
                data = yaml.safe_load(text)
            else:
                data = json.loads(text)

        if not isinstance(data, dict):
            raise PolicyError("inverse registry root must be a mapping")
        raw_specs = data.get("specs", [])
        if not isinstance(raw_specs, list):
            raise PolicyError("'specs' must be a list")
        specs = []
        for i, raw in enumerate(raw_specs):
            try:
                specs.append(InverseSpec.from_dict(raw))
            except ValidationError as exc:
                raise PolicyError(f"spec #{i}: {exc}") from None
        return cls(specs)


# ---------------------------------------------------------------------------
# A starter set for a generic accounts-payable surface.
#
# This is illustrative, not authoritative: the argument names and window values
# are the ones a real integration has to get right per system, and getting them
# wrong is the difference between an undo and a second incident. Treat these as
# the shape to copy, not values to trust.
# ---------------------------------------------------------------------------

AP_STARTER_SPECS: list[InverseSpec] = [
    InverseSpec(
        tool="invoices.read",
        kind=Reversibility.REVERSIBLE,
        inverse_tool="noop.none",
        arg_map=(),
        residue="",
        # A read changes nothing, so its "undo" is trivially complete. Modeling
        # reads as REVERSIBLE rather than exempt keeps one rule for everything.
    ),
    InverseSpec(
        tool="invoices.pay",
        kind=Reversibility.COMPENSABLE,
        inverse_tool="invoices.void_payment",
        arg_map=(
            ("payment_id", "result.payment_id"),
            ("invoice_id", "args.invoice_id"),
            ("reason", "const:reversed by praetor control plane"),
        ),
        snapshot_fields=("status", "paid_amount", "payment_id"),
        window_seconds=86_400.0,  # most rails settle within a day; after that, no void
        residue=(
            "The remittance advice already sent to the supplier is not recalled, "
            "and the payment appears as a void rather than an absence on the "
            "bank statement."
        ),
    ),
    InverseSpec(
        tool="invoices.approve",
        kind=Reversibility.REVERSIBLE,
        inverse_tool="invoices.set_status",
        arg_map=(
            ("invoice_id", "args.invoice_id"),
            ("status", "snapshot.status"),
        ),
        snapshot_fields=("status",),
    ),
    InverseSpec(
        tool="vendors.update",
        kind=Reversibility.REVERSIBLE,
        inverse_tool="vendors.update",
        arg_map=(
            ("vendor_id", "args.vendor_id"),
            ("bank_account", "snapshot.bank_account"),
            ("remit_to", "snapshot.remit_to"),
        ),
        snapshot_fields=("bank_account", "remit_to"),
        # Restoring the prior banking details is an exact inverse, which is why
        # vendor-master tampering is recoverable at all. This single spec covers
        # the most common agent-assisted payment-fraud pattern.
    ),
    InverseSpec(
        tool="vendors.create",
        kind=Reversibility.COMPENSABLE,
        inverse_tool="vendors.deactivate",
        arg_map=(("vendor_id", "result.vendor_id"),),
        residue=(
            "The vendor record is deactivated, not deleted: the vendor number is "
            "consumed and remains visible in the master-data audit history."
        ),
    ),
    InverseSpec(
        tool="email.send",
        kind=Reversibility.IRREVERSIBLE,
        # No inverse_tool, deliberately. A sent email cannot be recalled, and
        # modeling a "send a correction" follow-up as an undo would be a lie the
        # policy layer would then rely on.
    ),
    InverseSpec(
        tool="payments.wire",
        kind=Reversibility.IRREVERSIBLE,
        # A settled wire is final. This is the canonical example of an action
        # that must be gated by human approval rather than made recoverable.
    ),
]


def ap_starter_registry() -> InverseRegistry:
    """A registry preloaded with the illustrative accounts-payable specs."""
    return InverseRegistry(list(AP_STARTER_SPECS))
