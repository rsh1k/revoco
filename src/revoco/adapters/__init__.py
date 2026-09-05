"""
System-of-record adapters: the inverse-operation specs that do not generalize.

Everything else in revoco is transferable across customers. This package is not:
knowing that an SAP payment reversal is a three-step sequence, that a Workday
rescind dies the moment payroll runs, or that an S3 delete is recoverable only if
someone enabled versioning first, is per-system knowledge that has to be built once
and maintained forever.

Seven surfaces are covered:

============  =============================================================
``sap``       S/4HANA financial postings, supplier master, payments
``workday``   HCM business processes — compensation, staffing, payroll
``cloud``     AWS — S3, IAM, EC2/networking, RDS, Route 53, KMS
``identity``  Microsoft Entra ID and Okta
``devops``    GitHub refs and protection, Kubernetes, feature flags
``saas``      Salesforce records, Slack messages, Stripe payments
``workstation`` filesystem, git, shell — the surface coding agents touch
``database``  row writes, arbitrary SQL, schema migrations
============  =============================================================

Every spec is **unvalidated** — written from documentation and practitioner
sources, not executed against a live system. See ``docs/ADAPTERS.md`` for
per-spec citations and the validation checklist to work through before any of it
governs a real write.

The two things this collection taught the core model
----------------------------------------------------
**Reversibility is a property of the target, not the tool.** ``aws.s3.delete_object``
is recoverable against a versioned bucket and final against an unversioned one, with
identical arguments. ``entra.group.delete`` soft-deletes a security group and hard-
deletes a distribution group. That is what authorize-phase gates exist for: they are
evaluated *before* the write, and a closed gate degrades the classification so policy
escalates while escalation still means something.

**Snapshot-before-write creates undo paths that do not otherwise exist.** A deleted
Kubernetes object, a deleted git branch, a force-pushed ref, an overwritten file, a
revoked security-group rule — none of these has a native undo, and all of them become
recoverable once prior state is captured. Roughly a third of the specs here are
recoverable *only* because of that ordering. It is the clearest statement of what this
architecture buys.
"""

from __future__ import annotations

from typing import Any

from ..reversal.model import InverseSpec, ReversalGate, Reversibility, StateEquivalence
from ..reversal.registry import InverseRegistry
from . import cloud, database, devops, identity, ras_eval, saas, sap, workday, workstation
from .cloud import CLOUD_GATES, CLOUD_SPECS, cloud_registry
from .database import DATABASE_GATES, DATABASE_SPECS, database_registry
from .devops import (
    DEVOPS_EQUIVALENCE,
    DEVOPS_GATES,
    DEVOPS_SPECS,
    devops_registry,
)
from .identity import IDENTITY_GATES, IDENTITY_SPECS, identity_registry
from .ras_eval import RAS_EVAL_SPECS, ras_eval_registry
from .saas import SAAS_GATES, SAAS_SPECS, saas_registry
from .sap import SAP_GATES, SAP_SPECS, sap_registry
from .workday import WORKDAY_GATES, WORKDAY_SPECS, workday_registry
from .workstation import (
    WORKSTATION_EQUIVALENCE,
    WORKSTATION_GATES,
    WORKSTATION_SPECS,
    workstation_registry,
)

# Surface name -> (specs, gates). Ordered roughly by blast radius.
# `workspace` is deliberately absent from this map, and the absence is a decision
# rather than an oversight.
#
# SURFACES enumerates specs by fixed tool name -- that is what makes `all_specs`,
# `gate_catalog` and `revoco surfaces` meaningful. The workspace snapshot has no
# fixed forward tool: the shell classifier fills the name in per call, because the
# whole point is making an *arbitrary* command recoverable. Listing it here would
# advertise `workspace.guarded_command`, a placeholder nobody can call, and
# inflate the spec count with an operation that does not exist.
#
# It is still shipped, still drilled, and `revoco surfaces` names it below the
# table so the catalogue does not quietly omit a mechanism that is in the box.
#
# Do not confuse it with the `workstation` surface below: one letter apart,
# different things. `workstation` is tool-keyed and catalogued; `workspace` is
# the snapshot mechanism and is not.
SURFACES: dict[str, tuple[list[InverseSpec], tuple[ReversalGate, ...]]] = {
    "sap": (SAP_SPECS, SAP_GATES),
    "workday": (WORKDAY_SPECS, WORKDAY_GATES),
    "cloud": (CLOUD_SPECS, CLOUD_GATES),
    "identity": (IDENTITY_SPECS, IDENTITY_GATES),
    "devops": (DEVOPS_SPECS, DEVOPS_GATES),
    "database": (DATABASE_SPECS, DATABASE_GATES),
    "saas": (SAAS_SPECS, SAAS_GATES),
    "workstation": (WORKSTATION_SPECS, WORKSTATION_GATES),
}


# Which surfaces have written down what "state returned" means for them. A drill
# without one falls back to requiring every reported field to match exactly, which
# no real system survives — so whoever runs the first drill invents a relation at
# the call site, and the number it produces cannot be argued with afterwards.
# Absent is tracked rather than defaulted, because the gap is the reportable thing.
EQUIVALENCES: dict[str, StateEquivalence | None] = {
    "sap": None,
    "workday": None,
    "cloud": None,
    "identity": None,
    "devops": DEVOPS_EQUIVALENCE,
    "database": None,
    "saas": None,
    "workstation": WORKSTATION_EQUIVALENCE,
}


def equivalence(surface: str) -> StateEquivalence | None:
    """The declared state-equivalence relation for a surface, if it has one."""
    if surface not in SURFACES:
        raise KeyError(f"unknown surface {surface!r}; known: {sorted(SURFACES)}")
    return EQUIVALENCES.get(surface)


def all_specs(*surfaces: str) -> list[InverseSpec]:
    """Every spec across the named surfaces, or all of them if none are named."""
    names = surfaces or tuple(SURFACES)
    unknown = [n for n in names if n not in SURFACES]
    if unknown:
        raise KeyError(f"unknown surface(s) {unknown}; available: {sorted(SURFACES)}")
    out: list[InverseSpec] = []
    for name in names:
        out.extend(SURFACES[name][0])
    return out


def registry_for(*surfaces: str) -> InverseRegistry:
    """A combined registry for the named surfaces (all of them if none named).

    Tool names are namespaced per surface, so combining is safe. Prefer loading
    only the surfaces you actually govern: a registry claiming to classify SAP
    postings in a shop with no SAP is noise in every coverage report.
    """
    return InverseRegistry(all_specs(*surfaces))


def gate_catalog(*surfaces: str) -> dict[str, dict[str, Any]]:
    """Every gate across the named surfaces — the integrator's to-do list.

    Each entry your ``GateEvaluator`` does not handle fails closed, so this is the
    definitive list of questions you must be able to answer before the
    corresponding specs can execute. ``phase`` matters: ``authorize`` gates change
    whether an action is classified as undoable at all and are asked *before* the
    write, while ``undo`` gates are asked immediately before a rollback runs.
    """
    names = surfaces or tuple(SURFACES)
    out: dict[str, dict[str, Any]] = {}
    for name in names:
        if name not in SURFACES:
            raise KeyError(f"unknown surface {name!r}; available: {sorted(SURFACES)}")
        for gate in SURFACES[name][1]:
            out[gate.name] = {
                "surface": name,
                "phase": gate.check_at,
                "description": gate.description,
                "remediation": gate.remediation,
            }
    return out


def summary(*surfaces: str) -> dict[str, Any]:
    """Counts by reversal posture, plus the two figures worth reporting upward.

    ``snapshot_dependent`` is how many specs are recoverable only because prior
    state is captured before the write — the share of the undo surface this
    architecture creates rather than merely records.

    ``degradable`` is how many can turn out to be irreversible for a particular
    target despite an optimistic classification. That gap is why authorize-phase
    gates exist, and it is the number to watch: a spec that degrades and is never
    checked is a phantom rollback waiting to happen.
    """
    specs = all_specs(*surfaces)
    by_kind: dict[str, int] = {k.value: 0 for k in Reversibility}
    for s in specs:
        by_kind[s.kind.value] += 1
    return {
        "surfaces": list(surfaces or tuple(SURFACES)),
        "specs": len(specs),
        "by_kind": by_kind,
        "sequenced": len([s for s in specs if len(s.effective_steps) > 1]),
        "one_shot": len([s for s in specs if s.one_shot]),
        "gated": len([s for s in specs if s.gates]),
        "degradable": len([s for s in specs if s.authorize_gates]),
        "snapshot_dependent": len([s for s in specs if s.snapshot_fields]),
        "gates": len(gate_catalog(*surfaces)),
    }


__all__ = [
    # modules
    "sap", "workday", "cloud", "identity", "devops", "saas", "workstation", "database",
    "ras_eval", "RAS_EVAL_SPECS", "ras_eval_registry",
    # per-surface
    "SAP_SPECS", "SAP_GATES", "sap_registry",
    "WORKDAY_SPECS", "WORKDAY_GATES", "workday_registry",
    "CLOUD_SPECS", "CLOUD_GATES", "cloud_registry",
    "IDENTITY_SPECS", "IDENTITY_GATES", "identity_registry",
    "DEVOPS_SPECS", "DEVOPS_GATES", "devops_registry",
    "SAAS_SPECS", "SAAS_GATES", "saas_registry",
    "WORKSTATION_SPECS", "WORKSTATION_GATES", "workstation_registry",
    "DATABASE_SPECS", "DATABASE_GATES", "database_registry",
    # combined
    "SURFACES", "all_specs", "registry_for", "gate_catalog", "summary",
]
