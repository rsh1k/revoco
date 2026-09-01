"""
The reversal layer — plan an undo before the action, execute it after.

This is the capability none of the merged tools had, and the reason the merge is
worth doing rather than just co-locating three packages: a cascade rollback
scoped to a leaked delegation is only expressible because the authority layer
already knows which actions shared that grant.
"""

from .engine import (
    EVT_ABANDON,
    EVT_COMMIT,
    EVT_EXECUTED,
    EVT_EXPIRED,
    EVT_GATE_BLOCKED,
    EVT_PLAN,
    ReversalEngine,
)
from .horizon import Horizon, HorizonEntry
from .model import (
    CascadeReport,
    Exemption,
    GateEvaluator,
    InverseExecutor,
    InverseSpec,
    InverseStep,
    JournalEntry,
    JournalState,
    PlannedStep,
    ReversalGate,
    ReversalPlan,
    ReversalReceipt,
    Reversibility,
    StateEquivalence,
    StateReader,
    StepResult,
)
from .registry import AP_STARTER_SPECS, InverseRegistry, ap_starter_registry

__all__ = [
    "Reversibility",
    "Horizon",
    "HorizonEntry",
    "InverseSpec",
    "InverseStep",
    "ReversalGate",
    "StateEquivalence",
    "Exemption",
    "InverseRegistry",
    "ap_starter_registry",
    "AP_STARTER_SPECS",
    "ReversalEngine",
    "ReversalPlan",
    "PlannedStep",
    "StepResult",
    "JournalEntry",
    "JournalState",
    "ReversalReceipt",
    "CascadeReport",
    "StateReader",
    "InverseExecutor",
    "GateEvaluator",
    "EVT_PLAN",
    "EVT_COMMIT",
    "EVT_ABANDON",
    "EVT_EXECUTED",
    "EVT_EXPIRED",
    "EVT_GATE_BLOCKED",
]
