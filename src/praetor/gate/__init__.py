"""
The enforcement layer — per-action policy decisions.

Ported from the ``mcp-gate`` policy decision point, with two changes for the
merged control plane: rules match against the unified :class:`Principal` rather
than a separate identity type, and they can match on an action's reversal
posture.
"""

from .conditions import Condition, parse_condition
from .decision import Decision, Effect
from .engine import PolicyEngine, redact_arguments
from .policy import STARTER_POLICY, Budget, Policy, Rule, load_policy, starter_policy
from .session import InMemorySessionStore, SessionStore
from .threats import ScanResult, ThreatCategory, ThreatHit, ThreatScanner

__all__ = [
    "Decision",
    "Effect",
    "Policy",
    "Rule",
    "Budget",
    "load_policy",
    "starter_policy",
    "STARTER_POLICY",
    "PolicyEngine",
    "redact_arguments",
    "Condition",
    "parse_condition",
    "SessionStore",
    "InMemorySessionStore",
    "ThreatScanner",
    "ScanResult",
    "ThreatHit",
    "ThreatCategory",
]
