"""Shared primitives: crypto, identifiers, and the error hierarchy."""

from . import crypto, ids
from .errors import (
    AlreadyReversed,
    AuthorityError,
    ChainBroken,
    ExpiredGrant,
    NotReversible,
    PolicyError,
    ReversalError,
    ReversalGateClosed,
    ReversalPlanMissing,
    ReversalWindowExpired,
    RevocoError,
    ScopeViolation,
    SignatureError,
    TamperDetected,
    UnknownPrincipal,
    ValidationError,
)

__all__ = [
    "crypto",
    "ids",
    "RevocoError",
    "ValidationError",
    "PolicyError",
    "AuthorityError",
    "UnknownPrincipal",
    "ScopeViolation",
    "ExpiredGrant",
    "ChainBroken",
    "SignatureError",
    "TamperDetected",
    "ReversalError",
    "NotReversible",
    "ReversalWindowExpired",
    "AlreadyReversed",
    "ReversalPlanMissing",
    "ReversalGateClosed",
]
