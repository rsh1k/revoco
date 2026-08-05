"""
The delegated-authority layer — who may act, on whose behalf, within what limit.

Ported from ``veritrail``. The capability model (attenuating, Ed25519-signed
delegation chains that terminate at a human) is unchanged; what is new is
:attr:`Scope.min_reversibility`, which lets a grant require that everything done
under it be undoable.
"""

from .action import ActionRecord, build_signed_action
from .delegation import Delegation, build_signed_delegation
from .engine import AuthorityEngine, ChainResult
from .principals import Principal, PrincipalKind, PrincipalRegistry
from .revocation import Revocation, RevocationRegistry
from .scope import WILDCARD, Scope

__all__ = [
    "Scope",
    "WILDCARD",
    "Principal",
    "PrincipalKind",
    "PrincipalRegistry",
    "Delegation",
    "build_signed_delegation",
    "ActionRecord",
    "build_signed_action",
    "Revocation",
    "RevocationRegistry",
    "AuthorityEngine",
    "ChainResult",
]
