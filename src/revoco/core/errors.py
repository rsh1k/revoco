"""
revoco.core.errors
===================
One exception hierarchy for the whole control plane.

The three merged codebases each had their own error types (``ValidationError``,
``PolicyError``, ``IntegrityError``). Collapsing them into a single tree matters
for a control plane specifically: a caller wrapping ``revoco`` needs one
``except RevocoError`` to be sure it cannot leak an unhandled exception into a
fail-open path.
"""

from __future__ import annotations


class RevocoError(Exception):
    """Base class for every error raised by revoco."""


# ---- input / model errors -------------------------------------------------
class ValidationError(RevocoError):
    """Malformed input: bad field, out-of-range value, oversized payload."""


class PolicyError(RevocoError):
    """A policy document is invalid and cannot be loaded."""


# ---- authority errors -----------------------------------------------------
class AuthorityError(RevocoError):
    """Base for failures in the delegated-authority layer."""


class UnknownPrincipal(AuthorityError):
    """A referenced principal was never registered."""


class ScopeViolation(AuthorityError):
    """An action or sub-delegation exceeds the authority actually granted."""


class ExpiredGrant(AuthorityError):
    """The authorizing delegation is past its expiry."""


class ChainBroken(AuthorityError):
    """The delegation chain could not be walked back to a human root."""


class SignatureError(AuthorityError):
    """A signature failed to verify."""


# ---- ledger errors --------------------------------------------------------
class TamperDetected(RevocoError):
    """The hash chain does not validate: history has been altered."""


# ---- reversal errors ------------------------------------------------------
class ReversalError(RevocoError):
    """Base for failures in the reversal layer."""


class NotReversible(ReversalError):
    """No inverse operation is registered, or the action is irreversible."""


class ReversalWindowExpired(ReversalError):
    """The window in which the inverse operation was valid has closed."""


class AlreadyReversed(ReversalError):
    """The action has already been reversed; reversal is not idempotent-safe
    to repeat because the inverse would apply twice."""


class ReversalPlanMissing(ReversalError):
    """No reversal plan was journaled for this action, so it cannot be undone
    with any assurance about prior state."""


class ReversalGateClosed(ReversalError):
    """A precondition for the undo does not currently hold.

    Distinct from :class:`ReversalWindowExpired`: a closed gate may reopen (an
    accounting period can be reopened; a payroll can be rolled back by a
    specialist), whereas an expired time window cannot. Conflating them would
    tell an incident responder the rollback is gone when in fact it is blocked on
    something a human can clear.
    """
