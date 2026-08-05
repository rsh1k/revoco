"""
praetor.adapters.identity
=========================
Inverse-operation specs for Microsoft Entra ID and Okta.

Status: **specification, not a validated integration.** See ``docs/ADAPTERS.md``
for citations and the validation checklist.

Why this surface is different
-----------------------------
Identity is the one place where the *undo* is more dangerous than the original
action. Restoring a deleted account restores access. If an agent deleted the
account because it was compromised, a well-meaning cascade rollback hands the
attacker their session back. Nothing in this package can tell those two cases
apart, so the rule to take away is: **containment on an identity surface means
disable, not delete, and rollback here needs a human in the loop even when the
undo is technically clean.**

The two useful facts
--------------------
**Entra soft-deletes on a fixed 30-day clock.** Users, Microsoft 365 groups,
cloud security groups, and app registrations enter a restorable state for 30 days,
after which they are hard deleted and unrecoverable by anyone including Microsoft
Support. The window is not customizable. Crucially, *only certain object types
soft-delete* — distribution groups, for instance, do not — so the same "delete"
verb is recoverable or final depending on what it points at. That is an
authorize-phase gate.

**Okta separates deactivate from delete, and only one is reversible.**
Deactivation is undoable; deletion is not. And there is a trap in between:
deactivating a user does *not* re-evaluate group rules, so the account keeps its
group memberships while inactive. An undo that only reactivates the user is
correct; an undo that also "restores" memberships would add ones that were never
removed.
"""

from __future__ import annotations

from ..reversal.model import (
    PHASE_AUTHORIZE,
    InverseSpec,
    ReversalGate,
    Reversibility,
)
from ..reversal.registry import InverseRegistry

_ENTRA_SOFT_DELETE_WINDOW = 30 * 24 * 3600.0  # 30 days, not customizable

# ---------------------------------------------------------------------------
# Gates
# ---------------------------------------------------------------------------

GATE_ENTRA_SOFT_DELETABLE = ReversalGate(
    name="entra_object_type_soft_deletes",
    description=(
        "The object type must be one that Entra soft-deletes: users, Microsoft 365 "
        "groups, cloud security groups, or app registrations. Other types — "
        "distribution groups among them — are hard deleted immediately."
    ),
    remediation=(
        "For hard-deleting types there is no undo. Deny agent deletion of them "
        "outright, or require approval, rather than relying on a restore that does "
        "not exist."
    ),
    check_at=PHASE_AUTHORIZE,
)

GATE_ENTRA_STILL_RESTORABLE = ReversalGate(
    name="entra_object_still_in_soft_delete",
    description=(
        "The object must still be within its 30-day soft-delete window and not "
        "already permanently removed."
    ),
    remediation=(
        "After 30 days neither you nor Microsoft Support can restore it; the object "
        "must be recreated, with a new object id and all references rewritten."
    ),
)

GATE_IDENTITY_NOT_COMPROMISED = ReversalGate(
    name="identity_restore_is_intended",
    description=(
        "Restoring an identity restores access. A human must confirm the account was "
        "deleted or disabled by mistake rather than in response to a compromise."
    ),
    remediation=(
        "Route this to the on-call identity owner. An automated cascade must never "
        "silently re-enable credentials it cannot vouch for."
    ),
)

IDENTITY_GATES = (
    GATE_ENTRA_SOFT_DELETABLE,
    GATE_ENTRA_STILL_RESTORABLE,
    GATE_IDENTITY_NOT_COMPROMISED,
)


IDENTITY_SPECS: list[InverseSpec] = [
    # -- Entra ID -----------------------------------------------------------
    InverseSpec(
        tool="entra.user.delete",
        kind=Reversibility.COMPENSABLE,
        inverse_tool="entra.directoryobject.restore",
        arg_map=(("id", "args.id"),),
        snapshot_fields=("userPrincipalName", "displayName", "accountEnabled", "assignedLicenses"),
        window_seconds=_ENTRA_SOFT_DELETE_WINDOW,
        gates=(GATE_ENTRA_SOFT_DELETABLE, GATE_ENTRA_STILL_RESTORABLE,
               GATE_IDENTITY_NOT_COMPROMISED),
        degraded_kind=Reversibility.IRREVERSIBLE,
        residue=(
            "The object comes back with its id and properties, but licence "
            "assignments and some application assignments may need reapplying, and "
            "anything that failed for the user during the deleted interval stays "
            "failed. Downstream systems provisioned from Entra may have already "
            "deprovisioned the account."
        ),
        notes=(
            "A genuine time window, so window_seconds is correct here — 30 days, not "
            "customizable. This is the rare case where the clock-based model fits, "
            "which is worth noting given how often it does not."
        ),
    ),
    InverseSpec(
        tool="entra.group.delete",
        kind=Reversibility.COMPENSABLE,
        inverse_tool="entra.directoryobject.restore",
        arg_map=(("id", "args.id"),),
        snapshot_fields=("displayName", "groupTypes", "securityEnabled", "mailEnabled"),
        window_seconds=_ENTRA_SOFT_DELETE_WINDOW,
        gates=(GATE_ENTRA_SOFT_DELETABLE, GATE_ENTRA_STILL_RESTORABLE),
        degraded_kind=Reversibility.IRREVERSIBLE,
        residue=(
            "The group and its membership return, but access granted through it was "
            "absent for the whole deleted interval, and any conditional-access or "
            "licensing behaviour keyed on it behaved as though the group did not "
            "exist."
        ),
        notes=(
            "The authorize gate matters most here: Microsoft 365 and cloud security "
            "groups soft-delete, distribution groups do not. Same API verb, and one "
            "of them is unrecoverable."
        ),
    ),
    InverseSpec(
        tool="entra.group.add_member",
        kind=Reversibility.REVERSIBLE,
        inverse_tool="entra.group.remove_member",
        arg_map=(("groupId", "args.groupId"), ("memberId", "args.memberId")),
        notes=(
            "Privilege escalation via group membership is exactly reversible, which "
            "makes it the cheap case. Note the asymmetry with removal below."
        ),
    ),
    InverseSpec(
        tool="entra.group.remove_member",
        kind=Reversibility.REVERSIBLE,
        inverse_tool="entra.group.add_member",
        arg_map=(("groupId", "args.groupId"), ("memberId", "args.memberId")),
        notes=(
            "The lockout direction. Reversible, but membership removal may have "
            "triggered downstream deprovisioning that adding the member back does not "
            "reverse."
        ),
    ),
    InverseSpec(
        tool="entra.roleassignment.create",
        kind=Reversibility.REVERSIBLE,
        inverse_tool="entra.roleassignment.delete",
        arg_map=(("id", "result.id"),),
        notes=(
            "An agent granting itself or another principal a directory role is the "
            "highest-consequence write on this surface. Exactly reversible, and still "
            "the one to require approval on — by the time you undo it, the elevated "
            "principal has already been able to act."
        ),
    ),
    InverseSpec(
        tool="entra.user.update",
        kind=Reversibility.REVERSIBLE,
        inverse_tool="entra.user.update",
        arg_map=(
            ("id", "args.id"),
            ("accountEnabled", "snapshot.accountEnabled"),
            ("userPrincipalName", "snapshot.userPrincipalName"),
            ("displayName", "snapshot.displayName"),
        ),
        snapshot_fields=("accountEnabled", "userPrincipalName", "displayName"),
        notes=(
            "Covers the disable case (accountEnabled=false), which is the *right* "
            "containment action on this surface precisely because it is cleanly "
            "reversible where deletion is not."
        ),
    ),
    # -- Okta ---------------------------------------------------------------
    InverseSpec(
        tool="okta.user.deactivate",
        kind=Reversibility.COMPENSABLE,
        inverse_tool="okta.user.reactivate",
        arg_map=(("userId", "args.userId"),),
        snapshot_fields=("status",),
        gates=(GATE_IDENTITY_NOT_COMPROMISED,),
        residue=(
            "Reactivation restores the account but some application assignments may "
            "need to be reassigned. Group memberships were never removed — Okta does "
            "not re-evaluate group rules on deactivation — so they need no "
            "restoration and any attempt to 'restore' them would add memberships that "
            "were never lost."
        ),
        notes=(
            "The documented deactivate/group-rule interaction is the trap on this "
            "surface. An undo written from intuition rather than from the docs would "
            "get it wrong in the direction of granting extra access."
        ),
    ),
    InverseSpec(
        tool="okta.user.delete",
        kind=Reversibility.IRREVERSIBLE,
        notes=(
            "Deletion in Okta follows deactivation and is permanent. This is why the "
            "two are separate tools here: policy should permit deactivate freely and "
            "gate delete behind a human, because only one of them has an undo."
        ),
    ),
    InverseSpec(
        tool="okta.group.add_user",
        kind=Reversibility.REVERSIBLE,
        inverse_tool="okta.group.remove_user",
        arg_map=(("groupId", "args.groupId"), ("userId", "args.userId")),
    ),
    InverseSpec(
        tool="okta.group.remove_user",
        kind=Reversibility.REVERSIBLE,
        inverse_tool="okta.group.add_user",
        arg_map=(("groupId", "args.groupId"), ("userId", "args.userId")),
    ),
    InverseSpec(
        tool="okta.policy.deactivate",
        kind=Reversibility.REVERSIBLE,
        inverse_tool="okta.policy.activate",
        arg_map=(("policyId", "args.policyId"),),
        notes=(
            "An agent deactivating an MFA or sign-on policy is a security control "
            "being switched off. Technically reversible; every sign-in during the gap "
            "happened under the weaker policy and cannot be re-evaluated."
        ),
    ),
]


def identity_registry() -> InverseRegistry:
    """An :class:`InverseRegistry` preloaded with the identity specs (unvalidated)."""
    return InverseRegistry(list(IDENTITY_SPECS))


__all__ = ["IDENTITY_SPECS", "IDENTITY_GATES", "identity_registry"]
