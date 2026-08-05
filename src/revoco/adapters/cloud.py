"""
revoco.adapters.cloud
======================
Inverse-operation specs for AWS control-plane and data-plane writes.

Status: **specification, not a validated integration.** See ``docs/ADAPTERS.md``
for citations and the validation checklist.

The lesson this surface teaches
-------------------------------
On AWS, **reversibility is a property of the target's configuration, not of the
API call.** ``DeleteObject`` against a versioning-enabled bucket inserts a delete
marker you can remove; the identical call against a non-versioned bucket destroys
the object. Same tool, same arguments, opposite outcomes.

That is what authorize-phase gates are for. A control plane that classified
``aws.s3.delete_object`` as "compensable" once and for all would cheerfully tell
policy the action was undoable while an agent emptied an unversioned bucket. Here
the gate is evaluated *before* the delete, and a closed gate degrades the action
to irreversible, so the reversibility-first policy escalates to a human at the
only moment escalation is worth anything.

The other lesson: caches are not state you own
---------------------------------------------
Route 53 record changes are restorable, but resolvers worldwide keep serving the
bad answer until the TTL expires. The record is fixed; the outage is not over.
That gap is recorded as residue rather than papered over, because an incident
report that says "DNS restored at 14:02" and omits "and kept failing until 14:07"
is the kind of half-truth that erodes trust in the whole system.
"""

from __future__ import annotations

from ..reversal.model import (
    PHASE_AUTHORIZE,
    InverseSpec,
    InverseStep,
    ReversalGate,
    Reversibility,
)
from ..reversal.registry import InverseRegistry

# ---------------------------------------------------------------------------
# Gates
# ---------------------------------------------------------------------------

GATE_S3_VERSIONING = ReversalGate(
    name="aws_s3_versioning_enabled",
    description=(
        "The target bucket must have versioning enabled. Without it, a delete or "
        "overwrite destroys the object outright and there is nothing to restore."
    ),
    remediation=(
        "Enable versioning on buckets any agent can write to. This is the single "
        "highest-leverage change available on this surface: it converts every "
        "object delete and overwrite from irreversible to recoverable."
    ),
    check_at=PHASE_AUTHORIZE,
)

GATE_S3_MFA_DELETE_OFF = ReversalGate(
    name="aws_s3_mfa_delete_not_required",
    description=(
        "Removing a delete marker requires deleting a specific version, which MFA "
        "Delete blocks without an MFA code. An automated undo cannot supply one."
    ),
    remediation=(
        "Either accept that recovery on this bucket is a manual root-account "
        "operation, or run agents against buckets without MFA Delete."
    ),
)

GATE_IAM_VERSION_RETAINED = ReversalGate(
    name="aws_iam_policy_version_retained",
    description=(
        "IAM keeps at most five versions of a customer managed policy. The version "
        "that was default before the change must still be among them."
    ),
    remediation=(
        "If it was pruned, restore from the captured policy document by creating a "
        "new version rather than rolling back to an old one."
    ),
)

GATE_RDS_FINAL_SNAPSHOT = ReversalGate(
    name="aws_rds_final_snapshot_taken",
    description=(
        "A deleted DB instance is recoverable only from a snapshot. The delete call "
        "must have requested a final snapshot, or a recent automated one must exist."
    ),
    remediation=(
        "Never allow an agent to call DeleteDBInstance with SkipFinalSnapshot. Deny "
        "that argument shape in policy rather than relying on the undo."
    ),
    check_at=PHASE_AUTHORIZE,
)

GATE_KMS_PENDING_WINDOW = ReversalGate(
    name="aws_kms_key_still_pending_deletion",
    description=(
        "A KMS key scheduled for deletion can be recovered only while it is in "
        "PendingDeletion, during the waiting period set when it was scheduled."
    ),
    remediation="Cancel the deletion before the waiting period elapses.",
)

CLOUD_GATES = (
    GATE_S3_VERSIONING,
    GATE_S3_MFA_DELETE_OFF,
    GATE_IAM_VERSION_RETAINED,
    GATE_RDS_FINAL_SNAPSHOT,
    GATE_KMS_PENDING_WINDOW,
)


CLOUD_SPECS: list[InverseSpec] = [
    # -- S3 -----------------------------------------------------------------
    InverseSpec(
        tool="aws.s3.delete_object",
        kind=Reversibility.COMPENSABLE,
        inverse_tool="aws.s3.delete_object_version",
        arg_map=(
            ("Bucket", "args.Bucket"),
            ("Key", "args.Key"),
            ("VersionId", "result.VersionId"),
        ),
        gates=(GATE_S3_VERSIONING, GATE_S3_MFA_DELETE_OFF),
        degraded_kind=Reversibility.IRREVERSIBLE,
        residue=(
            "Undeleting works by deleting the delete marker, so the object's version "
            "history records both the deletion and its removal. Anything that read "
            "the key while the marker was current correctly saw a 404."
        ),
        notes=(
            "The canonical case for authorize-phase gates. With versioning on, the "
            "delete inserts a marker and `VersionId` in the response identifies it. "
            "With versioning off, this same call is unrecoverable — which is why the "
            "gate degrades the classification instead of hoping for the best."
        ),
    ),
    InverseSpec(
        tool="aws.s3.put_object",
        kind=Reversibility.COMPENSABLE,
        inverse_tool="aws.s3.copy_object",
        arg_map=(
            ("Bucket", "args.Bucket"),
            ("Key", "args.Key"),
            ("CopySource", "snapshot.PriorVersionSource"),
        ),
        snapshot_fields=("PriorVersionSource", "PriorVersionId", "ETag"),
        gates=(GATE_S3_VERSIONING,),
        degraded_kind=Reversibility.IRREVERSIBLE,
        residue=(
            "Restoring copies the prior version forward, creating a third version "
            "rather than removing the second. Consumers that read the key while the "
            "bad version was current got the bad content."
        ),
        notes=(
            "`PriorVersionSource` should be captured as bucket/key?versionId=... so "
            "the copy is unambiguous. Without versioning an overwrite destroys the "
            "prior bytes and no snapshot short of copying the whole object helps."
        ),
    ),
    # -- IAM ----------------------------------------------------------------
    InverseSpec(
        tool="aws.iam.create_policy_version",
        kind=Reversibility.REVERSIBLE,
        inverse_tool="aws.iam.set_default_policy_version",
        arg_map=(
            ("PolicyArn", "args.PolicyArn"),
            ("VersionId", "snapshot.DefaultVersionId"),
        ),
        snapshot_fields=("DefaultVersionId",),
        gates=(GATE_IAM_VERSION_RETAINED,),
        notes=(
            "IAM policy versioning is a genuine built-in undo: rolling back means "
            "making the previous version default again, with nothing deleted or "
            "recreated. The catch is the five-version ceiling — capture the prior "
            "default version id, and capture the document too so you can rebuild if "
            "the version was pruned."
        ),
    ),
    InverseSpec(
        tool="aws.iam.attach_role_policy",
        kind=Reversibility.REVERSIBLE,
        inverse_tool="aws.iam.detach_role_policy",
        arg_map=(("RoleName", "args.RoleName"), ("PolicyArn", "args.PolicyArn")),
        notes=(
            "Privilege grants are cleanly reversible, which is worth knowing: the "
            "dangerous direction on this surface is not granting access but removing "
            "it, or deleting the principal."
        ),
    ),
    InverseSpec(
        tool="aws.iam.detach_role_policy",
        kind=Reversibility.REVERSIBLE,
        inverse_tool="aws.iam.attach_role_policy",
        arg_map=(("RoleName", "args.RoleName"), ("PolicyArn", "args.PolicyArn")),
        notes="The lockout direction. Reversible, but the outage during it is not.",
    ),
    InverseSpec(
        tool="aws.iam.delete_role",
        kind=Reversibility.IRREVERSIBLE,
        notes=(
            "No soft delete. Recreating a role with the same name produces a "
            "different principal id, so every trust policy and every resource policy "
            "that referenced the old id must be rewritten. Treat recreation as a "
            "migration, not an undo."
        ),
    ),
    # -- EC2 / networking ---------------------------------------------------
    InverseSpec(
        tool="aws.ec2.authorize_security_group_ingress",
        kind=Reversibility.REVERSIBLE,
        inverse_tool="aws.ec2.revoke_security_group_ingress",
        arg_map=(
            ("GroupId", "args.GroupId"),
            ("IpPermissions", "args.IpPermissions"),
        ),
        notes="Opening a port is exactly reversible by closing it.",
    ),
    InverseSpec(
        tool="aws.ec2.revoke_security_group_ingress",
        kind=Reversibility.REVERSIBLE,
        inverse_tool="aws.ec2.authorize_security_group_ingress",
        arg_map=(
            ("GroupId", "args.GroupId"),
            ("IpPermissions", "snapshot.RevokedPermissions"),
        ),
        snapshot_fields=("RevokedPermissions",),
        notes=(
            "The self-lockout case: an agent tidying security groups removes the rule "
            "its own operators connect through. Restoring the exact permission set "
            "requires having captured it, because the revoke response does not "
            "return what it removed."
        ),
    ),
    InverseSpec(
        tool="aws.ec2.terminate_instances",
        kind=Reversibility.IRREVERSIBLE,
        notes=(
            "Instance-store data is gone; even where EBS volumes survive, the "
            "instance identity, its IPs, and anything in memory do not. Launching a "
            "replacement is not an undo."
        ),
    ),
    InverseSpec(
        tool="aws.rds.delete_db_instance",
        kind=Reversibility.COMPENSABLE,
        inverse_tool="aws.rds.restore_db_instance_from_snapshot",
        arg_map=(
            ("DBInstanceIdentifier", "args.DBInstanceIdentifier"),
            ("DBSnapshotIdentifier", "args.FinalDBSnapshotIdentifier"),
        ),
        gates=(GATE_RDS_FINAL_SNAPSHOT,),
        degraded_kind=Reversibility.IRREVERSIBLE,
        residue=(
            "A restore rebuilds the instance from the snapshot: writes after the "
            "snapshot are lost, the endpoint address changes, parameter and option "
            "group associations may need reapplying, and the restore itself takes "
            "long enough to be an outage."
        ),
        notes=(
            "Policy should deny SkipFinalSnapshot outright rather than depend on this "
            "spec. The undo exists, but 'we lost the last few minutes of writes and "
            "changed the endpoint' is a bad day even when it works."
        ),
    ),
    # -- DNS ----------------------------------------------------------------
    InverseSpec(
        tool="aws.route53.change_resource_record_sets",
        kind=Reversibility.COMPENSABLE,
        inverse_tool="aws.route53.change_resource_record_sets",
        arg_map=(
            ("HostedZoneId", "args.HostedZoneId"),
            ("ChangeBatch", "snapshot.PriorRecordSets"),
        ),
        snapshot_fields=("PriorRecordSets",),
        residue=(
            "The authoritative record is restored immediately, but resolvers and "
            "clients worldwide keep serving the wrong answer until the previous TTL "
            "expires. You cannot un-cache a DNS answer, so the record is fixed "
            "before the outage is over."
        ),
        notes=(
            "Worth pairing with a policy rule that caps TTL on agent-writable zones: "
            "a low TTL is what bounds the residue, and it has to be set before the "
            "mistake, not after."
        ),
    ),
    # -- KMS ----------------------------------------------------------------
    InverseSpec(
        tool="aws.kms.schedule_key_deletion",
        kind=Reversibility.REVERSIBLE,
        inverse_tool="aws.kms.cancel_key_deletion",
        arg_map=(("KeyId", "args.KeyId"),),
        gates=(GATE_KMS_PENDING_WINDOW,),
        notes=(
            "One of the better-designed destructive operations in AWS: the mandatory "
            "waiting period is a built-in undo window, and cancelling restores the "
            "key intact. The window length is set when deletion is scheduled, which "
            "is why this is a gate rather than a fixed window_seconds — read the "
            "actual PendingWindowInDays rather than assuming."
        ),
    ),
    InverseSpec(
        tool="aws.kms.disable_key",
        kind=Reversibility.REVERSIBLE,
        inverse_tool="aws.kms.enable_key",
        arg_map=(("KeyId", "args.KeyId"),),
        notes=(
            "Reversible, and the right containment move for a suspected key "
            "compromise: disable is undoable, scheduled deletion eventually is not."
        ),
    ),
    # -- multi-step example: restoring a bucket policy AND its public-access block
    InverseSpec(
        tool="aws.s3.put_bucket_policy",
        kind=Reversibility.REVERSIBLE,
        steps=(
            InverseStep(
                name="restore_public_access_block",
                tool="aws.s3.put_public_access_block",
                arg_map=(
                    ("Bucket", "args.Bucket"),
                    ("PublicAccessBlockConfiguration", "snapshot.PublicAccessBlock"),
                ),
                description=(
                    "Re-block public access FIRST. Restoring a restrictive policy "
                    "while the access block is still off leaves a window in which the "
                    "bucket is reachable, and the whole point of the undo is to close "
                    "that window."
                ),
                critical=True,
            ),
            InverseStep(
                name="restore_policy",
                tool="aws.s3.put_bucket_policy",
                arg_map=(
                    ("Bucket", "args.Bucket"),
                    ("Policy", "snapshot.PriorPolicy"),
                ),
                description="Put the captured prior bucket policy back.",
                critical=True,
            ),
        ),
        snapshot_fields=("PriorPolicy", "PublicAccessBlock"),
        notes=(
            "Ordering matters for the same reason it does in the SAP payment case: an "
            "undo executed in the wrong order can leave a worse state than the one it "
            "was correcting."
        ),
    ),
]


def cloud_registry() -> InverseRegistry:
    """An :class:`InverseRegistry` preloaded with the AWS specs (unvalidated)."""
    return InverseRegistry(list(CLOUD_SPECS))


__all__ = ["CLOUD_SPECS", "CLOUD_GATES", "cloud_registry"]
