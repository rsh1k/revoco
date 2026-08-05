"""
praetor.adapters.devops
=======================
Inverse-operation specs for GitHub and Kubernetes.

Status: **specification, not a validated integration.** See ``docs/ADAPTERS.md``
for citations and the validation checklist.

Why this surface is the best argument for the architecture
---------------------------------------------------------
This is where snapshot-before-write earns its keep, because it turns operations
that are *natively* unrecoverable into recoverable ones:

* **A deleted branch.** GitHub offers a restore button only for branches attached
  to a pull request; a branch deleted from the branches list has no UI recovery
  path. Git's reflog does not help either — reflogs are **local**, cannot be
  fetched from a remote, and expire. But a branch is just a pointer: capture the
  tip SHA before the delete and recreating the ref is an exact inverse. The
  recovery exists only if someone wrote the SHA down first, which is precisely
  what this control plane does.
* **A force push.** Same logic. The old commits are unreachable but not yet
  collected, so a force-update back to the captured SHA restores history exactly.
* **A deleted Kubernetes resource.** ``kubectl delete`` has no undo. Capture the
  manifest first and re-applying it is a compensating action — not perfect, since
  the object comes back with a new UID and its pods are recreated, but the
  difference between "we lost the Deployment spec" and "we lost four minutes of
  uptime" is the difference between an incident and an inconvenience.

The counterweight
-----------------
Kubernetes' own rollback has a hard cliff. ``kubectl rollout undo`` works by
pointing back at an old ReplicaSet, and ``revisionHistoryLimit`` (default 10)
prunes them. Once the target ReplicaSet is gone, ``unable to find specified
revision`` is final — the configuration is not stored anywhere else. So a rollback
capability that *looks* built-in silently evaporates under a burst of deploys,
which is exactly the phantom-rollback condition worth alerting on.
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

GATE_GIT_OBJECTS_PRESENT = ReversalGate(
    name="git_objects_not_collected",
    description=(
        "The captured commit must still exist on the remote. After a branch delete or "
        "force push the old commits become unreachable, and unreachable objects are "
        "eventually garbage collected."
    ),
    remediation=(
        "Recover promptly. If the objects are gone, the only remaining sources are a "
        "local clone that still has them or a backup — and reflogs are local-only, so "
        "they cannot be fetched from the remote."
    ),
)

GATE_K8S_REVISION_PRESENT = ReversalGate(
    name="k8s_revision_still_in_history",
    description=(
        "The target revision's ReplicaSet must still exist. revisionHistoryLimit "
        "(default 10) prunes old ReplicaSets, and a pruned revision cannot be "
        "recovered — its configuration is stored nowhere else."
    ),
    remediation=(
        "Re-apply the captured manifest instead of rolling back to a revision. Raise "
        "revisionHistoryLimit on workloads agents can deploy to."
    ),
)

GATE_K8S_MANIFEST_CAPTURED = ReversalGate(
    name="k8s_manifest_captured",
    description=(
        "The full prior manifest must have been captured before the delete. "
        "Kubernetes offers no undo for a deleted object, so the snapshot is the only "
        "copy."
    ),
    remediation=(
        "If the manifest is in Git, recover from there. Otherwise the object must be "
        "rebuilt by hand."
    ),
    check_at=PHASE_AUTHORIZE,
)

GATE_PVC_RETAINED = ReversalGate(
    name="k8s_persistent_data_retained",
    description=(
        "Any PersistentVolumeClaim the workload used must not have been reclaimed. "
        "With a Delete reclaim policy the underlying volume is destroyed with the "
        "claim, so re-applying the manifest restores the workload but not its data."
    ),
    remediation=(
        "Restore data from backup separately. Use Retain reclaim policy on volumes "
        "agents can touch."
    ),
)

DEVOPS_GATES = (
    GATE_GIT_OBJECTS_PRESENT,
    GATE_K8S_REVISION_PRESENT,
    GATE_K8S_MANIFEST_CAPTURED,
    GATE_PVC_RETAINED,
)


DEVOPS_SPECS: list[InverseSpec] = [
    # -- GitHub refs --------------------------------------------------------
    InverseSpec(
        tool="github.branch.delete",
        kind=Reversibility.REVERSIBLE,
        inverse_tool="github.ref.create",
        arg_map=(
            ("owner", "args.owner"),
            ("repo", "args.repo"),
            ("ref", "args.ref"),
            ("sha", "snapshot.tip_sha"),
        ),
        snapshot_fields=("tip_sha",),
        gates=(GATE_GIT_OBJECTS_PRESENT,),
        notes=(
            "A branch is a pointer, so recreating it at the captured SHA is an exact "
            "inverse — better than what GitHub's own UI offers, which only restores "
            "branches that were attached to a pull request. The whole recovery hinges "
            "on having captured tip_sha before the delete."
        ),
    ),
    InverseSpec(
        tool="github.ref.force_update",
        kind=Reversibility.REVERSIBLE,
        inverse_tool="github.ref.force_update",
        arg_map=(
            ("owner", "args.owner"),
            ("repo", "args.repo"),
            ("ref", "args.ref"),
            ("sha", "snapshot.prior_sha"),
            ("force", "const:true"),
        ),
        snapshot_fields=("prior_sha",),
        gates=(GATE_GIT_OBJECTS_PRESENT,),
        notes=(
            "Force-push recovery normally depends on someone's local reflog, which is "
            "not fetchable from the remote and expires. Capturing prior_sha server-side "
            "removes that dependency entirely."
        ),
    ),
    InverseSpec(
        tool="github.pr.merge",
        kind=Reversibility.COMPENSABLE,
        inverse_tool="github.pr.revert",
        arg_map=(
            ("owner", "args.owner"),
            ("repo", "args.repo"),
            ("merge_commit_sha", "result.sha"),
        ),
        residue=(
            "A revert adds a new commit rather than removing the merge, so history "
            "shows both. The merge event stands, and anything it triggered — a "
            "deployment, a release, a downstream consumer that already pulled — is not "
            "reverted with it."
        ),
        notes=(
            "The honest classification. Reverting is not un-merging, and on a "
            "protected branch it is not even the same operation as a force push back."
        ),
    ),
    InverseSpec(
        tool="github.repo.update_branch_protection",
        kind=Reversibility.REVERSIBLE,
        inverse_tool="github.repo.update_branch_protection",
        arg_map=(
            ("owner", "args.owner"),
            ("repo", "args.repo"),
            ("branch", "args.branch"),
            ("protection", "snapshot.protection"),
        ),
        snapshot_fields=("protection",),
        notes=(
            "An agent weakening branch protection is a control being switched off. "
            "Exactly restorable, and every push that landed while it was off stays "
            "landed — so this belongs behind approval regardless of its reversibility."
        ),
    ),
    InverseSpec(
        tool="github.repo.delete",
        kind=Reversibility.IRREVERSIBLE,
        notes=(
            "Deliberately conservative. Organization-owned repositories may be "
            "restorable within a retention window depending on plan and settings, but "
            "that was not verified for this spec, and classifying it optimistically "
            "would be the exact mistake this file exists to prevent. Verify against "
            "your own org before relaxing it."
        ),
    ),
    # -- Kubernetes ---------------------------------------------------------
    InverseSpec(
        tool="k8s.resource.delete",
        kind=Reversibility.COMPENSABLE,
        inverse_tool="k8s.resource.apply",
        # namespace and name are passed explicitly even though a manifest carries
        # them internally. The containment benchmark caught the original
        # manifest-only version: it assumed the executor would dig identity out of
        # the manifest, so an executor that expected them as arguments could not
        # resolve the target at all. An inverse that depends on an implicit
        # convention is a rollback waiting to fail in an unfamiliar integration.
        arg_map=(
            ("namespace", "args.namespace"),
            ("name", "args.name"),
            ("manifest", "snapshot.manifest"),
        ),
        snapshot_fields=("manifest",),
        gates=(GATE_K8S_MANIFEST_CAPTURED, GATE_PVC_RETAINED),
        degraded_kind=Reversibility.IRREVERSIBLE,
        residue=(
            "Re-applying restores the object's spec but not its identity: the new "
            "object has a fresh UID and resourceVersion, its pods are recreated, "
            "in-flight requests were dropped, and anything that watched the delete "
            "event acted on it. If a PersistentVolumeClaim was reclaimed, the data is "
            "gone even though the workload is back."
        ),
        notes=(
            "The flagship example of this architecture's value. kubectl delete has no "
            "undo; capturing the manifest first is what creates one. The authorize gate "
            "means an agent cannot delete something whose manifest we failed to "
            "capture without a human seeing it first."
        ),
    ),
    InverseSpec(
        tool="k8s.resource.apply",
        kind=Reversibility.COMPENSABLE,
        inverse_tool="k8s.resource.apply",
        arg_map=(("manifest", "snapshot.manifest"),),
        snapshot_fields=("manifest",),
        residue=(
            "Re-applying the prior manifest converges the spec back, but the "
            "intervening rollout happened: pods were replaced, and any traffic served "
            "by the bad version was served by it."
        ),
    ),
    InverseSpec(
        tool="k8s.deployment.set_image",
        kind=Reversibility.COMPENSABLE,
        inverse_tool="k8s.rollout.undo",
        arg_map=(
            ("namespace", "args.namespace"),
            ("name", "args.name"),
            ("to_revision", "snapshot.revision"),
        ),
        snapshot_fields=("revision", "image"),
        gates=(GATE_K8S_REVISION_PRESENT,),
        residue=(
            "The rollback is itself a new rollout: pods restart again, and the revision "
            "history now contains both the bad deploy and its reversal."
        ),
        notes=(
            "The gate is the point. This looks like a built-in undo, but "
            "revisionHistoryLimit silently prunes the revision you need — so the "
            "capability evaporates under a burst of deploys with no error until you "
            "reach for it. Capturing the image alongside the revision number gives a "
            "fallback that does not depend on history retention."
        ),
    ),
    InverseSpec(
        tool="k8s.scale",
        kind=Reversibility.REVERSIBLE,
        inverse_tool="k8s.scale",
        arg_map=(
            ("namespace", "args.namespace"),
            ("name", "args.name"),
            ("replicas", "snapshot.replicas"),
        ),
        snapshot_fields=("replicas",),
        notes=(
            "Includes the scale-to-zero case, which is how an agent takes a service "
            "down. Exactly reversible; the downtime is not."
        ),
    ),
    InverseSpec(
        tool="k8s.namespace.delete",
        kind=Reversibility.IRREVERSIBLE,
        notes=(
            "A namespace delete cascades to every object in it. Even with manifests "
            "captured, restoring is a rebuild of arbitrary depth with new identities "
            "throughout — not an undo. This is a deny-by-policy operation, not a "
            "recoverable one."
        ),
    ),
    # -- feature flags ------------------------------------------------------
    InverseSpec(
        tool="flags.set_targeting",
        kind=Reversibility.COMPENSABLE,
        inverse_tool="flags.set_targeting",
        arg_map=(
            ("project", "args.project"),
            ("flag_key", "args.flag_key"),
            ("environment", "args.environment"),
            ("targeting", "snapshot.targeting"),
        ),
        snapshot_fields=("targeting", "enabled"),
        residue=(
            "Flipping the flag back is immediate, but every user served the other "
            "variant in the meantime saw it, and anything they did under it — orders "
            "placed, emails triggered, records written — stands."
        ),
        notes=(
            "Feature flags read as trivially reversible and are the fastest way for an "
            "agent to change production behaviour at scale. The config reverts in a "
            "second; the consequences do not."
        ),
    ),
    # -- multi-step: restore a workload AND its autoscaler ------------------
    InverseSpec(
        tool="k8s.hpa.delete",
        kind=Reversibility.COMPENSABLE,
        steps=(
            InverseStep(
                name="restore_replicas",
                tool="k8s.scale",
                arg_map=(
                    ("namespace", "args.namespace"),
                    ("name", "snapshot.target_name"),
                    ("replicas", "snapshot.current_replicas"),
                ),
                description=(
                    "Put the replica count back FIRST. Recreating the autoscaler "
                    "against a workload left at the wrong size makes it scale from a "
                    "bad baseline, which is a second incident rather than a recovery."
                ),
                critical=True,
            ),
            InverseStep(
                name="recreate_hpa",
                tool="k8s.resource.apply",
                arg_map=(("manifest", "snapshot.manifest"),),
                description="Re-apply the captured HorizontalPodAutoscaler.",
                critical=True,
            ),
        ),
        snapshot_fields=("manifest", "target_name", "current_replicas"),
        residue=(
            "The autoscaler returns with fresh metrics history, so its first scaling "
            "decisions are made without the trend data it had before."
        ),
    ),
]


def devops_registry() -> InverseRegistry:
    """An :class:`InverseRegistry` preloaded with the devops specs (unvalidated)."""
    return InverseRegistry(list(DEVOPS_SPECS))


__all__ = ["DEVOPS_SPECS", "DEVOPS_GATES", "devops_registry"]
