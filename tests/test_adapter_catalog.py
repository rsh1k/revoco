"""Repo-wide invariants over every adapter spec, and the degradation path.

These are the tests that scale: rather than asserting facts about 91 specs one at
a time, they assert the properties every spec must have for the reversal layer to
be trustworthy. A new adapter that violates one fails here.
"""

from __future__ import annotations

import pytest

from revoco import ControlPlane, Scope, crypto
from revoco.adapters import (
    SURFACES,
    all_specs,
    gate_catalog,
    registry_for,
    summary,
)
from revoco.gate import load_policy
from revoco.reversal import InverseSpec, Reversibility
from revoco.reversal.model import PHASE_AUTHORIZE

REVERSIBILITY_FIRST = {
    "name": "test-reversibility-first",
    "default_effect": "deny",
    "rules": [
        {"id": "reads", "effect": "allow", "actions": ["read"]},
        {"id": "no-undo", "effect": "require_approval",
         "reversibility": ["irreversible", "unknown"]},
        {"id": "undoable", "effect": "allow", "reversibility": ["reversible", "compensable"]},
    ],
}


# ---------------------------------------------------------------------------
# Invariants across every spec on every surface
# ---------------------------------------------------------------------------


def test_all_surfaces_load():
    specs = all_specs()
    assert len(specs) > 80
    assert len(SURFACES) == 8


def test_every_spec_round_trips_through_dict():
    """Specs must survive YAML/JSON export, or they cannot be shipped as data."""
    for spec in all_specs():
        assert InverseSpec.from_dict(spec.to_dict()) == spec, spec.tool


def test_every_compensable_spec_names_its_residue():
    """An unnamed side effect is an unowned risk."""
    for spec in all_specs():
        if spec.kind is Reversibility.COMPENSABLE:
            assert spec.residue.strip(), f"{spec.tool} is compensable with no residue"


def test_no_spec_reads_a_snapshot_field_it_never_captures():
    """The easiest way to author a phantom rollback, checked repo-wide."""
    for spec in all_specs():
        referenced = {
            expr.split(".", 1)[1].split(".")[0]
            for step in spec.effective_steps
            for _name, expr in step.arg_map
            if expr.startswith("snapshot.")
        }
        undeclared = referenced - set(spec.snapshot_fields)
        assert not undeclared, f"{spec.tool} reads uncaptured snapshot fields {undeclared}"


def test_every_gate_explains_itself_and_offers_remediation():
    """A blocked rollback with no explanation is an unactionable alert."""
    for name, info in gate_catalog().items():
        assert info["description"].strip(), f"gate {name} has no description"
        assert info["remediation"].strip(), f"gate {name} has no remediation"


def test_gate_names_are_unique_across_surfaces():
    """Evaluators dispatch on the name, so a collision would silently cross wires."""
    seen: dict[str, str] = {}
    for surface, (_specs, gates) in SURFACES.items():
        for gate in gates:
            assert gate.name not in seen or seen[gate.name] == surface, (
                f"gate {gate.name} declared by both {seen[gate.name]} and {surface}"
            )
            seen[gate.name] = surface


def test_every_spec_gate_is_in_its_surface_catalog():
    """A gate used by a spec but absent from the catalog would never be documented."""
    catalog = set(gate_catalog())
    for spec in all_specs():
        for gate in spec.gates:
            assert gate.name in catalog, f"{spec.tool} uses undocumented gate {gate.name}"


def test_irreversible_and_unknown_specs_declare_no_undo_path():
    for spec in all_specs():
        if not spec.kind.is_undoable:
            assert spec.effective_steps == (), spec.tool


def test_undoable_specs_all_have_an_executable_path():
    for spec in all_specs():
        if spec.kind.is_undoable:
            assert spec.effective_steps, spec.tool


def test_degradation_never_increases_recoverability():
    for spec in all_specs():
        assert spec.degraded_kind.rank <= spec.kind.rank, spec.tool


def test_degraded_kind_is_pinned_for_specs_with_no_undo_path():
    """UNKNOWN ranks below IRREVERSIBLE, so a default would read as an upgrade."""
    for spec in all_specs():
        if not spec.kind.is_undoable:
            assert spec.degraded_kind is spec.kind, spec.tool


def test_authorize_gates_only_appear_on_specs_that_could_degrade():
    for spec in all_specs():
        if spec.authorize_gates:
            assert spec.kind.is_undoable, spec.tool


def test_tool_names_are_namespaced_so_surfaces_can_be_combined():
    for spec in all_specs():
        assert "." in spec.tool, f"{spec.tool} is not namespaced"


def test_combined_registry_has_no_tool_collisions():
    reg = registry_for()
    assert len(reg.all()) == len(all_specs())
    tools = [s.tool for s in all_specs()]
    assert len(tools) == len(set(tools))


def test_registry_for_selects_a_subset():
    reg = registry_for("workstation")
    assert reg.classify("fs.write_file") is Reversibility.REVERSIBLE
    assert reg.classify("sap.journalentry.post") is Reversibility.UNKNOWN


def test_unknown_surface_raises():
    with pytest.raises(KeyError, match="unknown surface"):
        registry_for("mainframe")


def test_summary_reports_the_two_numbers_worth_escalating():
    s = summary()
    # How much of the undo surface exists only because state is captured first.
    assert s["snapshot_dependent"] > 20
    # How many specs can turn out irreversible for a particular target.
    assert s["degradable"] > 5
    assert s["gates"] == len(gate_catalog())


# ---------------------------------------------------------------------------
# Surface-specific semantics worth pinning down
# ---------------------------------------------------------------------------


def test_arbitrary_shell_and_sql_stay_unclassified():
    """The correct answer, not a gap: neither can be classified in advance."""
    reg = registry_for()
    assert reg.classify("shell.exec") is Reversibility.UNKNOWN
    assert reg.classify("db.execute_sql") is Reversibility.UNKNOWN


def test_destructive_operations_with_no_recovery_are_marked_so():
    reg = registry_for()
    for tool in (
        "db.drop_table",
        "db.truncate_table",
        "k8s.namespace.delete",
        "aws.iam.delete_role",
        "aws.ec2.terminate_instances",
        "okta.user.delete",
        "git.clean",
        "slack.chat.delete",
        "stripe.subscription.cancel",
        "salesforce.record.hard_delete",
    ):
        assert reg.classify(tool) is Reversibility.IRREVERSIBLE, tool


def test_the_safe_alternative_is_reversible_in_each_dangerous_pair():
    """Each irreversible operation has a reversible sibling worth steering to."""
    reg = registry_for()
    pairs = [
        ("okta.user.delete", "okta.user.deactivate"),          # delete vs disable
        ("sap.journalentry.post", "sap.journalentry.park"),    # post vs park
        ("stripe.subscription.cancel", "stripe.subscription.update"),
        ("salesforce.record.hard_delete", "salesforce.record.delete"),
    ]
    for dangerous, safer in pairs:
        assert reg.classify(dangerous).rank < reg.classify(safer).rank, (dangerous, safer)


def test_snapshot_is_what_makes_these_recoverable_at_all():
    """Natively-unrecoverable operations, recoverable only via captured state."""
    reg = registry_for()
    for tool in (
        "k8s.resource.delete",
        "github.branch.delete",
        "github.ref.force_update",
        "fs.write_file",
        "fs.delete_file",
        "aws.ec2.revoke_security_group_ingress",
        "sap.supplier.bank.update",
    ):
        spec = reg.get(tool)
        assert spec is not None and spec.snapshot_fields, tool
        assert spec.kind.is_undoable, tool


def test_entra_soft_delete_uses_the_documented_thirty_day_window():
    spec = registry_for("identity").get("entra.user.delete")
    assert spec.window_seconds == 30 * 24 * 3600.0


def test_salesforce_has_both_a_clock_and_a_capacity_gate():
    """The recycle bin can purge early under volume, so the clock is not enough."""
    spec = registry_for("saas").get("salesforce.record.delete")
    assert spec.window_seconds == 15 * 24 * 3600.0
    assert any("recycle_bin" in g.name for g in spec.gates)


def test_identity_restore_requires_a_human_to_confirm_intent():
    """Restoring an identity restores access; a cascade must not do it silently."""
    for tool in ("entra.user.delete", "okta.user.deactivate"):
        spec = registry_for("identity").get(tool)
        assert any(g.name == "identity_restore_is_intended" for g in spec.gates), tool


# ---------------------------------------------------------------------------
# Authorize-phase degradation, end to end
# ---------------------------------------------------------------------------


def _plane(gate_evaluator, policy=None):
    cp = ControlPlane(
        policy=load_policy(policy or REVERSIBILITY_FIRST),
        inverse_registry=registry_for(),
        state_reader=lambda t, a, f: {f_: f"prior-{f_}" for f_ in f},
        gate_evaluator=gate_evaluator,
        approval_hook=lambda *a: False,   # nobody available: escalation blocks
    )
    h_priv, h_pub = crypto.generate_keypair()
    a_priv, a_pub = crypto.generate_keypair()
    cfo = cp.register_human("Owner", h_pub)
    bot = cp.register_agent("bot", a_pub)
    grant = cp.issue_root_delegation(
        human_private_key=h_priv, human_id=cfo.id, agent_id=bot.id,
        scope=Scope.make(
            tools={"aws.s3.delete_object", "k8s.resource.delete", "fs.write_file"},
            actions={"write"}, max_risk=80,
        ),
        purpose="tidy up storage and workloads", ttl_seconds=600,
    )
    return cp, bot, a_priv, grant


def test_versioned_bucket_delete_is_classified_recoverable_and_allowed():
    cp, bot, a_priv, grant = _plane(gate_evaluator=lambda ctx: True)
    v = cp.authorize(
        actor_private_key=a_priv, actor_id=bot.id, delegation_id=grant.id,
        tool="aws.s3.delete_object", args={"Bucket": "b", "Key": "k"},
        risk=40, description="tidy up storage", session_id="s1",
    )
    assert v.reversibility is Reversibility.COMPENSABLE
    assert v.allowed


def test_unversioned_bucket_delete_degrades_and_escalates_BEFORE_the_delete():
    """The money test for authorize-phase gates.

    Same tool, same arguments. Versioning off means the object is gone, so the
    classification must degrade and policy must stop the call — while stopping it
    still means something.
    """
    def no_versioning(ctx):
        if ctx.gate.name == "aws_s3_versioning_enabled":
            assert ctx.phase == PHASE_AUTHORIZE
            assert ctx.entry is None          # the write has not happened yet
            return "bucket 'b' has versioning suspended"
        return True

    cp, bot, a_priv, grant = _plane(gate_evaluator=no_versioning)
    v = cp.authorize(
        actor_private_key=a_priv, actor_id=bot.id, delegation_id=grant.id,
        tool="aws.s3.delete_object", args={"Bucket": "b", "Key": "k"},
        risk=40, description="tidy up storage", session_id="s1",
    )
    assert v.reversibility is Reversibility.IRREVERSIBLE
    assert not v.allowed
    assert v.stage == "enforce"                # policy refused it
    assert v.plan is None or not v.plan.kind.is_undoable


def test_degradation_is_recorded_on_the_ledger():
    cp, bot, a_priv, grant = _plane(
        gate_evaluator=lambda ctx: ctx.gate.name != "aws_s3_versioning_enabled"
    )
    cp.authorize(
        actor_private_key=a_priv, actor_id=bot.id, delegation_id=grant.id,
        tool="aws.s3.delete_object", args={"Bucket": "b", "Key": "k"},
        risk=40, description="tidy up storage", session_id="s1",
    )
    kinds = cp.ledger.counts_by_kind()
    assert kinds.get("reversal_kind_degraded", 0) >= 1
    assert cp.verify()


def test_a_missing_gate_evaluator_degrades_rather_than_assuming_the_best():
    """No evaluator means the precondition is unverifiable, which is not 'fine'."""
    cp = ControlPlane(
        policy=load_policy(REVERSIBILITY_FIRST),
        inverse_registry=registry_for("cloud"),
    )
    assert (
        cp.reversal.classify("aws.s3.delete_object", {"Bucket": "b", "Key": "k"})
        is Reversibility.IRREVERSIBLE
    )
    # ...and with no args at all, the optimistic kind is returned unchanged, which
    # is why callers that gate on the answer must pass args.
    assert cp.reversal.classify("aws.s3.delete_object") is Reversibility.COMPENSABLE


def test_kubernetes_delete_becomes_recoverable_through_the_captured_manifest():
    """The flagship snapshot-converts-irreversible case, end to end."""
    store = {"live": True}

    def reader(tool, args, fields):
        return {"manifest": {"kind": "Deployment", "metadata": {"name": args["name"]}}}

    applied: list[dict] = []

    def executor(tool, args):
        if tool == "k8s.resource.apply":
            applied.append(args["manifest"])
            store["live"] = True
        return {}

    cp = ControlPlane(
        policy=load_policy(REVERSIBILITY_FIRST),
        inverse_registry=registry_for("devops"),
        state_reader=reader,
        gate_evaluator=lambda ctx: True,
    )
    h_priv, h_pub = crypto.generate_keypair()
    a_priv, a_pub = crypto.generate_keypair()
    owner = cp.register_human("Owner", h_pub)
    bot = cp.register_agent("bot", a_pub)
    grant = cp.issue_root_delegation(
        human_private_key=h_priv, human_id=owner.id, agent_id=bot.id,
        scope=Scope.make(tools={"k8s.resource.delete"}, actions={"write"}, max_risk=80),
        purpose="delete stale workloads", ttl_seconds=600,
    )
    v = cp.authorize(
        actor_private_key=a_priv, actor_id=bot.id, delegation_id=grant.id,
        tool="k8s.resource.delete", args={"namespace": "prod", "name": "api"},
        risk=60, description="delete stale workload", session_id="s1",
    )
    assert v.allowed
    assert v.reversibility is Reversibility.COMPENSABLE
    assert v.plan.snapshot["manifest"]["metadata"]["name"] == "api"
    store["live"] = False                       # the delete happens
    cp.confirm(v, result={})

    receipt = cp.undo(v.action_id, executor)
    assert receipt.ok
    assert store["live"]
    assert applied[0]["metadata"]["name"] == "api"
    # And the residue is stated rather than glossed over.
    assert "UID" in receipt.residue or "uid" in receipt.residue.lower()


def test_shell_exec_escalates_every_time():
    cp = ControlPlane(
        policy=load_policy(REVERSIBILITY_FIRST),
        inverse_registry=registry_for("workstation"),
        approval_hook=lambda *a: False,
    )
    h_priv, h_pub = crypto.generate_keypair()
    a_priv, a_pub = crypto.generate_keypair()
    owner = cp.register_human("Owner", h_pub)
    bot = cp.register_agent("bot", a_pub)
    grant = cp.issue_root_delegation(
        human_private_key=h_priv, human_id=owner.id, agent_id=bot.id,
        scope=Scope.make(tools={"shell.exec"}, actions={"write"}, max_risk=80),
        purpose="run a command", ttl_seconds=600,
    )
    v = cp.authorize(
        actor_private_key=a_priv, actor_id=bot.id, delegation_id=grant.id,
        tool="shell.exec", args={"cmd": "make build"}, risk=50,
        description="run a command", session_id="s1",
    )
    assert v.reversibility is Reversibility.UNKNOWN
    assert not v.allowed
