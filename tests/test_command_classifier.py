"""Wiring the shell classifier into the engine.

A classifier that exists and nothing consults is the third instance of that
pattern in this codebase, so these tests are mostly about the seam rather than
the classification, which `test_shell_classifier.py` already covers.
"""

from __future__ import annotations

import pytest

from revoco.reversal import InverseRegistry, InverseSpec, Reversibility
from revoco.reversal.engine import ReversalEngine
from revoco.reversal.shell import command_classifier

BASH = {"command": "ls -la"}


def _engine(*, specs=(), snapshots=False, classifier=None):
    return ReversalEngine(
        InverseRegistry(list(specs)),
        command_classifier=classifier if classifier is not None
        else command_classifier(root="/repo", snapshots=snapshots),
    )


# ---- the bound that makes it safe ------------------------------------------

def test_a_declared_spec_is_never_overridden_by_the_classifier():
    """The classifier runs only where the registry has nothing to say. That bound
    is what lets it *raise* a posture at all — `classify_hook` cannot, because a
    hook that could raise one would let an integration manufacture recoverability
    the specs never claimed."""
    spec = InverseSpec(tool="bash", kind=Reversibility.IRREVERSIBLE)
    engine = _engine(specs=[spec])
    # `ls` alone would be IDEMPOTENT; the spec says otherwise and the spec wins.
    assert engine.classify("bash", BASH) is Reversibility.IRREVERSIBLE


def test_a_tool_the_classifier_declines_is_unchanged():
    """Asserted with a `command` argument present, so it distinguishes the
    shell-tool guard from the argument check. The first version passed
    `{"amount": 1}`, which both would reject — a mutation removing the guard
    survived it."""
    engine = _engine()
    assert engine.classify("invoices.pay", {"amount": 1}) is Reversibility.UNKNOWN
    assert engine.classify(
        "invoices.pay", {"command": "ls -la"}) is Reversibility.UNKNOWN
    assert command_classifier()("invoices.pay", {"command": "ls -la"}) is None


def test_a_classifier_that_raises_leaves_the_answer_unknown():
    """Fail closed. A broken integration must not be able to produce a posture."""
    def boom(tool, args):
        raise RuntimeError("bad classifier")

    assert _engine(classifier=boom).classify("bash", BASH) is Reversibility.UNKNOWN


def test_a_classifier_returning_nonsense_is_ignored():
    assert _engine(classifier=lambda t, a: "reversible").classify(
        "bash", BASH) is Reversibility.UNKNOWN


def test_no_classifier_at_all_behaves_as_before():
    engine = ReversalEngine(InverseRegistry([]))
    assert engine.classify("bash", BASH) is Reversibility.UNKNOWN


# ---- what it is allowed to claim -------------------------------------------

@pytest.mark.parametrize("command,expected", [
    ("ls -la", Reversibility.IDEMPOTENT),
    ("git push --force origin main", Reversibility.IRREVERSIBLE),
    ("some-vendor-cli deploy", Reversibility.UNKNOWN),
])
def test_the_postures_that_cost_nothing_to_honour(command, expected):
    assert _engine().classify("bash", {"command": command}) is expected


def test_a_local_write_stays_unknown_until_a_snapshot_exists():
    """The honest part. `rm -rf build/` is recoverable *from a snapshot of the
    working tree* — the snapshot is the inverse, and revoco does not take one.
    Returning REVERSIBLE would produce a plan the horizon counts as recoverable
    and `reverse()` refuses with "no inverse operation exists": a phantom
    rollback manufactured by the classifier."""
    cmd = {"command": "rm -rf build/"}
    assert _engine(snapshots=False).classify("bash", cmd) is Reversibility.UNKNOWN
    assert _engine(snapshots=True).classify("bash", cmd) is Reversibility.REVERSIBLE


# ---- the two derivations must agree ----------------------------------------

@pytest.mark.parametrize("command", [
    "ls -la", "git push --force origin main", "rm -rf build/", "weird-cli go",
])
def test_classify_and_plan_report_the_same_posture(command):
    """Two places derive the kind. If they disagreed, the gate would judge one
    posture and the journal would record another."""
    engine = _engine()
    args = {"command": command}
    assert engine.plan("bash", args).kind is engine.classify("bash", args)


def test_a_read_only_command_yields_a_plan_with_nothing_to_undo():
    plan = _engine().plan("bash", {"command": "ls -la"})
    assert plan.kind is Reversibility.IDEMPOTENT
    assert plan.inverse_tool is None
    assert not plan.kind.is_undoable
    assert not plan.kind.is_one_way, "a read is not standing exposure"


def test_an_escaping_command_is_a_known_one_way_door_not_an_unknown():
    """Both fail a reversibility floor, but they are different facts and a policy
    can act on the difference: one has a rule to write, the other has a spec to
    write."""
    plan = _engine().plan("bash", {"command": "aws s3 rm s3://b/k"})
    assert plan.kind is Reversibility.IRREVERSIBLE
    assert plan.kind.is_one_way


# ---- argument shapes -------------------------------------------------------

@pytest.mark.parametrize("args", [{}, {"command": ""}, {"command": None},
                                  {"command": 42}, {"cmd": "ls"}])
def test_a_call_with_no_usable_command_is_left_alone(args):
    assert _engine().classify("bash", args) is Reversibility.UNKNOWN


def test_classify_without_args_cannot_consult_the_classifier():
    """`classify(tool)` with no args is documented as skipping per-call
    evaluation. A shell command lives entirely in the args, so there is nothing
    to read and UNKNOWN is the only honest answer."""
    assert _engine().classify("bash") is Reversibility.UNKNOWN
