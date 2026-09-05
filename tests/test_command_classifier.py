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


def _engine(*, specs=(), classifier=None):
    return ReversalEngine(
        InverseRegistry(list(specs)),
        command_classifier=classifier if classifier is not None
        else command_classifier(root="/repo"),
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


@pytest.mark.parametrize("bogus", ["reversible", Reversibility.REVERSIBLE, 42, None])
def test_a_classifier_returning_nonsense_is_ignored(bogus):
    """A bare Reversibility is in this list deliberately: it is what the seam
    used to accept, and accepting it again would reopen the hole."""
    assert _engine(classifier=lambda t, a: bogus).classify(
        "bash", BASH) is Reversibility.UNKNOWN


def test_the_seam_takes_a_spec_so_a_groundless_claim_cannot_be_written():
    """The structural guarantee, replacing a rule that had to be remembered.

    An earlier version returned a bare posture, which let a classifier answer
    REVERSIBLE for a tool with no undo path — a plan the horizon counted as
    recoverable while `reverse()` refused it. An InverseSpec will not construct
    in that shape, so the mistake is now unrepresentable rather than tested for.
    """
    from revoco.core.errors import ValidationError

    with pytest.raises(ValidationError, match="requires an inverse_tool or steps"):
        InverseSpec(tool="bash", kind=Reversibility.REVERSIBLE)

    # And a spec that does name one is honoured, undo path and all.
    def snapshotting(tool, args):
        return InverseSpec(tool=tool, kind=Reversibility.REVERSIBLE,
                           inverse_tool="workspace.restore",
                           arg_map=(("tree", "snapshot.tree"),),
                           snapshot_fields=("tree",))

    engine = ReversalEngine(
        InverseRegistry([]), command_classifier=snapshotting,
        state_reader=lambda t, a, f: {x: "sha123" for x in f})
    plan = engine.plan("bash", {"command": "rm -rf build/"})
    assert plan.kind is Reversibility.REVERSIBLE
    assert plan.inverse_tool == "workspace.restore"
    assert plan.snapshot == {"tree": "sha123"}
    assert plan.is_executable, "a derived spec must travel the ordinary path"


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


def test_a_local_write_stays_unknown_because_there_is_no_inverse_to_run():
    """`rm -rf build/` is recoverable *from a snapshot of the working tree*. The
    snapshot is the inverse, and this seam cannot supply one — it returns a
    posture, and the undo path comes from a spec that does not exist for a tool
    the registry has never heard of."""
    assert _engine().classify(
        "bash", {"command": "rm -rf build/"}) is Reversibility.UNKNOWN


@pytest.mark.parametrize("command", [
    "ls -la", "rm -rf build/", "git push --force origin main", "weird-cli go",
    "mkdir out", "cd /tmp && rm -rf .", "echo x > f",
])
def test_no_posture_this_classifier_returns_is_ever_undoable(command):
    """The invariant, asserted directly rather than case by case.

    An undoable posture with no inverse is a phantom rollback: the horizon counts
    the entry recoverable and `reverse()` answers "no inverse operation exists".
    An earlier version took a `snapshots=True` flag meaning "assume one will be
    taken" and produced exactly that — a declaration of an undo with nothing
    behind it, which is the one thing this package refuses to accept from anyone
    else. Any future posture added here has to pass this.
    """
    engine = _engine()
    args = {"command": command}
    kind = engine.classify("bash", args)
    plan = engine.plan("bash", args)
    assert not kind.is_undoable, f"{command}: claims an undo with no inverse"
    assert plan.inverse_tool is None
    assert not plan.steps
    assert not plan.is_executable


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
