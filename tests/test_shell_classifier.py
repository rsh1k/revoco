"""Classifying a shell command by what a snapshot cannot undo.

The question is not whether a command looks dangerous. `rm -rf build/` looks
alarming and comes back from a snapshot; `curl -X POST .../charge` looks routine
and does not. Reversibility is a property of the target, not the verb.
"""

from __future__ import annotations

import pytest

from revoco.reversal import Reversibility
from revoco.reversal.shell import Reach, classify

ROOT = "/repo"


def r(cmd: str, root: str | None = ROOT):
    return classify(cmd, root)


# ---- the posture mapping ---------------------------------------------------

def test_a_read_only_command_is_idempotent_not_reversible():
    """The divergence from the source. A read changes nothing, so there is
    nothing to undo — the same distinction that stopped `fs.read_file` being
    drilled as though it had an inverse to prove. The original had no such
    posture and had to call it reversible."""
    v = r("ls -la")
    assert v.reach is Reach.READ_ONLY
    assert v.reversibility is Reversibility.IDEMPOTENT
    assert v.needs_snapshot is False


@pytest.mark.parametrize("cmd", [
    "rm -rf build/", "mv src/a src/b", "mkdir -p out", "chmod +x run.sh",
    "touch newfile", "cp a b",
])
def test_a_write_inside_the_root_is_reversible_and_snapshotted(cmd):
    """These fell to UNKNOWN before a local-write set existed, and UNKNOWN ranks
    below IRREVERSIBLE here — so a policy permitting reversible writes would have
    refused `mkdir`. Safe, and the kind of safe that gets a control switched off."""
    v = r(cmd)
    assert v.reach is Reach.LOCAL, cmd
    assert v.reversibility is Reversibility.REVERSIBLE
    assert v.needs_snapshot is True


@pytest.mark.parametrize("cmd,why", [
    ("git push --force origin main", "remote"),
    ("npm publish", "npm"),
    ("terraform apply", "infrastructure"),
    ("aws s3 rm s3://b/k", "cloud"),
    ("curl -X POST https://api.example.com/charge", "remote"),
    ("ssh box 'rm -rf /data'", "another machine"),
    ("sudo rm /etc/hosts", "root"),
])
def test_reaching_beyond_the_working_tree_is_irreversible(cmd, why):
    v = r(cmd)
    assert v.reach is Reach.ESCAPES, cmd
    assert v.reversibility is Reversibility.IRREVERSIBLE
    assert v.why, "an escape has to say what it reached"


@pytest.mark.parametrize("cmd", ["rm -rf ~", "mv src /etc/", "cp secrets ~/backup",
                                 "echo x > /etc/hosts"])
def test_the_same_verb_escapes_when_the_target_is_outside_the_root(cmd):
    """Reversibility is a property of the target. `rm -rf build/` and `rm -rf ~`
    differ only in the path, and only the path decides."""
    assert r(cmd).reach is Reach.ESCAPES


def test_an_unrecognised_command_stays_unknown():
    """Conservative by default. Omitting a command from the local-write set costs
    one escalation; wrongly calling something local costs an undo that was never
    possible."""
    v = r("some-vendor-cli deploy --prod")
    assert v.reach is Reach.UNKNOWN
    assert v.reversibility is Reversibility.UNKNOWN
    assert v.needs_snapshot is True


# ---- the ways a command hides what it does ---------------------------------

def test_a_compound_command_is_classified_by_its_worst_part():
    """`ls && rm -rf ~` must not be classified by `ls`."""
    assert r("ls && rm -rf ~").reach is Reach.ESCAPES
    assert r("cat a | grep b").reach is Reach.READ_ONLY


def test_navigating_out_of_the_root_makes_a_later_write_unrecoverable():
    """`cd` writes nothing on its own, but the snapshot still covers only the
    original directory, so everything after it lands somewhere uncovered."""
    assert r("cd /tmp/x").reach is Reach.READ_ONLY
    assert r("cd /tmp/x && rm -rf .").reach is Reach.ESCAPES


def test_a_redirect_makes_a_read_only_command_a_write():
    """`echo hi > important.conf` is not read-only because `echo` is."""
    assert r("echo hi").reach is Reach.READ_ONLY
    assert r("echo hi > notes.txt").reach is Reach.LOCAL
    assert r("echo hi > /etc/hosts").reach is Reach.ESCAPES


def test_a_read_only_subcommand_of_a_mutating_tool_is_read_only():
    assert r("git status").reach is Reach.READ_ONLY
    assert r("git commit -m x").reach is not Reach.READ_ONLY
    assert r("kubectl get pods").reach is Reach.READ_ONLY
    assert r("kubectl delete pod x").reach is Reach.ESCAPES


def test_reading_outside_the_root_is_still_fine():
    """Writing outside escapes. Reading outside does not."""
    assert r("cat /etc/hosts").reach is Reach.READ_ONLY


def test_unbalanced_quotes_are_unknown_rather_than_guessed():
    assert r('echo "unterminated').reach is Reach.UNKNOWN


def test_an_empty_command_needs_no_snapshot():
    assert r("").needs_snapshot is False
    assert r("   ").needs_snapshot is False


# ---- the escape check runs on the whole command ----------------------------

def test_an_escape_is_found_even_when_operators_would_hide_it():
    """Escapes are matched against the whole command before it is split, because
    quoting and nesting both defeat splitting — and the cost of a false positive
    is one prompt while a false negative is an unrecoverable action."""
    assert r("echo start; git push --force").reach is Reach.ESCAPES
    assert r("bash -c 'npm publish'").reach is Reach.ESCAPES
