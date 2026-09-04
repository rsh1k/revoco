"""The GitHub drill runner's safety rails, without touching GitHub.

The drill results themselves come from a live API and cannot be asserted here.
What can — and must — be asserted is the machinery that stands between a drill
and someone's production branch, because those are the parts whose failure is
silent and expensive.
"""

from __future__ import annotations

import importlib.util
import sys
from pathlib import Path

import pytest

_spec = importlib.util.spec_from_file_location(
    "drill_github", Path(__file__).resolve().parent.parent / "scripts" / "drill_github.py")
assert _spec and _spec.loader
drill_github = importlib.util.module_from_spec(_spec)
sys.modules["drill_github"] = drill_github
_spec.loader.exec_module(drill_github)

GitHub = drill_github.GitHub
GitHubApiError = drill_github.GitHubApiError


def _gh() -> GitHub:
    return GitHub("owner", "repo", "run1")


# ---- the rail between a drill and someone's main ---------------------------

@pytest.mark.parametrize("ref", [
    "main", "refs/heads/main", "master", "release/2026",
    "revoco-canary", "notrevoco-canary/x", "../revoco-canary/x",
])
def test_a_ref_outside_the_canary_namespace_is_refused(ref):
    """The specs take a ref name as an argument, so a mistake in a canary
    definition is a mistake aimed at a real branch. This check is the only thing
    standing in the way, and it is asserted against near-misses rather than
    against an obviously wrong name."""
    with pytest.raises(GitHubApiError, match="revoco-canary"):
        _gh()._guard(ref)


@pytest.mark.parametrize("ref", [
    "revoco-canary/run1/delete-me",
    "refs/heads/revoco-canary/run1/force-me",
])
def test_a_canary_ref_is_permitted(ref):
    assert _gh()._guard(ref).startswith("revoco-canary/")


def test_every_mutating_tool_goes_through_the_guard(monkeypatch):
    """A new executor branch that forgot the guard would be invisible until it
    deleted the wrong thing. Each is asserted to refuse a real branch name."""
    gh = _gh()
    monkeypatch.setattr(gh, "_api", lambda *a, **k: pytest.fail("reached the API"))
    for tool, args in (
        ("github.branch.delete", {"ref": "main"}),
        ("github.ref.create", {"ref": "main", "sha": "abc"}),
        ("github.ref.force_update", {"ref": "main", "sha": "abc"}),
    ):
        with pytest.raises(GitHubApiError, match="revoco-canary"):
            gh.execute(tool, args)


def test_an_unknown_tool_is_refused_rather_than_ignored():
    with pytest.raises(GitHubApiError, match="no executor"):
        _gh().execute("github.repo.delete", {})


# ---- the gate --------------------------------------------------------------

def test_an_unrecognised_gate_is_treated_as_closed(monkeypatch):
    """Unanswerable must mean closed. A gate this runner does not know how to
    check is one it cannot vouch for, and refusing the undo is the safe
    direction — the same reasoning the reversal engine already applies."""
    from revoco.reversal.model import GateContext, ReversalGate

    gh = _gh()
    evaluate = drill_github.gate_evaluator(gh)
    gate = ReversalGate(name="something_new", description="unknown to this runner")
    ctx = GateContext(gate=gate, tool="t", phase="undo", args={"sha": "abc"}, entry=None)
    assert evaluate(ctx) is False


def test_the_object_gate_answers_from_the_remote(monkeypatch):
    from revoco.reversal.model import GateContext, ReversalGate

    gh = _gh()
    gate = ReversalGate(name="git_objects_not_collected", description="d")
    evaluate = drill_github.gate_evaluator(gh)

    monkeypatch.setattr(gh, "commit_exists", lambda sha: True)
    assert evaluate(GateContext(gate=gate, tool="t", phase="undo",
                                args={"sha": "abc"}, entry=None)) is True

    monkeypatch.setattr(gh, "commit_exists", lambda sha: False)
    assert evaluate(GateContext(gate=gate, tool="t", phase="undo",
                                args={"sha": "abc"}, entry=None)) is False

    # No SHA to check is not a pass — asserted with `commit_exists` stubbed
    # True, so only the missing-argument guard can produce False. Stubbing it
    # False here (as the first version did) makes the assertion pass whether the
    # guard exists or not, which a mutation caught.
    monkeypatch.setattr(gh, "commit_exists", lambda sha: True)
    assert evaluate(GateContext(gate=gate, tool="t", phase="undo",
                                args={}, entry=None)) is False
    assert evaluate(GateContext(gate=gate, tool="t", phase="undo",
                                args={"sha": ""}, entry=None)) is False


# ---- teardown --------------------------------------------------------------

def test_the_sweep_reports_what_it_could_not_remove(monkeypatch):
    """A runner that leaks canaries into a tenancy is the incident it exists to
    prevent, so a failed teardown has to be reported rather than swallowed."""
    gh = _gh()
    gh.created = ["revoco-canary/run1/gone", "revoco-canary/run1/stuck"]
    monkeypatch.setattr(gh, "_api", lambda *a, **k: None)
    monkeypatch.setattr(gh, "ref_sha",
                        lambda ref: "abc" if ref.endswith("stuck") else None)
    assert gh.sweep() == ["revoco-canary/run1/stuck"]


def test_a_clean_sweep_reports_nothing(monkeypatch):
    gh = _gh()
    gh.created = ["revoco-canary/run1/a"]
    monkeypatch.setattr(gh, "_api", lambda *a, **k: None)
    monkeypatch.setattr(gh, "ref_sha", lambda ref: None)
    assert gh.sweep() == []


# ---- the relation ----------------------------------------------------------

def test_the_devops_surface_exempts_nothing():
    """Measured, not omitted. An earlier version excused `node_id` on the
    reasoning that a recreated ref gets a fresh one; a ref's node_id is a base64
    encoding of the ref path and is identical after a recreate at the same SHA.
    Asserting the empty set keeps that from being quietly re-added."""
    from revoco.adapters import EQUIVALENCES

    eq = EQUIVALENCES["devops"]
    assert eq is not None
    assert eq.fields == frozenset()
    assert "must return exactly" in eq.describe()
