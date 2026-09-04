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

def test_the_devops_relation_exempts_exactly_what_was_measured():
    """Every exemption on this surface was earned by a drill, and the set is
    asserted whole so a new one cannot be added without editing this."""
    from revoco.adapters import EQUIVALENCES

    eq = EQUIVALENCES["devops"]
    assert eq is not None
    assert eq.fields == {"base_sha", "pr_state"}
    for e in eq.exempt:
        assert "Measured" in e.reason, f"{e.field}: an exemption needs evidence"


def test_node_id_is_not_exempt():
    """It was, on the reasoning that a recreated ref gets a fresh one. A ref's
    node_id is a base64 encoding of the ref path and is identical after a
    recreate at the same SHA, so the exemption excused nothing. This keeps it
    from being quietly re-added."""
    from revoco.adapters import EQUIVALENCES

    assert "node_id" not in EQUIVALENCES["devops"].fields


def test_the_revert_inverse_is_given_enough_to_locate_the_branch():
    """The first live drill failed here. `github.pr.revert(owner, repo,
    merge_commit_sha)` names what to undo and not where — a revert moves a
    branch, and nothing in those three says which. The pull request number is
    the argument that answers it."""
    from revoco.adapters.devops import DEVOPS_SPECS

    spec = next(s for s in DEVOPS_SPECS if s.tool == "github.pr.merge")
    mapped = dict(spec.arg_map)
    assert "number" in mapped
    assert mapped["merge_commit_sha"] == "result.sha", (
        "the merge SHA is only knowable from the response, which is why the "
        "proxy confirms on the response rather than on the forward call"
    )


# ---- protection: the control that protects itself from cleanup -------------

def test_protection_is_stripped_before_refs_are_swept(monkeypatch):
    """A protected branch refuses deletion — the API answers 422 "Cannot delete
    this branch". Sweeping refs first would leak the canary that is hardest to
    remove by hand. Order is the whole fix, so order is what is asserted."""
    gh = _gh()
    gh.created = ["revoco-canary/run1/protect-me"]
    gh.protected = {"revoco-canary/run1/protect-me"}
    calls: list[str] = []

    def fake_api(*args, **kwargs):
        joined = " ".join(str(a) for a in args)
        if "protection" in joined:
            calls.append("unprotect")
        elif "git/refs" in joined and "DELETE" in joined:
            calls.append("delete-ref")
        return None

    monkeypatch.setattr(gh, "_api", fake_api)
    monkeypatch.setattr(gh, "ref_sha", lambda ref: None)
    gh.sweep()

    assert "unprotect" in calls and "delete-ref" in calls
    assert calls.index("unprotect") < calls.index("delete-ref"), (
        "refs swept before protection was removed; the branch would survive"
    )


def test_protection_writes_go_through_the_namespace_guard(monkeypatch):
    gh = _gh()
    monkeypatch.setattr(gh, "_api", lambda *a, **k: pytest.fail("reached the API"))
    with pytest.raises(GitHubApiError, match="revoco-canary"):
        gh.put_protection("main", {"enforce_admins": True})
    with pytest.raises(GitHubApiError, match="revoco-canary"):
        gh.execute("github.repo.update_branch_protection",
                   {"branch": "main", "protection": {}})


def test_protection_is_read_in_the_shape_the_write_accepts(monkeypatch):
    """GitHub returns each toggle nested under {"enabled": bool} and accepts it
    as a bare boolean. Round-tripping the GET response straight into the PUT is
    rejected, and a snapshot that cannot be replayed is a phantom rollback whose
    plan looks complete until it runs."""
    gh = _gh()
    monkeypatch.setattr(gh, "_api", lambda *a, **k: {
        "enforce_admins": {"enabled": True},
        "allow_force_pushes": {"enabled": False},
        "allow_deletions": {"enabled": False},
        "url": "https://api.github.com/...",
    })
    body = gh.get_protection("revoco-canary/run1/b")
    assert body is not None
    assert body["enforce_admins"] is True          # flattened, not {"enabled": ...}
    assert body["allow_force_pushes"] is False
    assert "url" not in body, "read-only fields must not be echoed into a write"


def test_an_unprotected_branch_reads_as_no_protection(monkeypatch):
    gh = _gh()
    monkeypatch.setattr(gh, "_api", lambda *a, **k: None)
    assert gh.get_protection("revoco-canary/run1/b") is None
