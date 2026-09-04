"""Validation runs and the comparison between them.

A drill says whether one inverse works now. These tests are about the sentence
two runs can say and one cannot: it was working, and it stopped.
"""

from __future__ import annotations

import pytest

from revoco import crypto
from revoco.core.errors import ValidationError
from revoco.drills import DrillOutcome, DrillResult
from revoco.reversal import Reversibility
from revoco.validation import (
    Change,
    ValidationRun,
    compare,
    render,
    report,
)


def _res(tool: str, outcome: DrillOutcome, at: float = 1000.0) -> DrillResult:
    return DrillResult(
        id=f"drl_{tool}_{int(at)}", tool=tool, outcome=outcome,
        declared_kind=Reversibility.REVERSIBLE, at=at, duration_ms=1.0,
    )


def _run(results, target="acme-sandbox", at=1000.0, rid="run_1") -> ValidationRun:
    return ValidationRun(id=rid, target=target, started_at=at, finished_at=at + 1,
                         results=tuple(results))


P, F = DrillOutcome.PASSED, DrillOutcome.FAILED


# ---- the comparison --------------------------------------------------------

def test_a_control_that_was_proven_and_is_not_is_the_headline():
    before = _run([_res("sap.bank.update", P)], rid="r1")
    after = _run([_res("sap.bank.update", F, at=2000.0)], rid="r2", at=2000.0)
    (change,) = compare(after, before)
    assert change.change is Change.REGRESSED
    assert change.before == "passed" and change.now == "failed"
    assert change.change.is_new_bad_news


def test_a_failure_that_was_already_failing_is_not_new_news():
    """A standing known issue is a status. Reporting it as an incident every run
    is how a report becomes noise nobody reads."""
    before = _run([_res("t", F)], rid="r1")
    after = _run([_res("t", F, at=2000.0)], rid="r2", at=2000.0)
    (change,) = compare(after, before)
    assert change.change is Change.STILL_FAILING
    assert change.change.is_alarm          # someone should still fix it
    assert not change.change.is_new_bad_news   # but it did not happen this week


def test_a_first_run_cannot_report_a_regression():
    """A baseline has nothing to compare against. Claiming a regression would be
    asserting something about a past that was never measured."""
    changes = compare(_run([_res("a", P), _res("b", F)]))
    assert {c.change for c in changes} == {Change.NEWLY_COVERED}


def test_recovery_is_reported_as_well_as_failure():
    before = _run([_res("t", F)], rid="r1")
    after = _run([_res("t", P, at=2000.0)], rid="r2", at=2000.0)
    assert compare(after, before)[0].change is Change.RECOVERED


# ---- the absence that reads as green ---------------------------------------

def test_a_control_that_stops_being_tested_is_reported_not_omitted():
    """The failure this module exists for.

    Drop a drill and every number improves: proven holds, failing falls, the
    report looks better than last week. Coverage shrinking must not be able to
    look like coverage improving.
    """
    before = _run([_res("kept", P), _res("dropped", P)], rid="r1")
    after = _run([_res("kept", P, at=2000.0)], rid="r2", at=2000.0)

    by_tool = {c.tool: c for c in compare(after, before)}
    assert by_tool["dropped"].change is Change.DISAPPEARED
    assert by_tool["dropped"].change.is_alarm
    assert by_tool["dropped"].change.is_new_bad_news
    assert "untested" in by_tool["dropped"].detail


def test_dropping_a_failing_control_does_not_produce_a_clean_report():
    """The gaming case, stated directly: deleting the drill that fails must not
    be a way to get a green report."""
    priv, _pub = crypto.generate_keypair()
    before = _run([_res("good", P), _res("bad", F)], rid="r1")
    after = _run([_res("good", P, at=2000.0)], rid="r2", at=2000.0)

    rep = report(after, previous=before, signer_private_key=priv, signer_id="ci")
    assert not rep.clean
    assert [c.tool for c in rep.disappeared] == ["bad"]
    assert rep.run.failing == ()          # nothing in this run failed...
    assert not rep.clean                  # ...and the report still is not clean


def test_a_run_with_nothing_worse_is_clean_even_with_a_standing_failure():
    priv, _pub = crypto.generate_keypair()
    before = _run([_res("t", F)], rid="r1")
    after = _run([_res("t", F, at=2000.0)], rid="r2", at=2000.0)
    rep = report(after, previous=before, signer_private_key=priv, signer_id="ci")
    assert rep.clean
    assert "no control got worse" in rep.headline


# ---- refusals --------------------------------------------------------------

def test_runs_against_different_targets_are_refused():
    """The difference between two tenants is the tenants, not the controls."""
    a = _run([_res("t", P)], target="tenant-a", rid="r1")
    b = _run([_res("t", F)], target="tenant-b", rid="r2")
    with pytest.raises(ValidationError):
        compare(b, a)


def test_a_run_without_a_target_is_refused():
    with pytest.raises(ValidationError):
        ValidationRun(id="r", target="", started_at=0, finished_at=1, results=())


def test_the_same_tool_twice_in_one_run_is_refused():
    with pytest.raises(ValidationError):
        _run([_res("t", P), _res("t", F)])


# ---- the signature ---------------------------------------------------------

def test_the_signature_covers_the_evidence_and_not_the_prose():
    """Reformatting the report must not invalidate it; editing a drill result
    must. The signature is over the run digest and the comparison."""
    priv, pub = crypto.generate_keypair()
    run = _run([_res("t", P)])
    rep = report(run, signer_private_key=priv, signer_id="ci")
    assert rep.verify_signature(pub)

    render(rep)                                  # rendering changes nothing
    assert rep.verify_signature(pub)

    tampered = report(_run([_res("t", F)]), signer_private_key=priv, signer_id="ci")
    import dataclasses
    forged = dataclasses.replace(tampered, signature=rep.signature)
    assert not forged.verify_signature(pub)


def test_a_run_survives_being_stored_and_read_back():
    """The whole point is comparing runs weeks apart, which means crossing a
    process boundary. A digest that changed on the way to disk would make every
    signed report unverifiable by the auditor it was produced for.

    The bug this caught: `started_at=1` and `started_at=1.0` are the same instant
    and canonicalise differently, so a run built with integer timestamps digested
    differently once JSON had been through it.
    """
    import json

    detailed = DrillResult(
        id="d1", tool="t", outcome=DrillOutcome.PARTIAL,
        declared_kind=Reversibility.COMPENSABLE, at=1.0, duration_ms=2.5,
        restored=("a",), unrestored=("b",), collateral=("c",),
        observed_residue=("mtime",), unavailable_reason="", residue="prose",
    )
    for started, finished in ((1, 2), (1.0, 2.0)):
        run = ValidationRun(id="r1", target="x", started_at=started,
                            finished_at=finished, results=(detailed,))
        back = ValidationRun.from_dict(json.loads(json.dumps(run.payload())))
        assert back.digest == run.digest
        assert back.results[0].unrestored == ("b",)
        assert back.results[0].observed_residue == ("mtime",)


def test_a_malformed_stored_run_is_refused_rather_than_half_read():
    with pytest.raises(ValidationError):
        ValidationRun.from_dict({"id": "r", "target": "x", "started_at": 0,
                                 "finished_at": 1,
                                 "results": [{"tool": "t"}]})


def test_the_digest_changes_when_any_result_does():
    assert _run([_res("t", P)]).digest != _run([_res("t", F)]).digest


def test_not_drillable_controls_do_not_count_as_coverage():
    """A read has nothing to prove. Counting it as a validated control inflates
    exactly the number the report exists to state honestly."""
    run = _run([_res("write", P), _res("read", DrillOutcome.NOT_DRILLABLE)])
    assert run.coverage == 1
    assert run.not_drillable == ("read",)


def test_the_rendered_report_leads_with_what_needs_attention():
    priv, _pub = crypto.generate_keypair()
    before = _run([_res("fine", P), _res("broke", P)], rid="r1")
    after = _run([_res("fine", P, at=2000.0), _res("broke", F, at=2000.0)],
                 rid="r2", at=2000.0)
    text = render(report(after, previous=before,
                         signer_private_key=priv, signer_id="ci"))
    assert text.index("REGRESSED") < text.index("STILL PROVEN")
    assert "verify offline" in text


def test_a_report_carries_the_previous_run_it_was_compared_against():
    """An auditor has to be able to ask which baseline this was measured from."""
    priv, _pub = crypto.generate_keypair()
    before = _run([_res("t", P)], rid="r1")
    after = _run([_res("t", P, at=2000.0)], rid="r2", at=2000.0)
    rep = report(after, previous=before, signer_private_key=priv, signer_id="ci")
    assert rep.previous_id == "r1"
    assert rep.previous_digest == before.digest
