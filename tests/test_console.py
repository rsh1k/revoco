"""The recoverability console.

A page that goes into an evidence pack and an incident ticket, rendered from
data an agent partly controls. The tests are about the three ways that combination
goes wrong: content that escapes into markup, a snapshot that lies about when it
was taken, and the one bucket that is misleading everywhere else being buried.
"""

from __future__ import annotations

import re

from revoco.console import render_html
from revoco.drills import DrillOutcome, DrillResult
from revoco.reversal import Reversibility
from revoco.reversal.horizon import Horizon, HorizonEntry
from revoco.validation import ValidationRun


def _entry(tool="t", kind=Reversibility.REVERSIBLE, remaining=None, **kw):
    return HorizonEntry(
        journal_id=kw.pop("journal_id", f"j-{tool}"), action_id="a1", tool=tool,
        kind=kind, session_id=kw.pop("session_id", "s1"), delegation_id="d1",
        committed_at=1_700_000_000.0, expires_at=kw.pop("expires_at", None),
        seconds_remaining=remaining, one_shot=False,
        residue=kw.pop("residue", ""), gates=kw.pop("gates", ()),
        reason=kw.pop("reason", ""),
    )


def _h(**kw) -> Horizon:
    return Horizon(at=1_700_000_000.0, warn_within=3600.0, **kw)


# ---- the page carries nothing with it --------------------------------------

def test_the_page_makes_no_request_and_runs_nothing():
    """It has to open from disk, out of an email attachment, inside an evidence
    pack, and on a machine with no network. Anything it fetches is something it
    can be missing."""
    page = render_html(_h(closing=(_entry(remaining=60),)))
    assert "<script" not in page.lower()
    assert not re.findall(r"https?://", page)
    assert "@import" not in page and "url(" not in page


# ---- content an agent chose --------------------------------------------

def test_a_tool_name_cannot_escape_into_markup():
    """Tool names, session ids and residue all originate in agent traffic. This
    page is then handed to an auditor, so an injected tag is not a defacement,
    it is a forged record."""
    nasty = '</td></script><img src=x onerror=alert(1)>'
    page = render_html(_h(standing_exposure=(
        _entry(tool=nasty, session_id=nasty, reason=nasty),)))

    # The payload must never appear as markup. Asserting the substring "onerror"
    # is absent would be wrong — escaped text legitimately contains it, and the
    # first version of this test failed on exactly that. What matters is that no
    # tag was opened and the payload survives only as inert text.
    assert nasty not in page, "the payload appears verbatim, so it was not escaped"
    assert "<img" not in page
    assert "</script>" not in page
    assert "&lt;img src=x onerror=alert(1)&gt;" in page


def test_the_subject_line_is_escaped_too():
    page = render_html(_h(), subject="<b>tenant</b>")
    assert "<b>tenant</b>" not in page
    assert "&lt;b&gt;tenant&lt;/b&gt;" in page


# ---- the bucket that is misleading elsewhere -------------------------------

def test_a_broken_undo_path_leads_the_page():
    """An entry that claims an undo it cannot run is counted as recoverable by
    everything that trusts the classification. It is the one thing here that is
    actively wrong elsewhere, so it goes first rather than alphabetically."""
    page = render_html(_h(
        broken=(_entry(tool="sap.pay", reason="unresolved inverse arguments"),),
        open_indefinitely=(_entry(tool="vendors.update"),),
        closing=(_entry(tool="payments.schedule", remaining=60),),
    ))
    order = [m for m in re.findall(r"<h2>([^<]+)", page)]
    assert order[0].startswith("Claims an undo")
    assert page.index("sap.pay") < page.index("vendors.update")


def test_the_broken_tile_is_only_red_when_it_has_something_in_it():
    """A permanently coloured alarm is one people stop seeing."""
    assert 'class="tile bad"' in render_html(_h(broken=(_entry(),)))
    assert 'class="tile bad"' not in render_html(_h(open_indefinitely=(_entry(),)))


# ---- honesty about what it is ----------------------------------------------

def test_the_page_is_stamped_with_the_snapshot_instant_not_the_render_instant():
    """A snapshot that re-dates itself when opened is not a snapshot. The
    horizon's own `at` is what appears, and the footer says the page cannot know
    anything after it."""
    page = render_html(_h())
    assert "2023-11-14" in page          # 1_700_000_000 UTC
    assert "does not refresh" in page


def test_nothing_counting_down_is_said_plainly_and_not_as_zero():
    """No deadline is not the same as no exposure, and rendering it as 0 would
    read as the safest possible number."""
    page = render_html(_h(standing_exposure=(_entry(kind=Reversibility.IRREVERSIBLE),)))
    assert "Nothing is counting down" in page
    assert "not the same as safe" in page


def test_an_empty_horizon_says_so():
    page = render_html(_h())
    assert "Nothing to recover and nothing standing" in page


# ---- round trip -------------------------------------------------------------

def test_a_horizon_survives_being_saved_and_read_back():
    """The reason to serialize one is to look at it somewhere other than where it
    was taken."""
    h = _h(closing=(_entry(tool="payments.schedule", remaining=90.0),),
           standing_exposure=(_entry(tool="payments.wire",
                                     kind=Reversibility.IRREVERSIBLE),),
           notes=["a note"])
    back = Horizon.from_dict(h.to_dict())
    assert back.at == h.at
    assert back.time_to_first_close == h.time_to_first_close
    assert [e.tool for e in back.closing] == ["payments.schedule"]
    assert back.standing_exposure[0].kind is Reversibility.IRREVERSIBLE
    assert back.notes == ["a note"]


# ---- the overlay: is there an undo, and has anyone shown it works ----------

def _run(*pairs) -> ValidationRun:
    results = tuple(
        DrillResult(id=f"d{i}", tool=tool, outcome=outcome,
                    declared_kind=Reversibility.REVERSIBLE, at=1_700_000_000.0,
                    duration_ms=1.0)
        for i, (tool, outcome) in enumerate(pairs))
    return ValidationRun(id="v", target="t", started_at=1_700_000_000.0,
                         finished_at=1_700_000_001.0, results=results)


def test_without_a_validation_run_the_page_says_nothing_is_known_to_work():
    """Absent evidence must not render as present evidence. The tile says so
    rather than being omitted, because a missing column reads as no problem."""
    page = render_html(_h(open_indefinitely=(_entry(tool="vendors.update"),)))
    assert "Undo proven" not in page
    assert "nothing here is known to work" in page


def test_a_recoverable_entry_whose_drill_failed_is_marked_and_counted():
    """The case the overlay exists for. The horizon reads a classification and
    says recoverable; the drill read the world and says the inverse does not
    restore. Every other view shows this as fine."""
    page = render_html(
        _h(open_indefinitely=(_entry(tool="vendors.update"),)),
        validation=_run(("vendors.update", DrillOutcome.FAILED)))
    assert "DISPROVEN" in page
    assert "proof unproven" in page
    assert "<b>1</b><span>Counted recoverable, undo not proven" in page


def test_a_recoverable_entry_never_drilled_counts_as_unproven():
    """Never asked and asked-and-told-no are different facts, and neither is
    proof. Both belong in the count."""
    page = render_html(
        _h(open_indefinitely=(_entry(tool="never.drilled"),)),
        validation=_run(("something.else", DrillOutcome.PASSED)))
    assert "never drilled" in page
    assert "<b>1</b><span>Counted recoverable, undo not proven" in page


def test_a_proven_undo_is_not_flagged():
    page = render_html(
        _h(open_indefinitely=(_entry(tool="vendors.update"),)),
        validation=_run(("vendors.update", DrillOutcome.PASSED)))
    assert "proof unproven" not in page
    assert "<b>0</b><span>Counted recoverable, undo not proven" in page


def test_an_undrilled_irreversible_action_is_not_flagged_as_unproven():
    """Noise discipline. Standing exposure is not claiming an undo, so an absent
    drill for it is not a contradiction — flagging it would put a permanent
    number on the tile and teach people to ignore it."""
    page = render_html(
        _h(standing_exposure=(_entry(tool="payments.wire",
                                     kind=Reversibility.IRREVERSIBLE),)),
        validation=_run(("something.else", DrillOutcome.PASSED)))
    assert "proof unproven" not in page
    assert "<b>0</b><span>Counted recoverable, undo not proven" in page


def test_a_control_with_nothing_to_prove_says_so_rather_than_unproven():
    """A read has no inverse to demonstrate. Reporting it as unproven would be
    counting the absence of a test that could never exist."""
    page = render_html(
        _h(open_indefinitely=(_entry(tool="fs.read_file"),)),
        validation=_run(("fs.read_file", DrillOutcome.NOT_DRILLABLE)))
    assert "nothing to prove" in page
    assert "proof unproven" not in page
