"""Importing benign traffic from external benchmark data.

These tests skip when no RAS-Eval clone is present, because the corpus has to work
without it — CI cannot depend on an unlicensed third-party checkout. What is *not*
skipped is the discipline: the rules that stop an import from manufacturing findings
out of missing data hold whether the data is there or not.
"""

from __future__ import annotations

import pytest

from revoco.adapters.ras_eval import RAS_EVAL_SPECS, ras_eval_registry
from revoco.bench import Harness, Outcome, score
from revoco.bench.external import (
    ENV_VAR,
    available,
    provenance,
    ras_eval_scenarios,
)
from revoco.bench.scenario import Intent
from revoco.reversal import InverseSpec, Reversibility

needs_data = pytest.mark.skipif(
    not available(), reason=f"no RAS-Eval clone; set {ENV_VAR} to include these"
)


# ---------------------------------------------------------------------------
# Holds with or without the data
# ---------------------------------------------------------------------------


def test_absent_data_yields_no_scenarios_rather_than_an_error():
    """The corpus must work without it, or CI depends on someone else's repo."""
    assert ras_eval_scenarios("/nonexistent/path/for/sure") == []
    prov = provenance("/nonexistent/path/for/sure")
    assert prov["available"] is False
    assert ENV_VAR in prov["note"]


def test_nothing_is_vendored():
    """No RAS-Eval data in this repository — it declares no license."""
    from pathlib import Path

    repo = Path(__file__).resolve().parent.parent
    assert not (repo / "RAS-Eval").exists()
    strays = [
        p for p in repo.rglob("tasks.json")
        if ".venv" not in str(p) and ".git" not in str(p)
    ]
    assert not strays, f"looks vendored: {strays}"


def test_the_classifications_are_ours_and_round_trip():
    for spec in RAS_EVAL_SPECS:
        assert InverseSpec.from_dict(spec.to_dict()) == spec, spec.tool


def test_reads_are_reversible_and_one_way_tools_are_not():
    reg = ras_eval_registry()
    assert reg.classify("get_weather") is Reversibility.REVERSIBLE
    assert reg.classify("send_email") is Reversibility.IRREVERSIBLE
    # Arbitrary shell stays unclassified here for the same reason it does in revoco's
    # own workstation adapter.
    assert reg.classify("execute_shell_command") is Reversibility.UNKNOWN


def test_create_cancel_pairs_are_mutual_inverses():
    """The interesting shape on this surface, and the one most tool APIs lack."""
    reg = ras_eval_registry()
    for a, b in (("set_alarm", "cancel_alarm"),
                 ("add_event_to_calendar", "remove_event_from_calendar")):
        assert reg.get(a).inverse_tool == b
        assert reg.get(b).inverse_tool == a


def test_the_argument_names_corrected_by_real_traces_stay_corrected():
    """Regression guard on the finding that justified this whole import.

    `insert_data` was first written with a `table` argument invented from the tool's
    name. Real traces pass `db_path` and `items`, so the inverse could never resolve
    and every legitimate insert raised a phantom rollback. Same for
    `convert_file_to_markdown`, which takes `save_path` rather than returning
    `output_path`.
    """
    reg = ras_eval_registry()
    insert = dict(reg.get("insert_data").effective_steps[0].arg_map)
    assert "args.db_path" in insert.values()
    assert not any(v == "args.table" for v in insert.values())

    convert = dict(reg.get("convert_file_to_markdown").effective_steps[0].arg_map)
    assert "args.save_path" in convert.values()


# ---------------------------------------------------------------------------
# Needs the data
# ---------------------------------------------------------------------------


@needs_data
def test_import_produces_benign_scenarios_with_real_arguments():
    scen = ras_eval_scenarios()
    assert scen
    assert all(s.intent is Intent.BENIGN for s in scen)
    assert all(s.technique == "EXT" for s in scen)
    # The point of importing rather than authoring: arguments a model chose.
    assert any(st.args for s in scen for st in s.steps)


@needs_data
def test_only_unique_tasks_are_imported_not_every_model_run():
    """Eight models ran the same 80 tasks; importing all of them would be padding."""
    scen = ras_eval_scenarios()
    assert len(scen) <= 80
    assert len({s.id for s in scen}) == len(scen)


@needs_data
def test_no_imported_scenario_carries_a_step_with_no_arguments():
    """A call with no observed arguments cannot resolve any inverse.

    Importing one manufactures a phantom-rollback false positive out of missing trace
    data rather than out of anything the control plane did. Four scenarios were
    dropped for exactly this reason.
    """
    for s in ras_eval_scenarios():
        for st in s.steps:
            spec = ras_eval_registry().get(st.tool)
            needs = spec and any(
                e.startswith("args.")
                for step in spec.effective_steps
                for _n, e in step.arg_map
            )
            if needs:
                assert st.args, f"{s.id}: {st.tool} imported with no arguments"


@needs_data
def test_unclassified_tools_are_skipped_rather_than_imported_as_unknown():
    known = {s.tool for s in RAS_EVAL_SPECS}
    for s in ras_eval_scenarios():
        for st in s.steps:
            assert st.tool in known, f"{s.id} imported unclassified {st.tool}"


@needs_data
def test_imported_traffic_is_not_blocked():
    """The measurement this import exists for.

    It found two real spec bugs on its first run — a 16.2% false-positive rate that
    the hand-authored corpus could not have surfaced, because I wrote both the spec
    and the scenario and used my invented argument names in each.
    """
    results = Harness().run_all(ras_eval_scenarios())
    fps = [r for r in results if r.outcome is Outcome.FALSE_POSITIVE]
    assert not fps, [
        (r.scenario.id, [s.reason for s in r.steps if not s.allowed]) for r in fps
    ]


@needs_data
def test_including_the_import_reaches_a_production_like_ratio():
    """2.2:1 hand-authored, ~6:1 with the import — the ADR-Bench comparison."""
    from revoco.bench import all_scenarios

    combined = all_scenarios() + ras_eval_scenarios()
    m = score(Harness().run_all(combined))
    assert m.benign / m.malicious > 4.0
    assert m.false_positive_rate == 0.0


@needs_data
def test_provenance_states_the_limits_rather_than_the_headline():
    prov = provenance()
    assert prov["license"].startswith("none declared")
    assert "not the 640" in prov["note"]
    assert "enterprise" in prov["note"]
