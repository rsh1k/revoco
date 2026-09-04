"""The demo is executable documentation, so it is tested like code."""

from __future__ import annotations

import json

import pytest

from revoco.adapters import EQUIVALENCES, SURFACES, equivalence
from revoco.cli import main
from revoco.demo import run_demo
from revoco.reversal.model import Reversibility


def test_demo_ends_with_the_fraud_undone(capsys):
    out = run_demo()
    erp = out["erp"]

    # The vendor's real banking details are back.
    assert erp.vendors["V-100"]["bank_account"] == "GB29-REAL-8888-1234"
    # The fraudulent payment is voided.
    assert erp.invoices["INV-7781"]["status"] == "approved"
    assert erp.invoices["INV-7781"]["payment_id"] is None

    # The rubber-stamp human approved the fraudulent steps; recovery did not
    # depend on them catching it.
    assert "vendors.update" in out["approvals"]

    report = out["containment"]
    assert len(report["revoked_delegations"]) == 2
    assert report["rollback"]["failed"] == 0
    assert report["fully_contained"]

    ev = out["evidence"]
    assert ev["integrity"]["chain_verified"] is True
    assert ev["activity"]["blocked"] >= 2


def test_demo_ledger_verifies_after_everything(capsys):
    out = run_demo()
    assert out["control_plane"].verify() is True


def test_cli_controls_json(capsys):
    assert main(["controls", "--json"]) == 0
    parsed = json.loads(capsys.readouterr().out)
    assert "EU AI Act" in parsed


def test_cli_policy_check_accepts_the_starter_policy(tmp_path, capsys):
    from revoco.gate.policy import STARTER_POLICY

    p = tmp_path / "policy.json"
    p.write_text(json.dumps(STARTER_POLICY))
    assert main(["policy-check", str(p)]) == 0
    assert "OK:" in capsys.readouterr().out


def test_cli_policy_check_rejects_a_bad_policy(tmp_path, capsys):
    p = tmp_path / "bad.json"
    p.write_text(json.dumps({"rules": [{"id": "r", "effect": "perhaps"}]}))
    assert main(["policy-check", str(p)]) == 1


def test_cli_policy_check_warns_on_a_permissive_default(tmp_path, capsys):
    p = tmp_path / "open.json"
    p.write_text(json.dumps({"default_effect": "allow", "rules": []}))
    assert main(["policy-check", str(p)]) == 0
    assert "WARNING" in capsys.readouterr().err


def test_cli_coverage_fails_when_a_tool_has_no_declared_inverse(tmp_path, capsys):
    from revoco.reversal.registry import ap_starter_registry

    f = tmp_path / "inv.json"
    f.write_text(json.dumps(ap_starter_registry().to_dict()))
    # Exit 1 makes this usable as a CI gate.
    assert main(["coverage", str(f), "--tools", "invoices.pay,brand.new"]) == 1
    assert main(["coverage", str(f), "--tools", "invoices.pay"]) == 0


def test_cli_inverses_check_round_trips_the_starter_registry(tmp_path, capsys):
    from revoco.reversal.registry import ap_starter_registry

    f = tmp_path / "inv.json"
    f.write_text(json.dumps(ap_starter_registry().to_dict()))
    assert main(["inverses-check", str(f)]) == 0
    assert "inverse specs" in capsys.readouterr().out


def test_every_posture_gets_a_column_so_the_surface_rows_add_up(capsys):
    """The table hard-coded four columns while the counts came from the enum, so
    adding IDEMPOTENT silently dropped a spec: workstation printed 14 specs above
    a row summing to 13. A row that does not add up is worse than a missing column,
    because nothing about it looks wrong.
    """
    assert main(["surfaces"]) == 0
    lines = capsys.readouterr().out.splitlines()
    header = next(ln for ln in lines if ln.strip().startswith("surface"))
    cols = header.split()[2:-1]          # drop 'surface', 'specs', 'equivalence'
    assert len(cols) == len(list(Reversibility))

    for row in lines:
        parts = row.split()
        if len(parts) < 2 + len(cols) or parts[0] not in SURFACES:
            continue
        total, counts = int(parts[1]), [int(x) for x in parts[2:2 + len(cols)]]
        assert sum(counts) == total, f"{parts[0]}: {counts} does not sum to {total}"


def test_every_surface_states_whether_it_has_an_equivalence_relation():
    """Absent is recorded rather than defaulted, so adding a surface forces the
    decision instead of silently inheriting exact-match comparison."""
    assert set(EQUIVALENCES) == set(SURFACES)
    assert EQUIVALENCES["workstation"] is not None


def test_the_missing_equivalence_surfaces_are_named_rather_than_just_counted(capsys):
    """Derived from the registry rather than hard-coded.

    The first version asserted "1/8" and failed the day a second surface got a
    relation — which is the tool working, and a test that has to be edited every
    time the thing it measures improves is a test that gets edited without being
    read."""
    declared = [n for n, eq in EQUIVALENCES.items() if eq is not None]
    missing = [n for n in SURFACES if EQUIVALENCES.get(n) is None]

    assert main(["surfaces"]) == 0
    out = capsys.readouterr().out
    assert (f"surfaces with a declared equivalence {len(declared)}/{len(SURFACES)}"
            in out)
    assert missing, "if every surface has one, this assertion needs rewriting"
    named = out.split("No equivalence relation is declared for:")[1]
    for name in missing:
        assert name in named


def test_an_unknown_surface_is_refused_rather_than_reported_as_having_none():
    with pytest.raises(KeyError):
        equivalence("nosuchsurface")


def _write_run(path, results, target="t", rid="r", at=1000.0):
    from revoco.validation import ValidationRun
    run = ValidationRun(id=rid, target=target, started_at=at,
                        finished_at=at + 1, results=tuple(results))
    path.write_text(json.dumps(run.payload()))
    return run


def _drill(tool, outcome, at=1000.0):
    from revoco.drills import DrillResult
    from revoco.reversal import Reversibility
    return DrillResult(id=f"d-{tool}-{at}", tool=tool, outcome=outcome,
                       declared_kind=Reversibility.REVERSIBLE, at=at, duration_ms=1.0)


def test_validation_report_exits_nonzero_only_when_something_got_worse(tmp_path, capsys):
    """A scheduler keys on the exit code, not the prose. A standing failure that
    has not moved is a status, and failing the run on it every night is how the
    alert gets muted."""
    from revoco.drills import DrillOutcome as D

    base = tmp_path / "base.json"
    worse = tmp_path / "worse.json"
    _write_run(base, [_drill("t", D.PASSED)], rid="r1")
    _write_run(worse, [_drill("t", D.FAILED, at=2000.0)], rid="r2", at=2000.0)

    assert main(["validation-report", str(worse), "--previous", str(base)]) == 1
    assert "REGRESSED" in capsys.readouterr().out

    assert main(["validation-report", str(base), "--previous", str(base)]) == 0


def test_an_unsigned_report_says_so_rather_than_signing_with_a_throwaway_key(
        tmp_path, capsys):
    """A signature from an ephemeral key verifies against nothing anyone knows.
    That is decoration presented as evidence, which is worse than no signature."""
    from revoco.drills import DrillOutcome as D

    run = tmp_path / "run.json"
    _write_run(run, [_drill("t", D.PASSED)])
    assert main(["validation-report", str(run)]) == 0
    out = capsys.readouterr().out
    assert "NOT SIGNED" in out
    assert "UNSIGNED" in out


def test_a_signed_report_verifies_for_someone_holding_only_the_public_key(
        tmp_path, capsys):
    """The whole point of the artefact: an auditor who distrusts the operator can
    check it without access to anything the operator controls."""
    from revoco.core import crypto
    from revoco.drills import DrillOutcome as D
    from revoco.validation import Change, ControlChange, ValidationReport, ValidationRun

    priv, pub = crypto.generate_keypair()
    key = tmp_path / "k"
    key.write_text(crypto.private_key_to_b64(priv))
    run = tmp_path / "run.json"
    _write_run(run, [_drill("t", D.PASSED)])

    assert main(["validation-report", str(run), "--signing-key", str(key),
                 "--signer", "ci", "--json"]) == 0
    d = json.loads(capsys.readouterr().out)

    rebuilt = ValidationReport(
        id=d["id"], run=ValidationRun.from_dict(d["run"]),
        previous_id=d["previous_id"], previous_digest=d["previous_digest"],
        changes=tuple(ControlChange(c["tool"], Change(c["change"]), c["now"],
                                    c["before"], c["detail"]) for c in d["changes"]),
        signer_id=d["signer_id"], signed_at=d["signed_at"], signature=d["signature"])
    assert rebuilt.verify_signature(pub)
