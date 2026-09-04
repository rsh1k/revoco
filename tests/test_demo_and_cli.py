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


def test_a_comparison_that_could_not_be_made_is_a_different_exit_code(tmp_path, capsys):
    """Three outcomes, not two.

    A scheduler that cannot tell "a control regressed" from "the comparison never
    happened" reads a broken runner as a healthy estate the moment nobody is
    reading the log — the same absence-looking-like-success the change taxonomy
    refuses. 0 nothing worse, 1 something did, 2 the check could not be made.
    """
    from revoco.drills import DrillOutcome as D

    a = tmp_path / "a.json"
    b = tmp_path / "b.json"
    _write_run(a, [_drill("t", D.PASSED)], target="tenant-a", rid="r1")
    _write_run(b, [_drill("t", D.PASSED, at=2000.0)], target="tenant-b",
               rid="r2", at=2000.0)

    assert main(["validation-report", str(b), "--previous", str(a)]) == 2
    assert "cannot compare" in capsys.readouterr().err

    assert main(["validation-report", str(tmp_path / "nope.json")]) == 2
    assert "cannot compare" in capsys.readouterr().err

    malformed = tmp_path / "bad.json"
    malformed.write_text("{not json")
    assert main(["validation-report", str(malformed)]) == 2


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


def test_horizon_can_be_rendered_straight_from_a_stored_journal(tmp_path, capsys):
    """The path an operator actually has. The process that held the horizon has
    exited; the journal on disk is what is left."""
    from revoco import ControlPlane, Scope, crypto
    from revoco.gate import load_policy
    from revoco.reversal import InverseRegistry, InverseSpec, Reversibility
    from revoco.store.sqlite import SqliteStore

    db = tmp_path / "s.db"
    store = SqliteStore(str(db))
    reg = InverseRegistry([
        InverseSpec(tool="payments.wire", kind=Reversibility.IRREVERSIBLE)])
    cp = ControlPlane(
        policy=load_policy({"name": "t", "default_effect": "allow",
                            "rules": [{"id": "a", "effect": "allow"}]}),
        inverse_registry=reg, store=store)
    hp, hb = crypto.generate_keypair()
    ap, ab = crypto.generate_keypair()
    cfo = cp.register_human("CFO", hb)
    bot = cp.register_agent("bot", ab)
    g = cp.issue_root_delegation(
        human_private_key=hp, human_id=cfo.id, agent_id=bot.id,
        scope=Scope.make(tools={"*"}, actions={"write"}, max_risk=90),
        purpose="p", ttl_seconds=600)
    v = cp.authorize(actor_private_key=ap, actor_id=bot.id, delegation_id=g.id,
                     tool="payments.wire", args={"amount": 1}, action="write",
                     risk=10, session_id="s1")
    cp.confirm(v)

    out_html = tmp_path / "c.html"
    assert main(["horizon", "--store", str(db), "--html", str(out_html)]) == 0
    page = out_html.read_text()
    assert "payments.wire" in page
    assert "Standing exposure" in page


def test_horizon_needs_something_to_read(capsys):
    assert main(["horizon"]) == 2
    assert "saved horizon or --store" in capsys.readouterr().err


def test_an_unreadable_store_is_refused_with_a_sentence(tmp_path, capsys):
    assert main(["horizon", "--store", str(tmp_path / "nope.db")]) == 2
    assert "cannot read the horizon" in capsys.readouterr().err
