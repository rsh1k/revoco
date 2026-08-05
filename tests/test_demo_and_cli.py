"""The demo is executable documentation, so it is tested like code."""

from __future__ import annotations

import json

from revoco.cli import main
from revoco.demo import run_demo


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
