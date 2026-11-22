"""The CLI is the CI gate, so the exit codes are the contract."""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from netaudit.cli import main


def _path(fixtures_dir: Path, name: str) -> str:
    return str(fixtures_dir / name)


def test_cli_good_table(capsys, fixtures_dir: Path) -> None:
    assert main(["scan", _path(fixtures_dir, "cisco_good.conf")]) == 0
    out = capsys.readouterr().out
    assert "grade=A" in out
    assert "no violations" in out


def test_cli_bad_table(capsys, fixtures_dir: Path) -> None:
    assert main(["scan", _path(fixtures_dir, "fortigate_bad.conf")]) == 0
    out = capsys.readouterr().out
    assert "vendor=fortigate" in out
    assert "FG-001" in out


def test_cli_fail_under_exit_one(fixtures_dir: Path) -> None:
    assert main(["scan", _path(fixtures_dir, "cisco_bad.conf"), "--fail-under", "90"]) == 1


def test_cli_fail_under_exit_zero(fixtures_dir: Path) -> None:
    assert main(["scan", _path(fixtures_dir, "cisco_good.conf"), "--fail-under", "80"]) == 0


def test_cli_json(capsys, fixtures_dir: Path) -> None:
    main(["scan", _path(fixtures_dir, "cisco_bad.conf"), "--format", "json"])
    payload = json.loads(capsys.readouterr().out)
    assert payload["vendor"] == "cisco"
    assert payload["score"] < 90
    assert payload["findings"][0]["severity"] in {"HIGH", "CRITICAL"}


def test_cli_sarif(capsys, fixtures_dir: Path) -> None:
    main(["scan", _path(fixtures_dir, "cisco_bad.conf"), "--format", "sarif"])
    out = capsys.readouterr().out
    assert '"version": "2.1.0"' in out
    document = json.loads(out)
    assert document["runs"][0]["results"]
    location = document["runs"][0]["results"][0]["locations"][0]
    uri = location["physicalLocation"]["artifactLocation"]["uri"]
    assert uri.startswith("tests/fixtures/") or "fixtures" in uri


def test_cli_markdown(capsys, fixtures_dir: Path) -> None:
    main(["scan", _path(fixtures_dir, "fortigate_bad.conf"), "--format", "markdown"])
    assert "# NetAudit report" in capsys.readouterr().out


def test_cli_explicit_rulepack(capsys, fixtures_dir: Path) -> None:
    ok = main(["scan", _path(fixtures_dir, "fortigate_bad.conf"), "--rulepack", "fortigate"])
    assert ok == 0
    assert "score=" in capsys.readouterr().out


def test_cli_version(capsys) -> None:
    with pytest.raises(SystemExit) as exit_info:
        main(["--version"])
    assert exit_info.value.code == 0
    assert "netaudit 0.1.0" in capsys.readouterr().out


def test_cli_undetectable_file(capsys, tmp_path: Path) -> None:
    junk = tmp_path / "notes.txt"
    junk.write_text("buy milk", encoding="utf-8")
    assert main(["scan", str(junk)]) == 2
    assert "could not be detected" in capsys.readouterr().err


def test_cli_missing_file(capsys, tmp_path: Path) -> None:
    assert main(["scan", str(tmp_path / "nope.conf")]) == 2
    assert "cannot read" in capsys.readouterr().err


def test_cli_explain_shows_triggering_flat_statement(capsys, fixtures_dir: Path) -> None:
    assert main(["scan", _path(fixtures_dir, "fortigate_bad.conf"), "--explain"]) == 0
    out = capsys.readouterr().out
    assert "FG-001" in out
    assert "evidence: system.global|admin-telnet=enable" in out
    assert "rulepack: src/netaudit/rulepacks/fortigate.yaml:5 (FG-001)" in out
    assert "match: ^system\\.global\\|admin-telnet=enable" in out
    assert "scope: system.global" in out


def test_cli_diff_only_emits_new_findings(capsys, fixtures_dir: Path) -> None:
    assert (
        main(
            [
                "diff",
                _path(fixtures_dir, "fortigate_bad.conf"),
                _path(fixtures_dir, "fortigate_good.conf"),
            ]
        )
        == 0
    )
    assert capsys.readouterr().out.strip() == "No newly introduced findings."


def test_cli_diff_is_a_gate_when_findings_are_introduced(capsys, fixtures_dir: Path) -> None:
    assert (
        main(
            [
                "diff",
                _path(fixtures_dir, "cisco_good.conf"),
                _path(fixtures_dir, "cisco_bad.conf"),
                "--format",
                "json",
            ]
        )
        == 1
    )
    payload = json.loads(capsys.readouterr().out)
    assert isinstance(payload, list)
    assert {finding["rule_id"] for finding in payload} >= {"CS-001"}
    assert all("resolved" not in finding for finding in payload)


def test_cli_diff_rejects_different_vendors(capsys, fixtures_dir: Path) -> None:
    assert (
        main(
            [
                "diff",
                _path(fixtures_dir, "fortigate_good.conf"),
                _path(fixtures_dir, "cisco_good.conf"),
            ]
        )
        == 2
    )
    assert "different vendors" in capsys.readouterr().err
