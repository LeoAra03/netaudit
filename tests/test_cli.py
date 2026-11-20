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


def test_cli_refuses_a_rulepack_from_another_vendor(capsys, fixtures_dir: Path) -> None:
    """The Cisco pack on a FortiGate config finds none of its own markers, so
    every ``expect: present`` rule reported a violation: three fabricated
    findings and exit 0 for a device the pack never looked at."""

    code = main(["scan", _path(fixtures_dir, "fortigate_bad.conf"), "--rulepack", "cisco"])
    captured = capsys.readouterr()
    assert code == 2
    assert "does not match detected vendor" in captured.err
    assert "CS-005" not in captured.out


@pytest.mark.parametrize("value", ["-1", "101"])
def test_cli_rejects_a_threshold_outside_the_score_range(
    capsys, fixtures_dir: Path, value: str
) -> None:
    with pytest.raises(SystemExit) as exit_info:
        main(["scan", _path(fixtures_dir, "cisco_good.conf"), "--fail-under", value])
    assert exit_info.value.code == 2
    assert "score must be 0-100" in capsys.readouterr().err


def test_cli_per_object_prints_every_occurrence(capsys, tmp_path: Path) -> None:
    device = tmp_path / "fw.conf"
    device.write_text(
        "config system interface\n"
        '    edit "p1"\n        set allowaccess http\n    next\n'
        '    edit "p2"\n        set allowaccess http\n    next\n'
        "end\n",
        encoding="utf-8",
    )
    assert main(["scan", str(device)]) == 0
    assert capsys.readouterr().out.count("FG-003") == 1

    assert main(["scan", str(device), "--per-object"]) == 0
    out = capsys.readouterr().out
    assert out.count("FG-003") == 2
    assert "[p1]" in out and "[p2]" in out


def test_cli_rules_table(capsys) -> None:
    assert main(["rules"]) == 0
    out = capsys.readouterr().out
    assert "FG-001" in out
    assert "CS-006" in out
    assert "severity" in out


def test_cli_rules_json_and_single_pack(capsys) -> None:
    assert main(["rules", "--pack", "fortigate", "--format", "json"]) == 0
    payload = json.loads(capsys.readouterr().out)
    assert [pack["name"] for pack in payload["packs"]] == ["fortigate"]
    rules = payload["packs"][0]["rules"]
    assert rules[0]["id"] == "FG-001"
    assert rules[0]["severity"] == "HIGH"
    assert rules[0]["scope"] == ["system.global"]
