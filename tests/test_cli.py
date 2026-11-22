"""The CLI is the CI gate, so the exit codes are the contract."""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from netaudit import rulepacks
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
    assert "netaudit 0.2.0" in capsys.readouterr().out


def test_cli_undetectable_file(capsys, tmp_path: Path) -> None:
    junk = tmp_path / "notes.txt"
    junk.write_text("buy milk", encoding="utf-8")
    assert main(["scan", str(junk)]) == 2
    assert "could not be detected" in capsys.readouterr().err


def test_cli_missing_file(capsys, tmp_path: Path) -> None:
    assert main(["scan", str(tmp_path / "nope.conf")]) == 2
    assert "cannot read" in capsys.readouterr().err


def test_cli_scan_broken_rulepack_exits_three(
    capsys, fixtures_dir: Path, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """A schema-invalid pack is exit 3, not the generic 'unreadable file' 2."""

    (tmp_path / "cisco.yaml").write_text("vendor: cisco\nrules: nope\n", encoding="utf-8")
    monkeypatch.setattr(rulepacks, "RULEPACK_DIR", tmp_path)
    assert main(["scan", _path(fixtures_dir, "cisco_bad.conf")]) == 3
    assert "missing 'rules' list" in capsys.readouterr().err


def test_cli_explain(capsys) -> None:
    assert main(["explain", "FG-009"]) == 0
    out = capsys.readouterr().out
    assert "FG-009 — Firewall policy permits any-any" in out
    assert "internet (x1.5)" in out
    assert "CIS Controls v8: 4.4" in out
    assert "Narrow source and destination" in out


def test_cli_explain_unknown_rule(capsys) -> None:
    assert main(["explain", "FG-999"]) == 2
    assert "unknown rule" in capsys.readouterr().err


def test_cli_explain_broken_pack_exits_three(
    capsys, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    (tmp_path / "fortigate.yaml").write_text("vendor: fortigate\nrules: nope\n", encoding="utf-8")
    monkeypatch.setattr(rulepacks, "RULEPACK_DIR", tmp_path)
    assert main(["explain", "FG-001"]) == 3
    assert "error:" in capsys.readouterr().err


def test_cli_diff_adds_findings_and_exits_one(capsys, fixtures_dir: Path) -> None:
    code = main(
        [
            "diff",
            _path(fixtures_dir, "fortigate_good.conf"),
            _path(fixtures_dir, "fortigate_bad.conf"),
        ]
    )
    assert code == 1
    out = capsys.readouterr().out
    assert "score 100 -> " in out
    assert "new: 8" in out and "fixed: 0" in out
    assert "FG-001" in out


def test_cli_diff_fixes_findings_and_exits_zero(capsys, fixtures_dir: Path) -> None:
    code = main(
        [
            "diff",
            _path(fixtures_dir, "fortigate_bad.conf"),
            _path(fixtures_dir, "fortigate_good.conf"),
        ]
    )
    assert code == 0
    out = capsys.readouterr().out
    assert "new: 0" in out and "fixed: 8" in out
    assert "FG-009" in out


def test_cli_diff_identical_configs(capsys, fixtures_dir: Path) -> None:
    path = _path(fixtures_dir, "cisco_bad.conf")
    assert main(["diff", path, path]) == 0
    out = capsys.readouterr().out
    assert "new: 0" in out and "fixed: 0" in out
    assert "no change in findings" in out


def test_cli_diff_missing_file(tmp_path: Path) -> None:
    assert main(["diff", str(tmp_path / "nope.conf"), str(tmp_path / "nope2.conf")]) == 2


def test_cli_diff_undetectable_vendor(capsys, tmp_path: Path) -> None:
    junk = tmp_path / "notes.txt"
    junk.write_text("buy milk", encoding="utf-8")
    good = tmp_path / "ok.conf"
    good.write_text("hostname r1\n", encoding="utf-8")
    assert main(["diff", str(good), str(junk)]) == 2
    assert "could not be detected" in capsys.readouterr().err
