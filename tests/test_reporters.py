"""Reporters: the exports are consumed by other tools, so their shape is a contract."""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

import pytest

from netaudit import __version__, reporters
from netaudit.models import Finding, Severity


def _finding(
    rule_id: str = "X-001",
    severity: Severity = Severity.HIGH,
    evidence: str = "system.global|admin-telnet=enable",
) -> Finding:
    return Finding(
        rule_id=rule_id,
        title="Something is wrong",
        severity=severity,
        evidence=evidence,
        remediation="fix it",
        reference="CIS whatever",
    )


def _sarif(filename: str, findings: list[Finding]) -> dict[str, Any]:
    document: dict[str, Any] = json.loads(reporters.sarif(filename, findings))
    return document


def test_sarif_uri_is_relative_to_the_working_directory(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """GitHub code scanning resolves ``uri`` against the repository root, and a
    space in an unencoded path makes the document an invalid URI reference."""

    monkeypatch.chdir(tmp_path)
    target = tmp_path / "configs" / "fw one.conf"
    target.parent.mkdir()
    target.write_text("config system global\nend\n", encoding="utf-8")

    document = _sarif(str(target), [_finding()])
    run = document["runs"][0]
    uri = run["results"][0]["locations"][0]["physicalLocation"]["artifactLocation"]["uri"]
    assert uri == "configs/fw%20one.conf"


def test_sarif_uri_outside_the_working_directory_is_a_file_uri(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    inside = tmp_path / "repo"
    inside.mkdir()
    monkeypatch.chdir(inside)
    outside = tmp_path / "elsewhere" / "fw.conf"
    outside.parent.mkdir()
    outside.write_text("config system global\nend\n", encoding="utf-8")

    document = _sarif(str(outside), [_finding()])
    run = document["runs"][0]
    uri = run["results"][0]["locations"][0]["physicalLocation"]["artifactLocation"]["uri"]
    assert uri.startswith("file://")
    assert uri.endswith("elsewhere/fw.conf")


def test_sarif_driver_version_matches_the_package() -> None:
    document = _sarif("fw.conf", [_finding()])
    driver = document["runs"][0]["tool"]["driver"]
    assert driver["version"] == __version__


def test_sarif_rule_index_points_at_the_matching_rule() -> None:
    """``reportingDescriptor`` has no ``index`` property -- the OASIS schema
    rejects it -- so the array position is what ``result.ruleIndex`` refers to."""

    document = _sarif("fw.conf", [_finding("B-2", Severity.LOW), _finding("A-1", Severity.HIGH)])
    run = document["runs"][0]
    rules = run["tool"]["driver"]["rules"]
    assert [rule["id"] for rule in rules] == ["B-2", "A-1"]
    for result in run["results"]:
        assert rules[result["ruleIndex"]]["id"] == result["ruleId"]


def test_sarif_carries_the_security_severity_github_reads() -> None:
    document = _sarif("fw.conf", [_finding(severity=Severity.CRITICAL)])
    rule = document["runs"][0]["tool"]["driver"]["rules"][0]
    assert rule["properties"]["security-severity"] == "9.5"
    assert rule["defaultConfiguration"]["level"] == "error"


def test_sarif_low_findings_are_notes() -> None:
    document = _sarif("fw.conf", [_finding(severity=Severity.LOW)])
    result = document["runs"][0]["results"][0]
    assert result["level"] == "note"


def test_sarif_lists_a_repeated_rule_once() -> None:
    """Per-object findings repeat the rule id; the driver must still declare it once."""

    document = _sarif(
        "fw.conf", [_finding("FG-003", evidence="[p1] x"), _finding("FG-003", evidence="[p2] y")]
    )
    run = document["runs"][0]
    assert len(run["tool"]["driver"]["rules"]) == 1
    assert len(run["results"]) == 2
    assert {result["ruleIndex"] for result in run["results"]} == {0}


def test_markdown_escapes_a_backtick_in_the_evidence() -> None:
    """A code span cannot contain the fence that opened it, so evidence carrying
    a backtick used to break the sentence in the ticket this report is pasted
    into."""

    report = reporters.markdown("fw.conf", "fortigate", 90, "A", [_finding(evidence="a`b")])
    assert "``a`b``" in report


def test_markdown_escapes_a_backtick_in_the_filename() -> None:
    report = reporters.markdown("we`ird.conf", "fortigate", 100, "A", [])
    assert "``we`ird.conf``" in report


def test_markdown_lists_every_finding() -> None:
    report = reporters.markdown("fw.conf", "fortigate", 80, "B", [_finding("A-1"), _finding("B-2")])
    assert report.count("## [") == 2
    assert "Findings: **2**" in report
