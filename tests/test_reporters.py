"""SARIF document shape: every result must resolve against the rules array."""

from __future__ import annotations

import json

from netaudit import reporters
from netaudit.models import Exposure, Finding, Severity


def _finding(
    rule_id: str,
    severity: Severity = Severity.HIGH,
    evidence: str = "interface port1",
) -> Finding:
    return Finding(
        rule_id=rule_id,
        title=f"Title for {rule_id}",
        severity=severity,
        evidence=evidence,
        remediation="fix it",
        reference="https://example.com/ref",
    )


def _document(filename: str, findings: list[Finding]) -> dict:
    return json.loads(reporters.sarif(filename, findings))


def test_one_result_per_finding() -> None:
    findings = [_finding("FG-001"), _finding("FG-002"), _finding("CS-001")]
    run = _document("device.conf", findings)["runs"][0]
    assert len(run["results"]) == len(findings)
    assert {r["ruleId"] for r in run["results"]} == {"FG-001", "FG-002", "CS-001"}


def test_rule_index_is_present_and_in_range() -> None:
    findings = [_finding(f"R-{i}") for i in range(5)]
    run = _document("device.conf", findings)["runs"][0]
    rules = run["tool"]["driver"]["rules"]
    for result in run["results"]:
        assert isinstance(result["ruleIndex"], int)
        assert 0 <= result["ruleIndex"] < len(rules)
        assert rules[result["ruleIndex"]]["id"] == result["ruleId"]


def test_every_result_rule_id_is_declared() -> None:
    findings = [_finding("FG-001"), _finding("FG-009"), _finding("FG-001")]
    run = _document("device.conf", findings)["runs"][0]
    declared = {rule["id"] for rule in run["tool"]["driver"]["rules"]}
    assert {result["ruleId"] for result in run["results"]} <= declared


def test_location_uri_is_relative_with_srcroot_base() -> None:
    run = _document("tests/fixtures/cisco_bad.conf", [_finding("CS-001")])["runs"][0]
    location = run["results"][0]["locations"][0]["physicalLocation"]
    artifact = location["artifactLocation"]
    assert artifact["uri"] == "tests/fixtures/cisco_bad.conf"
    assert not artifact["uri"].startswith(("/", "file:", "http"))
    assert artifact["uriBaseId"] == "%SRCROOT%"
    assert location["region"]["startLine"] == 1


def test_absolute_paths_are_made_relative() -> None:
    run = _document("/absolute/path/device.conf", [_finding("CS-001")])["runs"][0]
    artifact = run["results"][0]["locations"][0]["physicalLocation"]["artifactLocation"]
    assert artifact["uri"] == "absolute/path/device.conf"


def test_same_rule_twice_yields_one_rule_entry() -> None:
    findings = [
        _finding("FG-003", evidence="interface port1"),
        _finding("FG-003", evidence="interface port2"),
    ]
    run = _document("device.conf", findings)["runs"][0]
    rules = run["tool"]["driver"]["rules"]
    assert len(rules) == 1
    assert rules[0]["id"] == "FG-003"
    assert len(run["results"]) == 2
    assert {result["ruleIndex"] for result in run["results"]} == {0}


def test_results_sort_by_severity_and_schema_is_2_1_0() -> None:
    findings = [
        _finding("R-LOW", Severity.LOW),
        _finding("R-CRIT", Severity.CRITICAL),
        _finding("R-MED", Severity.MEDIUM),
        _finding("R-HIGH", Severity.HIGH),
    ]
    document = _document("device.conf", findings)
    assert document["version"] == "2.1.0"
    assert document["$schema"] == "https://json.schemastore.org/sarif-2.1.0.json"
    levels = [r["level"] for r in document["runs"][0]["results"]]
    assert levels == ["error", "error", "warning", "note"]


def test_empty_scan_declares_no_rules() -> None:
    run = _document("device.conf", [])["runs"][0]
    assert run["results"] == []
    assert run["tool"]["driver"]["rules"] == []


def test_markdown_reports_every_finding() -> None:
    text = reporters.markdown(
        "device.conf", "cisco", 42, "D", [_finding("CS-001"), _finding("CS-002")]
    )
    assert "# NetAudit report - `device.conf`" in text
    assert "CS-001" in text and "CS-002" in text
    assert "42/100" in text and "grade **D**" in text


def test_markdown_prints_the_exposure_multiplier() -> None:
    finding = Finding(
        rule_id="FG-009",
        title="t",
        severity=Severity.MEDIUM,
        evidence="e",
        remediation="r",
        reference="",
        exposure=Exposure.INTERNET,
    )
    text = reporters.markdown("device.conf", "fortigate", 85, "B", [finding])
    assert "- Exposure: internet (x1.5)" in text
