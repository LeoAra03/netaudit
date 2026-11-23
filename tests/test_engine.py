from __future__ import annotations

from collections.abc import Callable
from pathlib import Path

import pytest
import yaml

from netaudit import engine, parser, rulepacks, scoring
from netaudit.models import EXPOSURE_MULTIPLIERS, Exposure, Finding, Severity
from netaudit.rulepacks import (
    RuleNotFoundError,
    RulepackError,
    _build,
    find_rule,
    load_rulepack,
)


def _run(text: str, vendor: str) -> list[Finding]:
    config = parser.parse(text, vendor)
    return engine.evaluate(config, load_rulepack(vendor))


def test_bad_fortigate_flags_expected(config_text: Callable[[str], str]) -> None:
    findings = _run(config_text("fortigate_bad.conf"), "fortigate")
    assert {f.rule_id for f in findings} >= {"FG-001", "FG-006", "FG-007", "FG-009"}
    assert scoring.score(findings) < 60


def test_bad_cisco_flags_expected(config_text: Callable[[str], str]) -> None:
    findings = _run(config_text("cisco_bad.conf"), "cisco")
    assert {f.rule_id for f in findings} >= {"CS-001", "CS-002", "CS-005", "CS-007"}
    assert scoring.score(findings) < 60


def test_good_fortigate_is_clean(config_text: Callable[[str], str]) -> None:
    assert _run(config_text("fortigate_good.conf"), "fortigate") == []


def test_good_cisco_is_clean(config_text: Callable[[str], str]) -> None:
    assert _run(config_text("cisco_good.conf"), "cisco") == []


def test_evidence_names_the_interface(config_text: Callable[[str], str]) -> None:
    findings = _run(config_text("fortigate_bad.conf"), "fortigate")
    http = next(f for f in findings if f.rule_id == "FG-003")
    assert "[port1]" in http.evidence


def test_absent_rule_reports_missing_statement(config_text: Callable[[str], str]) -> None:
    """CS-006 fires because there is no syslog host at all."""

    findings = _run(config_text("cisco_bad.conf"), "cisco")
    missing = next(f for f in findings if f.rule_id == "CS-006")
    assert missing.evidence == "statement not found"


def test_findings_sorted_by_severity(config_text: Callable[[str], str]) -> None:
    findings = _run(config_text("fortigate_bad.conf"), "fortigate")
    severities = [f.severity for f in findings]
    assert severities == sorted(severities, reverse=True)


def test_scope_without_statements_is_not_applicable() -> None:
    """A rule scoped to a block the config never has must not fire."""

    config = parser.parse("hostname r1\n!\n", "cisco")
    rules = [r for r in load_rulepack("cisco") if r.scope]
    assert not [f for f in engine.evaluate(config, rules) if f.rule_id == "CS-001"]


def test_one_finding_per_rule(config_text: Callable[[str], str]) -> None:
    """Both srcaddr and dstaddr are `all`, but FG-009 reports once."""

    findings = _run(config_text("fortigate_bad.conf"), "fortigate")
    assert len([f for f in findings if f.rule_id == "FG-009"]) == 1


def test_grade_thresholds() -> None:
    assert scoring.grade(100) == "A"
    assert scoring.grade(85) == "B"
    assert scoring.grade(75) == "C"
    assert scoring.grade(65) == "D"
    assert scoring.grade(55) == "E"
    assert scoring.grade(0) == "F"


def test_score_never_negative(config_text: Callable[[str], str]) -> None:
    noisy = _run(config_text("fortigate_bad.conf"), "fortigate") * 5
    assert scoring.score(noisy) == 0


def test_severity_parse() -> None:
    assert Severity.parse("  High ") is Severity.HIGH
    with pytest.raises(ValueError, match="unknown severity"):
        Severity.parse("catastrophic")


def test_invalid_expect_raises() -> None:
    raw = {
        "id": "X-001",
        "title": "t",
        "severity": "low",
        "exposure": "internal",
        "match": "a",
        "expect": "abset",
        "remediation": "r",
    }
    with pytest.raises(RulepackError, match="invalid expect"):
        _build(raw)


def test_missing_field_raises() -> None:
    with pytest.raises(RulepackError, match="missing field"):
        _build({"id": "X-002", "title": "t", "severity": "low", "match": "a"})


def test_missing_exposure_raises() -> None:
    with pytest.raises(RulepackError, match="missing field.*exposure"):
        _build({"id": "X-006", "title": "t", "severity": "low", "match": "a", "remediation": "r"})


def test_invalid_exposure_raises() -> None:
    raw = {
        "id": "X-007",
        "title": "t",
        "severity": "low",
        "exposure": "dmz",
        "match": "a",
        "remediation": "r",
    }
    with pytest.raises(RulepackError, match="unknown exposure"):
        _build(raw)


def test_controls_must_be_a_mapping() -> None:
    raw = {
        "id": "X-008",
        "title": "t",
        "severity": "low",
        "exposure": "internal",
        "match": "a",
        "remediation": "r",
        "controls": "cis: 4.4",
    }
    with pytest.raises(RulepackError, match="controls must be a mapping"):
        _build(raw)


def test_bad_regex_raises() -> None:
    raw = {
        "id": "X-003",
        "title": "t",
        "severity": "low",
        "exposure": "internal",
        "match": "((",
        "remediation": "r",
    }
    with pytest.raises(RulepackError, match="bad pattern"):
        _build(raw)


def test_empty_severity_and_scope_errors() -> None:
    base = {"id": "X", "title": "t", "match": "a", "remediation": "r"}
    with pytest.raises(RulepackError, match="unknown severity"):
        _build({**base, "severity": "urgent", "exposure": "internal"})
    with pytest.raises(RulepackError, match="empty scope"):
        _build(
            {
                **base,
                "severity": "low",
                "exposure": "internal",
                "scope": ["system.global", "  "],
            }
        )


def test_unknown_rulepack_raises() -> None:
    with pytest.raises(RulepackError, match="unknown rulepack"):
        load_rulepack("juniper")


def test_rulepack_vendor_must_match_name(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    pack = tmp_path / "cisco.yaml"
    pack.write_text(yaml.safe_dump({"vendor": "fortigate", "rules": []}), encoding="utf-8")
    monkeypatch.setattr(rulepacks, "RULEPACK_DIR", tmp_path)
    with pytest.raises(RulepackError, match="does not match the rulepack name"):
        rulepacks.load_rulepack("cisco")


def test_rulepack_rules_key_required(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    (tmp_path / "cisco.yaml").write_text("vendor: cisco\nchecks: []\n", encoding="utf-8")
    monkeypatch.setattr(rulepacks, "RULEPACK_DIR", tmp_path)
    with pytest.raises(RulepackError, match="missing 'rules' list"):
        rulepacks.load_rulepack("cisco")


def test_rule_entry_must_be_a_mapping(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    (tmp_path / "cisco.yaml").write_text(
        "vendor: cisco\nrules:\n  - just a string\n", encoding="utf-8"
    )
    monkeypatch.setattr(rulepacks, "RULEPACK_DIR", tmp_path)
    with pytest.raises(RulepackError, match="not a mapping"):
        rulepacks.load_rulepack("cisco")


def test_duplicated_rule_id_raises(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    rule = {
        "id": "D-001",
        "title": "t",
        "severity": "low",
        "exposure": "internal",
        "match": "a",
        "remediation": "r",
    }
    (tmp_path / "cisco.yaml").write_text(
        yaml.safe_dump({"vendor": "cisco", "rules": [rule, rule]}), encoding="utf-8"
    )
    monkeypatch.setattr(rulepacks, "RULEPACK_DIR", tmp_path)
    with pytest.raises(RulepackError, match="duplicated rule id"):
        rulepacks.load_rulepack("cisco")


def test_bundled_rulepacks_all_load(fixtures_dir: Path) -> None:
    assert load_rulepack("fortigate")
    assert load_rulepack("cisco")
    assert fixtures_dir.is_dir()


def test_finding_carries_rule_exposure(config_text: Callable[[str], str]) -> None:
    findings = _run(config_text("fortigate_bad.conf"), "fortigate")
    exposure = {f.rule_id: f.exposure for f in findings}
    assert exposure["FG-001"] is Exposure.MANAGEMENT
    assert exposure["FG-009"] is Exposure.INTERNET


def test_exposure_multiplier_changes_score() -> None:
    def finding(exposure: Exposure) -> Finding:
        return Finding(
            rule_id="X-100",
            title="t",
            severity=Severity.HIGH,
            evidence="e",
            remediation="r",
            reference="",
            exposure=exposure,
        )

    # severity HIGH weighs 10: internet x1.5 = 15, management x1.2 = 12, internal x1.0 = 10.
    assert scoring.score([finding(Exposure.INTERNET)]) == 85
    assert scoring.score([finding(Exposure.MANAGEMENT)]) == 88
    assert scoring.score([finding(Exposure.INTERNAL)]) == 90
    assert EXPOSURE_MULTIPLIERS == {
        Exposure.INTERNET: 1.5,
        Exposure.MANAGEMENT: 1.2,
        Exposure.INTERNAL: 1.0,
    }


def test_exposure_parse() -> None:
    assert Exposure.parse("  Internet ") is Exposure.INTERNET
    with pytest.raises(ValueError, match="unknown exposure"):
        Exposure.parse("dmz")


def test_bundled_rules_carry_exposure_and_mapping() -> None:
    """The maintenance rule: no mapping row (and no exposure), no merge."""

    for pack in ("fortigate", "cisco"):
        for rule in load_rulepack(pack):
            assert rule.exposure in set(Exposure)
            assert rule.rationale.strip()
            assert rule.controls
            assert all(key and value for key, value in rule.controls.items())


def test_find_rule_returns_bundled_rule() -> None:
    rule = find_rule("FG-009")
    assert rule.exposure is Exposure.INTERNET
    assert rule.controls["cis"] == "4.4"
    assert rule.rationale


def test_find_rule_unknown_raises() -> None:
    with pytest.raises(RuleNotFoundError, match="unknown rule"):
        find_rule("XX-999")


def test_diff_reports_new_and_fixed(config_text: Callable[[str], str]) -> None:
    clean = _run(config_text("fortigate_good.conf"), "fortigate")
    dirty = _run(config_text("fortigate_bad.conf"), "fortigate")

    added, fixed = engine.diff(clean, dirty)
    assert {f.rule_id for f in added} == {f.rule_id for f in dirty}
    assert fixed == []

    added, fixed = engine.diff(dirty, clean)
    assert added == []
    assert {f.rule_id for f in fixed} == {f.rule_id for f in dirty}


def test_diff_keys_by_rule_id(config_text: Callable[[str], str]) -> None:
    """Dropping one finding shows exactly that rule as fixed, not the rest."""

    dirty = _run(config_text("cisco_bad.conf"), "cisco")
    trimmed = [f for f in dirty if f.rule_id != "CS-001"]
    added, fixed = engine.diff(dirty, trimmed)
    assert added == []
    assert [f.rule_id for f in fixed] == ["CS-001"]


def test_diff_identical_configs_is_empty(config_text: Callable[[str], str]) -> None:
    findings = _run(config_text("cisco_bad.conf"), "cisco")
    assert engine.diff(findings, findings) == ([], [])
