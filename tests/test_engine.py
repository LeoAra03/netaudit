"""Rule matching against statements, with hand-built rules."""

from __future__ import annotations

from netaudit import engine, parser
from netaudit.models import Rule, Severity


def _rule(**kwargs) -> Rule:
    base = {
        "id": "T-001",
        "title": "test rule",
        "severity": Severity.MEDIUM,
        "match": r"^system\.global\|admin-telnet=enable",
        "expect": "absent",
        "remediation": "set admin-telnet disable",
    }
    base.update(kwargs)
    return Rule(**base)


def _statements(raw: str, vendor: str = "fortigate"):
    return parser.parse(raw, vendor).statements


def test_absent_rule_fires_on_a_hit() -> None:
    config = parser.parse("config system global\n    set admin-telnet enable\nend\n")
    findings = engine.evaluate(config, [_rule()])
    assert [f.rule_id for f in findings] == ["T-001"]
    assert findings[0].evidence == "system.global|admin-telnet=enable"


def test_absent_rule_is_quiet_without_a_hit() -> None:
    config = parser.parse("config system global\n    set admin-telnet disable\nend\n")
    assert engine.evaluate(config, [_rule()]) == []


def test_present_rule_fires_when_nothing_matches() -> None:
    config = parser.parse("config system global\n    set hostname fw\nend\n")
    findings = engine.evaluate(config, [_rule(expect="present", match=r"password-policy")])
    assert findings[0].evidence == "statement not found"


def test_scope_decides_applicability() -> None:
    """A rule scoped to a block the config never has is not-applicable."""

    config = parser.parse("config firewall policy\n    edit 1\n        set srcaddr all\nend\n")
    scoped = _rule(scope=("system.global",), match=r"admin-telnet")
    assert engine.evaluate(config, [scoped]) == []


def test_findings_sorted_by_severity() -> None:
    config = parser.parse("config system global\n    set admin-telnet enable\nend\n")
    rules = [
        _rule(id="LOW-001", severity=Severity.LOW),
        _rule(id="HIGH-001", severity=Severity.HIGH),
        _rule(id="MED-001", severity=Severity.MEDIUM),
    ]
    severities = [f.severity for f in engine.evaluate(config, rules)]
    assert severities == sorted(severities, reverse=True)


def test_evidence_is_truncated() -> None:
    long_value = "x" * 400
    config = parser.parse(f"config system global\n    set admin-telnet {long_value}\nend\n")
    finding = engine.evaluate(config, [_rule(match=r"admin-telnet")])[0]
    assert len(finding.evidence) <= 160


def test_statements_are_built() -> None:
    assert _statements("config system global\nend\n")[0].key == "config"
