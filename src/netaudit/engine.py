"""Rule evaluation over parsed statements."""

from __future__ import annotations

import re
from collections.abc import Iterable
from fnmatch import fnmatch

from .models import DeviceConfig, Finding, Rule, Statement

_EVIDENCE_LIMIT = 160


def _in_scope(path: str, scopes: tuple[str, ...]) -> bool:
    if not scopes:
        return True
    return any(fnmatch(path, pattern) for pattern in scopes)


def _one_per_object(hits: Iterable[Statement]) -> list[Statement]:
    """Collapse hits so each object -- or block, when there is no object -- counts once.

    Two matching lines on the same interface are one problem with that interface;
    five exposed interfaces are five problems.
    """

    seen: set[tuple[tuple[str, ...], str]] = set()
    unique: list[Statement] = []
    for statement in hits:
        key = (statement.path, statement.object)
        if key in seen:
            continue
        seen.add(key)
        unique.append(statement)
    return unique


def _finding(rule: Rule, evidence: str) -> Finding:
    return Finding(
        rule_id=rule.id,
        title=rule.title,
        severity=rule.severity,
        evidence=evidence[:_EVIDENCE_LIMIT],
        remediation=rule.remediation,
        reference=rule.reference,
    )


def evaluate(
    config: DeviceConfig, rules: Iterable[Rule], per_object: bool = False
) -> list[Finding]:
    """Return Findings for the rules this config violates.

    ``expect: absent`` fires on a statement matching ``match``; ``expect:
    present`` fires when no scoped statement matches. A rule with a scope that
    matches nothing is not-applicable rather than violated, which is what lets
    one baseline mix vendors safely.

    By default a violated rule reports once, with the first statement as its
    evidence. With ``per_object=True`` it reports once per object instead, so a
    config with five exposed interfaces yields five findings and the score
    reflects the blast radius rather than the number of distinct rule ids.
    """

    findings: list[Finding] = []
    for rule in rules:
        compiled = re.compile(rule.match, re.IGNORECASE)
        candidates = [s for s in config.statements if _in_scope(".".join(s.path), rule.scope)]
        if rule.scope and not candidates:
            continue
        hits = [s for s in candidates if compiled.search(s.flat)]
        if rule.expect == "absent":
            selected = _one_per_object(hits) if per_object else hits[:1]
            findings.extend(_finding(rule, hit.evidence) for hit in selected)
        elif not hits:
            findings.append(_finding(rule, "statement not found"))
    return sorted(findings, key=lambda f: f.severity, reverse=True)
