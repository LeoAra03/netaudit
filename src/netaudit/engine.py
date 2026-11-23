"""Rule evaluation over parsed statements."""

from __future__ import annotations

import re
from collections.abc import Iterable
from fnmatch import fnmatch

from .models import DeviceConfig, Finding, Rule

_EVIDENCE_LIMIT = 160


def _in_scope(path: str, scopes: tuple[str, ...]) -> bool:
    if not scopes:
        return True
    return any(fnmatch(path, pattern) for pattern in scopes)


def evaluate(config: DeviceConfig, rules: Iterable[Rule]) -> list[Finding]:
    """Return one Finding per violated rule.

    ``expect: absent`` fires on the first statement matching ``match``;
    ``expect: present`` fires when no scoped statement matches. A rule with a
    scope that matches nothing is not-applicable rather than violated, which is
    what lets one baseline mix vendors safely.
    """

    findings: list[Finding] = []
    for rule in rules:
        compiled = re.compile(rule.match, re.IGNORECASE)
        candidates = [s for s in config.statements if _in_scope(".".join(s.path), rule.scope)]
        if rule.scope and not candidates:
            continue
        hit = next((s for s in candidates if compiled.search(s.flat)), None)
        violated = hit is not None if rule.expect == "absent" else hit is None
        if not violated:
            continue
        findings.append(
            Finding(
                rule_id=rule.id,
                title=rule.title,
                severity=rule.severity,
                evidence=(hit.evidence if hit else "statement not found")[:_EVIDENCE_LIMIT],
                remediation=rule.remediation,
                reference=rule.reference,
                exposure=rule.exposure,
            )
        )
    return sorted(findings, key=lambda f: f.severity, reverse=True)


def diff(
    before: Iterable[Finding], after: Iterable[Finding]
) -> tuple[list[Finding], list[Finding]]:
    """Split two scans into findings the change added and the ones it fixed.

    Keyed by rule id, which is the granularity findings already collapse to:
    ``netaudit diff`` reports new and fixed rules, not per-object churn.
    """

    old_list, new_list = list(before), list(after)
    old_ids = {f.rule_id for f in old_list}
    new_ids = {f.rule_id for f in new_list}
    added = [f for f in new_list if f.rule_id not in old_ids]
    fixed = [f for f in old_list if f.rule_id not in new_ids]
    return added, fixed
