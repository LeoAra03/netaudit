"""Markdown and SARIF renderers."""

from __future__ import annotations

import hashlib
import json
from collections.abc import Iterable
from typing import Any

from .models import Finding

_SARIF_LEVEL = {"CRITICAL": "error", "HIGH": "error", "MEDIUM": "warning"}
_SARIF_RANK = {"CRITICAL": 4, "HIGH": 3, "MEDIUM": 2, "LOW": 1, "INFO": 0}
_URI_BASE_ID = "%SRCROOT%"


def markdown(
    filename: str, vendor: str, score: int, grade: str, findings: Iterable[Finding]
) -> str:
    items = list(findings)
    lines = [
        f"# NetAudit report - `{filename}`",
        "",
        f"- Vendor: **{vendor}**",
        f"- Score: **{score}/100** (grade **{grade}**)",
        f"- Findings: **{len(items)}**",
        "",
    ]
    if not items:
        lines.append("No violations against the selected rulepack.")
    for finding in items:
        lines += [
            f"## [{finding.severity.name}] {finding.rule_id} - {finding.title}",
            "",
            f"- Evidence: `{finding.evidence}`",
            f"- Remediation: {finding.remediation}",
            f"- Reference: {finding.reference}",
            "",
        ]
    return "\n".join(lines)


def _rule(rule_id: str, title: str, severity: str, remediation: str) -> dict[str, Any]:
    return {
        "id": rule_id,
        "name": title.replace(" ", ""),
        "shortDescription": {"text": title},
        "fullDescription": {"text": f"{title} ({severity})"},
        "help": {"text": remediation},
        "helpUri": "https://github.com/LeoAra03/netaudit#rules",
        "defaultConfiguration": {"level": _SARIF_LEVEL.get(severity, "note")},
        "properties": {
            "tags": ["security", "network", severity.lower()],
            "precision": "medium",
        },
    }


def sarif(filename: str, findings: Iterable[Finding]) -> str:
    """SARIF 2.1.0 shaped for GitHub code scanning.

    Every result carries a ``ruleIndex`` into ``tool.driver.rules`` so the
    document resolves; rules are emitted once each even when several findings
    share one. The fix lives in ``message.text`` and the rule ``help`` because
    the spec has no ``remediation`` property on a result.
    """

    items = sorted(findings, key=lambda f: _SARIF_RANK.get(f.severity.name, 0), reverse=True)
    uri = filename.replace("\\", "/").lstrip("/")

    index: dict[str, int] = {}
    rules: list[dict[str, Any]] = []
    for finding in items:
        if finding.rule_id in index:
            continue
        index[finding.rule_id] = len(rules)
        rules.append(
            _rule(finding.rule_id, finding.title, finding.severity.name, finding.remediation)
        )

    results: list[dict[str, Any]] = []
    for finding in items:
        digest = hashlib.sha256(f"{finding.rule_id}|{uri}|{finding.evidence}".encode()).hexdigest()[
            :40
        ]
        results.append(
            {
                "ruleId": finding.rule_id,
                "ruleIndex": index[finding.rule_id],
                "level": _SARIF_LEVEL.get(finding.severity.name, "note"),
                "message": {"text": f"{finding.title}. {finding.remediation}"},
                "locations": [
                    {
                        "physicalLocation": {
                            "artifactLocation": {"uri": uri, "uriBaseId": _URI_BASE_ID},
                            "region": {"startLine": 1, "startColumn": 1},
                        }
                    }
                ],
                "partialFingerprints": {"netaudit/v1": digest},
            }
        )

    document = {
        "$schema": "https://json.schemastore.org/sarif-2.1.0.json",
        "version": "2.1.0",
        "runs": [
            {
                "tool": {
                    "driver": {
                        "name": "netaudit",
                        "informationUri": "https://github.com/LeoAra03/netaudit",
                        "version": "0.1.0",
                        "rules": rules,
                    }
                },
                "originalUriBaseIds": {_URI_BASE_ID: {"uri": "file:///"}},
                "results": results,
            }
        ],
    }
    return json.dumps(document, indent=2)
