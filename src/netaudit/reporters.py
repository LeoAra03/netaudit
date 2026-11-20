"""Markdown and SARIF renderers."""

from __future__ import annotations

import hashlib
import json
from collections.abc import Iterable

from .models import Finding

_SARIF_LEVEL = {"CRITICAL": "error", "HIGH": "error", "MEDIUM": "warning"}


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


def sarif(filename: str, findings: Iterable[Finding]) -> str:
    """SARIF 2.1.0, shaped for GitHub code scanning.

    The spec has no ``remediation`` property on a result, so the fix goes into
    ``message.text`` and into the rule ``help`` -- see docs/ai-workflow.md.
    """

    items = list(findings)
    rules = {
        f.rule_id: {
            "id": f.rule_id,
            "shortDescription": {"text": f.title},
            "fullDescription": {"text": f"{f.title} ({f.severity.name})"},
            "help": {"text": f.remediation},
            "defaultConfiguration": {"level": _SARIF_LEVEL.get(f.severity.name, "note")},
            "properties": {"tags": ["netaudit", f.severity.name.lower()], "precision": "medium"},
        }
        for f in items
    }
    results = []
    for f in items:
        fingerprint = hashlib.sha256(f"{f.rule_id}|{filename}|{f.evidence}".encode()).hexdigest()[
            :40
        ]
        results.append(
            {
                "ruleId": f.rule_id,
                "level": _SARIF_LEVEL.get(f.severity.name, "note"),
                "message": {"text": f"{f.title}. {f.remediation}"},
                "locations": [
                    {"physicalLocation": {"artifactLocation": {"uri": filename.replace("\\", "/")}}}
                ],
                "partialFingerprints": {"primaryLocationLineHash": fingerprint},
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
                        "rules": list(rules.values()),
                    }
                },
                "results": results,
            }
        ],
    }
    return json.dumps(document, indent=2)
