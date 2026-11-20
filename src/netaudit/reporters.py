"""Markdown and SARIF renderers."""

from __future__ import annotations

import hashlib
import json
from collections.abc import Iterable
from pathlib import Path
from urllib.parse import quote

from . import __version__
from .models import Finding

_SARIF_LEVEL = {"CRITICAL": "error", "HIGH": "error", "MEDIUM": "warning"}

# GitHub reads "security-severity" to bucket a rule, and ignores the SARIF level
# for that; the numbers are the CVSS-style bands its docs use.
_SECURITY_SEVERITY = {
    "CRITICAL": "9.5",
    "HIGH": "8.0",
    "MEDIUM": "5.5",
    "LOW": "3.0",
    "INFO": "0.0",
}


def _code(text: str) -> str:
    """A Markdown code span that survives backticks inside the evidence."""

    fence = "``" if "`" in text else "`"
    return f"{fence}{text}{fence}"


def _artifact_uri(filename: str) -> str:
    """A URI a code-scanning upload can actually resolve.

    ``artifactLocation.uri`` is an RFC 3986 reference, not a filesystem path: a
    space in the name (or a Windows drive letter) makes the document invalid,
    and an absolute path is meaningless to the repository the results land in.
    Report paths relative to the working directory when they are inside it, and
    fall back to a ``file:`` URI otherwise.
    """

    path = Path(filename)
    try:
        relative = path.resolve().relative_to(Path.cwd().resolve())
    except ValueError:
        return path.expanduser().resolve().as_uri()
    return quote(relative.as_posix(), safe="/")


def markdown(
    filename: str, vendor: str, score: int, grade: str, findings: Iterable[Finding]
) -> str:
    items = list(findings)
    lines = [
        f"# NetAudit report - {_code(filename)}",
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
            f"- Evidence: {_code(finding.evidence)}",
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
    uri = _artifact_uri(filename)
    rules: list[dict[str, object]] = []
    rule_index: dict[str, int] = {}
    for finding in items:
        if finding.rule_id in rule_index:
            continue
        rule_index[finding.rule_id] = len(rules)
        rules.append(
            {
                "id": finding.rule_id,
                "shortDescription": {"text": finding.title},
                "fullDescription": {"text": f"{finding.title} ({finding.severity.name})"},
                "help": {"text": finding.remediation},
                "defaultConfiguration": {"level": _SARIF_LEVEL.get(finding.severity.name, "note")},
                "properties": {
                    "tags": ["netaudit", finding.severity.name.lower()],
                    "precision": "medium",
                    "security-severity": _SECURITY_SEVERITY.get(finding.severity.name, "0.0"),
                },
            }
        )
    results = []
    for finding in items:
        fingerprint = hashlib.sha256(
            f"{finding.rule_id}|{uri}|{finding.evidence}".encode()
        ).hexdigest()[:40]
        results.append(
            {
                "ruleId": finding.rule_id,
                "ruleIndex": rule_index[finding.rule_id],
                "level": _SARIF_LEVEL.get(finding.severity.name, "note"),
                "message": {"text": f"{finding.title}. {finding.remediation}"},
                "locations": [{"physicalLocation": {"artifactLocation": {"uri": uri}}}],
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
                        "version": __version__,
                        "rules": rules,
                    }
                },
                "results": results,
            }
        ],
    }
    return json.dumps(document, indent=2)
