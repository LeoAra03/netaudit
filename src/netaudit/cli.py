"""Command line entrypoint, usable as a CI gate.

``netaudit scan device.conf --fail-under 80`` exits 1 below the threshold, so a
pipeline can block a config push without parsing the report. ``netaudit diff``
exits 1 when the second config adds findings, and ``netaudit explain`` settles
the argument about a rule before anyone edits the threshold instead.
"""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

from . import __version__, engine, parser, reporters, scoring
from .models import EXPOSURE_MULTIPLIERS, Finding
from .rulepacks import RuleNotFoundError, RulepackError, find_rule, load_rulepack

_CONTROL_LABELS = {
    "cis": "CIS Controls v8",
    "nist": "NIST SP 800-41r1",
    "iso": "ISO 27001:2022",
    "azure_waf": "Azure WAF",
}


def build_parser() -> argparse.ArgumentParser:
    root = argparse.ArgumentParser(prog="netaudit", description="Audit network device configs.")
    root.add_argument("--version", action="version", version=f"netaudit {__version__}")
    sub = root.add_subparsers(dest="command", required=True)

    scan = sub.add_parser("scan", help="audit a configuration file")
    scan.add_argument("path", type=Path, help="config file to audit")
    scan.add_argument("--rulepack", default="auto", choices=["auto", "fortigate", "cisco"])
    scan.add_argument(
        "--format",
        default="table",
        choices=["table", "json", "sarif", "markdown"],
        help="output shape (table for humans, sarif for code scanning)",
    )
    scan.add_argument("--fail-under", type=int, default=None, metavar="N", help="exit 1 below N")

    diff = sub.add_parser("diff", help="report new and fixed findings between two configs")
    diff.add_argument("before", type=Path, help="config before the change")
    diff.add_argument("after", type=Path, help="config after the change")

    explain = sub.add_parser("explain", help="show control, rationale and remediation for one rule")
    explain.add_argument("rule_id", help="rule id, e.g. FG-009")
    return root


def _audit(path: Path) -> tuple[str, list[Finding]] | int:
    """Scan one file, or return the exit code that explains why it could not."""

    try:
        raw = path.read_text(encoding="utf-8", errors="replace")
    except OSError as exc:
        print(f"error: cannot read {path}: {exc}", file=sys.stderr)
        return 2

    vendor = parser.detect_vendor(raw)
    if vendor == "unknown":
        print(f"error: vendor could not be detected for {path}", file=sys.stderr)
        return 2

    try:
        config = parser.parse(raw, vendor)
        findings = engine.evaluate(config, load_rulepack(vendor))
    except RulepackError as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 3
    except ValueError as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 2
    return vendor, findings


def _scan(args: argparse.Namespace) -> int:
    loaded = _audit(args.path)
    if isinstance(loaded, int):
        return loaded
    vendor, findings = loaded

    value = scoring.score(findings)
    letter = scoring.grade(value)

    if args.format == "json":
        print(
            json.dumps(
                {
                    "file": str(args.path),
                    "vendor": vendor,
                    "score": value,
                    "grade": letter,
                    "findings": [f.to_dict() for f in findings],
                },
                indent=2,
            )
        )
    elif args.format == "sarif":
        print(reporters.sarif(str(args.path), findings))
    elif args.format == "markdown":
        print(reporters.markdown(args.path.name, vendor, value, letter, findings))
    else:
        print(f"{args.path}  vendor={vendor}  score={value}  grade={letter}")
        for finding in findings:
            multiplier = EXPOSURE_MULTIPLIERS[finding.exposure]
            print(
                f"  [{finding.severity.name:<8}] {finding.rule_id} {finding.title}"
                f" ({finding.exposure.value} x{multiplier})"
            )
        if not findings:
            print("  no violations against the selected rulepack")

    if args.fail_under is not None and value < args.fail_under:
        print(f"error: score {value} below threshold {args.fail_under}", file=sys.stderr)
        return 1
    return 0


def _diff(before_path: Path, after_path: Path) -> int:
    before = _audit(before_path)
    if isinstance(before, int):
        return before
    after = _audit(after_path)
    if isinstance(after, int):
        return after

    added, fixed = engine.diff(before[1], after[1])
    old_score = scoring.score(before[1])
    new_score = scoring.score(after[1])
    print(
        f"{before_path} -> {after_path}  score {old_score} -> {new_score}"
        f"  new: {len(added)}  fixed: {len(fixed)}"
    )
    for finding in added:
        print(f"  new    [{finding.severity.name:<8}] {finding.rule_id} {finding.title}")
    for finding in fixed:
        print(f"  fixed  [{finding.severity.name:<8}] {finding.rule_id} {finding.title}")
    if not added and not fixed:
        print("  no change in findings")
    return 1 if added else 0


def _explain(rule_id: str) -> int:
    try:
        rule = find_rule(rule_id)
    except RuleNotFoundError as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 2
    except RulepackError as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 3

    multiplier = EXPOSURE_MULTIPLIERS[rule.exposure]
    controls = " · ".join(
        f"{_CONTROL_LABELS.get(key, key)}: {value}" for key, value in rule.controls.items()
    )
    print(f"{rule.id} — {rule.title}")
    print(f"severity:    {rule.severity.name.lower()}")
    print(f"exposure:    {rule.exposure.value} (x{multiplier})")
    print(f"controls:    {controls or 'none recorded'}")
    print(f"rationale:   {rule.rationale or 'none recorded'}")
    print(f"remediation: {rule.remediation}")
    print(f"reference:   {rule.reference or 'none'}")
    return 0


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)

    if args.command == "explain":
        return _explain(args.rule_id)
    if args.command == "diff":
        return _diff(args.before, args.after)
    return _scan(args)


if __name__ == "__main__":
    raise SystemExit(main())
