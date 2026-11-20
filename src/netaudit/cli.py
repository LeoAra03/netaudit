"""Command line entrypoint, usable as a CI gate.

``netaudit scan device.conf --fail-under 80`` exits 1 below the threshold, so a
pipeline can block a config push without parsing the report.
"""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

from . import __version__, engine, parser, reporters, scoring
from .models import Rule
from .rulepacks import RulepackError, available_packs, load_rulepack


def _percent(raw: str) -> int:
    """``--fail-under`` is a score, so anything outside 0-100 is a typo.

    ``--fail-under 150`` used to fail every scan and ``--fail-under -1`` never
    fail one, both silently.
    """

    try:
        value = int(raw)
    except ValueError:
        raise argparse.ArgumentTypeError(f"not a score: {raw!r}") from None
    if not 0 <= value <= 100:
        raise argparse.ArgumentTypeError(f"score must be 0-100, got {value}")
    return value


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
    scan.add_argument(
        "--fail-under", type=_percent, default=None, metavar="N", help="exit 1 below N (0-100)"
    )
    scan.add_argument(
        "--per-object",
        action="store_true",
        help="report once per object instead of once per rule",
    )

    rules = sub.add_parser("rules", help="list the checks a rulepack runs")
    rules.add_argument("--pack", default="auto", choices=["auto", "fortigate", "cisco"])
    rules.add_argument("--format", default="table", choices=["table", "json"], help="output shape")
    return root


def _rules_table(rows: list[tuple[str, Rule]]) -> str:
    header = ("pack", "id", "severity", "expect", "scope", "title")
    body = [
        (
            pack,
            rule.id,
            rule.severity.name,
            rule.expect,
            ",".join(rule.scope) or "-",
            rule.title,
        )
        for pack, rule in rows
    ]
    widths = [max(len(str(cell)) for cell in column) for column in zip(header, *body, strict=True)]
    lines = ["  ".join(cell.ljust(width) for cell, width in zip(header, widths, strict=True))]
    lines += [
        "  ".join(str(cell).ljust(width) for cell, width in zip(row, widths, strict=True))
        for row in body
    ]
    return "\n".join(lines)


def _rule_dict(rule: Rule) -> dict[str, object]:
    return {
        "id": rule.id,
        "title": rule.title,
        "severity": rule.severity.name,
        "expect": rule.expect,
        "scope": list(rule.scope),
        "reference": rule.reference,
    }


def _cmd_rules(args: argparse.Namespace) -> int:
    packs = available_packs() if args.pack == "auto" else [args.pack]
    try:
        loaded = {pack: load_rulepack(pack) for pack in packs}
    except RulepackError as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 2

    if args.format == "json":
        payload = {
            "packs": [
                {"name": pack, "rules": [_rule_dict(rule) for rule in rules]}
                for pack, rules in loaded.items()
            ]
        }
        print(json.dumps(payload, indent=2))
    else:
        print(_rules_table([(pack, rule) for pack, rules in loaded.items() for rule in rules]))
    return 0


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    if args.command == "rules":
        return _cmd_rules(args)

    try:
        raw = args.path.read_text(encoding="utf-8", errors="replace")
    except OSError as exc:
        print(f"error: cannot read {args.path}: {exc}", file=sys.stderr)
        return 2

    vendor = parser.detect_vendor(raw)
    if vendor == "unknown":
        print("error: vendor could not be detected", file=sys.stderr)
        return 2

    pack = vendor if args.rulepack == "auto" else args.rulepack
    if pack != vendor:
        # The HTTP surface refuses this too: the other vendor's pack finds none
        # of its own markers and reports every "expect: present" rule as missing,
        # which reads as a failed audit of a device it never looked at.
        print(
            f"error: rulepack {pack!r} does not match detected vendor {vendor!r}",
            file=sys.stderr,
        )
        return 2
    try:
        config = parser.parse(raw, vendor)
    except ValueError as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 2

    try:
        findings = engine.evaluate(config, load_rulepack(pack), per_object=args.per_object)
    except RulepackError as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 2

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
            print(f"  [{finding.severity.name:<8}] {finding.rule_id} {finding.title}")
            print(f"             evidence: {finding.evidence}")
        if not findings:
            print("  no violations against the selected rulepack")

    if args.fail_under is not None and value < args.fail_under:
        print(f"error: score {value} below threshold {args.fail_under}", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
