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
from .rulepacks import RulepackError, load_rulepack


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
    return root


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)

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
    try:
        config = parser.parse(raw, vendor)
    except ValueError as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 2

    try:
        findings = engine.evaluate(config, load_rulepack(pack))
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
        if not findings:
            print("  no violations against the selected rulepack")

    if args.fail_under is not None and value < args.fail_under:
        print(f"error: score {value} below threshold {args.fail_under}", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
