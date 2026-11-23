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
from .models import Finding, Rule
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
    scan.add_argument(
        "--explain",
        action="store_true",
        help="show the path|key=value evidence that triggered each finding",
    )

    diff = sub.add_parser("diff", help="gate on findings newly introduced between snapshots")
    diff.add_argument("before", type=Path, help="older snapshot")
    diff.add_argument("after", type=Path, help="newer snapshot")
    diff.add_argument("--rulepack", default="auto", choices=["auto", "fortigate", "cisco"])
    diff.add_argument("--format", choices=["table", "json"], default="table")
    return root


def _audit(path: Path, rulepack: str = "auto") -> tuple[str, list[Finding], list[Rule]]:
    raw = path.read_text(encoding="utf-8", errors="replace")
    vendor = parser.detect_vendor(raw)
    if vendor == "unknown":
        raise ValueError("vendor could not be detected")
    selected_pack = vendor if rulepack == "auto" else rulepack
    config = parser.parse(raw, vendor)
    rules = load_rulepack(selected_pack)
    return vendor, engine.evaluate(config, rules), rules


def _rule_line(pack_name: str, rule_id: str, field: str) -> int | None:
    """Find a rule field's source line for actionable --explain output."""

    rulepack_path = Path(__file__).parent / "rulepacks" / f"{pack_name}.yaml"
    lines = rulepack_path.read_text(encoding="utf-8").splitlines()
    in_rule = False
    for number, line in enumerate(lines, start=1):
        stripped = line.strip()
        if stripped == f"- id: {rule_id}":
            if field == "id":
                return number
            in_rule = True
            continue
        if in_rule and stripped.startswith("- id:"):
            break
        if in_rule and stripped.startswith(f"{field}:"):
            return number
    return None


def _scan(args: argparse.Namespace) -> int:
    try:
        vendor, findings, rules = _audit(args.path, args.rulepack)
    except OSError as exc:
        print(f"error: cannot read {args.path}: {exc}", file=sys.stderr)
        return 2
    except ValueError as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 2
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
            if args.explain:
                pack_name = vendor if args.rulepack == "auto" else args.rulepack
                rule = next(rule for rule in rules if rule.id == finding.rule_id)
                pack_file = f"src/netaudit/rulepacks/{pack_name}.yaml"
                id_line = _rule_line(pack_name, finding.rule_id, "id")
                match_line = _rule_line(pack_name, finding.rule_id, "match")
                print(f"      evidence: {finding.evidence}")
                print(f"      rulepack: {pack_file}:{id_line or '?'} ({finding.rule_id})")
                print(f"      match: {rule.match}  [line {match_line or '?'}]")
                print(f"      scope: {', '.join(rule.scope) or '*'}; expect: {rule.expect}")
        if not findings:
            print("  no violations against the selected rulepack")

    if args.fail_under is not None and value < args.fail_under:
        print(f"error: score {value} below threshold {args.fail_under}", file=sys.stderr)
        return 1
    return 0


def _diff(args: argparse.Namespace) -> int:
    try:
        before_vendor, before_findings, _ = _audit(args.before, args.rulepack)
        after_vendor, after_findings, _ = _audit(args.after, args.rulepack)
    except OSError as exc:
        print(f"error: cannot read snapshot: {exc}", file=sys.stderr)
        return 2
    except ValueError as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 2
    except RulepackError as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 2

    if before_vendor != after_vendor:
        print(
            f"error: snapshots use different vendors ({before_vendor} vs {after_vendor})",
            file=sys.stderr,
        )
        return 2

    old_ids = {finding.rule_id for finding in before_findings}
    new_findings = [finding for finding in after_findings if finding.rule_id not in old_ids]
    result = [finding.to_dict() for finding in new_findings]
    if args.format == "json":
        print(json.dumps(result, indent=2))
    elif new_findings:
        for finding in new_findings:
            print(f"[{finding.severity.name}] {finding.rule_id} {finding.title}")
            print(f"  evidence: {finding.evidence}")
            print(f"  remediation: {finding.remediation}")
    else:
        print("No newly introduced findings.")
    return 1 if new_findings else 0


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    if args.command == "diff":
        return _diff(args)
    return _scan(args)


if __name__ == "__main__":
    raise SystemExit(main())
