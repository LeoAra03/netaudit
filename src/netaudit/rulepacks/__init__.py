"""Bundled rulepacks and their validating loader.

Everything that can be checked about a rule is checked here, at load time, so a
typo in YAML fails loudly instead of silently reporting a clean device.
"""

from __future__ import annotations

import re
from pathlib import Path
from typing import Any

import yaml

from ..models import Rule, Severity

RULEPACK_DIR = Path(__file__).parent
VALID_EXPECT = {"present", "absent"}
_REQUIRED = ("id", "title", "severity", "match", "remediation")


class RulepackError(ValueError):
    """Raised when a rulepack is missing or malformed."""


def _as_dict(raw: object, name: str) -> dict[str, Any]:
    if not isinstance(raw, dict):
        raise RulepackError(f"{name}: rule entry is not a mapping: {raw!r}")
    return {str(key): value for key, value in raw.items()}


def _build(raw: dict[str, Any]) -> Rule:
    missing = [field for field in _REQUIRED if field not in raw]
    if missing:
        raise RulepackError(f"rule {raw.get('id', '?')}: missing field(s) {', '.join(missing)}")

    expect = str(raw.get("expect", "absent"))
    if expect not in VALID_EXPECT:
        raise RulepackError(f"{raw['id']}: invalid expect {expect!r}, must be present|absent")

    match = str(raw["match"])
    try:
        re.compile(match)
    except re.error as exc:
        raise RulepackError(f"{raw['id']}: bad pattern {exc}") from exc

    scope = tuple(str(s) for s in raw.get("scope", ()))
    if any(not s.strip() for s in scope):
        raise RulepackError(f"{raw['id']}: empty scope entry")

    try:
        severity = Severity.parse(str(raw["severity"]))
    except ValueError as exc:
        raise RulepackError(f"{raw['id']}: {exc}") from exc

    return Rule(
        id=str(raw["id"]),
        title=str(raw["title"]),
        severity=severity,
        match=match,
        expect=expect,
        remediation=str(raw["remediation"]),
        reference=str(raw.get("reference", "")),
        scope=scope,
    )


def available_packs() -> list[str]:
    """Names of the bundled rulepacks, sorted, without the ``.yaml`` suffix."""

    return sorted(path.stem for path in RULEPACK_DIR.glob("*.yaml"))


def load_rulepack(name: str) -> list[Rule]:
    path = RULEPACK_DIR / f"{name}.yaml"
    if not path.exists():
        raise RulepackError(f"unknown rulepack: {name}")
    data = yaml.safe_load(path.read_text(encoding="utf-8"))
    if not isinstance(data, dict) or not isinstance(data.get("rules"), list):
        raise RulepackError(f"{name}: missing 'rules' list")
    vendor = str(data.get("vendor", name))
    if vendor != name:
        raise RulepackError(f"{name}: vendor {vendor!r} does not match the rulepack name")
    rules = [_build(_as_dict(raw, name)) for raw in data["rules"]]
    seen: set[str] = set()
    for rule in rules:
        if rule.id in seen:
            raise RulepackError(f"{name}: duplicated rule id {rule.id}")
        seen.add(rule.id)
    return rules
