"""Bundled rulepacks and their loader."""

from __future__ import annotations

from pathlib import Path
from typing import Any

import yaml

from ..models import Rule, Severity

RULEPACK_DIR = Path(__file__).parent


class RulepackError(ValueError):
    """Raised when a rulepack is missing."""


def _build(raw: dict[str, Any]) -> Rule:
    return Rule(
        id=str(raw["id"]),
        title=str(raw["title"]),
        severity=Severity.parse(str(raw["severity"])),
        match=str(raw["match"]),
        expect=str(raw.get("expect", "absent")),
        remediation=str(raw["remediation"]),
        reference=str(raw.get("reference", "")),
        scope=tuple(str(s) for s in raw.get("scope", ())),
    )


def load_rulepack(name: str) -> list[Rule]:
    path = RULEPACK_DIR / f"{name}.yaml"
    if not path.exists():
        raise RulepackError(f"unknown rulepack: {name}")
    data = yaml.safe_load(path.read_text(encoding="utf-8"))
    if not isinstance(data, dict) or "rules" not in data:
        raise RulepackError(f"{name}: missing 'rules' key")
    return [_build(raw) for raw in data["rules"]]
