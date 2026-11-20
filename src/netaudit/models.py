"""Domain models.

Statements are the only thing parsers emit and the only thing rules match
against. That keeps vendor handling and rule authoring fully decoupled: a new
vendor means a new parser, a new check means a new line of YAML.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from enum import IntEnum


class Severity(IntEnum):
    """Ordered severity, so findings sort by weight."""

    INFO = 0
    LOW = 1
    MEDIUM = 2
    HIGH = 3
    CRITICAL = 4

    @classmethod
    def parse(cls, raw: str) -> Severity:
        try:
            return cls[raw.strip().upper()]
        except KeyError as exc:
            raise ValueError(f"unknown severity: {raw!r}") from exc


WEIGHTS: dict[Severity, int] = {
    Severity.INFO: 1,
    Severity.LOW: 2,
    Severity.MEDIUM: 5,
    Severity.HIGH: 10,
    Severity.CRITICAL: 20,
}


@dataclass(frozen=True)
class Statement:
    """One normalized config line, flattened as ``path|key=value``."""

    path: tuple[str, ...]
    key: str
    value: str

    @property
    def flat(self) -> str:
        return f"{'.'.join(self.path)}|{self.key}={self.value}"

    @property
    def evidence(self) -> str:
        return self.flat


@dataclass
class DeviceConfig:
    """A parsed configuration, ready to be evaluated."""

    vendor: str
    statements: list[Statement] = field(default_factory=list)


@dataclass(frozen=True)
class Rule:
    """One declarative check, loaded from a rulepack."""

    id: str
    title: str
    severity: Severity
    match: str
    expect: str
    remediation: str
    reference: str = ""
    scope: tuple[str, ...] = ()


@dataclass(frozen=True)
class Finding:
    """A violated rule, with the statement that proved it."""

    rule_id: str
    title: str
    severity: Severity
    evidence: str
    remediation: str
    reference: str

    def to_dict(self) -> dict[str, str]:
        return {
            "rule_id": self.rule_id,
            "title": self.title,
            "severity": self.severity.name,
            "evidence": self.evidence,
            "remediation": self.remediation,
            "reference": self.reference,
        }
