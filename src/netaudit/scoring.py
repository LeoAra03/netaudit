"""Deterministic 0-100 scoring so results stay comparable over time."""

from __future__ import annotations

from collections.abc import Iterable

from .models import WEIGHTS, Finding

_GRADES = ((90, "A"), (80, "B"), (70, "C"), (60, "D"), (50, "E"))


def score(findings: Iterable[Finding]) -> int:
    """100 minus the summed severity weight, floored at zero."""

    penalty = sum(WEIGHTS[f.severity] for f in findings)
    return max(0, 100 - penalty)


def grade(value: int) -> str:
    for threshold, letter in _GRADES:
        if value >= threshold:
            return letter
    return "F"
