"""Deterministic 0-100 scoring so results stay comparable over time."""

from __future__ import annotations

from collections.abc import Iterable

from .models import EXPOSURE_MULTIPLIERS, WEIGHTS, Finding

_GRADES = ((90, "A"), (80, "B"), (70, "C"), (60, "D"), (50, "E"))


def score(findings: Iterable[Finding]) -> int:
    """100 minus the summed severity weight times the exposure multiplier.

    ``max(0, 100 - sum(severity_weight * exposure_multiplier))``, truncated to
    an integer so two runs of the same config always print the same number.
    """

    penalty = sum(WEIGHTS[f.severity] * EXPOSURE_MULTIPLIERS[f.exposure] for f in findings)
    return max(0, int(100 - penalty))


def grade(value: int) -> str:
    for threshold, letter in _GRADES:
        if value >= threshold:
            return letter
    return "F"
