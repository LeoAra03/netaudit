"""Shared test setup."""

from __future__ import annotations

from collections.abc import Callable
from pathlib import Path

import pytest

FIXTURES = Path(__file__).parent / "fixtures"


@pytest.fixture()
def fixtures_dir() -> Path:
    return FIXTURES


@pytest.fixture()
def config_text() -> Callable[[str], str]:
    """Read one of the sample configs by file name."""

    def load(name: str) -> str:
        return (FIXTURES / name).read_text(encoding="utf-8")

    return load
