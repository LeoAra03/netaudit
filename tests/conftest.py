"""Shared test setup.

Two things matter here. The SQLite file is isolated per test, so a run never
reads rows left by the previous one. And the TestClient is created as a context
manager, otherwise the FastAPI lifespan (which initialises the schema) never
runs -- that bit cost me an hour.
"""

from __future__ import annotations

from collections.abc import Callable, Iterator
from pathlib import Path

import pytest
from fastapi.testclient import TestClient

from netaudit.api import app

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


@pytest.fixture(autouse=True)
def isolated_db(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("NETAUDIT_DB", str(tmp_path / "test.db"))


@pytest.fixture()
def client() -> Iterator[TestClient]:
    with TestClient(app) as test_client:
        yield test_client
