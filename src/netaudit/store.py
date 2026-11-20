"""SQLite persistence: one row per scan, findings stored as JSON.

The database path is resolved on every call from ``NETAUDIT_DB`` so a test can
point at a throwaway file without reloading the module. Single writer, single
uvicorn worker -- see docs/adr/0002-sqlite-persistence.md.
"""

from __future__ import annotations

import json
import os
import sqlite3
import uuid
from collections.abc import Iterator
from contextlib import closing, contextmanager
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

_SCHEMA = """
CREATE TABLE IF NOT EXISTS scans (
    id TEXT PRIMARY KEY,
    filename TEXT NOT NULL,
    vendor TEXT NOT NULL,
    score INTEGER NOT NULL,
    grade TEXT NOT NULL,
    findings TEXT NOT NULL,
    created_at TEXT NOT NULL
);
"""


def db_path() -> Path:
    return Path(os.environ.get("NETAUDIT_DB", "netaudit.db"))


@contextmanager
def _connect() -> Iterator[sqlite3.Connection]:
    path = db_path()
    path.parent.mkdir(parents=True, exist_ok=True)
    with closing(sqlite3.connect(path)) as conn:
        conn.row_factory = sqlite3.Row
        try:
            yield conn
            conn.commit()
        except Exception:
            conn.rollback()
            raise


def init_db() -> None:
    with _connect() as conn:
        conn.executescript(_SCHEMA)


def save_scan(record: dict[str, Any]) -> str:
    scan_id = uuid.uuid4().hex[:12]
    with _connect() as conn:
        conn.execute(
            "INSERT INTO scans (id, filename, vendor, score, grade, findings, created_at)"
            " VALUES (?, ?, ?, ?, ?, ?, ?)",
            (
                scan_id,
                record["filename"],
                record["vendor"],
                record["score"],
                record["grade"],
                json.dumps(record["findings"]),
                datetime.now(UTC).isoformat(timespec="seconds"),
            ),
        )
    return scan_id


def get_scan(scan_id: str) -> dict[str, Any] | None:
    with _connect() as conn:
        row = conn.execute("SELECT * FROM scans WHERE id = ?", (scan_id,)).fetchone()
    if row is None:
        return None
    record = dict(row)
    record["findings"] = json.loads(record["findings"])
    return record


def recent(limit: int = 10) -> list[dict[str, Any]]:
    with _connect() as conn:
        rows = conn.execute(
            "SELECT id, filename, vendor, score, grade, created_at FROM scans"
            " ORDER BY created_at DESC, rowid DESC LIMIT ?",
            (limit,),
        ).fetchall()
    return [dict(row) for row in rows]
