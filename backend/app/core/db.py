from __future__ import annotations

import json
import sqlite3
import threading
from functools import lru_cache
from pathlib import Path
from typing import Any

from app.core.config import settings

# Every table has the same shape: a JSON blob (the Pydantic model, serialized
# with `model_dump(mode="json")`) plus a `parent_id` column for the one filter
# each API actually needs (issues/reports by task_id, tasks by project_id).
# This keeps the storage layer generic instead of hand-rolling a table per
# entity, while still giving each entity a real file-backed, crash-safe home
# instead of a process-lifetime dict.
TABLES = ("projects", "review_tasks", "issues", "reports")

_SCHEMA = """
CREATE TABLE IF NOT EXISTS {table} (
    id TEXT PRIMARY KEY,
    parent_id TEXT,
    created_at TEXT NOT NULL,
    data TEXT NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_{table}_parent_id ON {table} (parent_id);
"""


class Database:
    """Minimal JSON-document store over SQLite.

    Not a general-purpose ORM: it exists to give the existing dict-based
    services (`ProjectService`, `ReviewService`, `IssueService`,
    `ReportService`) durable, restart-safe storage with the smallest possible
    change to their call sites. `table` is always an internal constant chosen
    by our own code (never derived from a request), so building the DDL/DML
    strings with an f-string is safe.
    """

    def __init__(self, path: Path) -> None:
        self._lock = threading.Lock()
        path.parent.mkdir(parents=True, exist_ok=True)
        self._conn = sqlite3.connect(str(path), check_same_thread=False)
        self._conn.execute("PRAGMA journal_mode=WAL")
        with self._lock:
            for table in TABLES:
                self._conn.executescript(_SCHEMA.format(table=table))
            self._conn.commit()

    def upsert(self, table: str, id_: str, parent_id: str | None, created_at: str, data: dict[str, Any]) -> None:
        assert table in TABLES
        payload = json.dumps(data, ensure_ascii=False, default=str)
        with self._lock:
            self._conn.execute(
                f"""
                INSERT INTO {table} (id, parent_id, created_at, data) VALUES (?, ?, ?, ?)
                ON CONFLICT(id) DO UPDATE SET parent_id = excluded.parent_id, data = excluded.data
                """,
                (id_, parent_id, created_at, payload),
            )
            self._conn.commit()

    def get(self, table: str, id_: str) -> dict[str, Any] | None:
        assert table in TABLES
        with self._lock:
            row = self._conn.execute(f"SELECT data FROM {table} WHERE id = ?", (id_,)).fetchone()
        return json.loads(row[0]) if row else None

    def list(self, table: str, parent_id: str | None = None) -> list[dict[str, Any]]:
        assert table in TABLES
        with self._lock:
            if parent_id is not None:
                rows = self._conn.execute(
                    f"SELECT data FROM {table} WHERE parent_id = ? ORDER BY rowid", (parent_id,)
                ).fetchall()
            else:
                rows = self._conn.execute(f"SELECT data FROM {table} ORDER BY rowid").fetchall()
        return [json.loads(row[0]) for row in rows]

    def replace_children(self, table: str, parent_id: str, rows: list[tuple[str, str, dict[str, Any]]]) -> None:
        """Atomically replace every row under `parent_id` with `rows`."""
        assert table in TABLES
        with self._lock:
            self._conn.execute(f"DELETE FROM {table} WHERE parent_id = ?", (parent_id,))
            self._conn.executemany(
                f"INSERT INTO {table} (id, parent_id, created_at, data) VALUES (?, ?, ?, ?)",
                [
                    (id_, parent_id, created_at, json.dumps(data, ensure_ascii=False, default=str))
                    for id_, created_at, data in rows
                ],
            )
            self._conn.commit()


@lru_cache
def get_db() -> Database:
    return Database(settings.database_path)
