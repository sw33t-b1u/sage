"""SQLite connection setup and schema initialization.

Mirrors sage.spanner.client. ``get_connection`` returns a configured
``sqlite3.Connection``; ``init_schema`` applies schema/sqlite_ddl.sql
idempotently (the DDL uses ``CREATE TABLE IF NOT EXISTS``).

Single-writer model: the ETL job opens a read-write connection (WAL
journal) and is the only writer; the Analysis API opens read-only
connections (``mode=ro``). This matches the existing operational model
where Spanner writes came exclusively from the ETL path.
"""

from __future__ import annotations

import sqlite3
from pathlib import Path

# schema/sqlite_ddl.sql lives at the repo root: src/sage/sqlite/client.py
# -> parents[3] == repo root.
DDL_PATH = Path(__file__).parents[3] / "schema" / "sqlite_ddl.sql"


def get_connection(path: str | Path, *, read_only: bool = False) -> sqlite3.Connection:
    """Return a configured SQLite connection.

    Args:
        path: Filesystem path to the SQLite database file.
        read_only: When True, open via the ``file:...?mode=ro`` URI so the
            connection cannot mutate the database (used by the Analysis
            API). When False, open read-write and enable WAL journaling
            for the single ETL writer.

    The connection uses ``sqlite3.Row`` as ``row_factory`` (column access
    by name) and turns foreign-key enforcement on. ``detect_types`` is
    left at 0 — timestamps are stored and read as ISO 8601 TEXT, matching
    the Spanner backend's string handling.
    """
    if read_only:
        uri = f"file:{Path(path)}?mode=ro"
        conn = sqlite3.connect(uri, uri=True, detect_types=0)
    else:
        conn = sqlite3.connect(str(path), detect_types=0)

    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA foreign_keys = ON")
    if not read_only:
        conn.execute("PRAGMA journal_mode = WAL")
    return conn


def init_schema(conn: sqlite3.Connection) -> None:
    """Apply schema/sqlite_ddl.sql to *conn* (idempotent).

    The DDL uses ``CREATE TABLE IF NOT EXISTS`` so re-running against an
    existing database is a no-op for already-present tables.
    """
    ddl_text = DDL_PATH.read_text(encoding="utf-8")
    conn.executescript(ddl_text)
    conn.commit()
