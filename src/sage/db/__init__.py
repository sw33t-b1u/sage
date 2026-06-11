"""sage.db — backend dispatch layer.

Routes database-handle acquisition and file synchronization between the
Spanner backend (``SAGE_DB=spanner``) and the SQLite backend
(``SAGE_DB=sqlite``, default). Callers in cli/etl/api obtain a handle via
``get_database(config)`` and never import a backend package directly.

This module is import-light on purpose: ``google-cloud-spanner`` is only
imported inside the Spanner branch, so a SQLite-only deployment never
loads the Spanner client.

DB file synchronization (Decision D-4):
  * ``materialize_db(config)`` returns a local Path to the SQLite file.
    - local backend: ``<base_dir>/db/sage.db`` (created in place).
    - gcs backend: downloads category ``db`` file ``sage.db`` into a temp
      directory; a missing remote file yields a fresh (non-existent) path
      so init_schema can create it.
  * ``publish_db(config, path)`` uploads the file back.
    - local backend: no-op (the file is already in place).
    - gcs backend: uploads the bytes to category ``db`` / ``sage.db``.
"""

from __future__ import annotations

import sqlite3
import tempfile
from pathlib import Path
from typing import Any

# StorageBackend category and filename for the materialized SQLite database.
_DB_CATEGORY = "db"
_DB_FILENAME = "sage.db"


def get_database(config: Any) -> Any:
    """Return a database handle for the configured backend.

    ``SAGE_DB=spanner`` -> a Spanner ``Database`` (via sage.spanner.client).
    ``SAGE_DB=sqlite``  -> an opened ``sqlite3.Connection`` to the
    materialized DB file. The connection is read-write; API callers that
    need read-only access should open their own connection with
    ``sage.sqlite.client.get_connection(..., read_only=True)``.
    """
    backend = getattr(config, "sage_db", "sqlite")
    if backend == "spanner":
        from sage.spanner.client import get_database as _spanner_get_database

        return _spanner_get_database(
            config.gcp_project_id,
            config.spanner_instance_id,
            config.spanner_database_id,
        )
    if backend == "sqlite":
        from sage.sqlite.client import get_connection

        path = materialize_db(config)
        return get_connection(path)
    raise ValueError(f"Unknown SAGE_DB backend '{backend}'. Valid values: 'sqlite', 'spanner'.")


def materialize_db(config: Any) -> Path:
    """Return a local filesystem Path to the SQLite database file.

    Local backend: ``<sage_storage_base_dir>/db/sage.db`` (parent dirs are
    created; the file itself is left to init_schema / first write).

    GCS backend: downloads the remote ``db/sage.db`` into a fresh temp
    directory and returns its path. If the remote file is absent, returns a
    (non-existent) path inside the temp dir so the caller can init_schema.
    """
    backend = getattr(config, "sage_storage", "local")
    if backend == "local":
        base = Path(getattr(config, "sage_storage_base_dir", "output"))
        db_dir = base / _DB_CATEGORY
        db_dir.mkdir(parents=True, exist_ok=True)
        return db_dir / _DB_FILENAME

    # gcs (or any non-local backend) — download into a temp dir.
    from sage.storage import create_storage_backend

    storage = create_storage_backend(config)
    tmp_dir = Path(tempfile.mkdtemp(prefix="sage-db-"))
    local_path = tmp_dir / _DB_FILENAME
    if storage.exists(_DB_CATEGORY, _DB_FILENAME):
        load_bytes = getattr(storage, "load_bytes", None)
        if load_bytes is not None:
            # Binary-safe path (preferred once StorageBackend grows it).
            local_path.write_bytes(load_bytes(_DB_CATEGORY, _DB_FILENAME))
        else:
            # StorageBackend.load() is text-only (UTF-8 decode). A SQLite
            # file is binary, so this fallback round-trips through latin-1
            # (a lossless byte<->str codec) and only works if load() itself
            # returned latin-1-decoded text. The current GCS/Local backends
            # decode UTF-8 and would fail on real binary data — a binary
            # ``load_bytes`` must land on StorageBackend before gcs mode
            # carries a real database file (tracked for the wiring phase).
            data = storage.load(_DB_CATEGORY, _DB_FILENAME)
            local_path.write_bytes(data.encode("latin-1"))
    return local_path


def publish_db(config: Any, path: str | Path) -> None:
    """Upload the SQLite DB file back to storage (gcs only; local is a no-op)."""
    backend = getattr(config, "sage_storage", "local")
    if backend == "local":
        return

    from sage.storage import create_storage_backend

    storage = create_storage_backend(config)
    data = Path(path).read_bytes()
    storage.save(_DB_CATEGORY, _DB_FILENAME, data)


def is_sqlite(handle: Any) -> bool:
    """Return True if *handle* is a SQLite connection (used to branch in wrappers)."""
    return isinstance(handle, sqlite3.Connection)
