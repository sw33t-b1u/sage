"""Tests for the sage.db dispatch layer and the SAGE_DB config switch.

Covers backend routing (sqlite vs spanner), materialize_db for both local
and gcs storage backends (gcs is mocked — no real GCS access), publish_db
no-op for local, the is_sqlite helper, and Config.from_env validation of
SAGE_DB (default / normalization / rejection of unknown values).
"""

from __future__ import annotations

import sqlite3
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import MagicMock, patch

import pytest

from sage import db
from sage.config import Config


def _local_config(tmp_path, sage_db="sqlite"):
    return SimpleNamespace(
        sage_db=sage_db,
        sage_storage="local",
        sage_storage_base_dir=str(tmp_path),
    )


# ---------------------------------------------------------------------------
# get_database routing
# ---------------------------------------------------------------------------


def test_get_database_sqlite_returns_connection(tmp_path):
    config = _local_config(tmp_path)
    handle = db.get_database(config)
    try:
        assert isinstance(handle, sqlite3.Connection)
        assert db.is_sqlite(handle) is True
    finally:
        handle.close()


def test_get_database_spanner_dispatches_to_spanner_client(tmp_path):
    config = SimpleNamespace(
        sage_db="spanner",
        gcp_project_id="proj",
        spanner_instance_id="inst",
        spanner_database_id="dbid",
    )
    sentinel = object()
    with patch("sage.spanner.client.get_database", return_value=sentinel) as mock_get:
        handle = db.get_database(config)
    assert handle is sentinel
    mock_get.assert_called_once_with("proj", "inst", "dbid")
    assert db.is_sqlite(handle) is False


def test_get_database_unknown_backend_raises(tmp_path):
    # RuntimeError unifies with Config.from_env's invalid-SAGE_DB error.
    config = SimpleNamespace(sage_db="postgres")
    with pytest.raises(RuntimeError, match="Unknown SAGE_DB backend"):
        db.get_database(config)


# ---------------------------------------------------------------------------
# materialize_db
# ---------------------------------------------------------------------------


def test_materialize_db_local_creates_db_dir(tmp_path):
    config = _local_config(tmp_path)
    path = db.materialize_db(config)
    assert path == Path(str(tmp_path)) / "db" / "sage.db"
    # The db/ directory is created (the file itself is left to init_schema).
    assert path.parent.is_dir()


def test_materialize_db_gcs_downloads_when_present():
    config = SimpleNamespace(sage_storage="gcs", sage_storage_bucket="b")
    storage = MagicMock()
    storage.exists.return_value = True
    # Binary-safe load_bytes is preferred when the backend provides it.
    storage.load_bytes.return_value = b"sqlite-bytes"
    with patch("sage.storage.create_storage_backend", return_value=storage):
        path = db.materialize_db(config)
    assert path.name == "sage.db"
    assert path.read_bytes() == b"sqlite-bytes"
    storage.exists.assert_called_once_with("db", "sage.db")
    storage.load.assert_not_called()


def test_materialize_db_gcs_requires_load_bytes():
    """The text (latin-1) fallback is gone — a backend without load_bytes
    fails loudly instead of risking a corrupted binary database file.
    """
    config = SimpleNamespace(sage_storage="gcs", sage_storage_bucket="b")
    # Restrict the mock surface to the pre-load_bytes interface.
    storage = MagicMock(spec=["save", "load", "list_files", "exists"])
    storage.exists.return_value = True
    with patch("sage.storage.create_storage_backend", return_value=storage):
        with pytest.raises(AttributeError, match="load_bytes"):
            db.materialize_db(config)
    storage.load.assert_not_called()


def test_materialize_db_gcs_absent_returns_fresh_path():
    config = SimpleNamespace(sage_storage="gcs", sage_storage_bucket="b")
    storage = MagicMock()
    storage.exists.return_value = False
    with patch("sage.storage.create_storage_backend", return_value=storage):
        path = db.materialize_db(config)
    # Remote file absent -> a non-existent path the caller can init_schema on.
    assert path.name == "sage.db"
    assert not path.exists()
    storage.load.assert_not_called()


# ---------------------------------------------------------------------------
# publish_db
# ---------------------------------------------------------------------------


def test_publish_db_local_is_noop(tmp_path):
    config = _local_config(tmp_path)
    db_file = tmp_path / "sage.db"
    db_file.write_bytes(b"x")
    # No storage backend is constructed for local mode.
    with patch("sage.storage.create_storage_backend") as mock_factory:
        db.publish_db(config, db_file)
    mock_factory.assert_not_called()


def test_publish_db_gcs_uploads(tmp_path):
    config = SimpleNamespace(sage_storage="gcs", sage_storage_bucket="b")
    db_file = tmp_path / "sage.db"
    db_file.write_bytes(b"sqlite-bytes")
    storage = MagicMock()
    with patch("sage.storage.create_storage_backend", return_value=storage):
        db.publish_db(config, db_file)
    storage.save.assert_called_once_with("db", "sage.db", b"sqlite-bytes")


# ---------------------------------------------------------------------------
# Config.from_env SAGE_DB switch
# ---------------------------------------------------------------------------
# The autouse conftest fixture scrubs SAGE_* from the environment, so each
# test sets exactly what it needs via monkeypatch.


def test_config_defaults_to_sqlite_without_gcp_vars():
    # No SAGE_DB and none of the four GCP/Spanner vars set -> sqlite default.
    cfg = Config.from_env()
    assert cfg.sage_db == "sqlite"
    assert cfg.gcp_project_id == ""


def test_config_sage_db_value_is_normalized(monkeypatch):
    monkeypatch.setenv("SAGE_DB", "  SQLite ")
    cfg = Config.from_env()
    assert cfg.sage_db == "sqlite"


def test_config_invalid_sage_db_raises_runtime_error(monkeypatch):
    monkeypatch.setenv("SAGE_DB", "foo")
    with pytest.raises(RuntimeError, match="Invalid SAGE_DB value 'foo'"):
        Config.from_env()


def test_config_spanner_backend_requires_gcp_vars(monkeypatch):
    monkeypatch.setenv("SAGE_DB", "spanner")
    with pytest.raises(RuntimeError, match="Required environment variables not set"):
        Config.from_env()
