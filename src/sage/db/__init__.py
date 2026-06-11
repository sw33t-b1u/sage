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

Read-layer wrappers: every public function of the backend ``query`` /
``incidents`` / ``annotations`` modules has a same-named wrapper here
that dispatches on the handle type (``is_sqlite``). Signatures and
return shapes are identical across backends, so callers in cli/etl/api
only change their import to ``sage.db``.
"""

from __future__ import annotations

import sqlite3
import tempfile
from pathlib import Path
from typing import TYPE_CHECKING, Any

if TYPE_CHECKING:
    from datetime import date

    from pydantic import BaseModel

    from sage.models.annotation import AnnotationType
    from sage.models.incident_request import IncidentRequest

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
    raise RuntimeError(f"Unknown SAGE_DB backend '{backend}'. Valid values: 'sqlite', 'spanner'.")


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


def _query_module(database: Any) -> Any:
    """Return the backend-appropriate query module for *database*."""
    if is_sqlite(database):
        from sage.sqlite import query as impl
    else:
        from sage.spanner import query as impl
    return impl


def _incidents_module(database: Any) -> Any:
    """Return the backend-appropriate incidents module for *database*."""
    if is_sqlite(database):
        from sage.sqlite import incidents as impl
    else:
        from sage.spanner import incidents as impl
    return impl


def _annotations_module(database: Any) -> Any:
    """Return the backend-appropriate annotations module for *database*."""
    if is_sqlite(database):
        from sage.sqlite import annotations as impl
    else:
        from sage.spanner import annotations as impl
    return impl


# ---------------------------------------------------------------------------
# Query wrappers (mirror sage.spanner.query / sage.sqlite.query)
# ---------------------------------------------------------------------------


def find_attack_paths(database: Any, asset_id: str, limit: int = 10) -> list[dict[str, Any]]:
    """Dispatching wrapper for the backend ``find_attack_paths``."""
    return _query_module(database).find_attack_paths(database, asset_id, limit)


def find_actor_ttps(
    database: Any,
    actor_stix_id: str,
    *,
    since: date | None = None,
    until: date | None = None,
) -> list[dict[str, Any]]:
    """Dispatching wrapper for the backend ``find_actor_ttps``."""
    return _query_module(database).find_actor_ttps(
        database, actor_stix_id, since=since, until=until
    )


def find_choke_points(database: Any, top_n: int = 20) -> list[dict[str, Any]]:
    """Dispatching wrapper for the backend ``find_choke_points``."""
    return _query_module(database).find_choke_points(database, top_n)


def find_asset_exposure(
    database: Any,
    *,
    since: date | None = None,
    until: date | None = None,
) -> list[dict[str, Any]]:
    """Dispatching wrapper for the backend ``find_asset_exposure``."""
    return _query_module(database).find_asset_exposure(database, since=since, until=until)


def find_incident_ttps(database: Any, incident_id: str) -> list[str]:
    """Dispatching wrapper for the backend ``find_incident_ttps``."""
    return _query_module(database).find_incident_ttps(database, incident_id)


def find_followedby_edges(database: Any) -> list[dict[str, Any]]:
    """Dispatching wrapper for the backend ``find_followedby_edges``."""
    return _query_module(database).find_followedby_edges(database)


def find_all_incident_ttps(database: Any) -> dict[str, list[str]]:
    """Dispatching wrapper for the backend ``find_all_incident_ttps``."""
    return _query_module(database).find_all_incident_ttps(database)


def load_pirs(database: Any) -> list[dict[str, Any]]:
    """Dispatching wrapper for the backend ``load_pirs``."""
    return _query_module(database).load_pirs(database)


def load_pir_edges(database: Any) -> dict[str, list[dict[str, Any]]]:
    """Dispatching wrapper for the backend ``load_pir_edges``."""
    return _query_module(database).load_pir_edges(database)


def find_actors_by_name(database: Any, name_query: str, limit: int = 20) -> list[dict[str, Any]]:
    """Dispatching wrapper for the backend ``find_actors_by_name``."""
    return _query_module(database).find_actors_by_name(database, name_query, limit)


def find_prioritized_actors_for_asset(
    database: Any,
    asset_id: str,
    *,
    since: date,
    until: date,
    limit: int,
) -> list[dict[str, Any]]:
    """Dispatching wrapper for the backend ``find_prioritized_actors_for_asset``."""
    return _query_module(database).find_prioritized_actors_for_asset(
        database, asset_id, since=since, until=until, limit=limit
    )


def find_vulnerabilities_for_asset(
    database: Any,
    asset_id: str,
    *,
    since: date,
    until: date,
    limit: int,
) -> list[dict[str, Any]]:
    """Dispatching wrapper for the backend ``find_vulnerabilities_for_asset``."""
    return _query_module(database).find_vulnerabilities_for_asset(
        database, asset_id, since=since, until=until, limit=limit
    )


def find_incidents_for_asset(
    database: Any,
    asset_id: str,
    *,
    since: date,
    until: date,
    limit: int,
) -> list[dict[str, Any]]:
    """Dispatching wrapper for the backend ``find_incidents_for_asset``."""
    return _query_module(database).find_incidents_for_asset(
        database, asset_id, since=since, until=until, limit=limit
    )


# ---------------------------------------------------------------------------
# Incident wrappers (mirror sage.spanner.incidents / sage.sqlite.incidents)
# ---------------------------------------------------------------------------


def upsert_incident(
    database: Any,
    req: IncidentRequest,
    *,
    now: Any = None,
) -> dict[str, Any]:
    """Dispatching wrapper for the backend ``upsert_incident``."""
    return _incidents_module(database).upsert_incident(database, req, now=now)


def read_incidents(
    database: Any,
    *,
    since: date,
    until: date,
    actor_stix_id: str | None,
    limit: int,
) -> list[dict[str, Any]]:
    """Dispatching wrapper for the backend ``read_incidents``."""
    return _incidents_module(database).read_incidents(
        database, since=since, until=until, actor_stix_id=actor_stix_id, limit=limit
    )


# ---------------------------------------------------------------------------
# Annotation wrappers (mirror sage.spanner.annotations / sage.sqlite.annotations)
# ---------------------------------------------------------------------------


def write_annotation(
    database: Any,
    annotator_id: str,
    actor_stix_id: str,
    annotation_type: AnnotationType,
    payload: BaseModel,
    evidence_url: str | None = None,
) -> dict:
    """Dispatching wrapper for the backend ``write_annotation``."""
    return _annotations_module(database).write_annotation(
        database, annotator_id, actor_stix_id, annotation_type, payload, evidence_url
    )
