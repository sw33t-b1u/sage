"""Write helpers for the ``AnnotatesActor`` edge table — mirror of
sage.spanner.annotations.

Same name, signature, and return shape as the Spanner counterpart, but
takes an ``sqlite3.Connection`` instead of a Spanner ``Database``.

Payloads arrive as already-validated Pydantic models — callers must run
``sage.models.annotation.validate_payload`` first so a structural error
fails the request before any row is written.
"""

from __future__ import annotations

import sqlite3
from datetime import UTC, datetime

import structlog
from pydantic import BaseModel

from sage.models.annotation import AnnotationType

logger = structlog.get_logger(__name__)

# Column order must match the AnnotatesActor DDL exactly. Keep aligned
# with the registration in ``sage.sqlite.upsert._TABLE_COLUMNS["AnnotatesActor"]``.
_COLUMNS: list[str] = [
    "annotator_id",
    "actor_stix_id",
    "annotation_type",
    "payload_json",
    "created_at",
    "evidence_url",
]


def write_annotation(
    conn: sqlite3.Connection,
    annotator_id: str,
    actor_stix_id: str,
    annotation_type: AnnotationType,
    payload: BaseModel,
    evidence_url: str | None = None,
) -> dict:
    """Insert one AnnotatesActor row.

    ``created_at`` is assigned client-side as ``datetime.now(UTC)`` in
    ISO 8601 TEXT (Decision D-3: SQLite has no server-side
    COMMIT_TIMESTAMP). The returned dict keeps the Spanner module's key
    set; ``created_at_pending`` is ``False`` here because the timestamp
    is already final at return time — there is no pending server-side
    commit assignment to wait for.
    """
    payload_json = payload.model_dump_json()
    created_at = datetime.now(UTC).isoformat()

    col_list = ", ".join(_COLUMNS)
    placeholders = ", ".join("?" for _ in _COLUMNS)
    pk = {"annotator_id", "actor_stix_id", "created_at"}
    pk_cols = "annotator_id, actor_stix_id, created_at"
    set_clause = ", ".join(f"{c} = excluded.{c}" for c in _COLUMNS if c not in pk)
    sql = (
        f"INSERT INTO AnnotatesActor ({col_list}) VALUES ({placeholders}) "  # noqa: S608
        f"ON CONFLICT({pk_cols}) DO UPDATE SET {set_clause}"
    )
    conn.execute(
        sql,
        (
            annotator_id,
            actor_stix_id,
            annotation_type.value,
            payload_json,
            created_at,
            evidence_url,
        ),
    )
    conn.commit()
    logger.info(
        "annotation_written",
        annotator_id=annotator_id,
        actor_stix_id=actor_stix_id,
        annotation_type=annotation_type.value,
    )
    return {
        "annotator_id": annotator_id,
        "actor_stix_id": actor_stix_id,
        "annotation_type": annotation_type.value,
        "created_at_pending": False,
    }
