"""Write helpers for the ``AnnotatesActor`` edge table (Initiative E Phase 5).

The table was created in SAGE 0.10.0 (read-side only); this module adds
the operator-facing write surface used by ``cmd/annotate_actor.py``.

Payloads arrive as already-validated Pydantic models — callers must run
``sage.models.annotation.validate_payload`` first so a structural error
fails the request before any Spanner mutation is buffered.
"""

from __future__ import annotations

import google.cloud.spanner as spanner
import structlog
from google.cloud.spanner_v1.database import Database
from pydantic import BaseModel

from sage.models.annotation import AnnotationType

logger = structlog.get_logger(__name__)

# Column order must match the AnnotatesActor DDL exactly — Spanner
# mutations are positional. Keep aligned with the registration in
# ``sage.spanner.upsert._TABLE_COLUMNS["AnnotatesActor"]``.
_COLUMNS: list[str] = [
    "annotator_id",
    "actor_stix_id",
    "annotation_type",
    "payload_json",
    "created_at",
    "evidence_url",
]


def write_annotation(
    database: Database,
    annotator_id: str,
    actor_stix_id: str,
    annotation_type: AnnotationType,
    payload: BaseModel,
    evidence_url: str | None = None,
) -> dict:
    """Insert one AnnotatesActor row.

    ``created_at`` is written as ``spanner.COMMIT_TIMESTAMP`` so the
    Spanner server assigns the timestamp at commit time. The returned
    dict carries ``created_at_pending: True`` to signal that the value
    is not yet known on the client side; downstream tooling can re-read
    the row to materialise the server-assigned timestamp.
    """
    payload_json = payload.model_dump_json()
    values = [
        [
            annotator_id,
            actor_stix_id,
            annotation_type.value,
            payload_json,
            spanner.COMMIT_TIMESTAMP,
            evidence_url,
        ]
    ]
    with database.batch() as b:
        b.insert_or_update(table="AnnotatesActor", columns=_COLUMNS, values=values)
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
        "created_at_pending": True,
    }
