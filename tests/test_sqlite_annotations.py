"""Tests for sage.sqlite.annotations against a real temp SQLite database.

Covers the write_annotation return shape, the stored row encoding
(payload JSON, client-assigned ISO created_at, evidence_url), and
created_at ordering across successive writes.
"""

from __future__ import annotations

import json
import time
from datetime import datetime

import pytest

from sage import db as sage_db
from sage.models.annotation import (
    AnalystNotePayload,
    AnnotationType,
    FalsePositivePayload,
)
from sage.sqlite.annotations import write_annotation
from sage.sqlite.client import get_connection, init_schema

ACTOR_1 = "intrusion-set--11111111-1111-1111-1111-111111111111"


@pytest.fixture
def conn(tmp_path):
    c = get_connection(tmp_path / "sage.db")
    init_schema(c)
    yield c
    c.close()


def test_write_annotation_return_shape(conn):
    result = write_annotation(
        conn,
        annotator_id="analyst-1",
        actor_stix_id=ACTOR_1,
        annotation_type=AnnotationType.ANALYST_NOTE,
        payload=AnalystNotePayload(note="tracked actor"),
    )
    # Same key set as the Spanner module; created_at_pending is False
    # because the timestamp is client-assigned and already final.
    assert result == {
        "annotator_id": "analyst-1",
        "actor_stix_id": ACTOR_1,
        "annotation_type": "analyst-note",
        "created_at_pending": False,
    }


def test_write_annotation_stored_row(conn):
    write_annotation(
        conn,
        annotator_id="analyst-1",
        actor_stix_id=ACTOR_1,
        annotation_type=AnnotationType.FALSE_POSITIVE,
        payload=FalsePositivePayload(reason="wrong region"),
        evidence_url="https://example.com/report",
    )
    row = conn.execute("SELECT * FROM AnnotatesActor").fetchone()
    assert row["annotator_id"] == "analyst-1"
    assert row["actor_stix_id"] == ACTOR_1
    assert row["annotation_type"] == "false-positive"
    assert row["evidence_url"] == "https://example.com/report"
    assert json.loads(row["payload_json"])["reason"] == "wrong region"
    # created_at is client-assigned ISO 8601 UTC TEXT (parseable, +00:00).
    created = datetime.fromisoformat(row["created_at"])
    assert created.tzinfo is not None


def test_write_annotation_ordering_by_created_at(conn):
    for note in ("first", "second", "third"):
        write_annotation(
            conn,
            annotator_id="analyst-1",
            actor_stix_id=ACTOR_1,
            annotation_type=AnnotationType.ANALYST_NOTE,
            payload=AnalystNotePayload(note=note),
        )
        # Ensure strictly increasing created_at (PK includes created_at).
        time.sleep(0.002)
    rows = conn.execute(
        "SELECT payload_json, created_at FROM AnnotatesActor ORDER BY created_at ASC"
    ).fetchall()
    assert [json.loads(r["payload_json"])["note"] for r in rows] == [
        "first",
        "second",
        "third",
    ]
    created = [r["created_at"] for r in rows]
    assert created == sorted(created)
    assert len(set(created)) == 3


def test_db_wrapper_dispatches_to_sqlite(conn):
    result = sage_db.write_annotation(
        conn,
        "analyst-2",
        ACTOR_1,
        AnnotationType.ANALYST_NOTE,
        AnalystNotePayload(note="via dispatch"),
    )
    assert result["created_at_pending"] is False
    n = conn.execute("SELECT COUNT(*) AS n FROM AnnotatesActor").fetchone()["n"]
    assert n == 1
