"""Tests for sage.sqlite.incidents against a real temp SQLite database.

Covers the PUT-like full-replace upsert (created/updated flags, child
IncidentUsesTTP replacement, warnings), and read_incidents (window
filter, actor filter via the Uses join, multi-id child fetch — the
SQLite replacement for Spanner's ``IN UNNEST(@ids)`` — kill_chain_phases
JSON-array normalisation, and diamond_model decoding).
"""

from __future__ import annotations

from datetime import UTC, date, datetime

import pytest

from sage import db as sage_db
from sage.models.incident_request import (
    IncidentRequest,
    IncidentSeverity,
    IncidentTTP,
    KillChainPhase,
)
from sage.sqlite import incidents, upsert
from sage.sqlite.client import get_connection, init_schema

INCIDENT_1 = "incident--aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa"
INCIDENT_2 = "incident--bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbbb"
TTP_1 = "attack-pattern--11111111-1111-4111-8111-111111111111"
TTP_2 = "attack-pattern--22222222-2222-4222-8222-222222222222"
TTP_3 = "attack-pattern--33333333-3333-4333-8333-333333333333"
ACTOR_1 = "intrusion-set--44444444-4444-4444-8444-444444444444"

DIAMOND = {
    "adversary": "APT-Test",
    "capability": "phishing",
    "infrastructure": "bulletproof host",
    "victim": "acme corp",
}


@pytest.fixture
def conn(tmp_path):
    c = get_connection(tmp_path / "sage.db")
    init_schema(c)
    yield c
    c.close()


def _request(
    incident_stix_id: str = INCIDENT_1,
    *,
    occurred_at: datetime | None = None,
    with_kcp: bool = True,
    ttps: list[IncidentTTP] | None = None,
) -> IncidentRequest:
    kcp = (
        [
            KillChainPhase(
                kill_chain_name="mitre-attack",
                phase_name="initial-access",
                x_ttp_stix_id=TTP_3,
            ),
            KillChainPhase(kill_chain_name="mitre-attack", phase_name="execution"),
        ]
        if with_kcp
        else []
    )
    return IncidentRequest(
        incident_stix_id=incident_stix_id,
        name="Phishing breach",
        occurred_at=occurred_at or datetime(2026, 5, 20, 8, 0, tzinfo=UTC),
        severity=IncidentSeverity.HIGH,
        description="Spearphish against finance",
        kill_chain_phases=kcp,
        ttps=ttps
        if ttps is not None
        else [
            IncidentTTP(ttp_stix_id=TTP_1, sequence_order=1),
            IncidentTTP(ttp_stix_id=TTP_2, sequence_order=2),
        ],
        diamond_model=DIAMOND,
    )


# ---------------------------------------------------------------------------
# upsert_incident
# ---------------------------------------------------------------------------


def test_upsert_incident_created_then_updated(conn):
    first = incidents.upsert_incident(conn, _request())
    assert first == {
        "incident_stix_id": INCIDENT_1,
        "accepted": True,
        "created": True,
        "updated": False,
        "warnings": [],
    }
    second = incidents.upsert_incident(conn, _request())
    assert second["created"] is False
    assert second["updated"] is True
    # Still exactly one Incident row.
    n = conn.execute("SELECT COUNT(*) AS n FROM Incident").fetchone()["n"]
    assert n == 1


def test_upsert_incident_row_encoding(conn):
    incidents.upsert_incident(conn, _request(), now=datetime(2026, 6, 1, tzinfo=UTC))
    row = conn.execute("SELECT * FROM Incident").fetchone()
    assert row["stix_id"] == INCIDENT_1
    assert row["severity"] == "high"
    assert row["source"] == incidents.DIRECT_API_SOURCE
    assert row["resolved_at"] is None
    assert row["occurred_at"] == "2026-05-20T08:00:00+00:00"
    assert row["stix_modified"] == "2026-06-01T00:00:00+00:00"
    # kill_chain_phases stored as a JSON array of phase names.
    assert incidents._decode_kill_chain_phases(row["kill_chain_phases"]) == [
        "initial-access",
        "execution",
    ]
    assert incidents._decode_diamond_model(row["diamond_model"]) == DIAMOND


def test_upsert_incident_replaces_child_rows(conn):
    incidents.upsert_incident(conn, _request())
    rows = conn.execute(
        "SELECT ttp_stix_id, sequence_order FROM IncidentUsesTTP ORDER BY ttp_stix_id"
    ).fetchall()
    # ttps[] rows + the kcp-derived TTP_3 row (sequence_order NULL).
    assert [(r["ttp_stix_id"], r["sequence_order"]) for r in rows] == [
        (TTP_1, 1),
        (TTP_2, 2),
        (TTP_3, None),
    ]
    # Re-POST with a different TTP set fully replaces the children.
    incidents.upsert_incident(
        conn,
        _request(with_kcp=False, ttps=[IncidentTTP(ttp_stix_id=TTP_2, sequence_order=7)]),
    )
    rows = conn.execute("SELECT ttp_stix_id, sequence_order FROM IncidentUsesTTP").fetchall()
    assert [(r["ttp_stix_id"], r["sequence_order"]) for r in rows] == [(TTP_2, 7)]


def test_upsert_incident_warnings(conn):
    result = incidents.upsert_incident(
        conn,
        _request(with_kcp=False, ttps=[IncidentTTP(ttp_stix_id=TTP_1, sequence_order=None)]),
    )
    codes = [w["code"] for w in result["warnings"]]
    assert codes == [incidents.WARNING_KCP_MISSING, incidents.WARNING_SEQUENCE_ORDER_NULL]
    assert all(w["message"] for w in result["warnings"])


# ---------------------------------------------------------------------------
# read_incidents
# ---------------------------------------------------------------------------


def test_read_incidents_shape(conn):
    incidents.upsert_incident(conn, _request())
    rows = incidents.read_incidents(
        conn,
        since=date(2026, 5, 1),
        until=date(2026, 5, 31),
        actor_stix_id=None,
        limit=10,
    )
    assert rows == [
        {
            "incident_stix_id": INCIDENT_1,
            "name": "Phishing breach",
            "description": "Spearphish against finance",
            "occurred_at": datetime(2026, 5, 20, 8, 0, tzinfo=UTC),
            "severity": "high",
            "source": "direct_api",
            "kill_chain_phases": ["initial-access", "execution"],
            "diamond_model": DIAMOND,
            # Children ordered by sequence_order with NULL (kcp-derived) last.
            "ttps": [
                {"ttp_stix_id": TTP_1, "sequence_order": 1},
                {"ttp_stix_id": TTP_2, "sequence_order": 2},
                {"ttp_stix_id": TTP_3, "sequence_order": None},
            ],
        }
    ]


def test_read_incidents_window_filters_and_orders(conn):
    incidents.upsert_incident(conn, _request())
    incidents.upsert_incident(
        conn,
        _request(INCIDENT_2, occurred_at=datetime(2026, 5, 25, 8, 0, tzinfo=UTC)),
    )
    rows = incidents.read_incidents(
        conn,
        since=date(2026, 5, 1),
        until=date(2026, 5, 31),
        actor_stix_id=None,
        limit=10,
    )
    # Multi-id child fetch (the UNNEST-replacement path) + occurred_at DESC.
    assert [r["incident_stix_id"] for r in rows] == [INCIDENT_2, INCIDENT_1]
    assert all(len(r["ttps"]) == 3 for r in rows)
    # since == until == occurrence day is a full calendar day match.
    rows = incidents.read_incidents(
        conn,
        since=date(2026, 5, 25),
        until=date(2026, 5, 25),
        actor_stix_id=None,
        limit=10,
    )
    assert [r["incident_stix_id"] for r in rows] == [INCIDENT_2]
    # An empty window returns [].
    assert (
        incidents.read_incidents(
            conn,
            since=date(2025, 1, 1),
            until=date(2025, 1, 31),
            actor_stix_id=None,
            limit=10,
        )
        == []
    )


def test_read_incidents_limit(conn):
    incidents.upsert_incident(conn, _request())
    incidents.upsert_incident(
        conn,
        _request(INCIDENT_2, occurred_at=datetime(2026, 5, 25, 8, 0, tzinfo=UTC)),
    )
    rows = incidents.read_incidents(
        conn,
        since=date(2026, 5, 1),
        until=date(2026, 5, 31),
        actor_stix_id=None,
        limit=1,
    )
    assert [r["incident_stix_id"] for r in rows] == [INCIDENT_2]


def test_read_incidents_actor_filter(conn):
    incidents.upsert_incident(conn, _request())  # uses TTP_1, TTP_2, TTP_3
    incidents.upsert_incident(
        conn,
        _request(
            INCIDENT_2,
            occurred_at=datetime(2026, 5, 25, 8, 0, tzinfo=UTC),
            with_kcp=False,
            ttps=[IncidentTTP(ttp_stix_id=TTP_2, sequence_order=1)],
        ),
    )
    # ACTOR_1 is only linked (via Uses) to TTP_1.
    upsert.upsert_rows(
        conn,
        "Uses",
        [{"actor_stix_id": ACTOR_1, "ttp_stix_id": TTP_1, "confidence": 80}],
    )
    rows = incidents.read_incidents(
        conn,
        since=date(2026, 5, 1),
        until=date(2026, 5, 31),
        actor_stix_id=ACTOR_1,
        limit=10,
    )
    assert [r["incident_stix_id"] for r in rows] == [INCIDENT_1]
    # Unknown actor -> no incidents.
    assert (
        incidents.read_incidents(
            conn,
            since=date(2026, 5, 1),
            until=date(2026, 5, 31),
            actor_stix_id="intrusion-set--99999999-9999-4999-8999-999999999999",
            limit=10,
        )
        == []
    )


def test_read_incidents_tolerates_relay_written_rows(conn):
    # Rows written by the generic upsert path (OpenCTI relay analogue)
    # with NULL kill_chain_phases / diamond_model normalise cleanly.
    upsert.upsert_rows(
        conn,
        "Incident",
        [
            {
                "stix_id": INCIDENT_1,
                "name": "Relay incident",
                "occurred_at": "2026-05-02T00:00:00+00:00",
                "severity": "low",
                "stix_modified": "2026-06-01T00:00:00+00:00",
            }
        ],
    )
    rows = incidents.read_incidents(
        conn,
        since=date(2026, 5, 1),
        until=date(2026, 5, 31),
        actor_stix_id=None,
        limit=10,
    )
    assert rows[0]["kill_chain_phases"] == []
    assert rows[0]["diamond_model"] is None
    assert rows[0]["source"] == "ir_feedback"  # DDL default applied by upsert layer
    assert rows[0]["ttps"] == []


# ---------------------------------------------------------------------------
# sage.db dispatch wrappers route the sqlite handle to this module
# ---------------------------------------------------------------------------


def test_db_wrappers_dispatch_to_sqlite(conn):
    result = sage_db.upsert_incident(conn, _request())
    assert result["created"] is True
    rows = sage_db.read_incidents(
        conn,
        since=date(2026, 5, 1),
        until=date(2026, 5, 31),
        actor_stix_id=None,
        limit=10,
    )
    assert [r["incident_stix_id"] for r in rows] == [INCIDENT_1]
