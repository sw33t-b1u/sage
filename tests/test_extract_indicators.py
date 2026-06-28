"""Tests for direct-relationship indicator extraction (sqlite backend)."""

from __future__ import annotations

import pytest

from sage import db as sage_db
from sage.sqlite import upsert
from sage.sqlite.client import get_connection, init_schema

ACTOR_1 = "intrusion-set--11111111-1111-1111-1111-111111111111"
ACTOR_2 = "intrusion-set--22222222-2222-2222-2222-222222222222"
TTP_1 = "attack-pattern--aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa"
OBS_DIRECT = "indicator--dddddddd-dddd-dddd-dddd-dddddddddddd1"
OBS_OTHER_ACTOR = "indicator--dddddddd-dddd-dddd-dddd-dddddddddddd2"
OBS_TTP_ONLY = "indicator--dddddddd-dddd-dddd-dddd-dddddddddddd3"
OBS_RED = "indicator--dddddddd-dddd-dddd-dddd-dddddddddddd4"

MODIFIED = "2026-06-01T00:00:00+00:00"


@pytest.fixture
def conn():
    c = get_connection(":memory:")
    init_schema(c)
    return c


def _seed(conn) -> None:
    upsert.upsert_rows(
        conn,
        "ThreatActor",
        [
            {
                "stix_id": ACTOR_1,
                "stix_type": "intrusion-set",
                "name": "APT99",
                "aliases": [],
                "sophistication": "advanced",
                "first_seen": "2024-01-01T00:00:00+00:00",
                "last_seen": "2026-05-10T00:00:00+00:00",
                "stix_modified": MODIFIED,
            },
            {
                "stix_id": ACTOR_2,
                "stix_type": "intrusion-set",
                "name": "APT100",
                "aliases": [],
                "sophistication": "intermediate",
                "first_seen": "2023-01-01T00:00:00+00:00",
                "last_seen": "2024-02-01T00:00:00+00:00",
                "stix_modified": MODIFIED,
            },
        ],
    )
    upsert.upsert_rows(
        conn,
        "Observable",
        [
            {
                "stix_id": OBS_DIRECT,
                "obs_type": "ip",
                "value": "203.0.113.10",
                "confidence": 80,
                "tlp": "amber",
                "first_seen": "2026-06-10T00:00:00+00:00",
                "last_seen": "2026-06-20T00:00:00+00:00",
                "stix_modified": MODIFIED,
            },
            {
                "stix_id": OBS_OTHER_ACTOR,
                "obs_type": "domain",
                "value": "evil.example.com",
                "confidence": 50,
                "tlp": "green",
                "first_seen": "2026-06-11T00:00:00+00:00",
                "last_seen": "2026-06-21T00:00:00+00:00",
                "stix_modified": MODIFIED,
            },
            {
                "stix_id": OBS_TTP_ONLY,
                "obs_type": "url",
                "value": "https://evil.example.com/x",
                "confidence": 50,
                "tlp": "green",
                "first_seen": "2026-06-12T00:00:00+00:00",
                "last_seen": "2026-06-22T00:00:00+00:00",
                "stix_modified": MODIFIED,
            },
            {
                "stix_id": OBS_RED,
                "obs_type": "ip",
                "value": "198.51.100.5",
                "confidence": 90,
                "tlp": "red",
                "first_seen": "2026-06-13T00:00:00+00:00",
                "last_seen": "2026-06-23T00:00:00+00:00",
                "stix_modified": MODIFIED,
            },
        ],
    )
    upsert.upsert_rows(
        conn,
        "IndicatesActor",
        [
            {"observable_stix_id": OBS_DIRECT, "actor_stix_id": ACTOR_1, "confidence": 70},
            {"observable_stix_id": OBS_OTHER_ACTOR, "actor_stix_id": ACTOR_2, "confidence": 60},
            {"observable_stix_id": OBS_RED, "actor_stix_id": ACTOR_1, "confidence": 90},
        ],
    )
    upsert.upsert_rows(
        conn,
        "IndicatesTTP",
        [
            {"observable_stix_id": OBS_TTP_ONLY, "ttp_stix_id": TTP_1, "confidence": 40},
        ],
    )


def test_returns_only_directly_linked_observables(conn) -> None:
    _seed(conn)

    rows = sage_db.find_indicators_for_actors(conn, [ACTOR_1])

    obs_ids = {r["observable_stix_id"] for r in rows}
    assert obs_ids == {OBS_DIRECT}  # OBS_RED excluded; OBS_TTP_ONLY/OBS_OTHER excluded


def test_excludes_tlp_red(conn) -> None:
    _seed(conn)

    rows = sage_db.find_indicators_for_actors(conn, [ACTOR_1])

    assert all(r["tlp"] != "red" for r in rows)
    assert OBS_RED not in {r["observable_stix_id"] for r in rows}


def test_multi_actor_selection_unions_results(conn) -> None:
    _seed(conn)

    rows = sage_db.find_indicators_for_actors(conn, [ACTOR_1, ACTOR_2])

    obs_ids = {r["observable_stix_id"] for r in rows}
    assert obs_ids == {OBS_DIRECT, OBS_OTHER_ACTOR}
    by_obs = {r["observable_stix_id"]: r for r in rows}
    assert by_obs[OBS_OTHER_ACTOR]["actor_stix_id"] == ACTOR_2
    assert by_obs[OBS_DIRECT]["actor_name"] == "APT99"


def test_empty_actor_list_returns_empty(conn) -> None:
    _seed(conn)
    assert sage_db.find_indicators_for_actors(conn, []) == []
