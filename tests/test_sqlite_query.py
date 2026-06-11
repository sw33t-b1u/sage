"""Tests for sage.sqlite.query against a real temp SQLite database.

Each of the public query functions gets at least one happy-path test
asserting the FULL return shape (keys, value types, ordering, limit)
plus an edge case (empty result / temporal window bounds). The database
is seeded exclusively through the sage.sqlite.upsert layer — no mocks —
so the JSON-array encoding and ISO-8601 TEXT timestamp conventions are
exercised end to end.
"""

from __future__ import annotations

from datetime import UTC, date, datetime

import pytest

from sage import db as sage_db
from sage.sqlite import query, upsert
from sage.sqlite.client import get_connection, init_schema

ACTOR_1 = "intrusion-set--11111111-1111-1111-1111-111111111111"
ACTOR_2 = "intrusion-set--22222222-2222-2222-2222-222222222222"
TTP_1 = "attack-pattern--aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa"
TTP_2 = "attack-pattern--bbbbbbbb-bbbb-bbbb-bbbb-bbbbbbbbbbbb"
TTP_3 = "attack-pattern--cccccccc-cccc-cccc-cccc-cccccccccccc"
VULN_1 = "vulnerability--dddddddd-dddd-dddd-dddd-dddddddddddd"
VULN_2 = "vulnerability--eeeeeeee-eeee-eeee-eeee-eeeeeeeeeeee"
INCIDENT_1 = "incident--12121212-1212-1212-1212-121212121212"
INCIDENT_2 = "incident--34343434-3434-3434-3434-343434343434"

MODIFIED = "2026-06-01T00:00:00+00:00"


def _seed(conn) -> None:
    upsert.upsert_rows(
        conn,
        "ThreatActor",
        [
            {
                "stix_id": ACTOR_1,
                "stix_type": "intrusion-set",
                "name": "APT99",
                "aliases": ["Fancy Test Bear"],
                "sophistication": "advanced",
                "first_seen": "2024-01-01T00:00:00+00:00",
                "last_seen": "2026-05-10T00:00:00+00:00",
                "stix_modified": MODIFIED,
            },
            {
                "stix_id": ACTOR_2,
                "stix_type": "intrusion-set",
                "name": "Quiet Apt Crew",
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
        "TTP",
        [
            {"stix_id": TTP_1, "name": "Valid Accounts", "stix_modified": MODIFIED},
            {"stix_id": TTP_2, "name": "PowerShell", "stix_modified": MODIFIED},
            {"stix_id": TTP_3, "name": "Exfiltration", "stix_modified": MODIFIED},
        ],
    )
    upsert.upsert_rows(
        conn,
        "Asset",
        [
            {
                "id": "asset-web",
                "name": "WebServer",
                "pir_adjusted_criticality": 9.0,
                "exposed_to_internet": 1,
                "last_updated": MODIFIED,
            },
            {
                "id": "asset-db",
                "name": "DbServer",
                "pir_adjusted_criticality": 7.0,
                "exposed_to_internet": 0,
                "last_updated": MODIFIED,
            },
        ],
    )
    upsert.upsert_rows(
        conn,
        "Targets",
        [
            {"actor_stix_id": ACTOR_1, "asset_id": "asset-web", "confidence": 80},
            {"actor_stix_id": ACTOR_2, "asset_id": "asset-web", "confidence": 60},
            {"actor_stix_id": ACTOR_1, "asset_id": "asset-db", "confidence": 70},
        ],
    )
    upsert.upsert_rows(
        conn,
        "Uses",
        [
            {
                "actor_stix_id": ACTOR_1,
                "ttp_stix_id": TTP_1,
                "confidence": 90,
                "last_observed": "2026-05-10T12:00:00+00:00",
            },
            {
                "actor_stix_id": ACTOR_1,
                "ttp_stix_id": TTP_2,
                "confidence": 50,
                "last_observed": "2026-03-01T12:00:00+00:00",
            },
            {
                "actor_stix_id": ACTOR_2,
                "ttp_stix_id": TTP_1,
                "confidence": 70,
                "last_observed": "2026-05-12T12:00:00+00:00",
            },
        ],
    )
    upsert.upsert_followed_by(
        conn,
        [
            {
                "src_ttp_stix_id": TTP_1,
                "dst_ttp_stix_id": TTP_2,
                "source": "threat_intel",
                "weight": 0.8,
            },
            {
                "src_ttp_stix_id": TTP_1,
                "dst_ttp_stix_id": TTP_3,
                "source": "threat_intel",
                "weight": 0.3,
            },
        ],
    )
    upsert.upsert_rows(
        conn,
        "PIR",
        [
            {
                "pir_id": "PIR-1",
                "intelligence_level": "strategic",
                "organizational_scope": "global",
                "decision_point": "Quarterly review",
                "description": "Track APT99 against internet-facing assets",
                "rationale": "High targeting overlap",
                "recommended_action": "Harden perimeter",
                "threat_actor_tags": ["apt-test"],
                "risk_composite": 12,
                "valid_from": "2026-01-01",
                "valid_until": "2026-12-31",
            },
            {
                "pir_id": "PIR-2",
                "intelligence_level": "operational",
                "description": "Future PIR not yet valid",
                "threat_actor_tags": [],
                "valid_from": "2026-06-01",
                "valid_until": "2026-12-31",
            },
        ],
    )
    upsert.upsert_rows(
        conn,
        "PirPrioritizesActor",
        [
            {
                "pir_id": "PIR-1",
                "actor_stix_id": ACTOR_1,
                "overlap_ratio": 0.75,
                "likelihood": 0.9,
                "rationale_json": '{"intent": 0.9}',
            },
            {
                "pir_id": "PIR-2",
                "actor_stix_id": ACTOR_2,
                "overlap_ratio": 0.4,
                "likelihood": 0.5,
                "rationale_json": None,
            },
        ],
    )
    upsert.upsert_rows(conn, "PirPrioritizesTTP", [{"pir_id": "PIR-1", "ttp_stix_id": TTP_1}])
    upsert.upsert_rows(
        conn,
        "PirWeightsAsset",
        [
            {
                "pir_id": "PIR-1",
                "asset_id": "asset-web",
                "matched_tag": "external-facing",
                "criticality_multiplier": 1.5,
            }
        ],
    )
    upsert.upsert_rows(
        conn,
        "Vulnerability",
        [
            {
                "stix_id": VULN_1,
                "cve_id": "CVE-2026-0001",
                "description": "RCE in web stack",
                "cvss_score": 9.8,
                "epss_score": 0.7,
                "published_date": "2026-05-15T00:00:00+00:00",
                "stix_modified": MODIFIED,
            },
            {
                "stix_id": VULN_2,
                "cve_id": "CVE-2025-9999",
                "description": "Old bug",
                "cvss_score": 5.0,
                "epss_score": 0.1,
                "published_date": "2025-01-01T00:00:00+00:00",
                "stix_modified": MODIFIED,
            },
        ],
    )
    upsert.upsert_rows(
        conn,
        "HasVulnerability",
        [
            {"asset_id": "asset-web", "vuln_stix_id": VULN_1},
            {"asset_id": "asset-web", "vuln_stix_id": VULN_2},
        ],
    )
    upsert.upsert_rows(
        conn,
        "Incident",
        [
            {
                "stix_id": INCIDENT_1,
                "name": "May breach",
                "occurred_at": "2026-05-20T08:00:00+00:00",
                "severity": "high",
                "source": "direct_api",
                "stix_modified": MODIFIED,
            },
            {
                "stix_id": INCIDENT_2,
                "name": "Old breach",
                "occurred_at": "2025-12-01T08:00:00+00:00",
                "severity": "low",
                "source": "ir_feedback",
                "stix_modified": MODIFIED,
            },
        ],
    )
    upsert.upsert_rows(
        conn,
        "IncidentUsesTTP",
        [
            {"incident_stix_id": INCIDENT_1, "ttp_stix_id": TTP_1, "sequence_order": 1},
            {"incident_stix_id": INCIDENT_1, "ttp_stix_id": TTP_2, "sequence_order": 2},
            {"incident_stix_id": INCIDENT_2, "ttp_stix_id": TTP_1, "sequence_order": None},
        ],
    )
    upsert.upsert_rows(
        conn,
        "TargetsAsset",
        [{"ttp_stix_id": TTP_1, "asset_id": "asset-web", "match_reason": "platform"}],
    )


@pytest.fixture
def conn(tmp_path):
    c = get_connection(tmp_path / "sage.db")
    init_schema(c)
    _seed(c)
    yield c
    c.close()


# ---------------------------------------------------------------------------
# find_attack_paths
# ---------------------------------------------------------------------------


def test_find_attack_paths_shape_and_order(conn):
    rows = query.find_attack_paths(conn, "asset-web")
    assert [r["confidence"] for r in rows] == [90, 70, 50]
    assert rows[0] == {
        "actor_stix_id": ACTOR_1,
        "actor_name": "APT99",
        "ttp_stix_id": TTP_1,
        "ttp_name": "Valid Accounts",
        "confidence": 90,
    }


def test_find_attack_paths_limit_and_empty(conn):
    assert len(query.find_attack_paths(conn, "asset-web", limit=2)) == 2
    assert query.find_attack_paths(conn, "asset-unknown") == []


# ---------------------------------------------------------------------------
# find_actor_ttps
# ---------------------------------------------------------------------------


def test_find_actor_ttps_shape_and_weight_order(conn):
    rows = query.find_actor_ttps(conn, ACTOR_1)
    # Uses(t1) + Uses(t2); only t1 has FollowedBy out-edges -> 2 rows by weight DESC.
    assert [r["weight"] for r in rows] == [0.8, 0.3]
    assert rows[0] == {
        "src_ttp_stix_id": TTP_1,
        "src_ttp_name": "Valid Accounts",
        "dst_ttp_stix_id": TTP_2,
        "dst_ttp_name": "PowerShell",
        "weight": 0.8,
        "source": "threat_intel",
    }


def test_find_actor_ttps_window_bounds(conn):
    # Window covering only May 2026 keeps Uses(t1) (last_observed 2026-05-10).
    rows = query.find_actor_ttps(conn, ACTOR_1, since=date(2026, 5, 1), until=date(2026, 5, 31))
    assert {r["src_ttp_stix_id"] for r in rows} == {TTP_1}
    # since == until == observation day counts as a full calendar day.
    rows = query.find_actor_ttps(conn, ACTOR_1, since=date(2026, 5, 10), until=date(2026, 5, 10))
    assert len(rows) == 2
    # A window with no observations yields no flow.
    assert (
        query.find_actor_ttps(conn, ACTOR_1, since=date(2026, 2, 1), until=date(2026, 2, 28)) == []
    )


# ---------------------------------------------------------------------------
# find_choke_points
# ---------------------------------------------------------------------------


def test_find_choke_points_shape_and_score(conn):
    rows = query.find_choke_points(conn)
    assert rows[0] == {
        "asset_id": "asset-web",
        "asset_name": "WebServer",
        "pir_adjusted_criticality": 9.0,
        "targeting_actor_count": 2,
        "choke_score": 18.0,
    }
    assert rows[1]["asset_id"] == "asset-db"
    assert rows[1]["choke_score"] == 7.0


def test_find_choke_points_top_n(conn):
    rows = query.find_choke_points(conn, top_n=1)
    assert len(rows) == 1
    assert rows[0]["asset_id"] == "asset-web"


# ---------------------------------------------------------------------------
# find_asset_exposure
# ---------------------------------------------------------------------------


def test_find_asset_exposure_only_exposed_assets(conn):
    rows = query.find_asset_exposure(conn)
    assert len(rows) == 1
    assert rows[0] == {
        "asset_id": "asset-web",
        "asset_name": "WebServer",
        "pir_adjusted_criticality": 9.0,
        "targeting_actor_count": 2,
        "reachable_ttp_count": 2,
    }


def test_find_asset_exposure_window_restricts_uses(conn):
    rows = query.find_asset_exposure(conn, since=date(2026, 5, 1), until=date(2026, 5, 31))
    # Both actors observed in May, but only t1 was observed in window.
    assert rows[0]["targeting_actor_count"] == 2
    assert rows[0]["reachable_ttp_count"] == 1


# ---------------------------------------------------------------------------
# find_incident_ttps / find_all_incident_ttps / find_followedby_edges
# ---------------------------------------------------------------------------


def test_find_incident_ttps(conn):
    assert sorted(query.find_incident_ttps(conn, INCIDENT_1)) == sorted([TTP_1, TTP_2])
    assert query.find_incident_ttps(conn, "incident--unknown") == []


def test_find_all_incident_ttps(conn):
    result = query.find_all_incident_ttps(conn)
    assert set(result) == {INCIDENT_1, INCIDENT_2}
    assert sorted(result[INCIDENT_1]) == sorted([TTP_1, TTP_2])
    assert result[INCIDENT_2] == [TTP_1]


def test_find_followedby_edges_shape(conn):
    rows = query.find_followedby_edges(conn)
    assert len(rows) == 2
    assert {"src_stix_id": TTP_1, "dst_stix_id": TTP_2, "weight": 0.8} in rows
    assert all(set(r) == {"src_stix_id", "dst_stix_id", "weight"} for r in rows)


# ---------------------------------------------------------------------------
# load_pirs / load_pir_edges
# ---------------------------------------------------------------------------


def test_load_pirs_shape(conn):
    rows = query.load_pirs(conn)
    assert [r["pir_id"] for r in rows] == ["PIR-1", "PIR-2"]
    assert rows[0] == {
        "pir_id": "PIR-1",
        "intelligence_level": "strategic",
        "organizational_scope": "global",
        "decision_point": "Quarterly review",
        "description": "Track APT99 against internet-facing assets",
        "rationale": "High targeting overlap",
        "recommended_action": "Harden perimeter",
        "threat_actor_tags": ["apt-test"],
        "risk_composite": 12,
        "valid_from": date(2026, 1, 1),
        "valid_until": date(2026, 12, 31),
    }
    # ARRAY columns normalise to list[str] even when empty.
    assert rows[1]["threat_actor_tags"] == []


def test_load_pir_edges_shape(conn):
    edges = query.load_pir_edges(conn)
    assert set(edges) == {"PirPrioritizesActor", "PirPrioritizesTTP", "PirWeightsAsset"}
    actor_rows = edges["PirPrioritizesActor"]
    assert {
        "pir_id": "PIR-1",
        "actor_stix_id": ACTOR_1,
        "overlap_ratio": 0.75,
    } in actor_rows
    assert edges["PirPrioritizesTTP"] == [{"pir_id": "PIR-1", "ttp_stix_id": TTP_1}]
    assert edges["PirWeightsAsset"] == [
        {
            "pir_id": "PIR-1",
            "asset_id": "asset-web",
            "matched_tag": "external-facing",
            "criticality_multiplier": 1.5,
        }
    ]


# ---------------------------------------------------------------------------
# find_actors_by_name
# ---------------------------------------------------------------------------


def test_find_actors_by_name_shape_and_order(conn):
    rows = query.find_actors_by_name(conn, "apt")
    # Case-insensitive substring; sorted by last_seen DESC.
    assert [r["stix_id"] for r in rows] == [ACTOR_1, ACTOR_2]
    assert rows[0] == {
        "stix_id": ACTOR_1,
        "name": "APT99",
        "description": None,
        "aliases": ["Fancy Test Bear"],
        "first_seen": datetime(2024, 1, 1, tzinfo=UTC),
        "last_seen": datetime(2026, 5, 10, tzinfo=UTC),
        "sophistication_level": "advanced",
    }
    assert rows[1]["aliases"] == []


def test_find_actors_by_name_limit_and_empty(conn):
    assert len(query.find_actors_by_name(conn, "apt", limit=1)) == 1
    assert query.find_actors_by_name(conn, "zzz-no-match") == []


# ---------------------------------------------------------------------------
# find_prioritized_actors_for_asset
# ---------------------------------------------------------------------------


def test_find_prioritized_actors_for_asset_validity_window(conn):
    rows = query.find_prioritized_actors_for_asset(
        conn, "asset-web", since=date(2026, 3, 1), until=date(2026, 3, 31), limit=5
    )
    # PIR-1 covers the window; PIR-2 (valid from June) does not -> ACTOR_2 absent.
    assert rows == [
        {
            "actor_stix_id": ACTOR_1,
            "actor_name": "APT99",
            "pir_id": "PIR-1",
            "overlap_ratio": 0.75,
            "likelihood": 0.9,
            "rationale_json": '{"intent": 0.9}',
        }
    ]


def test_find_prioritized_actors_for_asset_empty_outside_validity(conn):
    rows = query.find_prioritized_actors_for_asset(
        conn, "asset-web", since=date(2027, 1, 1), until=date(2027, 1, 31), limit=5
    )
    assert rows == []


# ---------------------------------------------------------------------------
# find_vulnerabilities_for_asset
# ---------------------------------------------------------------------------


def test_find_vulnerabilities_for_asset_window_and_shape(conn):
    rows = query.find_vulnerabilities_for_asset(
        conn, "asset-web", since=date(2026, 5, 1), until=date(2026, 5, 31), limit=5
    )
    # Only VULN_1 was published in window; VULN_2 (2025) is excluded.
    assert rows == [
        {
            "vuln_stix_id": VULN_1,
            "cve_id": "CVE-2026-0001",
            "description": "RCE in web stack",
            "cvss_score": 9.8,
            "epss_score": 0.7,
            "published_date": datetime(2026, 5, 15, tzinfo=UTC),
        }
    ]


def test_find_vulnerabilities_for_asset_order_and_limit(conn):
    rows = query.find_vulnerabilities_for_asset(
        conn, "asset-web", since=date(2025, 1, 1), until=date(2026, 12, 31), limit=5
    )
    # Wide window returns both, ordered by cvss DESC.
    assert [r["vuln_stix_id"] for r in rows] == [VULN_1, VULN_2]
    rows = query.find_vulnerabilities_for_asset(
        conn, "asset-web", since=date(2025, 1, 1), until=date(2026, 12, 31), limit=1
    )
    assert len(rows) == 1


# ---------------------------------------------------------------------------
# find_incidents_for_asset
# ---------------------------------------------------------------------------


def test_find_incidents_for_asset_window_and_shape(conn):
    rows = query.find_incidents_for_asset(
        conn, "asset-web", since=date(2026, 5, 1), until=date(2026, 5, 31), limit=5
    )
    # INCIDENT_1 occurred in window; INCIDENT_2 (2025-12) is excluded.
    assert rows == [
        {
            "incident_stix_id": INCIDENT_1,
            "incident_name": "May breach",
            "occurred_at": datetime(2026, 5, 20, 8, 0, tzinfo=UTC),
            "severity": "high",
            "source": "direct_api",
        }
    ]


def test_find_incidents_for_asset_wide_window_order(conn):
    rows = query.find_incidents_for_asset(
        conn, "asset-web", since=date(2025, 1, 1), until=date(2026, 12, 31), limit=5
    )
    # occurred_at DESC.
    assert [r["incident_stix_id"] for r in rows] == [INCIDENT_1, INCIDENT_2]


# ---------------------------------------------------------------------------
# sage.db dispatch wrappers route the sqlite handle to this module
# ---------------------------------------------------------------------------


def test_db_wrappers_dispatch_to_sqlite(conn):
    assert sage_db.find_attack_paths(conn, "asset-web") == query.find_attack_paths(
        conn, "asset-web"
    )
    assert sage_db.find_choke_points(conn, top_n=1) == query.find_choke_points(conn, top_n=1)
    assert sage_db.load_pirs(conn) == query.load_pirs(conn)
    assert sage_db.find_actors_by_name(conn, "apt") == query.find_actors_by_name(conn, "apt")
    assert sage_db.find_followedby_edges(conn) == query.find_followedby_edges(conn)
