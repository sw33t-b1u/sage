"""Tests for sage.sqlite.upsert against a real temp SQLite database.

Covers: insert -> row present with correct decoding (JSON arrays round-trip
to list, timestamps stored as ISO TEXT); idempotency (same PK upserted twice
-> still one row, values updated); precedence-aware edge upserts; and the
commit-timestamp fill behaviour.
"""

from __future__ import annotations

import json

import pytest

from sage.sqlite import upsert
from sage.sqlite.client import get_connection, init_schema


@pytest.fixture
def conn(tmp_path):
    c = get_connection(tmp_path / "sage.db")
    init_schema(c)
    yield c
    c.close()


def _count(conn, table: str) -> int:
    return conn.execute(f"SELECT COUNT(*) AS n FROM {table}").fetchone()["n"]  # noqa: S608


def _row(conn, table: str):
    return conn.execute(f"SELECT * FROM {table}").fetchone()  # noqa: S608


# ---------------------------------------------------------------------------
# Node tables
# ---------------------------------------------------------------------------


def test_threat_actor_insert_array_roundtrip(conn):
    rows = [
        {
            "stix_id": "threat-actor--1",
            "stix_type": "threat-actor",
            "name": "APT-Test",
            "aliases": ["FancyTest", "TestBear"],
            "tags": ["apt-china", "espionage"],
            "stix_modified": "2026-06-01T00:00:00+00:00",
        }
    ]
    assert upsert.upsert_rows(conn, "ThreatActor", rows) == 1
    assert _count(conn, "ThreatActor") == 1
    row = _row(conn, "ThreatActor")
    assert row["name"] == "APT-Test"
    # ARRAY columns are stored as JSON arrays that decode back to lists.
    assert json.loads(row["aliases"]) == ["FancyTest", "TestBear"]
    assert json.loads(row["tags"]) == ["apt-china", "espionage"]


def test_threat_actor_idempotent_update(conn):
    base = {
        "stix_id": "threat-actor--1",
        "stix_type": "threat-actor",
        "name": "Old Name",
        "aliases": ["A"],
        "stix_modified": "2026-06-01T00:00:00+00:00",
    }
    upsert.upsert_rows(conn, "ThreatActor", [base])
    updated = dict(base, name="New Name", aliases=["A", "B"])
    upsert.upsert_rows(conn, "ThreatActor", [updated])
    # Same PK upserted twice -> one row, updated values.
    assert _count(conn, "ThreatActor") == 1
    row = _row(conn, "ThreatActor")
    assert row["name"] == "New Name"
    assert json.loads(row["aliases"]) == ["A", "B"]


def test_ttp_insert(conn):
    rows = [
        {
            "stix_id": "attack-pattern--1",
            "attack_technique_id": "T1059.001",
            "tactic": "execution",
            "name": "PowerShell",
            "platforms": ["windows"],
            "detection_difficulty": 3,
            "stix_modified": "2026-06-01T00:00:00+00:00",
        }
    ]
    assert upsert.upsert_rows(conn, "TTP", rows) == 1
    row = _row(conn, "TTP")
    assert row["attack_technique_id"] == "T1059.001"
    assert row["detection_difficulty"] == 3
    assert json.loads(row["platforms"]) == ["windows"]


def test_asset_insert_with_commit_timestamp(conn):
    rows = [
        {
            "id": "asset-1",
            "name": "web-01",
            "asset_type": "server",
            "exposed_to_internet": 1,
            "tags": ["external-facing"],
            "last_updated": "2026-06-01T00:00:00+00:00",
        }
    ]
    assert upsert.upsert_rows(conn, "Asset", rows) == 1
    row = _row(conn, "Asset")
    assert row["name"] == "web-01"
    assert json.loads(row["tags"]) == ["external-facing"]
    # Default-bearing columns keep their DDL defaults when omitted.
    assert row["criticality"] == 5.0


def test_incident_json_column(conn):
    rows = [
        {
            "stix_id": "incident--1",
            "name": "Breach",
            "kill_chain_phases": ["initial-access", "execution"],
            "diamond_model": json.dumps({"adversary": "APT-Test"}),
            "source": "ir_feedback",
            "stix_modified": "2026-06-01T00:00:00+00:00",
        }
    ]
    assert upsert.upsert_rows(conn, "Incident", rows) == 1
    row = _row(conn, "Incident")
    assert json.loads(row["kill_chain_phases"]) == ["initial-access", "execution"]
    # diamond_model is plain JSON TEXT (not an ARRAY column) -> stored verbatim.
    assert json.loads(row["diamond_model"]) == {"adversary": "APT-Test"}


# ---------------------------------------------------------------------------
# Edge tables
# ---------------------------------------------------------------------------


def test_uses_edge_composite_pk_idempotent(conn):
    base = {
        "actor_stix_id": "threat-actor--1",
        "ttp_stix_id": "attack-pattern--1",
        "confidence": 50,
    }
    upsert.upsert_rows(conn, "Uses", [base])
    upsert.upsert_rows(conn, "Uses", [dict(base, confidence=90)])
    assert _count(conn, "Uses") == 1
    assert _row(conn, "Uses")["confidence"] == 90


def test_targets_edge(conn):
    rows = [
        {
            "actor_stix_id": "threat-actor--1",
            "asset_id": "asset-1",
            "confidence": 70,
            "source": "stix",
        }
    ]
    assert upsert.upsert_rows(conn, "Targets", rows) == 1
    assert _row(conn, "Targets")["confidence"] == 70


def test_followed_by_sets_commit_timestamp(conn):
    rows = [
        {
            "src_ttp_stix_id": "attack-pattern--1",
            "dst_ttp_stix_id": "attack-pattern--2",
            "source": "threat_intel",
            "weight": 0.8,
            "evidence_stix_ids": ["relationship--1"],
        }
    ]
    assert upsert.upsert_followed_by(conn, rows) == 1
    row = _row(conn, "FollowedBy")
    assert row["weight"] == 0.8
    assert json.loads(row["evidence_stix_ids"]) == ["relationship--1"]
    # last_calculated is filled with an ISO timestamp by the upsert helper.
    assert row["last_calculated"] is not None
    assert "T" in row["last_calculated"]


def test_followed_by_idempotent(conn):
    base = {
        "src_ttp_stix_id": "attack-pattern--1",
        "dst_ttp_stix_id": "attack-pattern--2",
        "source": "threat_intel",
        "weight": 0.5,
    }
    upsert.upsert_followed_by(conn, [base])
    upsert.upsert_followed_by(conn, [dict(base, weight=0.9)])
    assert _count(conn, "FollowedBy") == 1
    assert _row(conn, "FollowedBy")["weight"] == 0.9


def test_all_pk_table_upsert_does_nothing_on_conflict(conn):
    # PirPrioritizesTTP has only PK columns -> ON CONFLICT DO NOTHING.
    rows = [{"pir_id": "PIR-1", "ttp_stix_id": "attack-pattern--1"}]
    upsert.upsert_rows(conn, "PirPrioritizesTTP", rows)
    upsert.upsert_rows(conn, "PirPrioritizesTTP", rows)
    assert _count(conn, "PirPrioritizesTTP") == 1


# ---------------------------------------------------------------------------
# Commit-timestamp fill on the generic path
# ---------------------------------------------------------------------------


def test_pir_last_updated_filled_when_omitted(conn):
    rows = [
        {
            "pir_id": "PIR-1",
            "intelligence_level": "strategic",
            "description": "Test PIR",
            "threat_actor_tags": ["apt-china"],
            # last_updated omitted -> upsert fills commit timestamp.
        }
    ]
    assert upsert.upsert_rows(conn, "PIR", rows) == 1
    row = _row(conn, "PIR")
    assert row["last_updated"] is not None
    assert "T" in row["last_updated"]
    assert json.loads(row["threat_actor_tags"]) == ["apt-china"]


# ---------------------------------------------------------------------------
# Precedence-aware upserts
# ---------------------------------------------------------------------------


def test_has_access_precedence_skips_lower(conn):
    manual = {
        "identity_stix_id": "identity--1",
        "asset_id": "asset-1",
        "access_level": "admin",
        "source": "manual",
        "stix_modified": "2026-06-01T00:00:00+00:00",
    }
    assert upsert.upsert_has_access(conn, [manual]) == 1
    # A lower-precedence trace row must NOT overwrite the manual row.
    trace = dict(manual, access_level="read", source="trace")
    assert upsert.upsert_has_access(conn, [trace]) == 0
    row = _row(conn, "HasAccess")
    assert row["access_level"] == "admin"
    assert row["source"] == "manual"


def test_has_access_precedence_accepts_equal_or_higher(conn):
    trace = {
        "identity_stix_id": "identity--1",
        "asset_id": "asset-1",
        "access_level": "read",
        "source": "trace",
        "stix_modified": "2026-06-01T00:00:00+00:00",
    }
    upsert.upsert_has_access(conn, [trace])
    beacon = dict(trace, access_level="write", source="beacon")
    assert upsert.upsert_has_access(conn, [beacon]) == 1
    assert _row(conn, "HasAccess")["access_level"] == "write"


def test_user_account_precedence(conn):
    beacon = {
        "stix_id": "user-account--1",
        "account_login": "alice",
        "is_privileged": 1,
        "source": "beacon",
        "stix_modified": "2026-06-01T00:00:00+00:00",
    }
    upsert.upsert_user_account(conn, [beacon])
    trace = dict(beacon, account_login="alice2", source="trace")
    assert upsert.upsert_user_account(conn, [trace]) == 0
    assert _row(conn, "UserAccount")["account_login"] == "alice"


def test_account_on_asset_precedence(conn):
    beacon = {
        "user_account_stix_id": "user-account--1",
        "asset_id": "asset-1",
        "first_seen": "2026-06-01T00:00:00+00:00",
        "source": "beacon",
    }
    assert upsert.upsert_account_on_asset(conn, [beacon]) == 1
    trace = dict(beacon, first_seen="2026-06-02T00:00:00+00:00", source="trace")
    assert upsert.upsert_account_on_asset(conn, [trace]) == 0
    assert _count(conn, "AccountOnAsset") == 1
    assert _row(conn, "AccountOnAsset")["first_seen"] == "2026-06-01T00:00:00+00:00"


def test_user_account_belongs_to_precedence(conn):
    beacon = {
        "identity_stix_id": "identity--1",
        "user_account_stix_id": "user-account--1",
        "source": "beacon",
    }
    assert upsert.upsert_user_account_belongs_to(conn, [beacon]) == 1
    # Idempotent: same PK from the same source -> still one row.
    assert upsert.upsert_user_account_belongs_to(conn, [beacon]) == 1
    assert _count(conn, "UserAccountBelongsTo") == 1
    # Lower-precedence trace row is skipped.
    trace = dict(beacon, source="trace")
    assert upsert.upsert_user_account_belongs_to(conn, [trace]) == 0
    assert _row(conn, "UserAccountBelongsTo")["source"] == "beacon"


def test_attributed_to_actor_precedence(conn):
    trace = {
        "source_stix_id": "campaign--1",
        "target_actor_stix_id": "threat-actor--1",
        "source_type": "campaign",
        "target_type": "threat-actor",
        "confidence": 70,
        "source": "trace",
    }
    assert upsert.upsert_attributed_to_actor(conn, [trace]) == 1
    manual = dict(trace, confidence=95, source="manual")
    assert upsert.upsert_attributed_to_actor(conn, [manual]) == 1
    assert _count(conn, "AttributedToActor") == 1
    row = _row(conn, "AttributedToActor")
    assert row["confidence"] == 95
    assert row["source"] == "manual"


def test_attributed_to_identity_precedence(conn):
    manual = {
        "source_stix_id": "threat-actor--1",
        "identity_stix_id": "identity--1",
        "source_type": "threat-actor",
        "confidence": 80,
        "source": "manual",
    }
    assert upsert.upsert_attributed_to_identity(conn, [manual]) == 1
    trace = dict(manual, confidence=10, source="trace")
    assert upsert.upsert_attributed_to_identity(conn, [trace]) == 0
    assert _row(conn, "AttributedToIdentity")["confidence"] == 80


def test_upsert_pir_prioritizes_impersonation_target_overwrites_derived_at(conn):
    row = {
        "pir_id": "PIR-1",
        "identity_stix_id": "identity--1",
        "source_stix_id": "threat-actor--1",
        "effective_priority": 90,
        # Explicit derived_at is overwritten with the current timestamp
        # (Spanner parity: COMMIT_TIMESTAMP is substituted unconditionally).
        "derived_at": "2000-01-01T00:00:00+00:00",
    }
    assert upsert.upsert_pir_prioritizes_impersonation_target(conn, [row]) == 1
    stored = _row(conn, "PirPrioritizesImpersonationTarget")
    assert stored["derived_at"] != "2000-01-01T00:00:00+00:00"
    assert stored["derived_at"].startswith("2026") or "T" in stored["derived_at"]
    # Idempotent on PK.
    assert upsert.upsert_pir_prioritizes_impersonation_target(conn, [row]) == 1
    assert _count(conn, "PirPrioritizesImpersonationTarget") == 1


def test_impersonates_identity_precedence(conn):
    rows = [
        {
            "source_stix_id": "threat-actor--1",
            "identity_stix_id": "identity--1",
            "source_type": "threat-actor",
            "confidence": 60,
            "effective_priority": 90,
            "source": "trace",
        }
    ]
    assert upsert.upsert_impersonates_identity(conn, rows) == 1
    assert _row(conn, "ImpersonatesIdentity")["effective_priority"] == 90


# ---------------------------------------------------------------------------
# Recompute / derive cascades + fetch helpers
# ---------------------------------------------------------------------------


def test_recompute_effective_priority(conn):
    upsert.upsert_impersonates_identity(
        conn,
        [
            {
                "source_stix_id": "threat-actor--1",
                "identity_stix_id": "identity--1",
                "source_type": "threat-actor",
                "confidence": 60,
                "effective_priority": 60,
                "source": "trace",
            }
        ],
    )
    n = upsert.recompute_effective_priority_for_identity(conn, "identity--1", True)
    assert n == 1
    # 60 * 1.5 = 90 (flag-driven multiplier).
    assert _row(conn, "ImpersonatesIdentity")["effective_priority"] == 90


def test_derive_pir_prioritizes_impersonation_target(conn):
    upsert.upsert_rows(
        conn,
        "ThreatActor",
        [
            {
                "stix_id": "threat-actor--1",
                "stix_type": "threat-actor",
                "name": "APT-Test",
                "tags": ["apt-china"],
                "stix_modified": "2026-06-01T00:00:00+00:00",
            }
        ],
    )
    upsert.upsert_rows(
        conn,
        "PIR",
        [
            {
                "pir_id": "PIR-1",
                "intelligence_level": "strategic",
                "description": "Test",
                "threat_actor_tags": ["apt-china"],
            }
        ],
    )
    upsert.upsert_impersonates_identity(
        conn,
        [
            {
                "source_stix_id": "threat-actor--1",
                "identity_stix_id": "identity--1",
                "source_type": "threat-actor",
                "confidence": 60,
                "effective_priority": 90,
                "source": "trace",
            }
        ],
    )
    n = upsert.derive_pir_prioritizes_impersonation_target_for_identity(conn, "identity--1")
    assert n == 1
    row = _row(conn, "PirPrioritizesImpersonationTarget")
    assert row["pir_id"] == "PIR-1"
    assert row["effective_priority"] == 90
    assert row["derived_at"] is not None


def test_fetch_asset_rows_decodes_tags(conn):
    upsert.upsert_rows(
        conn,
        "Asset",
        [
            {
                "id": "asset-1",
                "name": "web-01",
                "tags": ["external-facing", "s3"],
                "last_updated": "2026-06-01T00:00:00+00:00",
            }
        ],
    )
    rows = upsert.fetch_asset_rows(conn)
    assert len(rows) == 1
    assert rows[0]["id"] == "asset-1"
    # tags decoded back to a Python list for PIRFilter.build_targets().
    assert rows[0]["tags"] == ["external-facing", "s3"]


def test_update_pir_criticality(conn):
    upsert.upsert_rows(
        conn,
        "Asset",
        [
            {
                "id": "asset-1",
                "name": "web-01",
                "criticality": 5.0,
                "last_updated": "2026-06-01T00:00:00+00:00",
            }
        ],
    )
    n = upsert.update_pir_criticality(conn, [{"id": "asset-1", "pir_adjusted_criticality": 8.5}])
    assert n == 1
    row = _row(conn, "Asset")
    assert row["pir_adjusted_criticality"] == 8.5
    # Other columns are untouched.
    assert row["criticality"] == 5.0
