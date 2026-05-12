"""Tests for Initiative C Phase 1 upsert helpers (SAGE 0.8.0).

Covers AttributedToActor / AttributedToIdentity / ImpersonatesIdentity
precedence-aware upserts and effective_priority recompute cascade.
"""

from __future__ import annotations

from unittest.mock import MagicMock

from sage.spanner.upsert import (
    recompute_effective_priority_for_identity,
    upsert_attributed_to_actor,
    upsert_attributed_to_identity,
    upsert_impersonates_identity,
)


def _ts() -> str:
    return "2026-05-12T00:00:00.000Z"


# ---------------------------------------------------------------------------
# Mock helpers
# ---------------------------------------------------------------------------


def _mock_db_with_existing(table: str, key_columns: list[str], existing: dict):
    """Return (mock Database, recorded mutations).

    ``existing`` maps tuple(key_values) → source string.
    The snapshot.read mock yields (*key_values, source) tuples.
    """
    recorded: list[tuple] = []

    def _record(table=None, columns=None, values=None, **_kw):
        recorded.append((table, list(columns), list(values)))

    batch = MagicMock()
    batch.insert_or_update.side_effect = _record
    batch_ctx = MagicMock()
    batch_ctx.__enter__.return_value = batch
    batch_ctx.__exit__.return_value = None

    snap = MagicMock()
    snap.read.return_value = [(*k, src) for k, src in existing.items()]
    snap_ctx = MagicMock()
    snap_ctx.__enter__.return_value = snap
    snap_ctx.__exit__.return_value = None

    db = MagicMock()
    db.snapshot.return_value = snap_ctx
    db.batch.return_value = batch_ctx
    return db, recorded


def _mock_db_for_recompute(existing_rows: list[dict]):
    """Return (mock Database, recorded update calls) for recompute tests."""
    updated: list[tuple] = []

    def _record_update(table, columns, values):
        updated.append((table, list(columns), list(values)))

    batch = MagicMock()
    batch.update.side_effect = _record_update
    batch_ctx = MagicMock()
    batch_ctx.__enter__.return_value = batch
    batch_ctx.__exit__.return_value = None

    snap = MagicMock()
    # execute_sql returns [(source_stix_id, confidence), ...]
    snap.execute_sql.return_value = [
        (row["source_stix_id"], row["confidence"]) for row in existing_rows
    ]
    snap_ctx = MagicMock()
    snap_ctx.__enter__.return_value = snap
    snap_ctx.__exit__.return_value = None

    db = MagicMock()
    db.snapshot.return_value = snap_ctx
    db.batch.return_value = batch_ctx
    return db, updated


# ---------------------------------------------------------------------------
# Case 1 & 2: insert and upsert
# ---------------------------------------------------------------------------


class TestInsertAndUpsert:
    def test_attributed_to_actor_insert_new_row(self):
        db, recorded = _mock_db_with_existing("AttributedToActor", [], {})
        row = {
            "source_stix_id": "campaign--ca000001-0000-4000-8000-000000000001",
            "target_actor_stix_id": "threat-actor--aa000001-0000-4000-8000-000000000011",
            "source_type": "campaign",
            "target_type": "threat-actor",
            "confidence": 70,
            "description": None,
            "first_observed": None,
            "stix_id": "relationship--aa000001-0000-4000-8000-000000000001",
            "source": "trace",
        }
        written = upsert_attributed_to_actor(db, [row])
        assert written == 1
        assert len(recorded) == 1

    def test_impersonates_identity_upsert_updates_existing_row(self):
        existing_key = (
            "threat-actor--aa000001-0000-4000-8000-000000000011",
            "identity--1d000001-0000-4000-8000-000000000001",
        )
        db, recorded = _mock_db_with_existing(
            "ImpersonatesIdentity",
            ["source_stix_id", "identity_stix_id"],
            {existing_key: "trace"},
        )
        row = {
            "source_stix_id": "threat-actor--aa000001-0000-4000-8000-000000000011",
            "identity_stix_id": "identity--1d000001-0000-4000-8000-000000000001",
            "source_type": "threat-actor",
            "confidence": 85,
            "description": "updated",
            "first_observed": None,
            "stix_id": "relationship--ee000001-0000-4000-8000-000000000001",
            "effective_priority": 85,
            "source": "trace",
        }
        # Same-source (trace → trace) should overwrite per equal-rank rule
        written = upsert_impersonates_identity(db, [row])
        assert written == 1


# ---------------------------------------------------------------------------
# Case 3: precedence
# ---------------------------------------------------------------------------


class TestPrecedence:
    def test_trace_cannot_overwrite_manual(self):
        existing_key = (
            "threat-actor--aa000001-0000-4000-8000-000000000011",
            "identity--1d000001-0000-4000-8000-000000000001",
        )
        db, recorded = _mock_db_with_existing(
            "ImpersonatesIdentity",
            ["source_stix_id", "identity_stix_id"],
            {existing_key: "manual"},
        )
        row = {
            "source_stix_id": "threat-actor--aa000001-0000-4000-8000-000000000011",
            "identity_stix_id": "identity--1d000001-0000-4000-8000-000000000001",
            "source_type": "threat-actor",
            "confidence": 70,
            "description": None,
            "first_observed": None,
            "stix_id": "relationship--ee000002-0000-4000-8000-000000000002",
            "effective_priority": 70,
            "source": "trace",
        }
        written = upsert_impersonates_identity(db, [row])
        assert written == 0
        # No batch.insert_or_update should have been called
        assert recorded == []

    def test_beacon_cannot_overwrite_manual_on_attributed_to_identity(self):
        existing_key = (
            "threat-actor--aa000001-0000-4000-8000-000000000011",
            "identity--1d000001-0000-4000-8000-000000000001",
        )
        db, recorded = _mock_db_with_existing(
            "AttributedToIdentity",
            ["source_stix_id", "identity_stix_id"],
            {existing_key: "manual"},
        )
        row = {
            "source_stix_id": "threat-actor--aa000001-0000-4000-8000-000000000011",
            "identity_stix_id": "identity--1d000001-0000-4000-8000-000000000001",
            "source_type": "threat-actor",
            "confidence": 85,
            "description": None,
            "first_observed": None,
            "stix_id": "relationship--aa000005-0000-4000-8000-000000000005",
            "source": "beacon",
        }
        written = upsert_attributed_to_identity(db, [row])
        assert written == 0
        assert recorded == []


# ---------------------------------------------------------------------------
# Case 4: effective_priority recompute on Identity roles change
# ---------------------------------------------------------------------------


class TestEffectivePriorityRecompute:
    def test_recompute_elevates_priority_when_role_added(self):
        # Existing ImpersonatesIdentity row has confidence=70 with no roles
        # (effective_priority was 70). Now Identity gains "cfo" role → 1.5x boost.
        existing = [
            {
                "source_stix_id": "threat-actor--ta000001-0000-4000-8000-000000000001",
                "confidence": 70,
            }
        ]
        db, updated = _mock_db_for_recompute(existing)

        count = recompute_effective_priority_for_identity(
            db,
            "identity--id000001-0000-4000-8000-000000000001",
            ["cfo"],
        )

        assert count == 1
        assert len(updated) == 1
        _table, columns, values = updated[0]
        assert "effective_priority" in columns
        # min(100, int(70 * 1.5)) = 100
        ep_idx = columns.index("effective_priority")
        assert values[0][ep_idx] == 100

    def test_recompute_no_rows_is_noop(self):
        db, updated = _mock_db_for_recompute([])
        count = recompute_effective_priority_for_identity(
            db, "identity--id000099-0000-4000-8000-000000000099", []
        )
        assert count == 0
        assert updated == []
