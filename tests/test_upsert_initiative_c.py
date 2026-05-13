"""Tests for Initiative C upsert helpers (SAGE 0.8.0 Phase 1 + 0.9.0 Phase 2).

Covers AttributedToActor / AttributedToIdentity / ImpersonatesIdentity
precedence-aware upserts, effective_priority recompute cascade, and
PirPrioritizesImpersonationTarget derivation (Phase 2).
"""

from __future__ import annotations

from unittest.mock import MagicMock

import google.cloud.spanner as spanner

from sage.etl.worker import _derive_pir_prioritizes_impersonation_target
from sage.spanner.constants import effective_priority
from sage.spanner.upsert import (
    recompute_effective_priority_for_identity,
    upsert_attributed_to_actor,
    upsert_attributed_to_identity,
    upsert_impersonates_identity,
    upsert_pir_prioritizes_impersonation_target,
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

    # ---- Phase 2: flag-first effective_priority cases ----

    def test_flag_true_alone_gives_1_5_multiplier(self):
        # flag=True, no roles → multiplier 1.5 (flag-first, role is irrelevant)
        existing = [
            {
                "source_stix_id": "threat-actor--ta000002-0000-4000-8000-000000000002",
                "confidence": 60,
            }
        ]
        db, updated = _mock_db_for_recompute(existing)
        count = recompute_effective_priority_for_identity(
            db,
            "identity--id000002-0000-4000-8000-000000000002",
            [],
            is_high_value_impersonation_target=True,
        )
        assert count == 1
        _table, columns, values = updated[0]
        ep_idx = columns.index("effective_priority")
        # min(100, int(60 * 1.5)) = 90
        assert values[0][ep_idx] == 90

    def test_flag_true_with_role_cfo_no_double_boost(self):
        # flag=True + role=cfo → multiplier 1.5, no double-boost (flag takes precedence)
        existing = [
            {
                "source_stix_id": "threat-actor--ta000003-0000-4000-8000-000000000003",
                "confidence": 80,
            }
        ]
        db, updated = _mock_db_for_recompute(existing)
        count = recompute_effective_priority_for_identity(
            db,
            "identity--id000003-0000-4000-8000-000000000003",
            ["cfo"],
            is_high_value_impersonation_target=True,
        )
        assert count == 1
        _table, columns, values = updated[0]
        ep_idx = columns.index("effective_priority")
        # min(100, int(80 * 1.5)) = 100
        assert values[0][ep_idx] == 100

    def test_flag_false_with_role_cfo_uses_role_fallback(self):
        # flag=False + role=cfo → multiplier 1.5 via HIGH_VALUE_IMPERSONATION_ROLES fallback
        existing = [
            {
                "source_stix_id": "threat-actor--ta000004-0000-4000-8000-000000000004",
                "confidence": 60,
            }
        ]
        db, updated = _mock_db_for_recompute(existing)
        count = recompute_effective_priority_for_identity(
            db,
            "identity--id000004-0000-4000-8000-000000000004",
            ["cfo"],
            is_high_value_impersonation_target=False,
        )
        assert count == 1
        _table, columns, values = updated[0]
        ep_idx = columns.index("effective_priority")
        # min(100, int(60 * 1.5)) = 90
        assert values[0][ep_idx] == 90

    def test_flag_false_no_role_gives_1_0_multiplier(self):
        # flag=False + no roles → multiplier 1.0
        existing = [
            {
                "source_stix_id": "threat-actor--ta000005-0000-4000-8000-000000000005",
                "confidence": 60,
            }
        ]
        db, updated = _mock_db_for_recompute(existing)
        count = recompute_effective_priority_for_identity(
            db,
            "identity--id000005-0000-4000-8000-000000000005",
            [],
            is_high_value_impersonation_target=False,
        )
        assert count == 1
        _table, columns, values = updated[0]
        ep_idx = columns.index("effective_priority")
        # min(100, int(60 * 1.0)) = 60
        assert values[0][ep_idx] == 60


# ---------------------------------------------------------------------------
# Phase 2: effective_priority unit tests (constants module)
# ---------------------------------------------------------------------------


class TestEffectivePriorityUnit:
    def test_flag_true_no_role(self):
        assert effective_priority(60, [], is_high_value_impersonation_target=True) == 90

    def test_flag_true_with_role_cfo_no_double_boost(self):
        # flag takes precedence; result same as flag-only
        assert effective_priority(80, ["cfo"], is_high_value_impersonation_target=True) == 100

    def test_flag_false_with_role_cfo(self):
        assert effective_priority(60, ["cfo"], is_high_value_impersonation_target=False) == 90

    def test_flag_false_no_role(self):
        assert effective_priority(60, [], is_high_value_impersonation_target=False) == 60

    def test_backward_compat_default_flag(self):
        # Calling with old 2-arg signature (flag omitted) behaves as flag=False
        assert effective_priority(70, ["cfo"]) == 100
        assert effective_priority(70, []) == 70

    def test_confidence_none_defaults_to_50(self):
        assert effective_priority(None, [], is_high_value_impersonation_target=True) == 75

    def test_capped_at_100(self):
        assert effective_priority(100, ["cfo"], is_high_value_impersonation_target=True) == 100


# ---------------------------------------------------------------------------
# Phase 2: PirPrioritizesImpersonationTarget derivation and upsert
# ---------------------------------------------------------------------------


class TestPirPrioritizesImpersonationTarget:
    """Tests for _derive_pir_prioritizes_impersonation_target (in-memory) and
    upsert_pir_prioritizes_impersonation_target."""

    def _impersonates_row(
        self,
        source_stix_id: str,
        identity_stix_id: str,
        effective_priority: int = 90,
    ) -> dict:
        return {
            "source_stix_id": source_stix_id,
            "identity_stix_id": identity_stix_id,
            "source_type": "threat-actor",
            "confidence": 60,
            "description": None,
            "first_observed": None,
            "stix_id": "relationship--pp000001-0000-4000-8000-000000000001",
            "effective_priority": effective_priority,
            "source": "trace",
        }

    def test_row_created_when_flag_true_and_tags_intersect(self):
        imp_rows = [
            self._impersonates_row(
                "threat-actor--ta000010-0000-4000-8000-000000000010",
                "identity--id000010-0000-4000-8000-000000000010",
                effective_priority=90,
            )
        ]
        identity_flag_map = {"identity--id000010-0000-4000-8000-000000000010": True}
        actor_tags_map = {
            "threat-actor--ta000010-0000-4000-8000-000000000010": ["apt-china", "espionage"]
        }
        pir_rows = [{"pir_id": "pir-001", "threat_actor_tags": ["espionage"]}]

        result = _derive_pir_prioritizes_impersonation_target(
            imp_rows, identity_flag_map, actor_tags_map, pir_rows
        )

        assert len(result) == 1
        row = result[0]
        assert row["pir_id"] == "pir-001"
        assert row["identity_stix_id"] == "identity--id000010-0000-4000-8000-000000000010"
        assert row["source_stix_id"] == "threat-actor--ta000010-0000-4000-8000-000000000010"
        assert row["effective_priority"] == 90

    def test_no_row_when_flag_false(self):
        imp_rows = [
            self._impersonates_row(
                "threat-actor--ta000011-0000-4000-8000-000000000011",
                "identity--id000011-0000-4000-8000-000000000011",
            )
        ]
        identity_flag_map = {"identity--id000011-0000-4000-8000-000000000011": False}
        actor_tags_map = {"threat-actor--ta000011-0000-4000-8000-000000000011": ["espionage"]}
        pir_rows = [{"pir_id": "pir-001", "threat_actor_tags": ["espionage"]}]

        result = _derive_pir_prioritizes_impersonation_target(
            imp_rows, identity_flag_map, actor_tags_map, pir_rows
        )
        assert result == []

    def test_no_row_when_tags_do_not_intersect(self):
        imp_rows = [
            self._impersonates_row(
                "threat-actor--ta000012-0000-4000-8000-000000000012",
                "identity--id000012-0000-4000-8000-000000000012",
            )
        ]
        identity_flag_map = {"identity--id000012-0000-4000-8000-000000000012": True}
        actor_tags_map = {"threat-actor--ta000012-0000-4000-8000-000000000012": ["hacktivism"]}
        pir_rows = [{"pir_id": "pir-001", "threat_actor_tags": ["espionage"]}]

        result = _derive_pir_prioritizes_impersonation_target(
            imp_rows, identity_flag_map, actor_tags_map, pir_rows
        )
        assert result == []

    def test_dedup_behavior_on_repeated_upsert(self):
        """Two identical derives should produce idempotent upserts (INSERT OR UPDATE)."""
        imp_rows = [
            self._impersonates_row(
                "threat-actor--ta000013-0000-4000-8000-000000000013",
                "identity--id000013-0000-4000-8000-000000000013",
                effective_priority=90,
            )
        ]
        identity_flag_map = {"identity--id000013-0000-4000-8000-000000000013": True}
        actor_tags_map = {"threat-actor--ta000013-0000-4000-8000-000000000013": ["financial"]}
        pir_rows = [{"pir_id": "pir-002", "threat_actor_tags": ["financial"]}]

        result1 = _derive_pir_prioritizes_impersonation_target(
            imp_rows, identity_flag_map, actor_tags_map, pir_rows
        )
        result2 = _derive_pir_prioritizes_impersonation_target(
            imp_rows, identity_flag_map, actor_tags_map, pir_rows
        )
        # Identical rows → same output; upsert_pir_prioritizes_impersonation_target
        # uses INSERT OR UPDATE so the second write is idempotent.
        assert result1 == result2

    def test_multiple_pir_rows_produce_multiple_edges(self):
        imp_rows = [
            self._impersonates_row(
                "threat-actor--ta000014-0000-4000-8000-000000000014",
                "identity--id000014-0000-4000-8000-000000000014",
                effective_priority=75,
            )
        ]
        identity_flag_map = {"identity--id000014-0000-4000-8000-000000000014": True}
        actor_tags_map = {
            "threat-actor--ta000014-0000-4000-8000-000000000014": ["espionage", "financial"]
        }
        pir_rows = [
            {"pir_id": "pir-A", "threat_actor_tags": ["espionage"]},
            {"pir_id": "pir-B", "threat_actor_tags": ["financial"]},
            {"pir_id": "pir-C", "threat_actor_tags": ["hacktivism"]},  # no match
        ]

        result = _derive_pir_prioritizes_impersonation_target(
            imp_rows, identity_flag_map, actor_tags_map, pir_rows
        )
        assert len(result) == 2
        pir_ids = {r["pir_id"] for r in result}
        assert pir_ids == {"pir-A", "pir-B"}

    def test_upsert_pir_prioritizes_impersonation_target_writes_rows(self):
        """upsert_pir_prioritizes_impersonation_target calls insert_or_update with commit_ts."""
        recorded: list[tuple] = []

        def _record(table=None, columns=None, values=None, **_kw):
            recorded.append((table, list(columns), [list(v) for v in values]))

        batch = MagicMock()
        batch.insert_or_update.side_effect = _record
        batch_ctx = MagicMock()
        batch_ctx.__enter__.return_value = batch
        batch_ctx.__exit__.return_value = None

        db = MagicMock()
        db.batch.return_value = batch_ctx

        rows = [
            {
                "pir_id": "pir-001",
                "identity_stix_id": "identity--id000015-0000-4000-8000-000000000015",
                "source_stix_id": "threat-actor--ta000015-0000-4000-8000-000000000015",
                "effective_priority": 90,
            }
        ]
        written = upsert_pir_prioritizes_impersonation_target(db, rows)
        assert written == 1
        assert len(recorded) == 1
        _table, columns, values = recorded[0]
        assert _table == "PirPrioritizesImpersonationTarget"
        assert "derived_at" in columns
        derived_at_idx = columns.index("derived_at")
        # derived_at must be replaced with COMMIT_TIMESTAMP sentinel
        assert values[0][derived_at_idx] is spanner.COMMIT_TIMESTAMP
