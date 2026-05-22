"""Tests for SAGE 0.10.0 actor_triage ingest path (Phase 6).

Covers:
  - DDL migration file content (PirPrioritizesActor ALTER + AnnotatesActor CREATE).
  - ingest_prioritized_actors() with BEACON 0.15.0-shaped fixture.
  - rationale_json fully populated (text + 3 factor dicts).
  - AnnotatesActor registered in _TABLE_COLUMNS (schema / read-path registration).
  - Graceful fallback when ScoreComponent sub-factors are missing (default 0.0).
  - likelihood stored as raw float (0.042 in → 0.042 stored; no rescale).
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any
from unittest.mock import MagicMock

import pytest

from sage.pir.ingest import ingest_prioritized_actors
from sage.spanner.upsert import _TABLE_COLUMNS

_MIGRATIONS_DIR = Path(__file__).parent.parent / "src" / "sage" / "spanner" / "migrations"
_MIGRATION_FILE = _MIGRATIONS_DIR / "20260522_120000_actor_rationale.sql"

# ---------------------------------------------------------------------------
# BEACON 0.15.0-shaped fixture — placeholder STIX IDs, no fabricated names
# ---------------------------------------------------------------------------

_ACTOR_ENTRY: dict[str, Any] = {
    "actor_id": "intrusion-set--00000000-0000-4000-8000-000000000001",
    "name": "TestActorZeta",
    "aliases": ["test-alias-z"],
    "likelihood": 0.042,
    "score_breakdown": {
        "intent": {
            "score": 0.25,
            "motivation_alignment": 0.5,
            "industry_match": 0.5,
        },
        "capability": {
            "score": 0.155,
            "sophistication_score": 0.667,
            "ttp_count_norm": 0.66,
            "recency_active_campaigns_90d": 0.25,
        },
        "opportunity": {
            "score": 0.029,
            "victimology_match": 1.0,
            "geographic_match": 0.047,
            "surface_ttp_coverage": 0.621,
        },
        "data_quality": {
            "degraded": False,
            "missing_sources": [],
        },
    },
    "rationale": {
        "text": "Likelihood = Intent(0.250) × Capability(0.155) × Opportunity(0.029) = 0.0011",
        "intent_factors": {"motivation_alignment": 0.5, "industry_match": 0.5},
        "capability_factors": {
            "sophistication_score": 0.667,
            "ttp_count_norm": 0.66,
            "recency_active_campaigns_90d": 0.25,
        },
        "opportunity_factors": {
            "victimology_match": 1.0,
            "geographic_match": 0.047,
            "surface_ttp_coverage": 0.621,
        },
    },
}


# ---------------------------------------------------------------------------
# Mock helpers
# ---------------------------------------------------------------------------


def _mock_db() -> tuple[MagicMock, list[tuple]]:
    """Return (mock Database, recorded mutations list)."""
    recorded: list[tuple] = []

    def _record(table: str, columns: list[str], values: list[tuple]) -> None:
        recorded.append((table, list(columns), list(values)))

    batch = MagicMock()
    batch.insert_or_update.side_effect = _record

    batch_ctx = MagicMock()
    batch_ctx.__enter__.return_value = batch
    batch_ctx.__exit__.return_value = None

    db = MagicMock()
    db.batch.return_value = batch_ctx
    return db, recorded


# ---------------------------------------------------------------------------
# DDL migration content tests
# ---------------------------------------------------------------------------


class TestDdlMigration:
    def test_migration_file_exists(self):
        assert _MIGRATION_FILE.exists(), f"Migration file not found: {_MIGRATION_FILE}"

    def test_migration_adds_likelihood_column(self):
        sql = _MIGRATION_FILE.read_text()
        assert "ADD COLUMN likelihood" in sql

    def test_migration_adds_rationale_json_column(self):
        sql = _MIGRATION_FILE.read_text()
        assert "ADD COLUMN rationale_json" in sql

    def test_migration_creates_annotates_actor_table(self):
        sql = _MIGRATION_FILE.read_text()
        assert "CREATE TABLE AnnotatesActor" in sql

    def test_migration_annotates_actor_has_correct_pk(self):
        sql = _MIGRATION_FILE.read_text()
        assert "PRIMARY KEY (annotator_id, actor_stix_id, created_at)" in sql

    def test_migration_includes_downgrade_comment(self):
        sql = _MIGRATION_FILE.read_text()
        assert "Downgrade" in sql or "downgrade" in sql.lower()

    def test_spanner_ddl_contains_annotates_actor(self):
        ddl_path = Path(__file__).parent.parent / "schema" / "spanner_ddl.sql"
        ddl = ddl_path.read_text()
        assert "CREATE TABLE AnnotatesActor" in ddl

    def test_spanner_ddl_contains_rationale_json_column(self):
        ddl_path = Path(__file__).parent.parent / "schema" / "spanner_ddl.sql"
        ddl = ddl_path.read_text()
        assert "rationale_json" in ddl


# ---------------------------------------------------------------------------
# AnnotatesActor schema registration
# ---------------------------------------------------------------------------


class TestAnnotatesActorRegistration:
    def test_annotates_actor_in_table_columns(self):
        assert "AnnotatesActor" in _TABLE_COLUMNS

    def test_annotates_actor_columns_match_ddl(self):
        expected = {
            "annotator_id",
            "actor_stix_id",
            "annotation_type",
            "payload_json",
            "created_at",
            "evidence_url",
        }
        assert set(_TABLE_COLUMNS["AnnotatesActor"]) == expected

    def test_pir_prioritizes_actor_has_new_columns(self):
        cols = _TABLE_COLUMNS["PirPrioritizesActor"]
        assert "likelihood" in cols
        assert "rationale_json" in cols
        assert "overlap_ratio" in cols  # original column preserved


# ---------------------------------------------------------------------------
# ingest_prioritized_actors — core ingest tests
# ---------------------------------------------------------------------------


class TestIngestPrioritizedActors:
    def test_single_actor_writes_one_row(self):
        db, recorded = _mock_db()
        count = ingest_prioritized_actors(db, "PIR-TEST-001", [_ACTOR_ENTRY])
        assert count == 1
        assert len(recorded) == 1

    def test_row_written_to_correct_table(self):
        db, recorded = _mock_db()
        ingest_prioritized_actors(db, "PIR-TEST-001", [_ACTOR_ENTRY])
        table, _cols, _vals = recorded[0]
        assert table == "PirPrioritizesActor"

    def test_pir_id_stored_correctly(self):
        db, recorded = _mock_db()
        ingest_prioritized_actors(db, "PIR-TEST-001", [_ACTOR_ENTRY])
        _, cols, values = recorded[0]
        idx = cols.index("pir_id")
        assert values[0][idx] == "PIR-TEST-001"

    def test_actor_stix_id_stored_correctly(self):
        db, recorded = _mock_db()
        ingest_prioritized_actors(db, "PIR-TEST-001", [_ACTOR_ENTRY])
        _, cols, values = recorded[0]
        idx = cols.index("actor_stix_id")
        assert values[0][idx] == "intrusion-set--00000000-0000-4000-8000-000000000001"

    def test_likelihood_raw_float_no_rescale(self):
        """0.042 in → 0.042 stored; no ×100 rescale."""
        db, recorded = _mock_db()
        ingest_prioritized_actors(db, "PIR-TEST-001", [_ACTOR_ENTRY])
        _, cols, values = recorded[0]
        idx = cols.index("likelihood")
        assert values[0][idx] == pytest.approx(0.042)

    def test_overlap_ratio_is_null_for_triage_rows(self):
        """overlap_ratio is NULL for triage-sourced rows (tag intersection not applicable)."""
        db, recorded = _mock_db()
        ingest_prioritized_actors(db, "PIR-TEST-001", [_ACTOR_ENTRY])
        _, cols, values = recorded[0]
        idx = cols.index("overlap_ratio")
        assert values[0][idx] is None

    def test_rationale_json_is_valid_json(self):
        db, recorded = _mock_db()
        ingest_prioritized_actors(db, "PIR-TEST-001", [_ACTOR_ENTRY])
        _, cols, values = recorded[0]
        idx = cols.index("rationale_json")
        parsed = json.loads(values[0][idx])
        assert isinstance(parsed, dict)

    def test_rationale_json_contains_all_four_fields(self):
        """Full Rationale: text + intent_factors + capability_factors + opportunity_factors."""
        db, recorded = _mock_db()
        ingest_prioritized_actors(db, "PIR-TEST-001", [_ACTOR_ENTRY])
        _, cols, values = recorded[0]
        idx = cols.index("rationale_json")
        parsed = json.loads(values[0][idx])
        assert "text" in parsed
        assert "intent_factors" in parsed
        assert "capability_factors" in parsed
        assert "opportunity_factors" in parsed

    def test_rationale_text_matches_source(self):
        db, recorded = _mock_db()
        ingest_prioritized_actors(db, "PIR-TEST-001", [_ACTOR_ENTRY])
        _, cols, values = recorded[0]
        idx = cols.index("rationale_json")
        parsed = json.loads(values[0][idx])
        assert "Intent" in parsed["text"]

    def test_rationale_intent_factors_populated(self):
        db, recorded = _mock_db()
        ingest_prioritized_actors(db, "PIR-TEST-001", [_ACTOR_ENTRY])
        _, cols, values = recorded[0]
        idx = cols.index("rationale_json")
        parsed = json.loads(values[0][idx])
        assert "motivation_alignment" in parsed["intent_factors"]
        assert "industry_match" in parsed["intent_factors"]

    def test_empty_prioritized_actors_returns_zero(self):
        db, recorded = _mock_db()
        count = ingest_prioritized_actors(db, "PIR-TEST-001", [])
        assert count == 0
        assert recorded == []

    def test_multiple_actors_all_written(self):
        entry2 = {
            **_ACTOR_ENTRY,
            "actor_id": "intrusion-set--00000000-0000-4000-8000-000000000002",
            "name": "TestActorEta",
            "likelihood": 0.001,
        }
        db, recorded = _mock_db()
        count = ingest_prioritized_actors(db, "PIR-TEST-001", [_ACTOR_ENTRY, entry2])
        assert count == 2


# ---------------------------------------------------------------------------
# Graceful fallback — missing sub-factors
# ---------------------------------------------------------------------------


class TestGracefulFallback:
    def test_missing_rationale_produces_empty_dicts(self):
        """Entry with no rationale key → rationale_json has empty dicts, empty text."""
        entry = {
            "actor_id": "intrusion-set--00000000-0000-4000-8000-000000000003",
            "name": "TestActorTheta",
            "likelihood": 0.01,
            "score_breakdown": {
                "intent": {"score": 0.1},
                "capability": {"score": 0.1},
                "opportunity": {"score": 0.1},
                "data_quality": {"degraded": True, "missing_sources": ["misp_galaxy"]},
            },
            # No "rationale" key — graceful fallback
        }
        db, recorded = _mock_db()
        count = ingest_prioritized_actors(db, "PIR-TEST-002", [entry])
        assert count == 1  # no exception

        _, cols, values = recorded[0]
        idx = cols.index("rationale_json")
        parsed = json.loads(values[0][idx])
        assert parsed["text"] == ""
        assert parsed["intent_factors"] == {}
        assert parsed["capability_factors"] == {}
        assert parsed["opportunity_factors"] == {}

    def test_missing_actor_id_skips_row(self):
        """Entry with no actor_id → skipped (not raised)."""
        entry = {
            "actor_id": "",
            "likelihood": 0.01,
            "rationale": {"text": "test"},
        }
        db, recorded = _mock_db()
        count = ingest_prioritized_actors(db, "PIR-TEST-003", [entry])
        assert count == 0
        assert recorded == []

    def test_none_likelihood_defaults_to_zero(self):
        """Entry with likelihood=None → stored as 0.0 (not raised)."""
        entry = {**_ACTOR_ENTRY, "likelihood": None}
        db, recorded = _mock_db()
        ingest_prioritized_actors(db, "PIR-TEST-004", [entry])
        _, cols, values = recorded[0]
        idx = cols.index("likelihood")
        assert values[0][idx] == 0.0

    def test_score_breakdown_with_no_sub_factors_in_components(self):
        """ScoreComponent with only 'score' and no sub-factors ingests without error."""
        entry = {
            **_ACTOR_ENTRY,
            "score_breakdown": {
                "intent": {"score": 0.2},
                "capability": {"score": 0.1},
                "opportunity": {"score": 0.05},
                "data_quality": {"degraded": False, "missing_sources": []},
            },
        }
        db, recorded = _mock_db()
        count = ingest_prioritized_actors(db, "PIR-TEST-005", [entry])
        assert count == 1  # no exception
