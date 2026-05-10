"""ETLWorker.process_bundle dispatch tests.

Filed by SAGE 0.5.3 follow-up — the 0.5.0 → 0.5.3 incident showed that
mapper-only unit tests are insufficient: schema + mapper + parser were
all updated for the Identity SDO but worker.py and upsert.py callsites
were missed, and 22 identities + 26 targets edges were silently dropped
in production. These tests exercise the worker's full type-dispatch
table so a missing branch is caught at unit-test time.

Spanner is fully mocked. Each `_mock_db()` returns a database whose
`batch()` records every Spanner mutation; tests assert on the recorded
table names and row payloads.
"""

from __future__ import annotations

from collections.abc import Iterable
from unittest.mock import MagicMock

import pytest

from sage.etl.worker import ETLWorker
from sage.pir.filter import PIRFilter

# ---------------------------------------------------------------------------
# Test fixtures
# ---------------------------------------------------------------------------


def _mock_db() -> tuple[MagicMock, list[tuple[str, list[str], list[tuple]]]]:
    """Return (mock Database, recorded mutations).

    Recorded mutations are tuples of ``(table, columns, [row_tuples])`` —
    one entry per ``batch.insert_or_update(...)`` call.
    """
    recorded: list[tuple[str, list[str], list[tuple]]] = []

    def _record(table: str, columns: Iterable[str], values: Iterable[tuple]) -> None:
        recorded.append((table, list(columns), list(values)))

    batch = MagicMock()
    batch.insert_or_update.side_effect = _record

    batch_ctx = MagicMock()
    batch_ctx.__enter__.return_value = batch
    batch_ctx.__exit__.return_value = None

    db = MagicMock()
    db.batch.return_value = batch_ctx
    return db, recorded


_PIR_FINANCIAL_CRIME: dict = {
    "pir_id": "PIR-2026-001",
    "intelligence_level": "operational",
    "description": "Financial crime threats",
    "threat_actor_tags": ["financial-crime"],
    "asset_weight_rules": [{"tag": "database", "criticality_multiplier": 2.0}],
    "valid_from": "2026-05-09",
    "valid_until": "2026-11-05",
}


@pytest.fixture
def pir_filter():
    return PIRFilter([_PIR_FINANCIAL_CRIME])


@pytest.fixture
def worker(pir_filter):
    db, recorded = _mock_db()
    w = ETLWorker(db, pir_filter)
    return w, recorded


def _ts() -> str:
    return "2026-05-10T01:00:00.000Z"


def _row_count(recorded, table: str) -> int:
    return sum(len(rows) for tbl, _cols, rows in recorded if tbl == table)


def _mutated_tables(recorded) -> set[str]:
    return {tbl for tbl, _cols, _rows in recorded}


# ---------------------------------------------------------------------------
# Identity dispatch (the 0.5.3 wiring fix)
# ---------------------------------------------------------------------------


class TestIdentityDispatch:
    """Regression: 0.5.0 added schema + mapper + parser for identity but
    never wired the worker dispatch. This test would have flagged the gap.
    """

    def test_identity_objects_upserted_to_identity_table(self, worker):
        w, recorded = worker
        objects = [
            {
                "type": "identity",
                "id": "identity--abc",
                "name": "Acme Corp Finance",
                "identity_class": "organization",
                "modified": _ts(),
            }
        ]
        stats = w.process_bundle(objects)
        assert stats["identities"] == 1
        assert _row_count(recorded, "Identity") == 1

    def test_multiple_identity_objects_upserted(self, worker):
        w, recorded = worker
        objects = [
            {
                "type": "identity",
                "id": f"identity--{i}",
                "name": f"Org {i}",
                "modified": _ts(),
            }
            for i in range(5)
        ]
        stats = w.process_bundle(objects)
        assert stats["identities"] == 5
        assert _row_count(recorded, "Identity") == 5

    def test_identity_skipped_when_mapper_returns_none(self, worker):
        w, recorded = worker
        # Non-identity objects in by_type["identity"] would be impossible;
        # this guards against future mapper return-None branches (e.g.
        # required-field validation) leaking into the upsert path.
        objects = [{"type": "indicator", "id": "indicator--x", "modified": _ts()}]
        stats = w.process_bundle(objects)
        assert stats["identities"] == 0
        assert "Identity" not in _mutated_tables(recorded)


# ---------------------------------------------------------------------------
# ActorTargetsIdentity dispatch (the 0.5.3 wiring fix)
# ---------------------------------------------------------------------------


class TestActorTargetsIdentityDispatch:
    """Regression: actor → identity targets relationships were dropped
    silently in 0.5.0 because the worker had no branch for the
    ActorTargetsIdentity table returned by the mapper.
    """

    def test_actor_targets_identity_edge_upserted(self, worker):
        w, recorded = worker
        objects = [
            # Actor with PIR-matching tag so it survives the filter.
            {
                "type": "intrusion-set",
                "id": "intrusion-set--fin7",
                "name": "FIN7",
                "labels": ["financial-crime"],
                "modified": _ts(),
            },
            {
                "type": "identity",
                "id": "identity--victim",
                "name": "Victim Bank",
                "modified": _ts(),
            },
            {
                "type": "relationship",
                "id": "relationship--rel1",
                "relationship_type": "targets",
                "source_ref": "intrusion-set--fin7",
                "target_ref": "identity--victim",
                "modified": _ts(),
            },
        ]
        stats = w.process_bundle(objects)
        assert stats["actor_targets_identity"] == 1
        assert _row_count(recorded, "ActorTargetsIdentity") == 1

    def test_targets_to_non_identity_target_dropped_at_mapper(self, worker):
        # mapper.map_relationship returns None for targets relationships
        # whose target is not an identity (e.g. malware → vulnerability).
        # The worker should not even see a row to dispatch.
        w, recorded = worker
        objects = [
            {
                "type": "intrusion-set",
                "id": "intrusion-set--x",
                "name": "X",
                "labels": ["financial-crime"],
                "modified": _ts(),
            },
            {
                "type": "vulnerability",
                "id": "vulnerability--cve",
                "name": "CVE-2025-0001",
                "modified": _ts(),
            },
            {
                "type": "relationship",
                "id": "relationship--rel2",
                "relationship_type": "targets",
                "source_ref": "intrusion-set--x",
                "target_ref": "vulnerability--cve",
                "modified": _ts(),
            },
        ]
        stats = w.process_bundle(objects)
        assert stats["actor_targets_identity"] == 0


# ---------------------------------------------------------------------------
# PIR-filter referential integrity (0.5.3 follow-on fix)
# ---------------------------------------------------------------------------


class TestPirFilterReferentialIntegrity:
    """Regression: PIR-filtered actors must not leave dangling FK edges.

    The CISA AA22-108a Lazarus E2E showed that filtered actors' Uses /
    UsesTool / IndicatesActor / ActorTargetsIdentity edges were still
    written, producing 47 dangling references against an empty
    ThreatActor table.
    """

    def _objects_with_filtered_actor_and_dependent_edges(self) -> list[dict]:
        # Lazarus has apt-north-korea / espionage labels — does NOT match
        # the financial-crime PIR. The PIR filter drops the actor row.
        return [
            {
                "type": "intrusion-set",
                "id": "intrusion-set--lazarus",
                "name": "Lazarus",
                "labels": ["apt-north-korea", "espionage"],
                "modified": _ts(),
            },
            {
                "type": "attack-pattern",
                "id": "attack-pattern--t1059",
                "name": "Command and Scripting Interpreter",
                "external_references": [{"source_name": "mitre-attack", "external_id": "T1059"}],
                "modified": _ts(),
            },
            {
                "type": "tool",
                "id": "tool--cobaltstrike",
                "name": "Cobalt Strike",
                "modified": _ts(),
            },
            {
                "type": "identity",
                "id": "identity--victim",
                "name": "Crypto Exchange",
                "modified": _ts(),
            },
            # Uses: actor → TTP
            {
                "type": "relationship",
                "id": "relationship--uses",
                "relationship_type": "uses",
                "source_ref": "intrusion-set--lazarus",
                "target_ref": "attack-pattern--t1059",
                "modified": _ts(),
            },
            # UsesTool: actor → tool
            {
                "type": "relationship",
                "id": "relationship--usestool",
                "relationship_type": "uses",
                "source_ref": "intrusion-set--lazarus",
                "target_ref": "tool--cobaltstrike",
                "modified": _ts(),
            },
            # ActorTargetsIdentity: actor → identity
            {
                "type": "relationship",
                "id": "relationship--targets",
                "relationship_type": "targets",
                "source_ref": "intrusion-set--lazarus",
                "target_ref": "identity--victim",
                "modified": _ts(),
            },
        ]

    def test_filtered_actor_drops_dependent_uses_edge(self, worker):
        w, recorded = worker
        stats = w.process_bundle(self._objects_with_filtered_actor_and_dependent_edges())
        assert stats["threat_actors"] == 0
        assert stats["uses"] == 0  # filtered out — no dangling FK
        assert _row_count(recorded, "Uses") == 0

    def test_filtered_actor_drops_dependent_uses_tool_edge(self, worker):
        w, recorded = worker
        stats = w.process_bundle(self._objects_with_filtered_actor_and_dependent_edges())
        assert stats["uses_tool"] == 0
        assert _row_count(recorded, "UsesTool") == 0

    def test_filtered_actor_drops_dependent_actor_targets_identity_edge(self, worker):
        w, recorded = worker
        stats = w.process_bundle(self._objects_with_filtered_actor_and_dependent_edges())
        assert stats["actor_targets_identity"] == 0
        assert _row_count(recorded, "ActorTargetsIdentity") == 0

    def test_identity_node_unaffected_by_actor_filter(self, worker):
        # Identity is not actor-dependent; PIR filter on actors must not
        # cascade onto Identity rows.
        w, recorded = worker
        stats = w.process_bundle(self._objects_with_filtered_actor_and_dependent_edges())
        assert stats["identities"] == 1
        assert _row_count(recorded, "Identity") == 1

    def test_kept_actor_keeps_dependent_edges(self, worker):
        w, recorded = worker
        # FIN7 with financial-crime tag matches the PIR.
        objects = [
            {
                "type": "intrusion-set",
                "id": "intrusion-set--fin7",
                "name": "FIN7",
                "labels": ["financial-crime"],
                "modified": _ts(),
            },
            {
                "type": "attack-pattern",
                "id": "attack-pattern--t1059",
                "name": "Command and Scripting Interpreter",
                "external_references": [{"source_name": "mitre-attack", "external_id": "T1059"}],
                "modified": _ts(),
            },
            {
                "type": "relationship",
                "id": "relationship--uses",
                "relationship_type": "uses",
                "source_ref": "intrusion-set--fin7",
                "target_ref": "attack-pattern--t1059",
                "modified": _ts(),
            },
        ]
        stats = w.process_bundle(objects)
        assert stats["threat_actors"] == 1
        assert stats["uses"] == 1


# ---------------------------------------------------------------------------
# Type dispatch table coverage
# ---------------------------------------------------------------------------


class TestRelationshipDispatchCompleteness:
    """Whole-table check: every relationship type the mapper can return
    must have a worker branch. The 0.5.0 → 0.5.3 incident showed that a
    new mapper table (`ActorTargetsIdentity`) can land without a worker
    dispatch branch, silently dropping rows.

    Update ``_TABLE_TO_STATS_KEY`` when mapper.py adds a new table.
    """

    _TABLE_TO_STATS_KEY: dict[str, str] = {
        "Uses": "uses",
        "MalwareUsesTTP": "malware_uses_ttp",
        "UsesTool": "uses_tool",
        "Exploits": "exploits",
        "IndicatesTTP": "indicates_ttp",
        "IndicatesActor": "indicates_actor",
        "ActorTargetsIdentity": "actor_targets_identity",
    }

    def test_every_mapper_table_has_a_worker_stat_key(self, worker):
        # Empty-bundle process_bundle returns the canonical stats dict.
        # If a mapper table lacks a worker branch, its key won't appear.
        w, _recorded = worker
        stats = w.process_bundle([])
        for table, key in self._TABLE_TO_STATS_KEY.items():
            assert key in stats, (
                f"Worker stats missing key '{key}' for mapper table "
                f"'{table}' — likely a dispatch branch was added to "
                f"mapper.py without updating worker.py."
            )
