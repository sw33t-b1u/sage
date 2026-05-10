"""Tests for spanner/upsert.py::upsert_has_access (Initiative A §7.4).

Precedence rules: ``manual > beacon > trace``. An incoming row writes
only when its ``source`` rank is equal-or-higher than the existing
row's source.
"""

from __future__ import annotations

from unittest.mock import MagicMock

from sage.spanner.upsert import upsert_has_access


def _ts() -> str:
    return "2026-05-10T00:00:00.000Z"


def _mock_db_with_existing(existing: dict[tuple[str, str], str]):
    """Return (mock Database, recorded inserts).

    ``existing`` maps (identity_stix_id, asset_id) → ``source`` of an
    already-present row. The snapshot.read mock yields tuples
    (identity_stix_id, asset_id, source) for each entry; batch records
    the table writes the function makes.
    """
    inserts: list[tuple[str, list[str], list[tuple]]] = []

    def _record(table, columns, values):
        inserts.append((table, list(columns), list(values)))

    batch = MagicMock()
    batch.insert_or_update.side_effect = _record
    batch_ctx = MagicMock()
    batch_ctx.__enter__.return_value = batch
    batch_ctx.__exit__.return_value = None

    snap = MagicMock()
    snap.read.return_value = [(ident, asset, src) for (ident, asset), src in existing.items()]
    snap_ctx = MagicMock()
    snap_ctx.__enter__.return_value = snap
    snap_ctx.__exit__.return_value = None

    db = MagicMock()
    db.snapshot.return_value = snap_ctx
    db.batch.return_value = batch_ctx
    return db, inserts


def _row(ident: str, asset: str, source: str) -> dict:
    return {
        "identity_stix_id": ident,
        "asset_id": asset,
        "access_level": "read",
        "role": "tester",
        "granted_at": None,
        "revoked_at": None,
        "source": source,
        "confidence": 50,
        "stix_modified": _ts(),
    }


class TestPrecedence:
    def test_manual_overwrites_beacon(self):
        db, inserts = _mock_db_with_existing({("identity--a", "asset-1"): "beacon"})
        written = upsert_has_access(db, [_row("identity--a", "asset-1", "manual")])
        assert written == 1
        assert len(inserts) == 1

    def test_beacon_overwrites_trace(self):
        db, inserts = _mock_db_with_existing({("identity--a", "asset-1"): "trace"})
        written = upsert_has_access(db, [_row("identity--a", "asset-1", "beacon")])
        assert written == 1

    def test_trace_does_not_overwrite_beacon(self):
        db, inserts = _mock_db_with_existing({("identity--a", "asset-1"): "beacon"})
        written = upsert_has_access(db, [_row("identity--a", "asset-1", "trace")])
        assert written == 0
        # No batch.insert_or_update call when nothing accepted.
        assert inserts == []

    def test_trace_does_not_overwrite_manual(self):
        db, inserts = _mock_db_with_existing({("identity--a", "asset-1"): "manual"})
        written = upsert_has_access(db, [_row("identity--a", "asset-1", "trace")])
        assert written == 0
        assert inserts == []

    def test_beacon_does_not_overwrite_manual(self):
        db, inserts = _mock_db_with_existing({("identity--a", "asset-1"): "manual"})
        written = upsert_has_access(db, [_row("identity--a", "asset-1", "beacon")])
        assert written == 0
        assert inserts == []

    def test_same_source_overwrites(self):
        # Equal rank still allows overwrite — re-running BEACON regen
        # must update its own rows (e.g. revoked_at change).
        db, inserts = _mock_db_with_existing({("identity--a", "asset-1"): "beacon"})
        written = upsert_has_access(db, [_row("identity--a", "asset-1", "beacon")])
        assert written == 1


class TestNewRows:
    def test_new_row_is_written_regardless_of_source(self):
        # No existing row → write proceeds.
        for source in ("trace", "beacon", "manual"):
            db, inserts = _mock_db_with_existing({})
            written = upsert_has_access(db, [_row("identity--x", "asset-1", source)])
            assert written == 1, f"source={source}"

    def test_empty_input_is_noop(self):
        db, inserts = _mock_db_with_existing({})
        assert upsert_has_access(db, []) == 0
        assert inserts == []


class TestMixedBatch:
    def test_some_accepted_some_skipped(self):
        existing = {
            ("identity--a", "asset-1"): "manual",  # blocks lower-precedence
            ("identity--b", "asset-1"): "trace",  # accepts beacon
        }
        db, inserts = _mock_db_with_existing(existing)
        rows = [
            _row("identity--a", "asset-1", "trace"),  # skipped
            _row("identity--b", "asset-1", "beacon"),  # accepted
            _row("identity--c", "asset-1", "trace"),  # accepted (new)
        ]
        written = upsert_has_access(db, rows)
        assert written == 2
