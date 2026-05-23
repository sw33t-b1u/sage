"""Temporal-window tests for ``sage.spanner.query`` (Initiative F Phase 7).

Validates that ``find_actor_ttps`` and ``find_asset_exposure`` bind
since/until into the Spanner parameter dict and inject the matching
``last_observed`` filter into the SQL — and that the pre-Initiative-F
behaviour (no temporal filter) is preserved when both bounds are None.
"""

from __future__ import annotations

from datetime import date, datetime, timedelta
from unittest.mock import MagicMock

from sage.spanner.query import (
    _to_window_bounds,
    find_actor_ttps,
    find_asset_exposure,
)


def _make_db(rows: list[list]) -> MagicMock:
    snap = MagicMock()
    snap.execute_sql.return_value = rows
    ctx = MagicMock()
    ctx.__enter__ = MagicMock(return_value=snap)
    ctx.__exit__ = MagicMock(return_value=False)
    db = MagicMock()
    db.snapshot.return_value = ctx
    return db


def _captured(db: MagicMock) -> tuple[str, dict, dict | None]:
    """Return (sql, params, param_types) of the latest execute_sql call."""
    snap = db.snapshot().__enter__()
    call = snap.execute_sql.call_args
    sql = call.args[0]
    params = call.kwargs.get("params") or (call.args[1] if len(call.args) > 1 else {})
    param_types = call.kwargs.get("param_types") or (call.args[2] if len(call.args) > 2 else None)
    return sql, params, param_types


class TestWindowBoundConversion:
    def test_none_passes_through(self):
        assert _to_window_bounds(None, None) == (None, None)

    def test_since_snaps_to_midnight(self):
        since_dt, _ = _to_window_bounds(date(2026, 5, 1), None)
        assert since_dt == datetime(2026, 5, 1, 0, 0, 0)

    def test_until_snaps_to_next_midnight_exclusive(self):
        # until=2026-05-01 means "include all of 2026-05-01" so the
        # exclusive upper bound used in SQL is 2026-05-02 00:00:00.
        _, until_dt = _to_window_bounds(None, date(2026, 5, 1))
        assert until_dt == datetime(2026, 5, 2, 0, 0, 0)

    def test_same_day_window_is_one_calendar_day(self):
        since_dt, until_dt = _to_window_bounds(date(2026, 5, 1), date(2026, 5, 1))
        assert (until_dt - since_dt) == timedelta(days=1)


class TestFindActorTTPsTemporal:
    def test_default_no_window_unchanged_sql(self):
        db = _make_db([])
        find_actor_ttps(db, actor_stix_id="intrusion-set--apt99")
        sql, params, _ = _captured(db)
        assert "since" not in params
        assert "until" not in params
        assert "@since" not in sql
        assert "@until" not in sql

    def test_since_only_binds_lower_bound(self):
        db = _make_db([])
        find_actor_ttps(
            db,
            actor_stix_id="intrusion-set--apt99",
            since=date(2025, 11, 1),
        )
        sql, params, ptypes = _captured(db)
        assert params["since"] == datetime(2025, 11, 1, 0, 0, 0)
        assert "since" in ptypes
        assert "u.last_observed >= @since" in sql
        assert "@until" not in sql

    def test_until_only_binds_upper_bound_as_next_day(self):
        db = _make_db([])
        find_actor_ttps(
            db,
            actor_stix_id="intrusion-set--apt99",
            until=date(2026, 5, 1),
        )
        sql, params, _ = _captured(db)
        assert params["until"] == datetime(2026, 5, 2, 0, 0, 0)
        assert "u.last_observed < @until" in sql

    def test_full_window_binds_both(self):
        db = _make_db([])
        find_actor_ttps(
            db,
            actor_stix_id="intrusion-set--apt99",
            since=date(2025, 11, 1),
            until=date(2026, 5, 1),
        )
        sql, params, _ = _captured(db)
        assert params["actor_id"] == "intrusion-set--apt99"
        assert params["since"] == datetime(2025, 11, 1, 0, 0, 0)
        assert params["until"] == datetime(2026, 5, 2, 0, 0, 0)
        assert "u.last_observed >= @since" in sql
        assert "u.last_observed < @until" in sql

    def test_result_shape_preserved(self):
        db = _make_db(
            [
                [
                    "attack-pattern--t1078",
                    "Valid Accounts",
                    "attack-pattern--t1068",
                    "Priv Esc",
                    0.72,
                    "threat_intel",
                ]
            ]
        )
        result = find_actor_ttps(
            db,
            actor_stix_id="intrusion-set--apt99",
            since=date(2025, 11, 1),
            until=date(2026, 5, 1),
        )
        assert result == [
            {
                "src_ttp_stix_id": "attack-pattern--t1078",
                "src_ttp_name": "Valid Accounts",
                "dst_ttp_stix_id": "attack-pattern--t1068",
                "dst_ttp_name": "Priv Esc",
                "weight": 0.72,
                "source": "threat_intel",
            }
        ]


class TestFindAssetExposureTemporal:
    def test_default_no_window_uses_no_params(self):
        db = _make_db([])
        find_asset_exposure(db)
        sql, params, _ = _captured(db)
        assert params == {}
        assert "@since" not in sql
        assert "@until" not in sql

    def test_window_binds_both_to_uses_last_observed(self):
        db = _make_db([])
        find_asset_exposure(
            db,
            since=date(2025, 11, 1),
            until=date(2026, 5, 1),
        )
        sql, params, _ = _captured(db)
        assert params["since"] == datetime(2025, 11, 1, 0, 0, 0)
        assert params["until"] == datetime(2026, 5, 2, 0, 0, 0)
        assert "u.last_observed >= @since" in sql
        assert "u.last_observed < @until" in sql

    def test_result_shape_preserved(self):
        db = _make_db([["asset-001", "WebServer", 9.0, 2, 12]])
        result = find_asset_exposure(db, since=date(2025, 11, 1), until=date(2026, 5, 1))
        assert result == [
            {
                "asset_id": "asset-001",
                "asset_name": "WebServer",
                "pir_adjusted_criticality": 9.0,
                "targeting_actor_count": 2,
                "reachable_ttp_count": 12,
            }
        ]
