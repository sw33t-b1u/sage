"""sage.spanner.query のユニットテスト。

Spanner エミュレーターの GQL サポートが限定的なため、
database.snapshot() をモックして各クエリ関数の出力形式・ロジックを検証する。
"""

from __future__ import annotations

from unittest.mock import MagicMock

import pytest

from sage.spanner.query import (
    find_actor_ttps,
    find_asset_exposure,
    find_attack_paths,
    find_choke_points,
)


def _make_db(rows: list[list]) -> MagicMock:
    """database.snapshot().execute_sql() が rows を返すモックを作成する。"""
    snap = MagicMock()
    snap.execute_sql.return_value = rows
    ctx = MagicMock()
    ctx.__enter__ = MagicMock(return_value=snap)
    ctx.__exit__ = MagicMock(return_value=False)
    db = MagicMock()
    db.snapshot.return_value = ctx
    return db


class TestFindAttackPaths:
    def test_returns_dicts_with_expected_keys(self):
        mock_rows = [
            ["intrusion-set--apt99", "APT99", "attack-pattern--t1078", "Valid Accounts", 90],
            ["intrusion-set--apt99", "APT99", "attack-pattern--t1068", "Priv Esc", 85],
        ]
        db = _make_db(mock_rows)

        result = find_attack_paths(db, asset_id="asset-001", limit=10)

        assert len(result) == 2
        assert result[0]["actor_stix_id"] == "intrusion-set--apt99"
        assert result[0]["actor_name"] == "APT99"
        assert result[0]["ttp_stix_id"] == "attack-pattern--t1078"
        assert result[0]["confidence"] == 90

    def test_empty_result_returns_empty_list(self):
        db = _make_db([])
        result = find_attack_paths(db, asset_id="asset-001")
        assert result == []

    def test_passes_asset_id_and_limit_as_params(self):
        db = _make_db([])
        find_attack_paths(db, asset_id="asset-xyz", limit=5)
        snap = db.snapshot().__enter__()
        call_kwargs = snap.execute_sql.call_args
        assert call_kwargs[1]["params"]["asset_id"] == "asset-xyz"
        assert call_kwargs[1]["params"]["limit"] == 5


class TestFindActorTTPs:
    def test_returns_followed_by_edges(self):
        mock_rows = [
            [
                "attack-pattern--t1078", "Valid Accounts",
                "attack-pattern--t1068", "Priv Esc",
                0.72, "threat_intel",
            ],
        ]
        db = _make_db(mock_rows)

        result = find_actor_ttps(db, actor_stix_id="intrusion-set--apt99")

        assert len(result) == 1
        assert result[0]["src_ttp_stix_id"] == "attack-pattern--t1078"
        assert result[0]["dst_ttp_stix_id"] == "attack-pattern--t1068"
        assert result[0]["weight"] == pytest.approx(0.72)
        assert result[0]["source"] == "threat_intel"

    def test_empty_result_returns_empty_list(self):
        db = _make_db([])
        result = find_actor_ttps(db, actor_stix_id="intrusion-set--unknown")
        assert result == []


class TestFindChokePoints:
    def test_returns_choke_score(self):
        mock_rows = [
            ["asset-001", "WebServer", 9.0, 3, 27.0],
            ["asset-002", "Backup",    6.0, 2, 12.0],
        ]
        db = _make_db(mock_rows)

        result = find_choke_points(db, top_n=10)

        assert len(result) == 2
        assert result[0]["asset_id"] == "asset-001"
        assert result[0]["choke_score"] == pytest.approx(27.0)
        assert result[0]["targeting_actor_count"] == 3

    def test_passes_top_n_as_param(self):
        db = _make_db([])
        find_choke_points(db, top_n=5)
        snap = db.snapshot().__enter__()
        call_kwargs = snap.execute_sql.call_args
        assert call_kwargs[1]["params"]["top_n"] == 5

    def test_empty_result_returns_empty_list(self):
        db = _make_db([])
        result = find_choke_points(db)
        assert result == []


class TestFindAssetExposure:
    def test_returns_exposure_data(self):
        mock_rows = [
            ["asset-001", "WebServer", 9.0, 2, 12],
        ]
        db = _make_db(mock_rows)

        result = find_asset_exposure(db)

        assert len(result) == 1
        assert result[0]["asset_id"] == "asset-001"
        assert result[0]["targeting_actor_count"] == 2
        assert result[0]["reachable_ttp_count"] == 12
        assert result[0]["pir_adjusted_criticality"] == pytest.approx(9.0)

    def test_empty_result_returns_empty_list(self):
        db = _make_db([])
        result = find_asset_exposure(db)
        assert result == []
