"""tests/test_api.py — FastAPI Analysis API エンドポイントのテスト。

TestClient を用いてエンドポイントごとの正常系・異常系を検証する。
Spanner と外部サービスはすべてモックする。
"""

from __future__ import annotations

from unittest.mock import MagicMock, patch

import pytest
from fastapi.testclient import TestClient

from sage.api.app import app

# ---------------------------------------------------------------------------
# TestClient セットアップ: lifespan をモックして Spanner 接続を省く
# ---------------------------------------------------------------------------


@pytest.fixture()
def client():
    mock_db = MagicMock()
    mock_config = MagicMock()
    mock_config.caldera_url = ""
    mock_config.caldera_api_key = ""
    mock_config.api_auth_token = ""  # Auth disabled — existing tests run without tokens

    # lifespan 内の Config.from_env() と Spanner 接続をモックして env var 依存を排除
    with (
        patch("sage.api.app.Config.from_env", return_value=mock_config),
        patch("sage.api.app.spanner.Client"),
    ):
        with TestClient(app, raise_server_exceptions=True) as c:
            # lifespan が app.state を上書きするため、起動後に差し替える
            c.app.state.database = mock_db
            c.app.state.config = mock_config
            yield c, mock_db


@pytest.fixture()
def authed_client():
    """Client with API authentication enabled (SAGE_API_AUTH_TOKEN set)."""
    mock_db = MagicMock()
    mock_config = MagicMock()
    mock_config.caldera_url = ""
    mock_config.caldera_api_key = ""
    mock_config.api_auth_token = "test-secret-token"

    with (
        patch("sage.api.app.Config.from_env", return_value=mock_config),
        patch("sage.api.app.spanner.Client"),
    ):
        with TestClient(app, raise_server_exceptions=True) as c:
            c.app.state.database = mock_db
            c.app.state.config = mock_config
            yield c, mock_db


# ---------------------------------------------------------------------------
# /attack-paths
# ---------------------------------------------------------------------------


class TestAttackPaths:
    def test_success(self, client):
        c, db = client
        rows = [{"actor_stix_id": "intrusion-set--apt99", "ttp_stix_id": "attack-pattern--t1078"}]
        with patch("sage.api.app.find_attack_paths", return_value=rows):
            resp = c.get("/attack-paths", params={"asset_id": "asset-001"})
        assert resp.status_code == 200
        assert resp.json() == rows

    def test_missing_asset_id(self, client):
        c, _ = client
        resp = c.get("/attack-paths")
        assert resp.status_code == 422

    def test_server_error(self, client):
        c, _ = client
        with patch("sage.api.app.find_attack_paths", side_effect=Exception("db error")):
            resp = c.get("/attack-paths", params={"asset_id": "asset-001"})
        assert resp.status_code == 500


# ---------------------------------------------------------------------------
# /choke-points
# ---------------------------------------------------------------------------


class TestChokePoints:
    def test_success(self, client):
        c, _ = client
        rows = [{"asset_id": "asset-001", "choke_score": 27.0}]
        with patch("sage.api.app.find_choke_points", return_value=rows):
            resp = c.get("/choke-points")
        assert resp.status_code == 200
        assert len(resp.json()) == 1

    def test_top_n_validation(self, client):
        c, _ = client
        resp = c.get("/choke-points", params={"top_n": 0})
        assert resp.status_code == 422


# ---------------------------------------------------------------------------
# /actor-ttps
# ---------------------------------------------------------------------------


class TestActorTtps:
    def test_success(self, client):
        c, _ = client
        rows = [{"src_ttp_stix_id": "attack-pattern--t1078", "weight": 0.8}]
        with patch("sage.api.app.find_actor_ttps", return_value=rows):
            resp = c.get("/actor-ttps", params={"actor_id": "intrusion-set--apt99"})
        assert resp.status_code == 200

    def test_missing_actor_id(self, client):
        c, _ = client
        resp = c.get("/actor-ttps")
        assert resp.status_code == 422


# ---------------------------------------------------------------------------
# /asset-exposure
# ---------------------------------------------------------------------------


class TestAssetExposure:
    def test_success(self, client):
        c, _ = client
        rows = [{"asset_id": "asset-001", "pir_adjusted_criticality": 9.0}]
        with patch("sage.api.app.find_asset_exposure", return_value=rows):
            resp = c.get("/asset-exposure")
        assert resp.status_code == 200

    def test_server_error(self, client):
        c, _ = client
        with patch("sage.api.app.find_asset_exposure", side_effect=Exception("timeout")):
            resp = c.get("/asset-exposure")
        assert resp.status_code == 500


# ---------------------------------------------------------------------------
# /similar-incidents
# ---------------------------------------------------------------------------


class TestSimilarIncidents:
    def test_success(self, client):
        c, _ = client
        rows = [{"incident_id": "incident--ref-1", "hybrid_score": 0.83}]
        with patch("sage.api.app.find_similar_incidents", return_value=rows):
            resp = c.get("/similar-incidents", params={"incident_id": "incident--query"})
        assert resp.status_code == 200
        assert resp.json()[0]["hybrid_score"] == 0.83

    def test_missing_incident_id(self, client):
        c, _ = client
        resp = c.get("/similar-incidents")
        assert resp.status_code == 422

    def test_alpha_out_of_range(self, client):
        c, _ = client
        resp = c.get(
            "/similar-incidents",
            params={"incident_id": "incident--query", "alpha": 1.5},
        )
        assert resp.status_code == 422


# ---------------------------------------------------------------------------
# /caldera/adversary
# ---------------------------------------------------------------------------


class TestCalderaAdversary:
    def test_no_config_returns_503(self, client):
        c, _ = client
        resp = c.post("/caldera/adversary", params={"actor_id": "intrusion-set--apt99"})
        assert resp.status_code == 503

    def test_success_with_config(self, client):
        c, _ = client
        app.state.config.caldera_url = "http://caldera.internal:8888"
        app.state.config.caldera_api_key = "test-key"

        ttp_rows = [{"src_ttp_stix_id": "A", "dst_ttp_stix_id": "B"}]
        sync_result = {"action": "created", "adversary_id": "new-id", "ability_count": 2}

        with (
            patch("sage.api.app.find_actor_ttps", return_value=ttp_rows),
            patch("sage.api.app.sync_actor_ttps", return_value=sync_result),
        ):
            resp = c.post("/caldera/adversary", params={"actor_id": "intrusion-set--apt99"})

        assert resp.status_code == 200
        assert resp.json()["action"] == "created"

        # 後処理: config を元に戻す
        app.state.config.caldera_url = ""
        app.state.config.caldera_api_key = ""


# ---------------------------------------------------------------------------
# Authentication
# ---------------------------------------------------------------------------


class TestAuthentication:
    def test_no_token_returns_401(self, authed_client):
        c, _ = authed_client
        resp = c.get("/choke-points")
        assert resp.status_code == 401

    def test_wrong_token_returns_403(self, authed_client):
        c, _ = authed_client
        resp = c.get("/choke-points", headers={"Authorization": "Bearer wrong-token"})
        assert resp.status_code == 403

    def test_valid_token_allows_access(self, authed_client):
        c, _ = authed_client
        rows = [{"asset_id": "asset-001", "choke_score": 27.0}]
        with patch("sage.api.app.find_choke_points", return_value=rows):
            resp = c.get(
                "/choke-points",
                headers={"Authorization": "Bearer test-secret-token"},
            )
        assert resp.status_code == 200

    def test_auth_disabled_allows_all(self, client):
        """When api_auth_token is empty, all requests pass without token."""
        c, _ = client
        rows = [{"asset_id": "asset-001", "choke_score": 27.0}]
        with patch("sage.api.app.find_choke_points", return_value=rows):
            resp = c.get("/choke-points")
        assert resp.status_code == 200


# ---------------------------------------------------------------------------
# Error message sanitization
# ---------------------------------------------------------------------------


class TestErrorSanitization:
    def test_500_does_not_leak_internal_details(self, client):
        c, _ = client
        with patch(
            "sage.api.app.find_attack_paths",
            side_effect=Exception("Spanner connection to sage-db failed: auth expired"),
        ):
            resp = c.get("/attack-paths", params={"asset_id": "asset-001"})
        assert resp.status_code == 500
        assert "Spanner" not in resp.text
        assert "sage-db" not in resp.text
        assert resp.json()["detail"] == "Internal server error"
