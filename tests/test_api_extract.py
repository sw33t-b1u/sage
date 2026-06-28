"""Tests for /indicators and /export/stix extraction endpoints."""

from __future__ import annotations

from unittest.mock import MagicMock, patch

import pytest
from fastapi.testclient import TestClient

from sage.api.app import app

ACTOR_1 = "intrusion-set--11111111-1111-1111-1111-111111111111"
OBS_1 = "indicator--dddddddd-dddd-dddd-dddd-ddddddddddd1"


@pytest.fixture()
def client():
    mock_db = MagicMock()
    mock_config = MagicMock()
    mock_config.caldera_url = ""
    mock_config.caldera_api_key = ""
    mock_config.api_auth_token = ""
    mock_config.activity_window_days = 90
    with (
        patch("sage.api.app.Config.from_env", return_value=mock_config),
        patch("sage.api.app.spanner.Client"),
    ):
        with TestClient(app, raise_server_exceptions=True) as c:
            c.app.state.database = mock_db
            c.app.state.config = mock_config
            yield c, mock_db


def _rows():
    return [
        {
            "observable_stix_id": OBS_1,
            "obs_type": "ip",
            "value": "203.0.113.10",
            "confidence": 80,
            "tlp": "amber",
            "first_seen": None,
            "last_seen": None,
            "actor_stix_id": ACTOR_1,
            "actor_stix_type": "intrusion-set",
            "actor_name": "APT99",
            "rel_confidence": 70,
        }
    ]


class TestIndicators:
    def test_success_multi_actor(self, client):
        c, _ = client
        with patch("sage.api.app.find_indicators_for_actors", return_value=_rows()) as mock_q:
            resp = c.get("/indicators", params=[("actor_id", ACTOR_1), ("actor_id", "x--2")])
        assert resp.status_code == 200
        body = resp.json()
        assert body["count"] == 1
        assert body["indicators"][0]["observable_stix_id"] == OBS_1
        # both selected actors forwarded
        assert mock_q.call_args[0][1] == [ACTOR_1, "x--2"]

    def test_requires_actor_id(self, client):
        c, _ = client
        resp = c.get("/indicators")
        assert resp.status_code == 422

    def test_server_error(self, client):
        c, _ = client
        with patch("sage.api.app.find_indicators_for_actors", side_effect=Exception("db")):
            resp = c.get("/indicators", params={"actor_id": ACTOR_1})
        assert resp.status_code == 500


class TestExportStix:
    def test_returns_bundle_json(self, client):
        c, _ = client
        with patch("sage.api.app.find_indicators_for_actors", return_value=_rows()):
            resp = c.get("/export/stix", params={"actor_id": ACTOR_1})
        assert resp.status_code == 200
        bundle = resp.json()
        assert bundle["type"] == "bundle"
        types = {o["type"] for o in bundle["objects"]}
        assert {"indicator", "intrusion-set", "relationship"}.issubset(types)

    def test_download_sets_attachment_header(self, client):
        c, _ = client
        with patch("sage.api.app.find_indicators_for_actors", return_value=_rows()):
            resp = c.get("/export/stix", params={"actor_id": ACTOR_1, "download": "true"})
        assert resp.status_code == 200
        assert "attachment" in resp.headers["content-disposition"]
        assert resp.headers["content-type"].startswith("application/stix+json")

    def test_requires_actor_id(self, client):
        c, _ = client
        resp = c.get("/export/stix")
        assert resp.status_code == 422
