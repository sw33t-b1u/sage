"""Tests for POST /api/annotate (Initiative E Phase 6).

TestClient-driven coverage of the FastAPI endpoint that wraps the
AnnotatesActor write surface. Spanner is mocked at the
``write_annotation`` boundary so no emulator is required.
"""

from __future__ import annotations

from unittest.mock import MagicMock, patch

import pytest
from fastapi.testclient import TestClient

from sage.api.app import app

VALID_ACTOR = "intrusion-set--00000000-0000-0000-0000-000000000001"

AUTH_TOKEN = "test-secret-token"
AUTH_HEADER = {"Authorization": f"Bearer {AUTH_TOKEN}"}


# ---------------------------------------------------------------------------
# TestClient fixtures — mirror the pattern in tests/test_api.py.
# ---------------------------------------------------------------------------
# Initiative G Phase 1 / Decision 10 retroactively gates POST /api/annotate
# behind a configured ``SAGE_API_AUTH_TOKEN`` (token unset → 503). The
# ``client`` fixture below therefore configures a real token and the
# request-emitting tests pass ``AUTH_HEADER``. The 503-when-unset
# behaviour is covered by ``test_api_incidents.py::TestAnnotateRetroactive``
# so we do not duplicate the unset-token fixture here.


@pytest.fixture()
def client():
    """Client with a configured token; tests must pass ``AUTH_HEADER``."""
    mock_db = MagicMock()
    mock_config = MagicMock()
    mock_config.caldera_url = ""
    mock_config.caldera_api_key = ""
    mock_config.api_auth_token = AUTH_TOKEN

    with (
        patch("sage.api.app.Config.from_env", return_value=mock_config),
        patch("sage.api.app.spanner.Client"),
    ):
        with TestClient(app, raise_server_exceptions=True) as c:
            c.app.state.database = mock_db
            c.app.state.config = mock_config
            yield c, mock_db


@pytest.fixture()
def authed_client():
    """Alias of ``client`` retained for the auth-specific test class."""
    mock_db = MagicMock()
    mock_config = MagicMock()
    mock_config.caldera_url = ""
    mock_config.caldera_api_key = ""
    mock_config.api_auth_token = AUTH_TOKEN

    with (
        patch("sage.api.app.Config.from_env", return_value=mock_config),
        patch("sage.api.app.spanner.Client"),
    ):
        with TestClient(app, raise_server_exceptions=True) as c:
            c.app.state.database = mock_db
            c.app.state.config = mock_config
            yield c, mock_db


# ---------------------------------------------------------------------------
# POST /api/annotate — happy path
# ---------------------------------------------------------------------------


class TestAnnotateHappyPath:
    def test_false_positive_success(self, client):
        c, _ = client
        with patch(
            "sage.api.annotation.write_annotation",
            return_value={
                "annotator_id": "alice@example.com",
                "actor_stix_id": VALID_ACTOR,
                "annotation_type": "false-positive",
                "created_at_pending": True,
            },
        ) as write_mock:
            resp = c.post(
                "/api/annotate",
                json={
                    "annotator_id": "alice@example.com",
                    "actor_stix_id": VALID_ACTOR,
                    "annotation_type": "false-positive",
                    "payload": {"reason": "Mis-tagged by upstream feed"},
                },
                headers=AUTH_HEADER,
            )
        assert resp.status_code == 200
        body = resp.json()
        assert body["annotator_id"] == "alice@example.com"
        assert body["actor_stix_id"] == VALID_ACTOR
        assert body["annotation_type"] == "false-positive"
        assert body["created_at_pending"] is True
        assert body["evidence_url"] is None
        write_mock.assert_called_once()

    def test_confidence_override_success(self, client):
        c, _ = client
        with patch(
            "sage.api.annotation.write_annotation",
            return_value={
                "annotator_id": "alice@example.com",
                "actor_stix_id": VALID_ACTOR,
                "annotation_type": "confidence-override",
                "created_at_pending": True,
            },
        ):
            resp = c.post(
                "/api/annotate",
                json={
                    "annotator_id": "alice@example.com",
                    "actor_stix_id": VALID_ACTOR,
                    "annotation_type": "confidence-override",
                    "payload": {
                        "original_likelihood": 0.3,
                        "overridden_likelihood": 0.8,
                        "reason": "Recent intrusion attempt confirmed",
                    },
                },
                headers=AUTH_HEADER,
            )
        assert resp.status_code == 200
        assert resp.json()["annotation_type"] == "confidence-override"


# ---------------------------------------------------------------------------
# POST /api/annotate — validation failures
# ---------------------------------------------------------------------------


class TestAnnotateValidation:
    def test_confidence_override_payload_out_of_range(self, client):
        """overridden_likelihood=1.5 fails the type-specific Pydantic model."""
        c, _ = client
        with patch("sage.api.annotation.write_annotation") as write_mock:
            resp = c.post(
                "/api/annotate",
                json={
                    "annotator_id": "alice@example.com",
                    "actor_stix_id": VALID_ACTOR,
                    "annotation_type": "confidence-override",
                    "payload": {
                        "original_likelihood": 0.3,
                        "overridden_likelihood": 1.5,
                        "reason": "bogus",
                    },
                },
                headers=AUTH_HEADER,
            )
        assert resp.status_code == 422
        write_mock.assert_not_called()

    def test_missing_annotator_id(self, client):
        """Request-model validation rejects missing required field."""
        c, _ = client
        resp = c.post(
            "/api/annotate",
            json={
                "actor_stix_id": VALID_ACTOR,
                "annotation_type": "false-positive",
                "payload": {"reason": "x"},
            },
            headers=AUTH_HEADER,
        )
        assert resp.status_code == 422

    def test_unknown_annotation_type(self, client):
        c, _ = client
        resp = c.post(
            "/api/annotate",
            json={
                "annotator_id": "alice@example.com",
                "actor_stix_id": VALID_ACTOR,
                "annotation_type": "not-a-real-type",
                "payload": {"reason": "x"},
            },
            headers=AUTH_HEADER,
        )
        assert resp.status_code == 422

    def test_malformed_actor_stix_id(self, client):
        c, _ = client
        resp = c.post(
            "/api/annotate",
            json={
                "annotator_id": "alice@example.com",
                "actor_stix_id": "bad-id-not-a-uuid",
                "annotation_type": "false-positive",
                "payload": {"reason": "x"},
            },
            headers=AUTH_HEADER,
        )
        assert resp.status_code == 422


# ---------------------------------------------------------------------------
# POST /api/annotate — authentication
# ---------------------------------------------------------------------------


class TestAnnotateAuth:
    def test_missing_authorization_returns_401(self, authed_client):
        c, _ = authed_client
        resp = c.post(
            "/api/annotate",
            json={
                "annotator_id": "alice@example.com",
                "actor_stix_id": VALID_ACTOR,
                "annotation_type": "false-positive",
                "payload": {"reason": "x"},
            },
        )
        assert resp.status_code == 401

    def test_wrong_bearer_returns_403(self, authed_client):
        c, _ = authed_client
        resp = c.post(
            "/api/annotate",
            headers={"Authorization": "Bearer wrong-token"},
            json={
                "annotator_id": "alice@example.com",
                "actor_stix_id": VALID_ACTOR,
                "annotation_type": "false-positive",
                "payload": {"reason": "x"},
            },
        )
        assert resp.status_code == 403
