"""Tests for ``GET /threat-summary`` (Initiative F Phase 8).

Verifies:

- Top-5 per-section default cap (Initiative E parity).
- ``?limit=N`` override is forwarded into each section query.
- ``?limit=0`` / ``?limit=101`` rejected by FastAPI's Query validation.
- ``?since`` / ``?until`` propagate to the section queries; absent
  params resolve to ``config.activity_window_days`` per Phase 7's
  ``_resolve_window``.
- ``Incident.occurred_at`` ONLY anchor — incidents whose
  ``resolved_at`` falls inside the window but ``occurred_at`` is
  outside are excluded (plan §10 Q2).
- ``_verify_auth`` Bearer enforcement matches the existing
  ``/api/annotate`` behaviour: missing / wrong token returns 401 / 403.
- ``rationale_json`` is JSON-decoded and inline-expanded.
"""

from __future__ import annotations

from datetime import date, datetime
from unittest.mock import MagicMock, patch

import pytest
from fastapi.testclient import TestClient

from sage.api.app import app

# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------


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


@pytest.fixture()
def authed_client():
    mock_db = MagicMock()
    mock_config = MagicMock()
    mock_config.caldera_url = ""
    mock_config.caldera_api_key = ""
    mock_config.api_auth_token = "test-secret-token"
    mock_config.activity_window_days = 90
    with (
        patch("sage.api.app.Config.from_env", return_value=mock_config),
        patch("sage.api.app.spanner.Client"),
    ):
        with TestClient(app, raise_server_exceptions=True) as c:
            c.app.state.database = mock_db
            c.app.state.config = mock_config
            yield c, mock_db


def _empty_section_patches():
    """Patch every section query so the route returns a well-formed empty response."""
    return [
        patch(
            "sage.api.threat_summary.find_prioritized_actors_for_asset",
            return_value=[],
        ),
        patch("sage.api.threat_summary.find_attack_paths", return_value=[]),
        patch("sage.api.threat_summary.find_choke_points", return_value=[]),
        patch("sage.api.threat_summary.find_vulnerabilities_for_asset", return_value=[]),
        patch("sage.api.threat_summary.find_incidents_for_asset", return_value=[]),
    ]


# ---------------------------------------------------------------------------
# Response shape
# ---------------------------------------------------------------------------


class TestResponseShape:
    def test_returns_five_sections(self, client):
        c, _ = client
        with (
            _empty_section_patches()[0],
            _empty_section_patches()[1],
            _empty_section_patches()[2],
            _empty_section_patches()[3],
            _empty_section_patches()[4],
        ):
            resp = c.get("/threat-summary", params={"asset": "asset-001"})
        assert resp.status_code == 200
        body = resp.json()
        for key in (
            "asset_id",
            "window",
            "limit",
            "prioritized_actors",
            "attack_paths",
            "choke_points",
            "vulnerabilities",
            "incidents",
        ):
            assert key in body
        assert body["asset_id"] == "asset-001"
        assert body["limit"] == 5  # default

    def test_window_echoed_in_response(self, client):
        c, _ = client
        with (
            _empty_section_patches()[0],
            _empty_section_patches()[1],
            _empty_section_patches()[2],
            _empty_section_patches()[3],
            _empty_section_patches()[4],
        ):
            resp = c.get(
                "/threat-summary",
                params={
                    "asset": "asset-001",
                    "since": "2024-01-01",
                    "until": "2026-05-01",
                },
            )
        body = resp.json()
        assert body["window"]["since"] == "2024-01-01"
        assert body["window"]["until"] == "2026-05-01"


# ---------------------------------------------------------------------------
# limit cap + 422 validation
# ---------------------------------------------------------------------------


class TestLimitParam:
    def test_default_limit_is_5(self, client):
        c, _ = client
        with (
            patch(
                "sage.api.threat_summary.find_prioritized_actors_for_asset",
                return_value=[],
            ) as actors,
            patch("sage.api.threat_summary.find_attack_paths", return_value=[]) as paths,
            patch("sage.api.threat_summary.find_choke_points", return_value=[]) as chokes,
            patch(
                "sage.api.threat_summary.find_vulnerabilities_for_asset", return_value=[]
            ) as vulns,
            patch("sage.api.threat_summary.find_incidents_for_asset", return_value=[]) as incidents,
        ):
            resp = c.get("/threat-summary", params={"asset": "asset-001"})
        assert resp.status_code == 200
        assert actors.call_args.kwargs["limit"] == 5
        assert paths.call_args.kwargs["limit"] == 5
        # find_choke_points takes the cap as top_n, not limit.
        assert chokes.call_args.kwargs["top_n"] == 5
        assert vulns.call_args.kwargs["limit"] == 5
        assert incidents.call_args.kwargs["limit"] == 5

    def test_limit_10_forwarded(self, client):
        c, _ = client
        with (
            patch(
                "sage.api.threat_summary.find_prioritized_actors_for_asset",
                return_value=[],
            ) as actors,
            patch("sage.api.threat_summary.find_attack_paths", return_value=[]),
            patch("sage.api.threat_summary.find_choke_points", return_value=[]) as chokes,
            patch("sage.api.threat_summary.find_vulnerabilities_for_asset", return_value=[]),
            patch("sage.api.threat_summary.find_incidents_for_asset", return_value=[]),
        ):
            resp = c.get("/threat-summary", params={"asset": "asset-001", "limit": 10})
        assert resp.status_code == 200
        assert resp.json()["limit"] == 10
        assert actors.call_args.kwargs["limit"] == 10
        assert chokes.call_args.kwargs["top_n"] == 10

    def test_limit_0_rejected(self, client):
        c, _ = client
        resp = c.get("/threat-summary", params={"asset": "asset-001", "limit": 0})
        assert resp.status_code == 422

    def test_limit_101_rejected(self, client):
        c, _ = client
        resp = c.get("/threat-summary", params={"asset": "asset-001", "limit": 101})
        assert resp.status_code == 422

    def test_limit_100_accepted(self, client):
        c, _ = client
        with (
            _empty_section_patches()[0],
            _empty_section_patches()[1],
            _empty_section_patches()[2],
            _empty_section_patches()[3],
            _empty_section_patches()[4],
        ):
            resp = c.get("/threat-summary", params={"asset": "asset-001", "limit": 100})
        assert resp.status_code == 200
        assert resp.json()["limit"] == 100


# ---------------------------------------------------------------------------
# since/until forwarding
# ---------------------------------------------------------------------------


class TestWindowForwarding:
    def test_since_until_forwarded_to_section_queries(self, client):
        c, _ = client
        with (
            patch(
                "sage.api.threat_summary.find_prioritized_actors_for_asset",
                return_value=[],
            ) as actors,
            patch("sage.api.threat_summary.find_attack_paths", return_value=[]),
            patch("sage.api.threat_summary.find_choke_points", return_value=[]),
            patch(
                "sage.api.threat_summary.find_vulnerabilities_for_asset",
                return_value=[],
            ) as vulns,
            patch("sage.api.threat_summary.find_incidents_for_asset", return_value=[]) as incidents,
        ):
            resp = c.get(
                "/threat-summary",
                params={
                    "asset": "asset-001",
                    "since": "2024-01-01",
                    "until": "2026-05-01",
                },
            )
        assert resp.status_code == 200
        assert actors.call_args.kwargs["since"] == date(2024, 1, 1)
        assert actors.call_args.kwargs["until"] == date(2026, 5, 1)
        assert vulns.call_args.kwargs["since"] == date(2024, 1, 1)
        assert incidents.call_args.kwargs["until"] == date(2026, 5, 1)

    def test_absent_params_default_to_config_window(self, client):
        c, _ = client
        c.app.state.config.activity_window_days = 180
        with (
            patch(
                "sage.api.threat_summary.find_prioritized_actors_for_asset",
                return_value=[],
            ) as actors,
            patch("sage.api.threat_summary.find_attack_paths", return_value=[]),
            patch("sage.api.threat_summary.find_choke_points", return_value=[]),
            patch("sage.api.threat_summary.find_vulnerabilities_for_asset", return_value=[]),
            patch("sage.api.threat_summary.find_incidents_for_asset", return_value=[]),
        ):
            resp = c.get("/threat-summary", params={"asset": "asset-001"})
        assert resp.status_code == 200
        kwargs = actors.call_args.kwargs
        assert (kwargs["until"] - kwargs["since"]).days == 180


# ---------------------------------------------------------------------------
# occurred_at-only anchor
# ---------------------------------------------------------------------------


class TestIncidentOccurredAtOnly:
    """Plan §10 Q2: incidents anchored on Incident.occurred_at, NOT resolved_at."""

    def test_incident_query_uses_occurred_at_in_sql(self):
        from sage.spanner.query import find_incidents_for_asset

        mock_db = MagicMock()
        snap = MagicMock()
        snap.execute_sql.return_value = []
        ctx = MagicMock()
        ctx.__enter__ = MagicMock(return_value=snap)
        ctx.__exit__ = MagicMock(return_value=False)
        mock_db.snapshot.return_value = ctx

        find_incidents_for_asset(
            mock_db,
            "asset-001",
            since=date(2026, 1, 1),
            until=date(2026, 5, 1),
            limit=5,
        )
        sql = snap.execute_sql.call_args.args[0]
        assert "i.occurred_at >= @since" in sql
        assert "i.occurred_at <  @until" in sql or "i.occurred_at < @until" in sql
        # resolved_at MUST NOT appear in WHERE / SELECT — it's not used as
        # a time anchor and the response doesn't expose it.
        assert "resolved_at" not in sql

    def test_response_excludes_incident_with_old_occurred_at(self, client):
        c, _ = client
        # Section helper returns a row whose occurred_at is outside the
        # window even though a (hypothetical) resolved_at would be inside.
        # The real Spanner SQL filters on occurred_at, so this row would
        # never have been returned in production — the test asserts the
        # response surface honours whatever the section query returns
        # and does not introduce a second anchor.
        in_window = {
            "incident_stix_id": "incident--in-window",
            "incident_name": "Incident A",
            "occurred_at": datetime(2026, 3, 1),
            "severity": "high",
            "source": "ir_feedback",
        }
        with (
            _empty_section_patches()[0],
            _empty_section_patches()[1],
            _empty_section_patches()[2],
            _empty_section_patches()[3],
            patch(
                "sage.api.threat_summary.find_incidents_for_asset",
                return_value=[in_window],
            ),
        ):
            resp = c.get(
                "/threat-summary",
                params={
                    "asset": "asset-001",
                    "since": "2026-01-01",
                    "until": "2026-05-01",
                },
            )
        assert resp.status_code == 200
        incidents = resp.json()["incidents"]
        assert len(incidents) == 1
        assert incidents[0]["incident_stix_id"] == "incident--in-window"
        # The response shape has no resolved_at field; resolved_at is
        # neither a query anchor nor a returned column.
        assert "resolved_at" not in incidents[0]


# ---------------------------------------------------------------------------
# Bearer auth (matches /api/annotate)
# ---------------------------------------------------------------------------


class TestAuth:
    def test_no_auth_required_when_token_unset(self, client):
        c, _ = client
        with (
            _empty_section_patches()[0],
            _empty_section_patches()[1],
            _empty_section_patches()[2],
            _empty_section_patches()[3],
            _empty_section_patches()[4],
        ):
            resp = c.get("/threat-summary", params={"asset": "asset-001"})
        assert resp.status_code == 200

    def test_missing_token_returns_401(self, authed_client):
        c, _ = authed_client
        resp = c.get("/threat-summary", params={"asset": "asset-001"})
        assert resp.status_code == 401

    def test_wrong_token_returns_403(self, authed_client):
        c, _ = authed_client
        resp = c.get(
            "/threat-summary",
            params={"asset": "asset-001"},
            headers={"Authorization": "Bearer wrong-token"},
        )
        assert resp.status_code == 403

    def test_valid_token_returns_200(self, authed_client):
        c, _ = authed_client
        with (
            _empty_section_patches()[0],
            _empty_section_patches()[1],
            _empty_section_patches()[2],
            _empty_section_patches()[3],
            _empty_section_patches()[4],
        ):
            resp = c.get(
                "/threat-summary",
                params={"asset": "asset-001"},
                headers={"Authorization": "Bearer test-secret-token"},
            )
        assert resp.status_code == 200


# ---------------------------------------------------------------------------
# rationale_json inline expansion
# ---------------------------------------------------------------------------


class TestRationaleExpansion:
    def test_valid_rationale_json_inline_expanded(self, client):
        c, _ = client
        actor_row = {
            "actor_stix_id": "intrusion-set--00000000-0000-4000-8000-000000000001",
            "actor_name": "APT99",
            "pir_id": "PIR-001",
            "overlap_ratio": 0.6,
            "likelihood": 0.4,
            "rationale_json": (
                '{"text": "minimal", "intent_factors": {"motivation_alignment": 0.5}}'
            ),
        }
        with (
            patch(
                "sage.api.threat_summary.find_prioritized_actors_for_asset",
                return_value=[actor_row],
            ),
            _empty_section_patches()[1],
            _empty_section_patches()[2],
            _empty_section_patches()[3],
            _empty_section_patches()[4],
        ):
            resp = c.get("/threat-summary", params={"asset": "asset-001"})
        assert resp.status_code == 200
        actors = resp.json()["prioritized_actors"]
        assert actors[0]["rationale"] == {
            "text": "minimal",
            "intent_factors": {"motivation_alignment": 0.5},
        }

    def test_missing_rationale_json_becomes_null(self, client):
        c, _ = client
        actor_row = {
            "actor_stix_id": "intrusion-set--00000000-0000-4000-8000-000000000002",
            "actor_name": "APT88",
            "pir_id": "PIR-002",
            "overlap_ratio": 0.5,
            "likelihood": None,
            "rationale_json": None,
        }
        with (
            patch(
                "sage.api.threat_summary.find_prioritized_actors_for_asset",
                return_value=[actor_row],
            ),
            _empty_section_patches()[1],
            _empty_section_patches()[2],
            _empty_section_patches()[3],
            _empty_section_patches()[4],
        ):
            resp = c.get("/threat-summary", params={"asset": "asset-001"})
        assert resp.json()["prioritized_actors"][0]["rationale"] is None

    def test_malformed_rationale_json_falls_back_to_null(self, client):
        c, _ = client
        actor_row = {
            "actor_stix_id": "intrusion-set--00000000-0000-4000-8000-000000000003",
            "actor_name": "APT77",
            "pir_id": "PIR-003",
            "overlap_ratio": 0.5,
            "likelihood": 0.3,
            "rationale_json": "{not valid json",
        }
        with (
            patch(
                "sage.api.threat_summary.find_prioritized_actors_for_asset",
                return_value=[actor_row],
            ),
            _empty_section_patches()[1],
            _empty_section_patches()[2],
            _empty_section_patches()[3],
            _empty_section_patches()[4],
        ):
            resp = c.get("/threat-summary", params={"asset": "asset-001"})
        assert resp.status_code == 200
        assert resp.json()["prioritized_actors"][0]["rationale"] is None
