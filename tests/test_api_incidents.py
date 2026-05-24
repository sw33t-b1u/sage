"""Tests for ``POST /api/incidents`` (Initiative G Phase 1).

Mocks the Spanner upsert helper so no emulator is required. Auth
behaviour is verified against three configurations:

* token unset → ``503`` for POST (Decision 10 / plan §2.10)
* token set, no header → ``401``
* token set, wrong header → ``403``

Also covers the retroactive auth gate on ``POST /api/annotate`` — when
the token is unset that endpoint must now return ``503`` as well (the
existing E happy-path tests have been updated separately to pass the
Bearer header).
"""

from __future__ import annotations

from unittest.mock import MagicMock, patch

import pytest
from fastapi.testclient import TestClient

from sage.api.app import app

VALID_INCIDENT = "incident--00000000-0000-0000-0000-000000000001"
VALID_ACTOR_ANNOT = "intrusion-set--00000000-0000-0000-0000-000000000001"
VALID_TTP_A = "attack-pattern--00000000-0000-0000-0000-0000000000aa"
VALID_TTP_B = "attack-pattern--00000000-0000-0000-0000-0000000000bb"
VALID_TTP_C = "attack-pattern--00000000-0000-0000-0000-0000000000cc"

AUTH_TOKEN = "test-secret-token"
AUTH_HEADER = {"Authorization": f"Bearer {AUTH_TOKEN}"}


# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------


def _make_client(*, token: str):
    mock_db = MagicMock()
    mock_config = MagicMock()
    mock_config.caldera_url = ""
    mock_config.caldera_api_key = ""
    mock_config.api_auth_token = token
    mock_config.activity_window_days = 90
    return mock_db, mock_config


@pytest.fixture()
def client_no_token():
    """Token UNSET — POST routes must return 503."""
    mock_db, mock_config = _make_client(token="")
    with (
        patch("sage.api.app.Config.from_env", return_value=mock_config),
        patch("sage.api.app.spanner.Client"),
    ):
        with TestClient(app, raise_server_exceptions=True) as c:
            c.app.state.database = mock_db
            c.app.state.config = mock_config
            yield c, mock_db


@pytest.fixture()
def client_with_token():
    """Token SET — POST routes require Bearer header."""
    mock_db, mock_config = _make_client(token=AUTH_TOKEN)
    with (
        patch("sage.api.app.Config.from_env", return_value=mock_config),
        patch("sage.api.app.spanner.Client"),
    ):
        with TestClient(app, raise_server_exceptions=True) as c:
            c.app.state.database = mock_db
            c.app.state.config = mock_config
            yield c, mock_db


def _valid_body(**overrides):
    body = {
        "incident_stix_id": VALID_INCIDENT,
        "name": "Compromise of mail relay",
        "occurred_at": "2026-05-20T12:34:56Z",
        "severity": "high",
        "kill_chain_phases": [
            {
                "kill_chain_name": "mitre-attack",
                "phase_name": "initial-access",
                "x_ttp_stix_id": VALID_TTP_A,
            }
        ],
        "ttps": [
            {"ttp_stix_id": VALID_TTP_A, "sequence_order": 0},
            {"ttp_stix_id": VALID_TTP_B, "sequence_order": 1},
        ],
        "diamond_model": {
            "adversary": "APT99",
            "capability": "spear-phishing kit",
            "infrastructure": "fastflux nodes",
            "victim": "mail relay (asset-001)",
        },
        "description": "MIR-ticket 4242",
    }
    body.update(overrides)
    return body


# ---------------------------------------------------------------------------
# Happy path / response shape
# ---------------------------------------------------------------------------


class TestIncidentHappyPath:
    def test_valid_post_returns_200_and_persists(self, client_with_token):
        c, _ = client_with_token
        with patch(
            "sage.api.incidents.upsert_incident",
            return_value={
                "incident_stix_id": VALID_INCIDENT,
                "accepted": True,
                "created": True,
                "updated": False,
                "warnings": [],
            },
        ) as upsert_mock:
            resp = c.post("/api/incidents", json=_valid_body(), headers=AUTH_HEADER)
        assert resp.status_code == 200, resp.text
        body = resp.json()
        assert body["incident_stix_id"] == VALID_INCIDENT
        assert body["accepted"] is True
        assert body["created"] is True
        assert body["updated"] is False
        assert body["warnings"] == []
        upsert_mock.assert_called_once()
        # The request model survived end-to-end (severity passed through)
        kwargs = upsert_mock.call_args.kwargs
        assert kwargs["req"].severity.value == "high"


# ---------------------------------------------------------------------------
# Validation failures
# ---------------------------------------------------------------------------


class TestIncidentValidation:
    def test_bad_stix_id_returns_422(self, client_with_token):
        c, _ = client_with_token
        with patch("sage.api.incidents.upsert_incident") as upsert_mock:
            resp = c.post(
                "/api/incidents",
                json=_valid_body(incident_stix_id="incident--not-a-uuid"),
                headers=AUTH_HEADER,
            )
        assert resp.status_code == 422
        upsert_mock.assert_not_called()

    def test_missing_required_field_returns_422(self, client_with_token):
        c, _ = client_with_token
        body = _valid_body()
        body.pop("name")
        resp = c.post("/api/incidents", json=body, headers=AUTH_HEADER)
        assert resp.status_code == 422

    def test_unknown_severity_returns_422(self, client_with_token):
        c, _ = client_with_token
        resp = c.post(
            "/api/incidents",
            json=_valid_body(severity="catastrophic"),
            headers=AUTH_HEADER,
        )
        assert resp.status_code == 422

    def test_diamond_model_missing_quadrant_returns_422(self, client_with_token):
        c, _ = client_with_token
        body = _valid_body()
        del body["diamond_model"]["victim"]
        resp = c.post("/api/incidents", json=body, headers=AUTH_HEADER)
        assert resp.status_code == 422

    def test_diamond_model_unknown_key_returns_422(self, client_with_token):
        c, _ = client_with_token
        body = _valid_body()
        body["diamond_model"]["unknown_quadrant"] = "x"
        resp = c.post("/api/incidents", json=body, headers=AUTH_HEADER)
        assert resp.status_code == 422


# ---------------------------------------------------------------------------
# Auth gate (Decision 10)
# ---------------------------------------------------------------------------


class TestIncidentAuth:
    def test_token_unset_returns_503(self, client_no_token):
        """POST without a configured token is rejected even if syntactically valid."""
        c, _ = client_no_token
        with patch("sage.api.incidents.upsert_incident") as upsert_mock:
            resp = c.post("/api/incidents", json=_valid_body())
        assert resp.status_code == 503
        upsert_mock.assert_not_called()

    def test_missing_authorization_returns_401(self, client_with_token):
        c, _ = client_with_token
        resp = c.post("/api/incidents", json=_valid_body())
        assert resp.status_code == 401

    def test_wrong_token_returns_403(self, client_with_token):
        c, _ = client_with_token
        resp = c.post(
            "/api/incidents",
            json=_valid_body(),
            headers={"Authorization": "Bearer not-the-token"},
        )
        assert resp.status_code == 403


# ---------------------------------------------------------------------------
# PUT-like full replace + warning emission (plan §2.1)
# ---------------------------------------------------------------------------


class TestIncidentPutLikeReplaceAndWarnings:
    def test_second_post_with_same_id_returns_updated_true(self, client_with_token):
        c, _ = client_with_token
        call_count = {"n": 0}

        def fake_upsert(*, database, req):
            call_count["n"] += 1
            return {
                "incident_stix_id": req.incident_stix_id,
                "accepted": True,
                "created": call_count["n"] == 1,
                "updated": call_count["n"] > 1,
                "warnings": [],
            }

        body_first = _valid_body(ttps=[{"ttp_stix_id": VALID_TTP_A, "sequence_order": 0}])
        body_second = _valid_body(
            ttps=[
                {"ttp_stix_id": VALID_TTP_B, "sequence_order": 0},
                {"ttp_stix_id": VALID_TTP_C, "sequence_order": 1},
            ]
        )

        with patch("sage.api.incidents.upsert_incident", side_effect=fake_upsert):
            r1 = c.post("/api/incidents", json=body_first, headers=AUTH_HEADER)
            r2 = c.post("/api/incidents", json=body_second, headers=AUTH_HEADER)

        assert r1.status_code == 200
        assert r1.json()["created"] is True
        assert r1.json()["updated"] is False
        assert r2.status_code == 200
        assert r2.json()["created"] is False
        assert r2.json()["updated"] is True

    def test_kcp_missing_warning_when_kill_chain_phases_empty(self, client_with_token):
        """Plan §2.1: omitting kill_chain_phases must surface a warning."""
        from sage.models.incident_request import IncidentRequest
        from sage.spanner.incidents import _collect_warnings

        req = IncidentRequest.model_validate(_valid_body(kill_chain_phases=[]))
        warnings = _collect_warnings(req)
        codes = [w["code"] for w in warnings]
        assert "kcp_missing" in codes

    def test_sequence_order_null_warning_when_any_null(self, client_with_token):
        from sage.models.incident_request import IncidentRequest
        from sage.spanner.incidents import _collect_warnings

        req = IncidentRequest.model_validate(
            _valid_body(
                ttps=[
                    {"ttp_stix_id": VALID_TTP_A, "sequence_order": 0},
                    {"ttp_stix_id": VALID_TTP_B},  # sequence_order omitted → None
                ]
            )
        )
        warnings = _collect_warnings(req)
        codes = [w["code"] for w in warnings]
        assert "sequence_order_null" in codes

    def test_warnings_surface_in_response_body(self, client_with_token):
        """The POST response includes the warnings list verbatim."""
        c, _ = client_with_token
        with patch(
            "sage.api.incidents.upsert_incident",
            return_value={
                "incident_stix_id": VALID_INCIDENT,
                "accepted": True,
                "created": True,
                "updated": False,
                "warnings": [
                    {"code": "kcp_missing", "message": "kill_chain_phases is empty"},
                    {
                        "code": "sequence_order_null",
                        "message": "one or more sequence_order=null",
                    },
                ],
            },
        ):
            resp = c.post("/api/incidents", json=_valid_body(), headers=AUTH_HEADER)
        assert resp.status_code == 200
        codes = [w["code"] for w in resp.json()["warnings"]]
        assert codes == ["kcp_missing", "sequence_order_null"]


# ---------------------------------------------------------------------------
# Spanner upsert helper — verify direct_api source + PUT-like delete-then-insert
# ---------------------------------------------------------------------------


class TestSpannerUpsertContract:
    """Drives the txn function inside ``upsert_incident`` against a stub.

    These tests document the wire contract (delete-then-insert, source
    discriminator, child row dedupe) without spinning up an emulator.
    """

    def _run(self, body):
        from sage.models.incident_request import IncidentRequest
        from sage.spanner import incidents as inc_mod

        req = IncidentRequest.model_validate(body)
        txn = MagicMock()
        txn.read.return_value = iter([])  # no existing row

        captured: dict[str, list] = {}

        def fake_run_in_transaction(callback):
            return callback(txn)

        database = MagicMock()
        database.run_in_transaction = fake_run_in_transaction

        result = inc_mod.upsert_incident(database=database, req=req)

        # Capture mutation calls
        captured["delete"] = [call for call in txn.execute_update.call_args_list]
        captured["upsert"] = [call for call in txn.insert_or_update.call_args_list]
        return result, captured, txn

    def test_source_is_direct_api(self):
        result, captured, _ = self._run(_valid_body())
        # First insert_or_update is Incident row
        incident_call = captured["upsert"][0]
        columns = incident_call.kwargs["columns"]
        values = incident_call.kwargs["values"][0]
        source_idx = columns.index("source")
        assert values[source_idx] == "direct_api"
        assert result["created"] is True
        assert result["updated"] is False

    def test_delete_runs_before_insert_for_replace(self):
        _, captured, _ = self._run(_valid_body())
        # execute_update is the DELETE FROM IncidentUsesTTP statement
        assert len(captured["delete"]) == 1
        sql = captured["delete"][0].args[0]
        assert "DELETE FROM IncidentUsesTTP" in sql

    def test_iut_rows_dedupe_kcp_and_ttps_for_same_ttp(self):
        """When kcp.x_ttp_stix_id and ttps[] reference the same TTP, ttps[] wins."""
        body = _valid_body(
            kill_chain_phases=[
                {
                    "kill_chain_name": "mitre-attack",
                    "phase_name": "execution",
                    "x_ttp_stix_id": VALID_TTP_A,
                }
            ],
            ttps=[{"ttp_stix_id": VALID_TTP_A, "sequence_order": 7}],
        )
        _, captured, _ = self._run(body)
        # captured["upsert"][0] is Incident, captured["upsert"][1] is IncidentUsesTTP
        iut_call = captured["upsert"][1]
        values = iut_call.kwargs["values"]
        assert len(values) == 1  # deduped
        # sequence_order = 7 (from ttps[]) wins over None (from kcp)
        assert values[0][2] == 7


# ---------------------------------------------------------------------------
# Retroactive Decision 10: POST /api/annotate must also gate on token
# ---------------------------------------------------------------------------


class TestAnnotateRetroactive:
    def test_annotate_unset_token_returns_503(self, client_no_token):
        """Verify Initiative E path inherits Decision 10 / Phase 10 harmonization."""
        c, _ = client_no_token
        resp = c.post(
            "/api/annotate",
            json={
                "annotator_id": "alice@example.com",
                "actor_stix_id": VALID_ACTOR_ANNOT,
                "annotation_type": "false-positive",
                "payload": {"reason": "x"},
            },
        )
        assert resp.status_code == 503

    def test_annotate_with_token_still_works(self, client_with_token):
        """No regression on the existing E happy path when a token is supplied."""
        c, _ = client_with_token
        with patch(
            "sage.api.annotation.write_annotation",
            return_value={
                "annotator_id": "alice@example.com",
                "actor_stix_id": VALID_ACTOR_ANNOT,
                "annotation_type": "false-positive",
                "created_at_pending": True,
            },
        ):
            resp = c.post(
                "/api/annotate",
                json={
                    "annotator_id": "alice@example.com",
                    "actor_stix_id": VALID_ACTOR_ANNOT,
                    "annotation_type": "false-positive",
                    "payload": {"reason": "x"},
                },
                headers=AUTH_HEADER,
            )
        assert resp.status_code == 200
