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

from datetime import UTC, date, datetime
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


# ---------------------------------------------------------------------------
# GET /api/incidents (Initiative G Phase 2)
# ---------------------------------------------------------------------------


def _sample_read_row(
    *,
    incident_stix_id: str = VALID_INCIDENT,
    occurred_at: datetime | None = None,
    diamond_model: dict[str, str] | None = None,
    ttps: list[dict[str, object]] | None = None,
) -> dict[str, object]:
    """Build a fake row in the shape ``read_incidents`` returns."""
    return {
        "incident_stix_id": incident_stix_id,
        "name": "Compromise of mail relay",
        "description": "MIR-ticket 4242",
        "occurred_at": occurred_at or datetime(2026, 5, 20, 12, 34, 56, tzinfo=UTC),
        "severity": "high",
        "source": "direct_api",
        "kill_chain_phases": ["initial-access", "execution"],
        "diamond_model": diamond_model
        or {
            "adversary": "APT99",
            "capability": "spear-phishing kit",
            "infrastructure": "fastflux nodes",
            "victim": "mail relay (asset-001)",
        },
        "ttps": ttps
        if ttps is not None
        else [
            {"ttp_stix_id": VALID_TTP_A, "sequence_order": 0},
            {"ttp_stix_id": VALID_TTP_B, "sequence_order": 1},
        ],
    }


class TestGetIncidentsHappyPath:
    def test_default_window_returns_200(self, client_no_token):
        """No params, no token configured -> permissive GET works."""
        c, _ = client_no_token
        rows = [_sample_read_row()]
        with patch("sage.api.incidents.read_incidents", return_value=rows) as read_mock:
            resp = c.get("/api/incidents")
        assert resp.status_code == 200, resp.text
        body = resp.json()
        assert body["count"] == 1
        assert "since" in body["window"]
        assert "until" in body["window"]
        kwargs = read_mock.call_args.kwargs
        assert kwargs["limit"] == 50
        assert kwargs["actor_stix_id"] is None

    def test_response_window_echoes_resolved_bounds(self, client_no_token):
        """Caller can verify which window was actually applied."""
        c, _ = client_no_token
        with patch("sage.api.incidents.read_incidents", return_value=[]):
            resp = c.get(
                "/api/incidents",
                params={"since": "2026-01-15", "until": "2026-04-30"},
            )
        assert resp.status_code == 200
        body = resp.json()
        assert body["window"]["since"] == "2026-01-15"
        assert body["window"]["until"] == "2026-04-30"

    def test_response_includes_ttps_and_diamond_model_inline(self, client_no_token):
        c, _ = client_no_token
        rows = [_sample_read_row()]
        with patch("sage.api.incidents.read_incidents", return_value=rows):
            resp = c.get("/api/incidents")
        assert resp.status_code == 200
        entry = resp.json()["incidents"][0]
        assert entry["ttps"] == [
            {"ttp_stix_id": VALID_TTP_A, "sequence_order": 0},
            {"ttp_stix_id": VALID_TTP_B, "sequence_order": 1},
        ]
        assert entry["diamond_model"] == {
            "adversary": "APT99",
            "capability": "spear-phishing kit",
            "infrastructure": "fastflux nodes",
            "victim": "mail relay (asset-001)",
        }
        assert entry["kill_chain_phases"] == ["initial-access", "execution"]
        assert entry["source"] == "direct_api"


class TestGetIncidentsFilters:
    def test_since_until_forwarded_to_helper(self, client_no_token):
        c, _ = client_no_token
        with patch("sage.api.incidents.read_incidents", return_value=[]) as read_mock:
            resp = c.get(
                "/api/incidents",
                params={"since": "2026-01-01", "until": "2026-05-01"},
            )
        assert resp.status_code == 200
        kwargs = read_mock.call_args.kwargs
        assert kwargs["since"].isoformat() == "2026-01-01"
        assert kwargs["until"].isoformat() == "2026-05-01"

    def test_incidents_outside_window_excluded(self):
        """Helper binds the right window — params snap to next-day exclusive upper."""
        from sage.spanner import incidents as inc_mod

        in_window_row = (
            VALID_INCIDENT,
            "in window",
            "",
            datetime(2026, 3, 1, tzinfo=UTC),
            "high",
            "direct_api",
            ["initial-access"],
            None,
        )

        captured: dict[str, object] = {}

        def fake_execute_sql(sql, params=None, param_types=None):
            captured.setdefault("calls", []).append({"sql": sql, "params": params})
            # First call = main query; subsequent = IUT lookup
            if len(captured["calls"]) == 1:
                return iter([in_window_row])
            return iter([])

        snap = MagicMock()
        snap.__enter__ = MagicMock(return_value=snap)
        snap.__exit__ = MagicMock(return_value=False)
        snap.execute_sql = MagicMock(side_effect=fake_execute_sql)
        database = MagicMock()
        database.snapshot.return_value = snap

        result = inc_mod.read_incidents(
            database,
            since=date(2026, 1, 1),
            until=date(2026, 5, 1),
            actor_stix_id=None,
            limit=50,
        )
        assert len(result) == 1
        main_params = captured["calls"][0]["params"]
        assert main_params["since"].date() == date(2026, 1, 1)
        # Snap-to-next-day-exclusive: until=2026-05-01 -> 2026-05-02 00:00 UTC
        assert main_params["until"].date() == date(2026, 5, 2)

    def test_actor_stix_id_filter_passed_through(self, client_no_token):
        c, _ = client_no_token
        with patch("sage.api.incidents.read_incidents", return_value=[]) as read_mock:
            resp = c.get(
                "/api/incidents",
                params={"actor_stix_id": VALID_ACTOR_ANNOT},
            )
        assert resp.status_code == 200
        kwargs = read_mock.call_args.kwargs
        assert kwargs["actor_stix_id"] == VALID_ACTOR_ANNOT

    def test_actor_stix_id_invalid_pattern_returns_422(self, client_no_token):
        c, _ = client_no_token
        resp = c.get(
            "/api/incidents",
            params={"actor_stix_id": "not-a-stix-id"},
        )
        assert resp.status_code == 422

    def test_actor_filter_emits_exists_clause(self):
        """Spanner SQL includes the EXISTS subquery + bind when actor filter active."""
        from sage.spanner import incidents as inc_mod

        captured: dict[str, object] = {"sqls": [], "params_list": []}

        def fake_execute_sql(sql, params=None, param_types=None):
            captured["sqls"].append(sql)
            captured["params_list"].append(params)
            return iter([])

        snap = MagicMock()
        snap.__enter__ = MagicMock(return_value=snap)
        snap.__exit__ = MagicMock(return_value=False)
        snap.execute_sql = MagicMock(side_effect=fake_execute_sql)
        database = MagicMock()
        database.snapshot.return_value = snap

        inc_mod.read_incidents(
            database,
            since=date(2026, 1, 1),
            until=date(2026, 5, 1),
            actor_stix_id=VALID_ACTOR_ANNOT,
            limit=50,
        )
        main_sql = captured["sqls"][0]
        assert "EXISTS" in main_sql
        assert "Uses u2" in main_sql
        assert "@actor_stix_id" in main_sql
        assert captured["params_list"][0]["actor_stix_id"] == VALID_ACTOR_ANNOT


class TestGetIncidentsLimit:
    def test_limit_propagated_to_helper(self, client_no_token):
        c, _ = client_no_token
        with patch("sage.api.incidents.read_incidents", return_value=[]) as read_mock:
            resp = c.get("/api/incidents", params={"limit": 10})
        assert resp.status_code == 200
        assert read_mock.call_args.kwargs["limit"] == 10

    def test_limit_zero_returns_422(self, client_no_token):
        c, _ = client_no_token
        resp = c.get("/api/incidents", params={"limit": 0})
        assert resp.status_code == 422

    def test_limit_above_max_returns_422(self, client_no_token):
        c, _ = client_no_token
        resp = c.get("/api/incidents", params={"limit": 101})
        assert resp.status_code == 422

    def test_default_limit_is_50(self, client_no_token):
        c, _ = client_no_token
        with patch("sage.api.incidents.read_incidents", return_value=[]) as read_mock:
            c.get("/api/incidents")
        assert read_mock.call_args.kwargs["limit"] == 50


class TestGetIncidentsAuth:
    def test_get_permissive_when_token_unset(self, client_no_token):
        """GET is permissive when SAGE_API_AUTH_TOKEN is unset (plan §2.4)."""
        c, _ = client_no_token
        with patch("sage.api.incidents.read_incidents", return_value=[]):
            resp = c.get("/api/incidents")
        assert resp.status_code == 200

    def test_get_200_with_valid_bearer_when_token_set(self, client_with_token):
        c, _ = client_with_token
        with patch("sage.api.incidents.read_incidents", return_value=[]):
            resp = c.get("/api/incidents", headers=AUTH_HEADER)
        assert resp.status_code == 200

    def test_get_401_missing_bearer_when_token_set(self, client_with_token):
        c, _ = client_with_token
        resp = c.get("/api/incidents")
        assert resp.status_code == 401

    def test_get_403_wrong_bearer(self, client_with_token):
        c, _ = client_with_token
        resp = c.get(
            "/api/incidents",
            headers={"Authorization": "Bearer wrong-token"},
        )
        assert resp.status_code == 403


class TestGetIncidentsDecoders:
    """Cover the Spanner-column -> response shape conversion helpers."""

    def test_diamond_model_decodes_string_payload(self):
        from sage.spanner.incidents import _decode_diamond_model

        raw = '{"adversary": "APT99", "capability": "kit", "infrastructure": "x", "victim": "y"}'
        assert _decode_diamond_model(raw) == {
            "adversary": "APT99",
            "capability": "kit",
            "infrastructure": "x",
            "victim": "y",
        }

    def test_diamond_model_passes_through_dict(self):
        from sage.spanner.incidents import _decode_diamond_model

        payload = {"adversary": "APT99"}
        assert _decode_diamond_model(payload) is payload

    def test_diamond_model_returns_none_for_malformed_json(self):
        from sage.spanner.incidents import _decode_diamond_model

        assert _decode_diamond_model("{not valid") is None

    def test_kill_chain_phases_empty_for_null_column(self):
        from sage.spanner.incidents import _decode_kill_chain_phases

        assert _decode_kill_chain_phases(None) == []
        assert _decode_kill_chain_phases([]) == []

    def test_kill_chain_phases_coerces_to_str(self):
        from sage.spanner.incidents import _decode_kill_chain_phases

        assert _decode_kill_chain_phases(["initial-access", "execution"]) == [
            "initial-access",
            "execution",
        ]


class TestGetIncidentsHelperShape:
    """Exercise ``read_incidents`` directly to lock the IUT-attach contract."""

    def test_ttps_attached_per_incident(self):
        from sage.spanner import incidents as inc_mod

        main_row = (
            VALID_INCIDENT,
            "x",
            "",
            datetime(2026, 3, 1, tzinfo=UTC),
            "high",
            "direct_api",
            ["initial-access"],
            None,
        )
        iut_rows = [
            (VALID_INCIDENT, VALID_TTP_A, 0),
            (VALID_INCIDENT, VALID_TTP_B, 1),
        ]
        call_count = {"n": 0}

        def fake_execute_sql(sql, params=None, param_types=None):
            call_count["n"] += 1
            if call_count["n"] == 1:
                return iter([main_row])
            return iter(iut_rows)

        snap = MagicMock()
        snap.__enter__ = MagicMock(return_value=snap)
        snap.__exit__ = MagicMock(return_value=False)
        snap.execute_sql = MagicMock(side_effect=fake_execute_sql)
        database = MagicMock()
        database.snapshot.return_value = snap

        result = inc_mod.read_incidents(
            database,
            since=date(2026, 1, 1),
            until=date(2026, 5, 1),
            actor_stix_id=None,
            limit=50,
        )
        assert len(result) == 1
        assert result[0]["ttps"] == [
            {"ttp_stix_id": VALID_TTP_A, "sequence_order": 0},
            {"ttp_stix_id": VALID_TTP_B, "sequence_order": 1},
        ]

    def test_empty_main_query_skips_iut_lookup(self):
        from sage.spanner import incidents as inc_mod

        snap = MagicMock()
        snap.__enter__ = MagicMock(return_value=snap)
        snap.__exit__ = MagicMock(return_value=False)
        snap.execute_sql = MagicMock(return_value=iter([]))
        database = MagicMock()
        database.snapshot.return_value = snap

        result = inc_mod.read_incidents(
            database,
            since=date(2026, 1, 1),
            until=date(2026, 5, 1),
            actor_stix_id=None,
            limit=50,
        )
        assert result == []
        assert snap.execute_sql.call_count == 1
