"""Tests for ``cmd/register_incident.py`` (Initiative G Phase 3)."""

from __future__ import annotations

import importlib
import json
import sys
from pathlib import Path
from unittest.mock import MagicMock, patch

import pytest
from click.testing import CliRunner

# The CLI mutates sys.path inside its module body before importing
# ``sage.*``; importlib.import_module is used so each test run picks
# up a clean module instance even after sys.path side-effects.
sys.path.insert(0, str(Path(__file__).parent.parent / "src"))
sys.path.insert(0, str(Path(__file__).parent.parent / "cmd"))

register_incident = importlib.import_module("register_incident")


VALID_INCIDENT = "incident--00000000-0000-0000-0000-000000000001"
NAV_FIXTURE = Path(__file__).parent / "fixtures" / "navigator_layer_sample.json"


def _make_runner() -> CliRunner:
    # click>=8.2 split stderr by default; the old ``mix_stderr=False``
    # kwarg was removed. Constructing with no args reproduces the
    # separated-stream behaviour expected by these tests
    # (``result.stderr`` is populated).
    return CliRunner()


def _api_success_response(*, incident_stix_id: str = VALID_INCIDENT) -> dict:
    return {
        "incident_stix_id": incident_stix_id,
        "accepted": True,
        "created": True,
        "updated": False,
        "warnings": [],
    }


# ---------------------------------------------------------------------------
# --from-file mode (non-interactive happy path)
# ---------------------------------------------------------------------------


class TestFromFileMode:
    def test_posts_payload_as_is(self, tmp_path):
        payload = {
            "incident_stix_id": VALID_INCIDENT,
            "name": "MIR-4242",
            "occurred_at": "2026-05-20T12:34:56Z",
            "severity": "high",
            "kill_chain_phases": [],
            "ttps": [],
        }
        path = tmp_path / "payload.json"
        path.write_text(json.dumps(payload))

        with patch.object(
            register_incident, "_submit_via_api", return_value=_api_success_response()
        ) as submit_mock:
            runner = _make_runner()
            result = runner.invoke(
                register_incident.main,
                ["--from-file", str(path), "--no-interactive"],
            )
        assert result.exit_code == 0, result.output + result.stderr
        submit_mock.assert_called_once()
        kwargs = submit_mock.call_args.kwargs
        assert kwargs["payload"]["incident_stix_id"] == VALID_INCIDENT

    def test_invalid_payload_returns_exit_2(self, tmp_path):
        path = tmp_path / "bad.json"
        path.write_text(json.dumps({"incident_stix_id": "incident--not-a-uuid"}))

        runner = _make_runner()
        result = runner.invoke(
            register_incident.main,
            ["--from-file", str(path), "--no-interactive"],
        )
        assert result.exit_code == 2
        assert "IncidentRequest validation" in result.stderr

    def test_unreadable_file_returns_usage_error(self, tmp_path):
        """Missing payload file should fail fast with a UsageError."""
        runner = _make_runner()
        result = runner.invoke(
            register_incident.main,
            ["--from-file", str(tmp_path / "does-not-exist.json"), "--no-interactive"],
        )
        # click.Path(exists=True) rejects at parse time → exit 2
        assert result.exit_code == 2

    def test_navigator_layer_ignored_with_warning_when_from_file(self, tmp_path):
        payload = {
            "incident_stix_id": VALID_INCIDENT,
            "name": "x",
            "occurred_at": "2026-05-20T12:34:56Z",
            "severity": "high",
            "kill_chain_phases": [],
            "ttps": [],
        }
        path = tmp_path / "payload.json"
        path.write_text(json.dumps(payload))

        with patch.object(
            register_incident, "_submit_via_api", return_value=_api_success_response()
        ):
            runner = _make_runner()
            result = runner.invoke(
                register_incident.main,
                [
                    "--from-file",
                    str(path),
                    "--navigator-layer",
                    str(NAV_FIXTURE),
                    "--no-interactive",
                ],
            )
        assert result.exit_code == 0
        assert "navigator-layer is ignored" in result.stderr


# ---------------------------------------------------------------------------
# --navigator-layer parsing → payload structure
# ---------------------------------------------------------------------------


class TestNavigatorLayerMode:
    def test_techniques_become_kcps_and_ttps_in_order(self):
        with patch.object(
            register_incident, "_submit_via_api", return_value=_api_success_response()
        ) as submit_mock:
            runner = _make_runner()
            result = runner.invoke(
                register_incident.main,
                [
                    "--navigator-layer",
                    str(NAV_FIXTURE),
                    "--name",
                    "MIR-4242",
                    "--occurred-at",
                    "2026-05-20T12:34:56Z",
                    "--severity",
                    "high",
                    "--id",
                    VALID_INCIDENT,
                    "--no-interactive",
                ],
            )
        assert result.exit_code == 0, result.output + result.stderr
        payload = submit_mock.call_args.kwargs["payload"]
        kcps = payload["kill_chain_phases"]
        ttps = payload["ttps"]
        assert len(kcps) == 3
        assert len(ttps) == 3
        # Order preserved
        assert [k["phase_name"] for k in kcps] == [
            "initial-access",
            "execution",
            "initial-access",
        ]
        # sequence_order is the source-array index
        assert [t["sequence_order"] for t in ttps] == [0, 1, 2]
        # Same surrogate stix_id between kcp.x_ttp_stix_id and ttps[].ttp_stix_id
        for kcp, ttp in zip(kcps, ttps, strict=True):
            assert kcp["x_ttp_stix_id"] == ttp["ttp_stix_id"]
        # UUID5 derivation is deterministic — re-running the helper
        # should produce the same stix_id for the same technique_id.
        derived = register_incident._derive_ttp_stix_id_from_technique("T1566")
        assert derived == ttps[0]["ttp_stix_id"]

    def test_malformed_navigator_returns_usage_error(self, tmp_path):
        bad = tmp_path / "bad.json"
        bad.write_text(json.dumps({"name": "no techniques"}))
        runner = _make_runner()
        result = runner.invoke(
            register_incident.main,
            [
                "--navigator-layer",
                str(bad),
                "--name",
                "x",
                "--occurred-at",
                "2026-05-20T12:34:56Z",
                "--severity",
                "high",
                "--no-interactive",
            ],
        )
        assert result.exit_code == 2
        assert "techniques" in result.stderr


# ---------------------------------------------------------------------------
# --id override + auto-UUID4
# ---------------------------------------------------------------------------


class TestIncidentIdHandling:
    def test_id_override_used_when_supplied(self):
        with patch.object(
            register_incident, "_submit_via_api", return_value=_api_success_response()
        ) as submit_mock:
            runner = _make_runner()
            result = runner.invoke(
                register_incident.main,
                [
                    "--id",
                    VALID_INCIDENT,
                    "--name",
                    "x",
                    "--occurred-at",
                    "2026-05-20T12:34:56Z",
                    "--severity",
                    "high",
                    "--no-interactive",
                ],
            )
        assert result.exit_code == 0, result.output + result.stderr
        assert submit_mock.call_args.kwargs["payload"]["incident_stix_id"] == VALID_INCIDENT

    def test_default_id_is_uuid4_prefixed(self):
        with (
            patch.object(
                register_incident,
                "_default_incident_stix_id",
                return_value=VALID_INCIDENT,
            ),
            patch.object(
                register_incident,
                "_submit_via_api",
                return_value=_api_success_response(),
            ) as submit_mock,
        ):
            runner = _make_runner()
            result = runner.invoke(
                register_incident.main,
                [
                    "--name",
                    "x",
                    "--occurred-at",
                    "2026-05-20T12:34:56Z",
                    "--severity",
                    "high",
                    "--no-interactive",
                ],
            )
        assert result.exit_code == 0, result.output + result.stderr
        assert submit_mock.call_args.kwargs["payload"]["incident_stix_id"] == VALID_INCIDENT


# ---------------------------------------------------------------------------
# --no-api Spanner-direct path
# ---------------------------------------------------------------------------


class TestNoApiMode:
    def test_calls_spanner_upsert_directly(self):
        fake_db = MagicMock()
        fake_config = MagicMock()
        fake_config.gcp_project_id = "proj"
        fake_config.spanner_instance_id = "inst"
        fake_config.spanner_database_id = "db"

        with (
            patch(
                "sage.config.Config.from_env",
                return_value=fake_config,
            ),
            patch(
                "sage.spanner.client.get_database",
                return_value=fake_db,
            ),
            patch(
                "sage.spanner.incidents.upsert_incident",
                return_value=_api_success_response(),
            ) as upsert_mock,
        ):
            runner = _make_runner()
            result = runner.invoke(
                register_incident.main,
                [
                    "--id",
                    VALID_INCIDENT,
                    "--name",
                    "x",
                    "--occurred-at",
                    "2026-05-20T12:34:56Z",
                    "--severity",
                    "high",
                    "--no-api",
                    "--no-interactive",
                ],
            )
        assert result.exit_code == 0, result.output + result.stderr
        upsert_mock.assert_called_once()
        assert upsert_mock.call_args.kwargs["database"] is fake_db


# ---------------------------------------------------------------------------
# Default API mode + token propagation
# ---------------------------------------------------------------------------


class TestApiTransport:
    def test_post_via_requests_includes_payload_and_bearer(self):
        fake_response = MagicMock()
        fake_response.status_code = 200
        fake_response.json.return_value = _api_success_response()
        with patch("requests.post", return_value=fake_response) as post_mock:
            runner = _make_runner()
            result = runner.invoke(
                register_incident.main,
                [
                    "--id",
                    VALID_INCIDENT,
                    "--name",
                    "x",
                    "--occurred-at",
                    "2026-05-20T12:34:56Z",
                    "--severity",
                    "high",
                    "--api-url",
                    "http://api.example.com:8000",
                    "--token",
                    "my-token",
                    "--no-interactive",
                ],
            )
        assert result.exit_code == 0, result.output + result.stderr
        post_mock.assert_called_once()
        args, kwargs = post_mock.call_args
        assert args[0] == "http://api.example.com:8000/api/incidents"
        assert kwargs["headers"]["Authorization"] == "Bearer my-token"
        assert kwargs["json"]["incident_stix_id"] == VALID_INCIDENT

    def test_token_falls_back_to_env(self, monkeypatch):
        monkeypatch.setenv("SAGE_API_AUTH_TOKEN", "env-token")
        fake_response = MagicMock()
        fake_response.status_code = 200
        fake_response.json.return_value = _api_success_response()
        with patch("requests.post", return_value=fake_response) as post_mock:
            runner = _make_runner()
            result = runner.invoke(
                register_incident.main,
                [
                    "--id",
                    VALID_INCIDENT,
                    "--name",
                    "x",
                    "--occurred-at",
                    "2026-05-20T12:34:56Z",
                    "--severity",
                    "high",
                    "--no-interactive",
                ],
            )
        assert result.exit_code == 0, result.output + result.stderr
        assert post_mock.call_args.kwargs["headers"]["Authorization"] == "Bearer env-token"

    def test_api_error_returns_click_exception_exit_code(self):
        fake_response = MagicMock()
        fake_response.status_code = 503
        fake_response.text = "SAGE_API_AUTH_TOKEN not configured"
        with patch("requests.post", return_value=fake_response):
            runner = _make_runner()
            result = runner.invoke(
                register_incident.main,
                [
                    "--id",
                    VALID_INCIDENT,
                    "--name",
                    "x",
                    "--occurred-at",
                    "2026-05-20T12:34:56Z",
                    "--severity",
                    "high",
                    "--no-interactive",
                ],
            )
        # ClickException default exit code is 1
        assert result.exit_code != 0
        assert "POST /api/incidents failed" in result.stderr


# ---------------------------------------------------------------------------
# Interactive Diamond Model prompts
# ---------------------------------------------------------------------------


class TestInteractiveDiamondModel:
    def test_prompts_for_4_quadrants(self):
        """Feed 4 lines (adversary/capability/infrastructure/victim) over stdin."""
        with patch.object(
            register_incident, "_submit_via_api", return_value=_api_success_response()
        ) as submit_mock:
            runner = _make_runner()
            # Inputs in prompt order: adversary, capability, infrastructure, victim
            stdin_feed = "APT99\nspear-phishing kit\nfastflux nodes\nmail relay\n"
            result = runner.invoke(
                register_incident.main,
                [
                    "--id",
                    VALID_INCIDENT,
                    "--name",
                    "MIR-4242",
                    "--occurred-at",
                    "2026-05-20T12:34:56Z",
                    "--severity",
                    "high",
                ],
                input=stdin_feed,
            )
        assert result.exit_code == 0, result.output + result.stderr
        payload = submit_mock.call_args.kwargs["payload"]
        assert payload["diamond_model"] == {
            "adversary": "APT99",
            "capability": "spear-phishing kit",
            "infrastructure": "fastflux nodes",
            "victim": "mail relay",
        }

    def test_diamond_flag_overrides_prompt(self):
        """--diamond key=value wins over the matching interactive prompt."""
        with patch.object(
            register_incident, "_submit_via_api", return_value=_api_success_response()
        ) as submit_mock:
            runner = _make_runner()
            stdin_feed = "PROMPT-ADV\nPROMPT-CAP\nPROMPT-INF\nPROMPT-VIC\n"
            result = runner.invoke(
                register_incident.main,
                [
                    "--id",
                    VALID_INCIDENT,
                    "--name",
                    "MIR-4242",
                    "--occurred-at",
                    "2026-05-20T12:34:56Z",
                    "--severity",
                    "high",
                    "--diamond",
                    "adversary=FLAG-WINS",
                ],
                input=stdin_feed,
            )
        assert result.exit_code == 0, result.output + result.stderr
        diamond = submit_mock.call_args.kwargs["payload"]["diamond_model"]
        assert diamond["adversary"] == "FLAG-WINS"
        # Other quadrants come from the prompts
        assert diamond["capability"] == "PROMPT-CAP"


# ---------------------------------------------------------------------------
# --diamond key=value validation (rejects unknown keys)
# ---------------------------------------------------------------------------


class TestDiamondFlagValidation:
    def test_unknown_diamond_key_returns_usage_error(self):
        runner = _make_runner()
        result = runner.invoke(
            register_incident.main,
            [
                "--id",
                VALID_INCIDENT,
                "--name",
                "x",
                "--occurred-at",
                "2026-05-20T12:34:56Z",
                "--severity",
                "high",
                "--diamond",
                "unknown_quadrant=foo",
                "--no-interactive",
            ],
        )
        assert result.exit_code == 2
        assert "--diamond key must be one of" in result.stderr

    def test_diamond_without_equals_returns_usage_error(self):
        runner = _make_runner()
        result = runner.invoke(
            register_incident.main,
            [
                "--id",
                VALID_INCIDENT,
                "--name",
                "x",
                "--occurred-at",
                "2026-05-20T12:34:56Z",
                "--severity",
                "high",
                "--diamond",
                "no-equals-sign",
                "--no-interactive",
            ],
        )
        assert result.exit_code == 2
        assert "KEY=VALUE" in result.stderr


# ---------------------------------------------------------------------------
# Non-interactive missing required field
# ---------------------------------------------------------------------------


class TestRequiredFieldEnforcement:
    @pytest.mark.parametrize("missing_flag", ["--name", "--occurred-at", "--severity"])
    def test_missing_required_flag_in_non_interactive(self, missing_flag):
        args = [
            "--id",
            VALID_INCIDENT,
            "--name",
            "x",
            "--occurred-at",
            "2026-05-20T12:34:56Z",
            "--severity",
            "high",
            "--no-interactive",
        ]
        # Drop the flag we're testing
        idx = args.index(missing_flag)
        del args[idx : idx + 2]
        runner = _make_runner()
        result = runner.invoke(register_incident.main, args)
        assert result.exit_code == 2
