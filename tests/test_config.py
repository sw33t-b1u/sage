"""Tests for sage.config.Config.from_env() — required/optional env handling."""

import pytest


@pytest.fixture(autouse=True)
def _isolate_env(monkeypatch):
    """Strip all SAGE-relevant env vars so each test sets only what it needs."""
    for key in (
        "SAGE_DB",
        "GCP_PROJECT_ID",
        "SPANNER_INSTANCE",
        "SPANNER_DB",
        "SAGE_ETL_INPUT_BUCKET",
        "OPENCTI_URL",
        "OPENCTI_TOKEN",
        "PIR_FILE_PATH",
        "TLP_MAX_LEVEL",
        "ACTIVITY_WINDOW_DAYS",
        "SAGE_ACTIVITY_WINDOW_DAYS",
        "SLACK_WEBHOOK_URL",
        "GHE_TOKEN",
        "GHE_REPO",
        "GHE_API_BASE",
        "CALDERA_URL",
        "CALDERA_API_KEY",
        "SAGE_API_AUTH_TOKEN",
        "SAGE_STORAGE",
        "SAGE_STORAGE_BASE_DIR",
        "SAGE_STORAGE_BUCKET",
        "SAGE_STORAGE_PREFIX",
    ):
        monkeypatch.delenv(key, raising=False)


class TestFromEnvRequiredMinimum:
    def test_succeeds_with_only_4_required_vars(self, monkeypatch):
        """OpenCTI vars are now optional; 4 vars suffice."""
        for k, v in {
            "GCP_PROJECT_ID": "test-proj",
            "SPANNER_INSTANCE": "test-inst",
            "SPANNER_DB": "test-db",
            "SAGE_ETL_INPUT_BUCKET": "test-bucket",
        }.items():
            monkeypatch.setenv(k, v)
        from sage.config import Config

        cfg = Config.from_env(dotenv_path="/nonexistent/.env")
        assert cfg.opencti_url == ""
        assert cfg.opencti_token == ""
        assert cfg.gcp_project_id == "test-proj"

    def test_missing_required_var_includes_hint_in_message(self, monkeypatch):
        """Error message must mention the missing var, .env, and --set-env-vars.

        The 4 GCP/Spanner vars are only required for the Spanner backend, so
        this test selects it explicitly via SAGE_DB=spanner. With the default
        sqlite backend none of the four are required.
        """
        monkeypatch.setenv("SAGE_DB", "spanner")
        for k, v in {
            "GCP_PROJECT_ID": "test-proj",
            "SPANNER_INSTANCE": "test-inst",
            "SPANNER_DB": "test-db",
            # SAGE_ETL_INPUT_BUCKET intentionally missing
        }.items():
            monkeypatch.setenv(k, v)
        from sage.config import Config

        with pytest.raises(RuntimeError) as excinfo:
            Config.from_env(dotenv_path="/nonexistent/.env")
        msg = str(excinfo.value)
        assert "SAGE_ETL_INPUT_BUCKET" in msg
        assert ".env" in msg
        assert "--set-env-vars" in msg

    def test_opencti_vars_picked_up_when_provided(self, monkeypatch):
        """Optional fields still load when env is set."""
        for k, v in {
            "GCP_PROJECT_ID": "test-proj",
            "SPANNER_INSTANCE": "test-inst",
            "SPANNER_DB": "test-db",
            "SAGE_ETL_INPUT_BUCKET": "test-bucket",
            "OPENCTI_URL": "https://opencti.example.com",
            "OPENCTI_TOKEN": "secret-token",
        }.items():
            monkeypatch.setenv(k, v)
        from sage.config import Config

        cfg = Config.from_env(dotenv_path="/nonexistent/.env")
        assert cfg.opencti_url == "https://opencti.example.com"
        assert cfg.opencti_token == "secret-token"


class TestRunEtlOpenctiGuard:
    def test_run_etl_opencti_mode_without_credentials_exits(self, tmp_path, monkeypatch):
        """run_etl guard: OpenCTI mode + no credentials → SystemExit with --input hint.

        Approach: Import sage.cli.run_etl directly. Monkeypatch Config.from_env,
        get_database, PIRFilter, ETLWorker, and create_storage_backend so no network
        calls are made. Then call main() directly and assert SystemExit.
        This is more reliable than subprocess (avoids Spanner client init race).
        """
        import sys
        from unittest.mock import MagicMock, patch

        from sage.cli.run_etl import main as run_etl_main

        # Build a minimal stub config — no OPENCTI_URL / OPENCTI_TOKEN
        from sage.config import Config

        stub_config = Config(
            gcp_project_id="test-proj",
            spanner_instance_id="test-inst",
            spanner_database_id="test-db",
            sage_etl_input_bucket="test-bucket",
            opencti_url="",
            opencti_token="",
            pir_file_path=str(tmp_path / "pir.json"),
        )

        # Patch sys.argv so argparse sees no --input flag → OpenCTI branch is taken
        monkeypatch.setattr(sys, "argv", ["run_etl.py"])

        with (
            patch("sage.cli.run_etl.Config") as mock_config_cls,
            patch("sage.cli.run_etl.get_database", return_value=MagicMock()),
            patch("sage.cli.run_etl.PIRFilter") as mock_pir_cls,
            patch("sage.cli.run_etl.ETLWorker", return_value=MagicMock()),
            patch("sage.cli.run_etl.create_storage_backend") as mock_storage,
        ):
            mock_config_cls.from_env.return_value = stub_config
            mock_pir_cls.from_file.return_value = MagicMock()
            # storage.list_files returns empty list → falls through to OpenCTI branch
            mock_storage_instance = MagicMock()
            mock_storage_instance.list_files.return_value = []
            mock_storage.return_value = mock_storage_instance

            with pytest.raises(SystemExit) as excinfo:
                run_etl_main()

        exit_val = excinfo.value.code
        # SystemExit raised with a non-empty string message is truthy
        assert exit_val, f"Expected non-zero/truthy SystemExit, got {exit_val!r}"
        assert "--input" in str(exit_val), (
            f"Expected '--input' in SystemExit message, got: {exit_val!r}"
        )
