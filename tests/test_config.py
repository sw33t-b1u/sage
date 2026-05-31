"""Tests for sage.config.Config.from_env() — required/optional env handling."""

import pytest


@pytest.fixture(autouse=True)
def _isolate_env(monkeypatch):
    """Strip all SAGE-relevant env vars so each test sets only what it needs."""
    for key in (
        "PROJECT_ID",
        "SPANNER_INSTANCE",
        "SPANNER_DB",
        "GCS_BUCKET",
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
        "SAGE_GCS_BUCKET",
        "SAGE_GCS_PREFIX",
    ):
        monkeypatch.delenv(key, raising=False)


class TestFromEnvRequiredMinimum:
    def test_succeeds_with_only_4_required_vars(self, monkeypatch):
        """OpenCTI vars are now optional; 4 vars suffice."""
        for k, v in {
            "PROJECT_ID": "test-proj",
            "SPANNER_INSTANCE": "test-inst",
            "SPANNER_DB": "test-db",
            "GCS_BUCKET": "test-bucket",
        }.items():
            monkeypatch.setenv(k, v)
        from sage.config import Config

        cfg = Config.from_env(dotenv_path="/nonexistent/.env")
        assert cfg.opencti_url == ""
        assert cfg.opencti_token == ""
        assert cfg.gcp_project_id == "test-proj"

    def test_missing_required_var_includes_hint_in_message(self, monkeypatch):
        """Error message must mention the missing var, .env, and --set-env-vars."""
        for k, v in {
            "PROJECT_ID": "test-proj",
            "SPANNER_INSTANCE": "test-inst",
            "SPANNER_DB": "test-db",
            # GCS_BUCKET intentionally missing
        }.items():
            monkeypatch.setenv(k, v)
        from sage.config import Config

        with pytest.raises(RuntimeError) as excinfo:
            Config.from_env(dotenv_path="/nonexistent/.env")
        msg = str(excinfo.value)
        assert "GCS_BUCKET" in msg
        assert ".env" in msg
        assert "--set-env-vars" in msg

    def test_opencti_vars_picked_up_when_provided(self, monkeypatch):
        """Optional fields still load when env is set."""
        for k, v in {
            "PROJECT_ID": "test-proj",
            "SPANNER_INSTANCE": "test-inst",
            "SPANNER_DB": "test-db",
            "GCS_BUCKET": "test-bucket",
            "OPENCTI_URL": "https://opencti.example.com",
            "OPENCTI_TOKEN": "secret-token",
        }.items():
            monkeypatch.setenv(k, v)
        from sage.config import Config

        cfg = Config.from_env(dotenv_path="/nonexistent/.env")
        assert cfg.opencti_url == "https://opencti.example.com"
        assert cfg.opencti_token == "secret-token"
