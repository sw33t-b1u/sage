import os
from dataclasses import dataclass
from pathlib import Path

# TLP priority order (used for filtering)
TLP_LEVELS = {"white": 0, "green": 1, "amber": 2, "red": 3}


def _load_dotenv(path: str = ".env") -> None:
    """Load .env file contents into os.environ (stdlib only, no external dependencies).

    Already-set environment variables are not overwritten.
    """
    env_file = Path(path)
    if not env_file.exists():
        return
    with env_file.open() as f:
        for line in f:
            line = line.strip()
            if not line or line.startswith("#") or "=" not in line:
                continue
            key, _, value = line.partition("=")
            key = key.strip()
            value = value.strip().strip('"').strip("'")
            if key and key not in os.environ:
                os.environ[key] = value


@dataclass
class Config:
    gcp_project_id: str
    spanner_instance_id: str
    spanner_database_id: str
    gcs_landing_bucket: str
    pir_file_path: str = "/config/pir.json"
    # OpenCTI — optional; only required for OpenCTI ingestion mode.
    # Not needed when running ETL with --input (local bundle) or for sage serve-api.
    opencti_url: str = ""
    opencti_token: str = ""
    # Ingest only data at or below this TLP level (red is always excluded)
    tlp_max_level: str = "amber"
    # Lookback window in days for FollowedBy activity score calculation
    activity_window_days: int = 90
    # Slack webhook URL (omit to disable notifications)
    slack_webhook_url: str = ""
    # GitHub Enterprise: Personal Access Token and "owner/repo" format
    ghe_token: str = ""
    ghe_repo: str = ""
    # Override API base URL for GitHub Enterprise Server (e.g. https://ghe.example.com/api/v3)
    ghe_api_base: str = "https://api.github.com"
    # Caldera: server URL and API key
    caldera_url: str = ""
    caldera_api_key: str = ""
    # Analysis API: bearer token for authentication (omit to disable auth — NOT recommended)
    api_auth_token: str = ""
    # Storage backend: "local" (default) or "gcs"
    sage_storage: str = "local"
    # Base directory for local storage (shared output directory with TRACE/BEACON)
    sage_storage_base_dir: str = "output"
    # GCS bucket name (required when sage_storage="gcs")
    sage_gcs_bucket: str = ""
    # GCS object key prefix (optional)
    sage_gcs_prefix: str = ""

    @classmethod
    def from_env(cls, dotenv_path: str = ".env") -> "Config":
        _load_dotenv(dotenv_path)
        missing = [
            k
            for k in (
                "PROJECT_ID",
                "SPANNER_INSTANCE",
                "SPANNER_DB",
                "GCS_BUCKET",
            )
            if not os.environ.get(k)
        ]
        if missing:
            raise RuntimeError(
                f"Required environment variables not set: {', '.join(missing)}. "
                "Hint: populate them in `.env` (local) or `--set-env-vars` (Cloud Run). "
                "See docs/setup.md Step 2 for the full env-var matrix."
            )

        return cls(
            gcp_project_id=os.environ["PROJECT_ID"],
            spanner_instance_id=os.environ["SPANNER_INSTANCE"],
            spanner_database_id=os.environ["SPANNER_DB"],
            gcs_landing_bucket=os.environ["GCS_BUCKET"],
            opencti_url=os.environ.get("OPENCTI_URL", ""),
            opencti_token=os.environ.get("OPENCTI_TOKEN", ""),
            pir_file_path=os.environ.get("PIR_FILE_PATH", "/config/pir.json"),
            tlp_max_level=os.environ.get("TLP_MAX_LEVEL", "amber"),
            # SAGE-specific override takes precedence; falls back to the
            # cross-project ACTIVITY_WINDOW_DAYS (set by operator for the
            # whole BEACON/TRACE/SAGE pipeline); final default 90.
            activity_window_days=int(
                os.environ.get(
                    "SAGE_ACTIVITY_WINDOW_DAYS",
                    os.environ.get("ACTIVITY_WINDOW_DAYS", "90"),
                )
            ),
            slack_webhook_url=os.environ.get("SLACK_WEBHOOK_URL", ""),
            ghe_token=os.environ.get("GHE_TOKEN", ""),
            ghe_repo=os.environ.get("GHE_REPO", ""),
            ghe_api_base=os.environ.get("GHE_API_BASE", "https://api.github.com"),
            caldera_url=os.environ.get("CALDERA_URL", ""),
            caldera_api_key=os.environ.get("CALDERA_API_KEY", ""),
            api_auth_token=os.environ.get("SAGE_API_AUTH_TOKEN", ""),
            sage_storage=os.environ.get("SAGE_STORAGE", "local"),
            sage_storage_base_dir=os.environ.get("SAGE_STORAGE_BASE_DIR", "output"),
            sage_gcs_bucket=os.environ.get("SAGE_GCS_BUCKET", ""),
            sage_gcs_prefix=os.environ.get("SAGE_GCS_PREFIX", ""),
        )
