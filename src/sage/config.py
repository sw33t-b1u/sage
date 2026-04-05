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
    opencti_url: str
    opencti_token: str
    pir_file_path: str = "/config/pir.json"
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

    @classmethod
    def from_env(cls, dotenv_path: str = ".env") -> "Config":
        _load_dotenv(dotenv_path)
        missing = [
            k
            for k in (
                "GCP_PROJECT_ID",
                "SPANNER_INSTANCE_ID",
                "SPANNER_DATABASE_ID",
                "GCS_LANDING_BUCKET",
                "OPENCTI_URL",
                "OPENCTI_TOKEN",
            )
            if not os.environ.get(k)
        ]
        if missing:
            raise RuntimeError(f"Required environment variables not set: {', '.join(missing)}")

        return cls(
            gcp_project_id=os.environ["GCP_PROJECT_ID"],
            spanner_instance_id=os.environ["SPANNER_INSTANCE_ID"],
            spanner_database_id=os.environ["SPANNER_DATABASE_ID"],
            gcs_landing_bucket=os.environ["GCS_LANDING_BUCKET"],
            opencti_url=os.environ["OPENCTI_URL"],
            opencti_token=os.environ["OPENCTI_TOKEN"],
            pir_file_path=os.environ.get("PIR_FILE_PATH", "/config/pir.json"),
            tlp_max_level=os.environ.get("TLP_MAX_LEVEL", "amber"),
            activity_window_days=int(os.environ.get("ACTIVITY_WINDOW_DAYS", "90")),
            slack_webhook_url=os.environ.get("SLACK_WEBHOOK_URL", ""),
            ghe_token=os.environ.get("GHE_TOKEN", ""),
            ghe_repo=os.environ.get("GHE_REPO", ""),
            ghe_api_base=os.environ.get("GHE_API_BASE", "https://api.github.com"),
            caldera_url=os.environ.get("CALDERA_URL", ""),
            caldera_api_key=os.environ.get("CALDERA_API_KEY", ""),
        )
