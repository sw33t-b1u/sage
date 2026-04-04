import os
from dataclasses import dataclass
from pathlib import Path

# TLP 順序（フィルタリングに使用）
TLP_LEVELS = {"white": 0, "green": 1, "amber": 2, "red": 3}


def _load_dotenv(path: str = ".env") -> None:
    """
    .env ファイルの内容を os.environ に読み込む（stdlib のみ、外部依存なし）。
    既に設定済みの環境変数は上書きしない。
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
    # amber 以下のデータのみ取り込む（red は除外）
    tlp_max_level: str = "amber"
    # FollowedBy 重み計算の活動観測ウィンドウ（日）
    activity_window_days: int = 90
    # Slack webhook URL（省略時は通知なし）
    slack_webhook_url: str = ""
    # GitHub Enterprise: Personal Access Token と "owner/repo" 形式
    ghe_token: str = ""
    ghe_repo: str = ""
    # Caldera: URL と API キー
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
            raise RuntimeError(f"必須環境変数が未設定です: {', '.join(missing)}")

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
            caldera_url=os.environ.get("CALDERA_URL", ""),
            caldera_api_key=os.environ.get("CALDERA_API_KEY", ""),
        )
