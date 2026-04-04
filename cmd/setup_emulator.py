"""Spannerエミュレーター用インスタンス・データベース作成スクリプト。

SPANNER_EMULATOR_HOST が設定されている場合、Pythonクライアントが自動的に
エミュレーターへ接続する（gcloud CLI のエンドポイント設定は不要）。

使用方法:
    export SPANNER_EMULATOR_HOST=localhost:9010
    uv run python cmd/setup_emulator.py
"""

from __future__ import annotations

import os
import sys
from pathlib import Path

import structlog
from google.api_core.exceptions import AlreadyExists
from google.cloud import spanner
from google.cloud.spanner_admin_instance_v1.types import spanner_instance_admin

sys.path.insert(0, str(Path(__file__).parent.parent / "src"))

from sage.config import Config

structlog.configure(
    processors=[
        structlog.processors.TimeStamper(fmt="iso"),
        structlog.processors.JSONRenderer(),
    ]
)
logger = structlog.get_logger(__name__)


def main() -> None:
    if not os.environ.get("SPANNER_EMULATOR_HOST"):
        logger.error("env_missing", var="SPANNER_EMULATOR_HOST", hint="emulator only")
        sys.exit(1)

    config = Config.from_env()

    spanner_client = spanner.Client(project=config.gcp_project_id)
    instance_admin = spanner_client.instance_admin_api

    # インスタンス作成
    instance_name = f"projects/{config.gcp_project_id}/instances/{config.spanner_instance_id}"
    try:
        operation = instance_admin.create_instance(
            request=spanner_instance_admin.CreateInstanceRequest(
                parent=f"projects/{config.gcp_project_id}",
                instance_id=config.spanner_instance_id,
                instance=spanner_instance_admin.Instance(
                    name=instance_name,
                    config=f"projects/{config.gcp_project_id}/instanceConfigs/emulator-config",
                    display_name="local emulator",
                    node_count=1,
                ),
            )
        )
        operation.result(timeout=30)
        logger.info("instance_created", instance_id=config.spanner_instance_id)
    except AlreadyExists:
        logger.info("instance_already_exists", instance_id=config.spanner_instance_id)

    # データベース作成
    instance = spanner_client.instance(config.spanner_instance_id)
    try:
        database = instance.database(config.spanner_database_id)
        operation = database.create()
        operation.result(timeout=30)
        logger.info("database_created", database_id=config.spanner_database_id)
    except AlreadyExists:
        logger.info("database_already_exists", database_id=config.spanner_database_id)

    logger.info("emulator_setup_complete")


if __name__ == "__main__":
    main()
