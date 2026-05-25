"""ETL エントリポイント。

Cloud Run Job として実行される。
環境変数から設定を読み込み、OpenCTI → Spanner Graph の ETL を実行する。

使用方法:
    uv run python cmd/run_etl.py
    uv run python cmd/run_etl.py --input /path/to/bundle.json
"""

from __future__ import annotations

import argparse
import json
import sys
from datetime import UTC, datetime, timedelta
from pathlib import Path

import structlog

# src を Python パスに追加
sys.path.insert(0, str(Path(__file__).parent.parent / "src"))

from sage.config import Config
from sage.etl.worker import ETLWorker
from sage.notify.slack import notify_etl_complete
from sage.opencti.client import OpenCTIClient
from sage.pir.filter import PIRFilter
from sage.spanner.client import get_database
from sage.spanner.query import find_choke_points
from sage.spanner.upsert import fetch_asset_rows
from sage.stix.parser import parse_bundle
from sage.storage import create_storage_backend

structlog.configure(
    processors=[
        structlog.processors.TimeStamper(fmt="iso"),
        structlog.processors.JSONRenderer(),
    ]
)
logger = structlog.get_logger(__name__)


def main() -> None:
    parser = argparse.ArgumentParser(description="Threat Intel ETL Worker")
    parser.add_argument(
        "--input",
        "-i",
        type=Path,
        help="OpenCTI を使わずローカルの STIX バンドル JSON を処理する（手動更新用）",
    )
    parser.add_argument(
        "--since-days",
        type=int,
        default=1,
        help="差分取得の対象日数（デフォルト: 1日分）",
    )
    args = parser.parse_args()

    config = Config.from_env()
    pir_filter = PIRFilter.from_file(Path(config.pir_file_path))
    database = get_database(
        config.gcp_project_id,
        config.spanner_instance_id,
        config.spanner_database_id,
    )
    worker = ETLWorker(
        database,
        pir_filter,
        config.tlp_max_level,
        activity_window_days=config.activity_window_days,
    )

    if args.input:
        logger.info("mode", type="manual", path=str(args.input))
        with args.input.open() as f:
            bundle = json.load(f)
        objects = parse_bundle(bundle)
    else:
        # Try StorageBackend first — if any STIX bundles exist in the
        # "stix" category, load the latest one.
        storage = create_storage_backend(config)
        stix_files = storage.list_files("stix")
        if stix_files:
            latest = stix_files[-1]
            logger.info("mode", type="storage", file=latest, backend=config.sage_storage)
            raw = storage.load("stix", latest)
            bundle = json.loads(raw)
            objects = parse_bundle(bundle)
        else:
            modified_after = datetime.now(tz=UTC) - timedelta(days=args.since_days)
            logger.info("mode", type="opencti", modified_after=modified_after.isoformat())
            client = OpenCTIClient(config.opencti_url, config.opencti_token)
            bundle = client.fetch_stix_bundle(modified_after=modified_after)
            client.save_bundle_to_gcs(bundle, config.gcs_landing_bucket)
            objects = parse_bundle(bundle)

    # Targets エッジ生成のために事前に資産データを取得する
    asset_rows = fetch_asset_rows(database)
    logger.info("fetched_assets", count=len(asset_rows))

    # ETL 前のチョークスコアを保存（前回比変化検知用）
    prev_choke_rows = find_choke_points(database, top_n=50)

    stats = worker.process_bundle(objects, asset_rows=asset_rows)
    logger.info("done", **stats)

    # ETL 後のチョークスコアを取得して前回比を Slack に通知
    if config.slack_webhook_url:
        choke_rows = find_choke_points(database, top_n=50)
        notify_etl_complete(config.slack_webhook_url, stats, choke_rows, prev_choke_rows)


if __name__ == "__main__":
    main()
