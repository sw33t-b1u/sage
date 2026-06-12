"""ETL エントリポイント。

Cloud Run Job として実行される。
環境変数から設定を読み込み、OpenCTI → グラフ DB の ETL を実行する。

DB バックエンドは ``SAGE_DB`` で切り替わる。sqlite（既定）の場合は
``sage.db.database_session`` が DB ファイルを materialize → 書き込み →
publish（gcs のみ）する。spanner の場合は従来どおり直接書き込む。

使用方法:
    uv run sage run-etl
    uv run sage run-etl --input /path/to/bundle.json
"""

from __future__ import annotations

import argparse
import json
from datetime import UTC, datetime, timedelta
from pathlib import Path

import structlog

from sage.config import Config
from sage.db import database_session, fetch_asset_rows, find_choke_points
from sage.etl.worker import ETLWorker
from sage.notify.slack import notify_etl_complete
from sage.pir.filter import PIRFilter
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

    with database_session(config, publish=True) as database:
        _run(args, config, pir_filter, database)


def _run(
    args: argparse.Namespace,
    config: Config,
    pir_filter: PIRFilter,
    database: object,
) -> None:
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
        # "stix" category, process all of them.
        storage = create_storage_backend(config)
        stix_files = storage.list_files("stix")
        if stix_files:
            logger.info(
                "mode",
                type="storage",
                backend=config.sage_storage,
                bundle_count=len(stix_files),
            )
            # Accumulate asset rows once; process each bundle individually so
            # that stats reflect the full run.
            asset_rows = fetch_asset_rows(database)
            logger.info("fetched_assets", count=len(asset_rows))
            prev_choke_rows = find_choke_points(database, top_n=50)

            combined_stats: dict = {}
            for stix_filename in stix_files:
                logger.info("processing_bundle", file=stix_filename)
                content = storage.load("stix", stix_filename)
                bundle = json.loads(content)
                objects = parse_bundle(bundle)
                stats = worker.process_bundle(objects, asset_rows=asset_rows)
                for k, v in stats.items():
                    combined_stats[k] = combined_stats.get(k, 0) + v

            logger.info(
                "storage_etl_complete",
                bundles_processed=len(stix_files),
                **combined_stats,
            )

            if config.slack_webhook_url:
                choke_rows = find_choke_points(database, top_n=50)
                notify_etl_complete(
                    config.slack_webhook_url, combined_stats, choke_rows, prev_choke_rows
                )
            return
        else:
            modified_after = datetime.now(tz=UTC) - timedelta(days=args.since_days)
            logger.info("mode", type="opencti", modified_after=modified_after.isoformat())
            if not config.opencti_url or not config.opencti_token:
                logger.error(
                    "opencti_credentials_missing",
                    hint="set OPENCTI_URL / OPENCTI_TOKEN in .env or pass --input <bundle.json>",
                )
                raise SystemExit(
                    "OpenCTI mode requested but OPENCTI_URL / OPENCTI_TOKEN are not set. "
                    "Either provide them via .env / --set-env-vars, or pass --input <bundle.json> "
                    "to process a local STIX bundle instead."
                )
            # Lazy import: pycti pulls libmagic which is only needed when
            # OpenCTI mode is actually used.
            from sage.opencti.client import OpenCTIClient  # noqa: PLC0415

            client = OpenCTIClient(config.opencti_url, config.opencti_token)
            bundle = client.fetch_stix_bundle(modified_after=modified_after)
            client.save_bundle_to_gcs(bundle, config.sage_etl_input_bucket)
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
