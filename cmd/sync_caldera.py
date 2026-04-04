"""Caldera 連携 CLI — アクター TTP を Caldera Adversary プロファイルに同期する。

Usage:
  uv run python -m cmd.sync_caldera --actor-id intrusion-set--xxx
  uv run python -m cmd.sync_caldera --list-adversaries

環境変数:
  CALDERA_URL, CALDERA_API_KEY が必要。
  GCP_PROJECT_ID 等は Config.from_env() 経由で読み込む。
"""

from __future__ import annotations

import argparse
import json
import sys

import structlog
from google.cloud import spanner

from sage.caldera.client import get_adversaries, sync_actor_ttps
from sage.config import Config
from sage.spanner.query import find_actor_ttps

logger = structlog.get_logger(__name__)


def main() -> None:
    parser = argparse.ArgumentParser(description="Sync actor TTPs to Caldera adversary profile")
    group = parser.add_mutually_exclusive_group(required=True)
    group.add_argument("--actor-id", help="ThreatActor STIX ID")
    group.add_argument(
        "--list-adversaries", action="store_true", help="List existing Caldera adversaries"
    )
    args = parser.parse_args()

    config = Config.from_env()

    if not config.caldera_url or not config.caldera_api_key:
        print(
            "Error: CALDERA_URL and CALDERA_API_KEY must be set.",
            file=sys.stderr,
        )
        sys.exit(1)

    if args.list_adversaries:
        adversaries = get_adversaries(config.caldera_url, config.caldera_api_key)
        print(json.dumps(adversaries, ensure_ascii=False, indent=2))
        return

    spanner_client = spanner.Client(project=config.gcp_project_id)
    instance = spanner_client.instance(config.spanner_instance_id)
    database = instance.database(config.spanner_database_id)

    ttp_rows = find_actor_ttps(database, args.actor_id)
    if not ttp_rows:
        print(f"No TTP found for actor: {args.actor_id}", file=sys.stderr)
        sys.exit(1)

    result = sync_actor_ttps(
        caldera_url=config.caldera_url,
        api_key=config.caldera_api_key,
        actor_stix_id=args.actor_id,
        ttp_rows=ttp_rows,
    )

    print(json.dumps(result, ensure_ascii=False, indent=2))
    logger.info(
        "sync_caldera_done",
        actor_id=args.actor_id,
        action=result["action"],
        ability_count=result["ability_count"],
    )


if __name__ == "__main__":
    main()
