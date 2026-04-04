"""指定資産への攻撃経路を表示するスクリプト。

Spanner GQL を用いて、指定した資産に Targets エッジで紐づく ThreatActor と
その TTP（Uses エッジ）を信頼度順に表示する。

使用方法:
    uv run python cmd/query_attack_paths.py --asset-id asset-001
    uv run python cmd/query_attack_paths.py --asset-id asset-001 --limit 5
    uv run python cmd/query_attack_paths.py --actor-id intrusion-set--apt99
"""

from __future__ import annotations

import argparse
import sys
from pathlib import Path

import structlog

sys.path.insert(0, str(Path(__file__).parent.parent / "src"))

from sage.config import Config
from sage.spanner.client import get_database
from sage.spanner.query import find_actor_ttps, find_attack_paths

structlog.configure(
    processors=[
        structlog.processors.TimeStamper(fmt="iso"),
        structlog.processors.JSONRenderer(),
    ]
)
logger = structlog.get_logger(__name__)


def _print_attack_paths(rows: list[dict], asset_id: str) -> None:
    if not rows:
        print(f"資産 {asset_id} への攻撃経路が見つかりませんでした。")
        return

    print(f"\n=== 資産 {asset_id} への攻撃経路 ===\n")
    current_actor = None
    for row in rows:
        if row["actor_stix_id"] != current_actor:
            current_actor = row["actor_stix_id"]
            print(f"【攻撃元アクター】{row['actor_name']} ({row['actor_stix_id']})")
        print(f"  TTP: {row['ttp_name']} ({row['ttp_stix_id']})  信頼度: {row['confidence']}")
    print()


def _print_actor_ttps(rows: list[dict], actor_id: str) -> None:
    if not rows:
        print(f"アクター {actor_id} の攻撃フローが見つかりませんでした。")
        return

    print(f"\n=== アクター {actor_id} の攻撃フロー（FollowedBy） ===\n")
    for row in rows:
        print(
            f"  {row['src_ttp_name']} → {row['dst_ttp_name']}"
            f"  weight={row['weight']:.2f}  source={row['source']}"
        )
    print()


def main() -> None:
    parser = argparse.ArgumentParser(description="攻撃経路クエリ")
    group = parser.add_mutually_exclusive_group(required=True)
    group.add_argument(
        "--asset-id",
        help="クエリ対象の資産 ID（Asset.id）",
    )
    group.add_argument(
        "--actor-id",
        help="クエリ対象のアクター STIX ID",
    )
    parser.add_argument(
        "--limit",
        type=int,
        default=10,
        help="最大表示件数（デフォルト: 10）",
    )
    args = parser.parse_args()

    config = Config.from_env()
    database = get_database(
        config.gcp_project_id,
        config.spanner_instance_id,
        config.spanner_database_id,
    )

    if args.asset_id:
        rows = find_attack_paths(database, asset_id=args.asset_id, limit=args.limit)
        _print_attack_paths(rows, args.asset_id)
    else:
        rows = find_actor_ttps(database, actor_stix_id=args.actor_id)
        _print_actor_ttps(rows, args.actor_id)


if __name__ == "__main__":
    main()
