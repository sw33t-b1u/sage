"""チョークポイント資産レポートを Markdown で出力するスクリプト。

Spanner の Targets エッジと pir_adjusted_criticality を元に
choke_score（= pir_adjusted_criticality × 攻撃元アクター数）でランキングし、
Blue Team 向けの Markdown レポートを stdout / ファイル / GHE Issue へ出力する。

使用方法:
    uv run python cmd/report_choke_points.py
    uv run python cmd/report_choke_points.py --top 10 --output report.md
    uv run python cmd/report_choke_points.py --ghe   # GHE Issue として投稿
"""

from __future__ import annotations

import argparse
import sys
from datetime import UTC, datetime
from pathlib import Path

import structlog

sys.path.insert(0, str(Path(__file__).parent.parent / "src"))

from sage.config import Config
from sage.notify.github import post_choke_point_issue
from sage.spanner.client import get_database
from sage.spanner.query import find_choke_points

structlog.configure(
    processors=[
        structlog.processors.TimeStamper(fmt="iso"),
        structlog.processors.JSONRenderer(),
    ]
)
logger = structlog.get_logger(__name__)


def render_markdown(rows: list[dict], generated_at: str) -> str:
    lines = [
        "# SAGE チョークポイントレポート",
        "",
        f"生成日時: {generated_at}",
        "",
        "## 上位チョークポイント資産",
        "",
        "| 順位 | 資産 ID | 資産名 | PIR調整済み重要度 | 攻撃元アクター数 | チョークスコア |",
        "|------|---------|--------|-----------------|----------------|--------------|",
    ]
    for i, row in enumerate(rows, 1):
        lines.append(
            f"| {i} "
            f"| {row['asset_id']} "
            f"| {row['asset_name']} "
            f"| {row['pir_adjusted_criticality']:.1f} "
            f"| {row['targeting_actor_count']} "
            f"| {row['choke_score']:.1f} |"
        )

    lines += [
        "",
        "---",
        "",
        "**チョークスコア** = PIR調整済み重要度 × 攻撃元アクター数",
        "",
        "_このレポートは SAGE (Security Attack Graph Engine) により自動生成されました。_",
    ]
    return "\n".join(lines)


def main() -> None:
    parser = argparse.ArgumentParser(description="チョークポイント資産レポートを生成")
    parser.add_argument(
        "--top",
        type=int,
        default=20,
        help="表示する上位N件（デフォルト: 20）",
    )
    parser.add_argument(
        "--output",
        type=Path,
        default=None,
        help="出力先ファイルパス（省略時は stdout）",
    )
    parser.add_argument(
        "--ghe",
        action="store_true",
        help="GHE Issue として投稿する（GHE_TOKEN / GHE_REPO 環境変数が必要）",
    )
    args = parser.parse_args()

    config = Config.from_env()
    database = get_database(
        config.gcp_project_id,
        config.spanner_instance_id,
        config.spanner_database_id,
    )

    logger.info("querying_choke_points", top_n=args.top)
    rows = find_choke_points(database, top_n=args.top)

    if not rows:
        logger.warning("no_choke_points_found")
        print("チョークポイント資産が見つかりませんでした。")
        print("ETL と資産ロードを先に実行してください。")
        return

    now = datetime.now(tz=UTC)
    generated_at = now.strftime("%Y-%m-%d %H:%M UTC")
    report = render_markdown(rows, generated_at)

    if args.ghe:
        iso_week = now.strftime("%Y-W%V")
        title = f"[SAGE] チョークポイントレポート {iso_week}"
        issue_url = post_choke_point_issue(
            token=config.ghe_token,
            repo=config.ghe_repo,
            title=title,
            body=report,
        )
        if issue_url:
            logger.info("ghe_issue_posted", url=issue_url)
        else:
            logger.error("ghe_issue_failed")
    elif args.output:
        args.output.write_text(report, encoding="utf-8")
        logger.info("report_written", path=str(args.output))
    else:
        print(report)


if __name__ == "__main__":
    main()
