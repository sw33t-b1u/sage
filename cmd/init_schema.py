"""Spanner Graph スキーマ初期化スクリプト。

schema/spanner_ddl.sql の DDL を実行して Spanner データベースにスキーマを作成する。
既存テーブルはスキップされる（Spanner は IF NOT EXISTS 未対応のため、エラーを個別処理）。

使用方法:
    uv run python cmd/init_schema.py
"""

from __future__ import annotations

import sys
from pathlib import Path

import structlog
from google.api_core.exceptions import AlreadyExists
from google.cloud import spanner

sys.path.insert(0, str(Path(__file__).parent.parent / "src"))

from sage.config import Config

structlog.configure(
    processors=[
        structlog.processors.TimeStamper(fmt="iso"),
        structlog.processors.JSONRenderer(),
    ]
)
logger = structlog.get_logger(__name__)

DDL_PATH = Path(__file__).parent.parent / "schema" / "spanner_ddl.sql"


def split_ddl_statements(ddl: str) -> list[str]:
    """DDL をセミコロンで分割してステートメントリストを返す。

    コメント行を除去し、空のステートメントをスキップする。
    CREATE PROPERTY GRAPH は複数行にまたがるため、単純な split ではなく
    セミコロンを最終デリミタとして処理する。
    """
    # コメント行を除去
    lines = [line for line in ddl.splitlines() if not line.strip().startswith("--")]
    cleaned = "\n".join(lines)

    # セミコロンで分割
    statements = [s.strip() for s in cleaned.split(";")]
    return [s for s in statements if s]


def main() -> None:
    config = Config.from_env()
    ddl_text = DDL_PATH.read_text()
    statements = split_ddl_statements(ddl_text)

    spanner_client = spanner.Client(project=config.gcp_project_id)
    instance = spanner_client.instance(config.spanner_instance_id)
    database = instance.database(config.spanner_database_id)

    logger.info("applying_ddl", statement_count=len(statements))

    # Spanner は DDL を一括で送れるが、既存テーブルエラーを個別処理するため1件ずつ実行
    success, skipped, failed = 0, 0, 0
    for stmt in statements:
        first_line = stmt.splitlines()[0][:80]
        try:
            operation = database.update_ddl([stmt])
            operation.result(timeout=120)
            logger.info("applied", statement=first_line)
            success += 1
        except AlreadyExists:
            logger.info("skipped_exists", statement=first_line)
            skipped += 1
        except Exception as exc:
            logger.error("failed", statement=first_line, error=str(exc))
            failed += 1

    logger.info("done", success=success, skipped=skipped, failed=failed)
    if failed:
        sys.exit(1)


if __name__ == "__main__":
    main()
