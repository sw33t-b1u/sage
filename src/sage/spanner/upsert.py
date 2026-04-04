"""Spanner Graph への upsert 操作。

INSERT OR UPDATE (insert_or_update mutation) を使用して冪等性を担保する。
同一 stix_id のオブジェクトが複数回 ETL されても重複しない。
"""

from __future__ import annotations

from typing import Any

import google.cloud.spanner as spanner
import structlog
from google.cloud.spanner_v1.database import Database

logger = structlog.get_logger(__name__)

# テーブルごとのカラム定義（順序は Spanner DDL と一致させる）
_TABLE_COLUMNS: dict[str, list[str]] = {
    "ThreatActor": [
        "stix_id",
        "stix_type",
        "name",
        "aliases",
        "sophistication",
        "motivation",
        "tags",
        "first_seen",
        "last_seen",
        "stix_modified",
    ],
    "TTP": [
        "stix_id",
        "attack_technique_id",
        "tactic",
        "name",
        "description",
        "platforms",
        "detection_difficulty",
        "stix_modified",
    ],
    "Vulnerability": [
        "stix_id",
        "cve_id",
        "description",
        "cvss_score",
        "epss_score",
        "affected_platforms",
        "published_date",
        "stix_modified",
    ],
    "MalwareTool": [
        "stix_id",
        "stix_type",
        "name",
        "description",
        "capabilities",
        "stix_modified",
    ],
    "Observable": [
        "stix_id",
        "obs_type",
        "value",
        "confidence",
        "tlp",
        "first_seen",
        "last_seen",
        "stix_modified",
    ],
    "Incident": [
        "stix_id",
        "name",
        "description",
        "occurred_at",
        "resolved_at",
        "severity",
        "kill_chain_phases",
        "diamond_model",
        "source",
        "stix_modified",
    ],
    "Asset": [
        "id",
        "name",
        "asset_type",
        "environment",
        "criticality",
        "pir_adjusted_criticality",
        "owner",
        "network_segment",
        "network_cidr",
        "network_zone",
        "exposed_to_internet",
        "tags",
        "last_updated",
    ],
    "SecurityControl": ["id", "name", "control_type", "coverage"],
    "Uses": [
        "actor_stix_id",
        "ttp_stix_id",
        "confidence",
        "first_observed",
        "last_observed",
        "stix_id",
    ],
    "UsesTool": [
        "actor_stix_id",
        "tool_stix_id",
        "confidence",
        "first_observed",
        "last_observed",
        "stix_id",
    ],
    "Exploits": ["ttp_stix_id", "vuln_stix_id", "stix_id"],
    "MalwareUsesTTP": [
        "malware_stix_id",
        "ttp_stix_id",
        "confidence",
        "first_observed",
        "last_observed",
        "stix_id",
    ],
    "Targets": ["actor_stix_id", "asset_id", "confidence", "source"],
    "HasVulnerability": [
        "asset_id",
        "vuln_stix_id",
        "remediation_status",
        "detected_at",
    ],
    "ConnectedTo": [
        "src_asset_id",
        "dst_asset_id",
        "protocol",
        "port",
        "direction",
        "allowed",
    ],
    "ProtectedBy": ["asset_id", "control_id"],
    "IndicatesTTP": ["observable_stix_id", "ttp_stix_id", "confidence", "stix_id"],
    "IndicatesActor": ["observable_stix_id", "actor_stix_id", "confidence", "stix_id"],
    "FollowedBy": [
        "src_ttp_stix_id",
        "dst_ttp_stix_id",
        "source",
        "weight",
        "actor_stix_id",
        "evidence_stix_ids",
        "last_calculated",
    ],
    "IncidentUsesTTP": ["incident_stix_id", "ttp_stix_id", "sequence_order"],
}

# バッチサイズ（Spanner mutation の上限は 20,000 mutations/transaction）
_BATCH_SIZE = 500


def upsert_rows(
    database: Database,
    table: str,
    rows: list[dict[str, Any]],
) -> int:
    """指定テーブルへ rows を一括 upsert する。挿入/更新した行数を返す。"""
    if not rows:
        return 0

    columns = _TABLE_COLUMNS[table]
    total = 0

    for batch in _chunk(rows, _BATCH_SIZE):
        values = [_row_to_values(r, columns) for r in batch]
        with database.batch() as b:
            b.insert_or_update(table=table, columns=columns, values=values)
        total += len(batch)

    logger.info("upserted", table=table, count=total)
    return total


def upsert_followed_by(
    database: Database,
    rows: list[dict[str, Any]],
) -> int:
    """FollowedBy を upsert する。last_calculated に commit_timestamp を使用。"""
    if not rows:
        return 0

    columns = _TABLE_COLUMNS["FollowedBy"]
    total = 0

    for batch in _chunk(rows, _BATCH_SIZE):
        # last_calculated は ALLOW_COMMIT_TIMESTAMP 対応カラム
        values = []
        for r in batch:
            row_vals = _row_to_values(r, columns)
            # last_calculated (最後のカラム) を commit timestamp に置き換え
            row_vals[-1] = spanner.COMMIT_TIMESTAMP
            values.append(row_vals)

        with database.batch() as b:
            b.insert_or_update(table="FollowedBy", columns=columns, values=values)
        total += len(batch)

    logger.info("upserted_followed_by", count=total)
    return total


# ---------------------------------------------------------------------------
# クエリ (読み取り)
# ---------------------------------------------------------------------------


def update_pir_criticality(
    database: Database,
    asset_rows: list[dict],
) -> int:
    """Asset.pir_adjusted_criticality を部分更新する（id 以外のカラムは変更しない）。

    batch.update() を使用して pir_adjusted_criticality のみを更新する。
    """
    if not asset_rows:
        return 0

    columns = ["id", "pir_adjusted_criticality"]
    total = 0
    for batch_rows in _chunk(asset_rows, _BATCH_SIZE):
        values = [[r["id"], r.get("pir_adjusted_criticality")] for r in batch_rows]
        with database.batch() as b:
            b.update(table="Asset", columns=columns, values=values)
        total += len(batch_rows)

    logger.info("updated_pir_criticality", count=total)
    return total


def fetch_asset_rows(database: Database) -> list[dict]:
    """Spanner から Asset テーブルの全行を取得して dict のリストで返す。

    ETL 実行前に呼び出して process_bundle() の asset_rows 引数に渡す。
    返却する dict は PIRFilter.build_targets() が必要とする id / tags を含む。
    """
    columns = _TABLE_COLUMNS["Asset"]
    rows = []
    with database.snapshot() as snap:
        result = snap.read(table="Asset", columns=columns, keyset=spanner.KeySet(all_=True))
        for r in result:
            rows.append(dict(zip(columns, r)))
    return rows


# ---------------------------------------------------------------------------
# ユーティリティ
# ---------------------------------------------------------------------------


def _row_to_values(row: dict, columns: list[str]) -> list:
    return [row.get(col) for col in columns]


def _chunk(lst: list, size: int):
    for i in range(0, len(lst), size):
        yield lst[i : i + size]


