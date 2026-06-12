"""社内資産データをグラフ DB に投入するスクリプト。

tests/fixtures/sample_assets.json または指定ファイルを読み込み、
SecurityControl / Asset / HasVulnerability /
ConnectedTo / ProtectedBy / Targets テーブルへ upsert する。
DB バックエンドは ``SAGE_DB``（sqlite 既定 / spanner）で切り替わる。

使用方法:
    uv run sage load-assets
    uv run sage load-assets --input path/to/assets.json
"""

from __future__ import annotations

import argparse
import json
import sys
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

import structlog

from sage.config import Config
from sage.db import database_session, is_sqlite, run_sql, upsert_rows
from sage.stix.mapper import _CVE_ID_PATTERN, deterministic_vuln_stix_id
from sage.storage import create_storage_backend

structlog.configure(
    processors=[
        structlog.processors.TimeStamper(fmt="iso"),
        structlog.processors.JSONRenderer(),
    ]
)
logger = structlog.get_logger(__name__)

DEFAULT_ASSET_FILE = Path(__file__).parents[3] / "input" / "assets.json"


def _now() -> datetime:
    return datetime.now(tz=UTC)


def load_assets(database: Any, data: dict) -> None:
    stats: dict[str, int] = {}

    # Asset.last_updated uses ALLOW_COMMIT_TIMESTAMP on Spanner; the SQLite
    # upsert boundary canonicalizes the datetime to ISO 8601 UTC TEXT.
    if is_sqlite(database):
        last_updated: Any = _now()
    else:
        from google.cloud import spanner  # noqa: PLC0415

        last_updated = spanner.COMMIT_TIMESTAMP

    # セグメント情報を id→dict で引けるようにしておく
    seg_map = {s["id"]: s for s in data.get("network_segments", [])}

    # SecurityControl
    ctrl_rows = [
        {
            "id": c["id"],
            "name": c["name"],
            "control_type": c.get("control_type"),
            "coverage": c.get("coverage", []),
        }
        for c in data.get("security_controls", [])
    ]
    stats["security_controls"] = upsert_rows(database, "SecurityControl", ctrl_rows)

    # Asset (ネットワークセグメント情報をインライン展開)
    asset_rows = []
    for a in data.get("assets", []):
        seg = seg_map.get(a.get("network_segment_id", ""), {})
        asset_rows.append(
            {
                "id": a["id"],
                "name": a["name"],
                "asset_type": a.get("asset_type"),
                "environment": a.get("environment"),
                "criticality": a.get("criticality", 5.0),
                "pir_adjusted_criticality": None,
                "owner": a.get("owner"),
                "network_segment": seg.get("name"),
                "network_cidr": seg.get("cidr"),
                "network_zone": seg.get("zone"),
                "exposed_to_internet": a.get("exposed_to_internet", False),
                "tags": a.get("tags", []),
                "last_updated": last_updated,
            }
        )
    stats["assets"] = upsert_rows(database, "Asset", asset_rows)

    # ProtectedBy (Asset → SecurityControl)
    pb_rows = []
    for a in data.get("assets", []):
        for ctrl_id in a.get("security_control_ids", []):
            pb_rows.append({"asset_id": a["id"], "control_id": ctrl_id})
    stats["protected_by"] = upsert_rows(database, "ProtectedBy", pb_rows)

    # ConnectedTo (Asset ↔ Asset)
    conn_rows = [
        {
            "src_asset_id": c["src"],
            "dst_asset_id": c["dst"],
            "protocol": c.get("protocol"),
            "port": c.get("port"),
            "direction": "unidirectional",
            "allowed": True,
        }
        for c in data.get("asset_connections", [])
    ]
    stats["connected_to"] = upsert_rows(database, "ConnectedTo", conn_rows)

    # HasVulnerability — vuln_stix_id は CVE名から解決する必要があるため
    # STIXバンドルのVulnerabilityテーブルを参照してstix_idを逆引きする
    # SAGE 1.2.0: CVEがSpannerに存在しない場合、決定論的stix_idでスタブ
    # Vulnerabilityノードを作成してからHasVulnerabilityエッジを生成する。
    # 後のCTI ETLで同じCVEが到着した際にINSERT OR UPDATEで情報が補完される。
    cve_to_stix = _resolve_cve_ids(database)
    hv_rows = []
    stub_vuln_rows = []
    for hv in data.get("asset_vulnerabilities", []):
        cve_ref = hv["vuln_stix_id_ref"]
        stix_id = cve_to_stix.get(cve_ref)
        if not stix_id:
            if not _CVE_ID_PATTERN.fullmatch(cve_ref):
                logger.warning(
                    "cve_invalid_format",
                    cve=cve_ref,
                    hint="CVE-YYYY-NNNNN 形式でないため stub を作成しません",
                )
                continue
            stix_id = deterministic_vuln_stix_id(cve_ref)
            stub_vuln_rows.append(
                {
                    "stix_id": stix_id,
                    "cve_id": cve_ref,
                    "stix_modified": _now(),
                }
            )
            logger.info("vuln_stub_created", cve=cve_ref, stix_id=stix_id)
        hv_rows.append(
            {
                "asset_id": hv["asset_id"],
                "vuln_stix_id": stix_id,
                "remediation_status": hv.get("remediation_status", "open"),
                "detected_at": _now(),
            }
        )
    if stub_vuln_rows:
        upsert_rows(database, "Vulnerability", stub_vuln_rows)
    stats["has_vulnerability"] = upsert_rows(database, "HasVulnerability", hv_rows)

    # Targets (ThreatActor → Asset) — actor名からstix_idを解決
    actor_to_stix = _resolve_actor_names(database)
    target_rows = []
    for t in data.get("actor_targets", []):
        actor_name = t["actor_stix_id_ref"]
        stix_id = actor_to_stix.get(actor_name)
        if not stix_id:
            logger.warning("actor_not_found", name=actor_name, hint="ETL先行必須")
            continue
        target_rows.append(
            {
                "actor_stix_id": stix_id,
                "asset_id": t["asset_id"],
                "confidence": t.get("confidence"),
                "source": "manual",
            }
        )
    stats["targets"] = upsert_rows(database, "Targets", target_rows)

    logger.info("load_assets_complete", **stats)


def _resolve_cve_ids(database: Any) -> dict[str, str]:
    """Vulnerabilityテーブルから cve_id → stix_id のマップを返す。"""
    sql = "SELECT stix_id, cve_id FROM Vulnerability WHERE cve_id IS NOT NULL"
    return {row[1]: row[0] for row in run_sql(database, sql)}


def _resolve_actor_names(database: Any) -> dict[str, str]:
    """ThreatActorテーブルから name → stix_id のマップを返す。"""
    return {row[1]: row[0] for row in run_sql(database, "SELECT stix_id, name FROM ThreatActor")}


def main() -> None:
    parser = argparse.ArgumentParser(description="社内資産データを Spanner へロード")
    parser.add_argument(
        "--input",
        "-i",
        type=Path,
        default=None,
        help="資産JSONファイルパス (省略時は StorageBackend から最新ファイルを使用)",
    )
    args = parser.parse_args()

    config = Config.from_env()

    if args.input is not None:
        input_path = args.input
        if not input_path.exists():
            logger.error("file_not_found", path=str(input_path))
            sys.exit(1)
        with input_path.open() as f:
            data = json.load(f)
        logger.info("loading_assets", file=str(input_path))
    else:
        # Try StorageBackend — load the latest assets file from "assets" category
        storage = create_storage_backend(config)
        asset_files = storage.list_files("assets")
        if asset_files:
            latest = asset_files[-1]
            logger.info("loading_assets", file=latest, backend=config.sage_storage)
            raw = storage.load("assets", latest)
            data = json.loads(raw)
        elif DEFAULT_ASSET_FILE.exists():
            # Fallback to default path for backward compatibility
            logger.info("loading_assets", file=str(DEFAULT_ASSET_FILE))
            with DEFAULT_ASSET_FILE.open() as f:
                data = json.load(f)
        else:
            logger.error("no_assets_file_found", hint="Specify --input or configure StorageBackend")
            sys.exit(1)

    with database_session(config, publish=True) as database:
        load_assets(database, data)
