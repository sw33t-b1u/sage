"""社内資産データを Spanner に投入するスクリプト。

tests/fixtures/sample_assets.json または指定ファイルを読み込み、
NetworkSegment / SecurityControl / Asset / HasVulnerability /
ConnectedTo / ProtectedBy / Targets テーブルへ upsert する。

使用方法:
    export SPANNER_EMULATOR_HOST=localhost:9010  # エミュレーター使用時
    uv run python cmd/load_assets.py
    uv run python cmd/load_assets.py --file path/to/assets.json
"""

from __future__ import annotations

import argparse
import json
import sys
from datetime import UTC, datetime
from pathlib import Path

import structlog
from google.cloud import spanner

sys.path.insert(0, str(Path(__file__).parent.parent / "src"))

from sage.config import Config
from sage.spanner.upsert import upsert_rows

structlog.configure(
    processors=[
        structlog.processors.TimeStamper(fmt="iso"),
        structlog.processors.JSONRenderer(),
    ]
)
logger = structlog.get_logger(__name__)

DEFAULT_ASSET_FILE = Path(__file__).parent.parent / "tests" / "fixtures" / "sample_assets.json"


def _now() -> datetime:
    return datetime.now(tz=UTC)


def load_assets(database: spanner.Database, data: dict) -> None:
    stats: dict[str, int] = {}

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
                "last_updated": spanner.COMMIT_TIMESTAMP,
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
    cve_to_stix = _resolve_cve_ids(database)
    hv_rows = []
    for hv in data.get("asset_vulnerabilities", []):
        cve_ref = hv["vuln_stix_id_ref"]
        stix_id = cve_to_stix.get(cve_ref)
        if not stix_id:
            logger.warning("cve_not_found", cve=cve_ref, hint="先にSTIXバンドルをETLしてください")
            continue
        hv_rows.append(
            {
                "asset_id": hv["asset_id"],
                "vuln_stix_id": stix_id,
                "remediation_status": hv.get("remediation_status", "open"),
                "detected_at": _now(),
            }
        )
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


def _resolve_cve_ids(database: spanner.Database) -> dict[str, str]:
    """Vulnerabilityテーブルから cve_id → stix_id のマップを返す。"""
    result = {}
    with database.snapshot() as snap:
        sql = "SELECT stix_id, cve_id FROM Vulnerability WHERE cve_id IS NOT NULL"
        rows = snap.execute_sql(sql)
        for row in rows:
            result[row[1]] = row[0]
    return result


def _resolve_actor_names(database: spanner.Database) -> dict[str, str]:
    """ThreatActorテーブルから name → stix_id のマップを返す。"""
    result = {}
    with database.snapshot() as snap:
        rows = snap.execute_sql("SELECT stix_id, name FROM ThreatActor")
        for row in rows:
            result[row[1]] = row[0]
    return result


def main() -> None:
    parser = argparse.ArgumentParser(description="社内資産データを Spanner へロード")
    parser.add_argument(
        "--file",
        type=Path,
        default=DEFAULT_ASSET_FILE,
        help=f"資産JSONファイルパス (デフォルト: {DEFAULT_ASSET_FILE})",
    )
    args = parser.parse_args()

    if not args.file.exists():
        logger.error("file_not_found", path=str(args.file))
        sys.exit(1)

    config = Config.from_env()
    spanner_client = spanner.Client(project=config.gcp_project_id)
    instance = spanner_client.instance(config.spanner_instance_id)
    database = instance.database(config.spanner_database_id)

    with args.file.open() as f:
        data = json.load(f)

    logger.info("loading_assets", file=str(args.file))
    load_assets(database, data)


if __name__ == "__main__":
    main()
