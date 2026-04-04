"""ETL ワーカー — STIX バンドル → Spanner Graph への変換・書き込み。

処理フロー:
  1. STIX オブジェクトをタイプ別に分類
  2. TLP フィルタ（設定レベル超のものを除外）
  3. PIR フィルタ（関連性スコアが閾値以下を除外）
  4. ノード upsert（ThreatActor, TTP, Vulnerability, MalwareTool, Observable, Incident）
  5. エッジ upsert（Uses, MalwareUsesTTP, UsesTool, Exploits, Indicates*, IncidentUsesTTP）
  6. FollowedBy(ir_feedback) 導出・upsert（IncidentUsesTTP から生成）
  7. Targets エッジ生成（PIR タグマッチング）
  8. FollowedBy(threat_intel) 重み計算・upsert（ir_feedback pairs を ir_multiplier に使用）
"""

from __future__ import annotations

from collections import defaultdict
from typing import Any

import structlog
from google.cloud.spanner_v1.database import Database

from sage.config import TLP_LEVELS
from sage.pir.filter import PIRFilter
from sage.spanner.upsert import update_pir_criticality, upsert_followed_by, upsert_rows
from sage.stix.mapper import (
    StixMapper,
    build_followed_by_weights,
    build_ir_feedback_followed_by,
)

logger = structlog.get_logger(__name__)


class ETLWorker:
    """STIX バンドルを処理して Spanner Graph へ書き込む。"""

    def __init__(
        self,
        database: Database,
        pir_filter: PIRFilter,
        tlp_max_level: str = "amber",
    ) -> None:
        self._db = database
        self._pir = pir_filter
        self._tlp_max = TLP_LEVELS.get(tlp_max_level, 2)
        self._mapper = StixMapper()

    def process_bundle(
        self,
        objects: list[dict[str, Any]],
        asset_rows: list[dict[str, Any]] | None = None,
    ) -> dict[str, int]:
        """STIX オブジェクトリストを処理する。処理数の集計を返す。

        Args:
            objects: stix/parser.py で parse_bundle した結果
            asset_rows: Targets 生成に使用する内部資産データ。
                        省略時は Targets エッジを生成しない。

        Returns:
            {"threat_actors": N, "ttps": N, ...} の集計 dict
        """
        # --- タイプ別に分類 ---
        by_type: dict[str, list[dict]] = defaultdict(list)
        for obj in objects:
            by_type[obj["type"]].append(obj)

        stats: dict[str, int] = {}

        # --- ThreatActor ---
        actor_rows = []
        for obj in by_type["threat-actor"] + by_type["intrusion-set"]:
            row = self._mapper.map_threat_actor(obj)
            if row and self._pir.is_relevant_actor(row):
                actor_rows.append(row)
        stats["threat_actors"] = upsert_rows(self._db, "ThreatActor", actor_rows)

        # --- TTP ---
        ttp_rows = []
        for obj in by_type["attack-pattern"]:
            row = self._mapper.map_ttp(obj)
            if row:
                ttp_rows.append(row)
        stats["ttps"] = upsert_rows(self._db, "TTP", ttp_rows)
        ttp_phase_map = {r["stix_id"]: r["tactic"] or "" for r in ttp_rows}

        # --- Vulnerability ---
        vuln_rows = [
            r for obj in by_type["vulnerability"] if (r := self._mapper.map_vulnerability(obj))
        ]
        stats["vulnerabilities"] = upsert_rows(self._db, "Vulnerability", vuln_rows)

        # --- MalwareTool ---
        mt_rows = [
            r
            for obj in by_type["malware"] + by_type["tool"]
            if (r := self._mapper.map_malware_tool(obj))
        ]
        stats["malware_tools"] = upsert_rows(self._db, "MalwareTool", mt_rows)

        # --- Observable (TLPフィルタあり) ---
        obs_rows = []
        for obj in by_type["indicator"]:
            row = self._mapper.map_observable(obj)
            if row and self._passes_tlp(row.get("tlp", "white")):
                obs_rows.append(row)
        stats["observables"] = upsert_rows(self._db, "Observable", obs_rows)

        # --- Incident (IR フィードバック) ---
        incident_rows = [r for obj in by_type["incident"] if (r := self._mapper.map_incident(obj))]
        stats["incidents"] = upsert_rows(self._db, "Incident", incident_rows)

        # --- Relationships ---
        uses_rows: list[dict] = []
        malware_uses_ttp_rows: list[dict] = []
        uses_tool_rows: list[dict] = []
        exploits_rows: list[dict] = []
        ind_ttp_rows: list[dict] = []
        ind_actor_rows: list[dict] = []
        incident_ttp_rows: list[dict] = []

        for obj in by_type["relationship"]:
            result = self._mapper.map_relationship(obj)
            if not result:
                continue
            table, row = result
            if table == "Uses":
                uses_rows.append(row)
            elif table == "MalwareUsesTTP":
                malware_uses_ttp_rows.append(row)
            elif table == "UsesTool":
                uses_tool_rows.append(row)
            elif table == "Exploits":
                exploits_rows.append(row)
            elif table == "IndicatesTTP":
                ind_ttp_rows.append(row)
            elif table == "IndicatesActor":
                ind_actor_rows.append(row)

        # IncidentUsesTTP は incident オブジェクトから直接生成（sequence_order 付き）
        for obj in by_type["incident"]:
            for row in self._mapper.map_incident_ttp_edges(obj):
                incident_ttp_rows.append(row)

        stats["uses"] = upsert_rows(self._db, "Uses", uses_rows)
        stats["malware_uses_ttp"] = upsert_rows(self._db, "MalwareUsesTTP", malware_uses_ttp_rows)
        stats["uses_tool"] = upsert_rows(self._db, "UsesTool", uses_tool_rows)
        stats["exploits"] = upsert_rows(self._db, "Exploits", exploits_rows)
        stats["indicates_ttp"] = upsert_rows(self._db, "IndicatesTTP", ind_ttp_rows)
        stats["indicates_actor"] = upsert_rows(self._db, "IndicatesActor", ind_actor_rows)
        stats["incident_uses_ttp"] = upsert_rows(self._db, "IncidentUsesTTP", incident_ttp_rows)

        # --- FollowedBy(ir_feedback): IncidentUsesTTP から導出 ---
        ir_fb_rows, ir_feedback_pairs = build_ir_feedback_followed_by(incident_ttp_rows)
        stats["followed_by_ir"] = upsert_followed_by(self._db, ir_fb_rows)

        # --- Targets: PIR タグマッチングで自動生成 ---
        targets_rows: list[dict] = []
        if asset_rows:
            targets_rows = self._pir.build_targets(actor_rows, asset_rows)
            stats["targets"] = upsert_rows(self._db, "Targets", targets_rows)

            # --- pir_adjusted_criticality 更新: Targets エッジ存在を考慮した 1.5 倍補正 ---
            updated_assets = self._pir.update_asset_criticality(
                asset_rows, actor_rows, targets_rows
            )
            stats["pir_criticality_updated"] = update_pir_criticality(self._db, updated_assets)
        else:
            stats["targets"] = 0
            stats["pir_criticality_updated"] = 0

        # --- FollowedBy(threat_intel): 4因子計算（ir_feedback pairs を ir_multiplier に利用） ---
        ttp_vuln_data = _build_ttp_vuln_data(exploits_rows, vuln_rows)
        fb_rows = build_followed_by_weights(
            uses_rows,
            ttp_phase_map,
            ttp_vuln_data=ttp_vuln_data,
            ir_feedback_pairs=ir_feedback_pairs,
        )
        stats["followed_by"] = upsert_followed_by(self._db, fb_rows)

        logger.info("etl_complete", **stats)
        return stats

    def _passes_tlp(self, tlp: str) -> bool:
        return TLP_LEVELS.get(tlp, 0) <= self._tlp_max


def _build_ttp_vuln_data(
    exploits_rows: list[dict],
    vuln_rows: list[dict],
) -> dict[str, dict]:
    """Exploits エッジと Vulnerability ノードから TTP → 脆弱性データの辞書を構築する。

    同一 TTP に複数の脆弱性が紐づく場合は最大スコアを採用する。
    """
    vuln_map = {r["stix_id"]: r for r in vuln_rows}
    result: dict[str, dict] = {}

    for edge in exploits_rows:
        ttp_id = edge["ttp_stix_id"]
        vuln = vuln_map.get(edge["vuln_stix_id"], {})
        cvss = vuln.get("cvss_score")
        epss = vuln.get("epss_score")

        existing = result.get(ttp_id, {})
        # 複数脆弱性がある場合は max スコアを保持
        new_cvss = max(filter(None, [existing.get("cvss_score"), cvss]), default=None)
        new_epss = max(filter(None, [existing.get("epss_score"), epss]), default=None)
        result[ttp_id] = {"cvss_score": new_cvss, "epss_score": new_epss}

    return result
