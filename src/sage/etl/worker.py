"""ETL worker — transforms STIX bundles and writes them to Spanner Graph.

Processing flow:
  1. Classify STIX objects by type
  2. TLP filter (exclude objects above the configured level)
  3. PIR filter (exclude objects below the relevance threshold)
  4. Node upsert (ThreatActor, TTP, Vulnerability, MalwareTool, Observable, Incident)
  5. Edge upsert (Uses, MalwareUsesTTP, UsesTool, Exploits, Indicates*, IncidentUsesTTP)
  6. Derive and upsert FollowedBy(ir_feedback) edges from IncidentUsesTTP
  7. Generate Targets edges via PIR tag matching
  8. Calculate and upsert FollowedBy(threat_intel) weights
     (using ir_feedback pairs as ir_multiplier)
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
    """Processes a STIX bundle and writes the results to Spanner Graph."""

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
        """Process a list of STIX objects and return ingestion counts.

        Args:
            objects: Result of stix/parser.py parse_bundle()
            asset_rows: Internal asset data used to generate Targets edges.
                        Targets edges are skipped when omitted.

        Returns:
            Counts dict: {"threat_actors": N, "ttps": N, ...}
        """
        # --- Classify by type ---
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

        # --- Observable (TLP-filtered) ---
        obs_rows = []
        for obj in by_type["indicator"]:
            row = self._mapper.map_observable(obj)
            if row and self._passes_tlp(row.get("tlp", "white")):
                obs_rows.append(row)
        stats["observables"] = upsert_rows(self._db, "Observable", obs_rows)

        # --- Incident (IR feedback) ---
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

        # IncidentUsesTTP is generated directly from incident objects (includes sequence_order)
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

        # --- FollowedBy(ir_feedback): derived from IncidentUsesTTP ---
        ir_fb_rows, ir_feedback_pairs = build_ir_feedback_followed_by(incident_ttp_rows)
        stats["followed_by_ir"] = upsert_followed_by(self._db, ir_fb_rows)

        # --- Targets: auto-generated via PIR tag matching ---
        targets_rows: list[dict] = []
        if asset_rows:
            targets_rows = self._pir.build_targets(actor_rows, asset_rows)
            stats["targets"] = upsert_rows(self._db, "Targets", targets_rows)

            # --- Update pir_adjusted_criticality ---
            # Apply 1.5x multiplier when a Targets edge exists.
            updated_assets = self._pir.update_asset_criticality(
                asset_rows, actor_rows, targets_rows
            )
            stats["pir_criticality_updated"] = update_pir_criticality(self._db, updated_assets)
        else:
            stats["targets"] = 0
            stats["pir_criticality_updated"] = 0

        # --- PIR node + Strategic→Operational→Tactical cascade edges ---
        stats["pirs"] = upsert_rows(self._db, "PIR", self._pir.build_pir_nodes())
        pir_actor_edges = self._pir.build_pir_actor_edges(actor_rows)
        stats["pir_prioritizes_actor"] = upsert_rows(
            self._db, "PirPrioritizesActor", pir_actor_edges
        )
        stats["pir_prioritizes_ttp"] = upsert_rows(
            self._db, "PirPrioritizesTTP", self._pir.build_pir_ttp_edges(uses_rows, pir_actor_edges)
        )
        if asset_rows:
            stats["pir_weights_asset"] = upsert_rows(
                self._db, "PirWeightsAsset", self._pir.build_pir_asset_edges(asset_rows)
            )
        else:
            stats["pir_weights_asset"] = 0

        # --- FollowedBy(threat_intel): 4-factor weight calculation ---
        # ir_feedback pairs are used as ir_multiplier.
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
    """Build a TTP → vulnerability data dict from Exploits edges and Vulnerability nodes.

    When multiple vulnerabilities are linked to the same TTP, the maximum scores are used.
    """
    vuln_map = {r["stix_id"]: r for r in vuln_rows}
    result: dict[str, dict] = {}

    for edge in exploits_rows:
        ttp_id = edge["ttp_stix_id"]
        vuln = vuln_map.get(edge["vuln_stix_id"], {})
        cvss = vuln.get("cvss_score")
        epss = vuln.get("epss_score")

        existing = result.get(ttp_id, {})
        # Keep the max score when multiple vulnerabilities map to the same TTP
        new_cvss = max(filter(None, [existing.get("cvss_score"), cvss]), default=None)
        new_epss = max(filter(None, [existing.get("epss_score"), epss]), default=None)
        result[ttp_id] = {"cvss_score": new_cvss, "epss_score": new_epss}

    return result
