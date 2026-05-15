"""PIR (Priority Intelligence Requirement) filtering and asset weighting.

Responsibilities:
1. Compute relevance scores for incoming STIX objects and skip those below the threshold.
2. Update Asset.pir_adjusted_criticality based on matching PIR rules.
"""

from __future__ import annotations

import json
from collections import defaultdict
from pathlib import Path
from typing import Any

import structlog

logger = structlog.get_logger(__name__)

# Minimum relevance score — objects below this threshold are not stored in Spanner
RELEVANCE_THRESHOLD = 0.1


class PIRFilter:
    """Filter and weight objects according to a PIR JSON definition.

    PIR JSON schema (see docs/high-level-design.md):
    {
      "pir_id": "PIR-2025-001",
      "organizational_scope": "Financial Crime Intelligence Team (department)",
      "description": "...",
      "threat_actor_tags": ["apt-china", "espionage"],
      "asset_weight_rules": [
        {"tag": "external-facing", "criticality_multiplier": 2.0},
        ...
      ],
      "valid_from": "2025-01-01",
      "valid_until": "2025-12-31"
    }
    """

    def __init__(self, pir_list: list[dict[str, Any]]) -> None:
        self._pirs = pir_list

    @classmethod
    def from_file(cls, path: Path) -> PIRFilter:
        with path.open() as f:
            data = json.load(f)
        pirs = data if isinstance(data, list) else [data]
        for pir in pirs:
            logger.info(
                "pir_loaded",
                pir_id=pir.get("pir_id"),
                organizational_scope=pir.get("organizational_scope", "entire company"),
            )
        return cls(pirs)

    # -----------------------------------------------------------------------
    # ThreatActor filtering
    # -----------------------------------------------------------------------

    def is_relevant_actor(self, actor_row: dict) -> bool:
        """Return True if the actor matches any PIR's threat_actor_tags.

        Returns True for all actors when no PIRs are loaded.
        """
        if not self._pirs:
            return True

        actor_tags: set[str] = set(actor_row.get("tags") or [])
        actor_name: str = (actor_row.get("name") or "").lower()

        for pir in self._pirs:
            pir_tags: set[str] = set(pir.get("threat_actor_tags", []))
            if pir_tags & actor_tags:
                return True
            # Best-effort name substring match when no tags are present
            if any(t.lower() in actor_name for t in pir_tags):
                return True

        return False

    def actor_relevance_score(self, actor_row: dict) -> float:
        """Return a relevance score (0.0–1.0) for the given actor."""
        if not self._pirs:
            return 1.0

        actor_tags: set[str] = set(actor_row.get("tags") or [])
        max_score = 0.0

        for pir in self._pirs:
            pir_tags: set[str] = set(pir.get("threat_actor_tags", []))
            if not pir_tags:
                continue
            overlap = len(pir_tags & actor_tags) / len(pir_tags)
            max_score = max(max_score, overlap)

        return max_score

    # -----------------------------------------------------------------------
    # Asset weighting
    # -----------------------------------------------------------------------

    def adjust_asset_criticality(self, asset_row: dict) -> dict:
        """Apply PIR rules and return asset_row with pir_adjusted_criticality set.

        When multiple PIRs match, the highest multiplier is applied.
        """
        base = asset_row.get("criticality", 5.0) or 5.0
        asset_tags: set[str] = set(asset_row.get("tags") or [])

        max_multiplier = 1.0
        for pir in self._pirs:
            for rule in pir.get("asset_weight_rules", []):
                if rule["tag"] in asset_tags:
                    max_multiplier = max(max_multiplier, rule["criticality_multiplier"])

        adjusted = min(base * max_multiplier, 10.0)
        return {**asset_row, "pir_adjusted_criticality": adjusted}

    def adjust_assets(self, asset_rows: list[dict]) -> list[dict]:
        """Apply PIR weighting to a list of asset rows."""
        return [self.adjust_asset_criticality(r) for r in asset_rows]

    def update_asset_criticality(
        self,
        asset_rows: list[dict],
        actor_rows: list[dict],
        targets_rows: list[dict],
    ) -> list[dict]:
        """Compute pir_adjusted_criticality taking Targets edges into account.

        Formula from HLD 5.4:
          pir_adjusted_criticality =
            base_criticality
            × MAX(matching PIR rules' criticality_multiplier)
            × (1.5 if any Targets-linked actor matches a PIR, else 1.0)

        Args:
            asset_rows: all asset nodes (must include id, criticality, tags)
            actor_rows: ThreatActor rows already processed by the ETL
            targets_rows: Targets edge rows (PIR-auto-generated + manual)

        Returns:
            Copy of asset_rows with pir_adjusted_criticality populated
        """
        actor_map = {a["stix_id"]: a for a in actor_rows}

        # Map asset_id → set of actor stix_ids reachable via Targets edges
        asset_to_actors: dict[str, set[str]] = defaultdict(set)
        for t in targets_rows:
            asset_to_actors[t["asset_id"]].add(t["actor_stix_id"])

        result = []
        for asset in asset_rows:
            base = asset.get("criticality", 5.0) or 5.0
            asset_tags: set[str] = set(asset.get("tags") or [])

            max_multiplier = 1.0
            has_pir_actor_target = False

            for pir in self._pirs:
                pir_actor_tags: set[str] = set(pir.get("threat_actor_tags", []))

                for rule in pir.get("asset_weight_rules", []):
                    if rule["tag"] in asset_tags:
                        max_multiplier = max(max_multiplier, rule["criticality_multiplier"])

                # Check whether any Targets-linked actor matches this PIR
                for actor_id in asset_to_actors.get(asset["id"], set()):
                    actor = actor_map.get(actor_id)
                    if actor and set(actor.get("tags") or []) & pir_actor_tags:
                        has_pir_actor_target = True

            targets_multiplier = 1.5 if has_pir_actor_target else 1.0
            adjusted = min(base * max_multiplier * targets_multiplier, 10.0)
            result.append({**asset, "pir_adjusted_criticality": adjusted})

        return result

    # -----------------------------------------------------------------------
    # TTP filtering (prioritising externally-exposed TTPs)
    # -----------------------------------------------------------------------

    def build_targets(
        self,
        actor_rows: list[dict],
        asset_rows: list[dict],
    ) -> list[dict]:
        """Generate Targets edges from PIR tag matching.

        For each PIR:
          matched_actors = actors whose tags intersect PIR.threat_actor_tags
          matched_assets = assets whose tags intersect {PIR.asset_weight_rules[*].tag}
        All (actor, asset) combinations produce a Targets edge.

        Confidence is derived from the actor–PIR tag overlap ratio (0–100 INT).
        When multiple PIRs match the same (actor, asset) pair, the highest
        confidence value is kept.
        """
        targets: dict[tuple[str, str], dict] = {}

        for pir in self._pirs:
            pir_actor_tags: set[str] = set(pir.get("threat_actor_tags", []))
            pir_asset_tags: set[str] = {rule["tag"] for rule in pir.get("asset_weight_rules", [])}
            if not pir_actor_tags or not pir_asset_tags:
                continue

            matched_actors = [a for a in actor_rows if set(a.get("tags") or []) & pir_actor_tags]
            matched_assets = [a for a in asset_rows if set(a.get("tags") or []) & pir_asset_tags]

            for actor in matched_actors:
                actor_overlap = len(set(actor.get("tags") or []) & pir_actor_tags)
                confidence = min(int(actor_overlap / len(pir_actor_tags) * 100), 100)
                for asset in matched_assets:
                    key = (actor["stix_id"], asset["id"])
                    # Keep the highest confidence when multiple PIRs match the same pair
                    if key not in targets or targets[key]["confidence"] < confidence:
                        targets[key] = {
                            "actor_stix_id": actor["stix_id"],
                            "asset_id": asset["id"],
                            "confidence": confidence,
                            "source": "pir_auto",
                        }

        return list(targets.values())

    def ttp_relevance_score(self, ttp_row: dict, actor_rows: list[dict]) -> float:
        """Return the relevance score for a TTP.

        TTPs used by PIR-relevant actors are prioritised.
        Only pass actor_rows that have already passed is_relevant_actor().
        """
        if not actor_rows:
            return 0.0
        # Presence of actor_rows means this TTP is used by a PIR-relevant actor
        return 1.0

    # -----------------------------------------------------------------------
    # PIR as first-class graph node — row builders for Spanner upsert.
    # Each method returns a list of dicts that maps 1:1 to the DDL columns.
    # -----------------------------------------------------------------------

    def build_pir_nodes(self) -> list[dict]:
        """Return one PIR row per loaded PIR, ready for Spanner upsert."""
        rows: list[dict] = []
        for pir in self._pirs:
            rows.append(
                {
                    "pir_id": pir["pir_id"],
                    "intelligence_level": pir.get("intelligence_level", "operational"),
                    "organizational_scope": pir.get("organizational_scope"),
                    "decision_point": pir.get("decision_point"),
                    "description": pir.get("description", ""),
                    "rationale": pir.get("rationale"),
                    "recommended_action": pir.get("recommended_action"),
                    "threat_actor_tags": list(pir.get("threat_actor_tags", [])),
                    "risk_composite": (pir.get("risk_score") or {}).get("composite"),
                    "valid_from": pir.get("valid_from"),
                    "valid_until": pir.get("valid_until"),
                }
            )
        return rows

    def build_pir_actor_edges(self, actor_rows: list[dict]) -> list[dict]:
        """PIR → ThreatActor edges (TAP). Emits one edge per (PIR, actor) where
        tags intersect. `overlap_ratio` is the fraction of PIR tags matched.
        """
        edges: list[dict] = []
        for pir in self._pirs:
            pir_tags = set(pir.get("threat_actor_tags", []))
            if not pir_tags:
                continue
            for actor in actor_rows:
                actor_tags = set(actor.get("tags") or [])
                overlap = pir_tags & actor_tags
                if not overlap:
                    continue
                edges.append(
                    {
                        "pir_id": pir["pir_id"],
                        "actor_stix_id": actor["stix_id"],
                        "overlap_ratio": round(len(overlap) / len(pir_tags), 4),
                    }
                )
        return edges

    def build_pir_ttp_edges(
        self,
        uses_rows: list[dict],
        pir_actor_edges: list[dict],
    ) -> list[dict]:
        """PIR → TTP edges (PTTP), derived transitively: for each PIR, union of
        TTPs used by its prioritized actors (via Uses edges).
        """
        pir_to_actors: dict[str, set[str]] = defaultdict(set)
        for edge in pir_actor_edges:
            pir_to_actors[edge["pir_id"]].add(edge["actor_stix_id"])

        actor_to_ttps: dict[str, set[str]] = defaultdict(set)
        for u in uses_rows:
            actor_to_ttps[u["actor_stix_id"]].add(u["ttp_stix_id"])

        seen: set[tuple[str, str]] = set()
        edges: list[dict] = []
        for pir_id, actor_ids in pir_to_actors.items():
            for actor_id in actor_ids:
                for ttp_id in actor_to_ttps.get(actor_id, set()):
                    key = (pir_id, ttp_id)
                    if key in seen:
                        continue
                    seen.add(key)
                    edges.append({"pir_id": pir_id, "ttp_stix_id": ttp_id})
        return edges

    def build_pir_asset_edges(self, asset_rows: list[dict]) -> list[dict]:
        """PIR → Asset edges. For each (PIR, asset) where any
        asset_weight_rules[*].tag intersects asset.tags, keep the highest
        multiplier seen.
        """
        best: dict[tuple[str, str], dict] = {}
        for pir in self._pirs:
            rules = pir.get("asset_weight_rules", [])
            if not rules:
                continue
            for asset in asset_rows:
                asset_tags = set(asset.get("tags") or [])
                best_match: tuple[float, str] | None = None
                for rule in rules:
                    tag = rule.get("tag")
                    if tag in asset_tags:
                        mult = float(rule.get("criticality_multiplier", 1.0))
                        if best_match is None or mult > best_match[0]:
                            best_match = (mult, tag)
                if best_match is None:
                    continue
                key = (pir["pir_id"], asset["id"])
                mult, tag = best_match
                existing = best.get(key)
                if existing is None or (existing["criticality_multiplier"] or 0) < mult:
                    best[key] = {
                        "pir_id": pir["pir_id"],
                        "asset_id": asset["id"],
                        "matched_tag": tag,
                        "criticality_multiplier": mult,
                    }
        return list(best.values())
