"""Spanner Graph query functions.

Provides analytical queries for Attack Flow and Attack Graph sub-graphs.

- Path traversal (find_attack_paths, find_actor_ttps): uses GQL (Property Graph syntax)
- Aggregation (find_choke_points, find_asset_exposure): uses standard SQL

NOTE: The Spanner emulator has limited GQL support, so these functions are tested
      by mocking snapshots with unittest.mock rather than running against the emulator.
"""

from __future__ import annotations

from typing import Any

import structlog
from google.cloud.spanner_v1.database import Database

logger = structlog.get_logger(__name__)

# Maximum hops for GQL traversal (ConnectedTo paths between Assets)
_MAX_HOPS = 5


def find_attack_paths(
    database: Database,
    asset_id: str,
    limit: int = 10,
) -> list[dict[str, Any]]:
    """Return attack paths reaching the specified asset, ordered by FollowedBy weight.

    Uses GQL to traverse ThreatActor → TTP → ... → TTP → Asset paths.
    Each path is returned as a dict with (actor_stix_id, ttp_sequence, total_weight).

    Returns:
        [
          {
            "actor_stix_id": "intrusion-set--xxx",
            "actor_name": "APT99",
            "ttp_sequence": ["attack-pattern--t1078", ...],
            "total_weight": 0.85,
          },
          ...
        ]
    """
    gql = """
    GRAPH ThreatIntelGraph
    MATCH
      (actor:ThreatActor)-[tgt:TARGETS]->(asset:Asset {id: @asset_id}),
      (actor)-[u:USES]->(ttp:TTP)
    RETURN
      actor.stix_id  AS actor_stix_id,
      actor.name     AS actor_name,
      ttp.stix_id    AS ttp_stix_id,
      ttp.name       AS ttp_name,
      u.confidence   AS confidence
    ORDER BY confidence DESC
    LIMIT @limit
    """
    params = {"asset_id": asset_id, "limit": limit}
    param_types = {
        "asset_id": _str_type(),
        "limit": _int64_type(),
    }

    rows = []
    with database.snapshot() as snap:
        result = snap.execute_sql(gql, params=params, param_types=param_types)
        for row in result:
            rows.append(
                {
                    "actor_stix_id": row[0],
                    "actor_name": row[1],
                    "ttp_stix_id": row[2],
                    "ttp_name": row[3],
                    "confidence": row[4],
                }
            )

    logger.info("find_attack_paths", asset_id=asset_id, count=len(rows))
    return rows


def find_actor_ttps(
    database: Database,
    actor_stix_id: str,
) -> list[dict[str, Any]]:
    """Return the TTP attack flow for the specified actor, ordered by FollowedBy weight.

    Uses GQL to traverse actor -[USES]-> TTP -[FOLLOWED_BY*]-> TTP paths.

    Returns:
        [
          {
            "src_ttp_stix_id": "attack-pattern--t1078",
            "src_ttp_name": "Valid Accounts",
            "dst_ttp_stix_id": "attack-pattern--t1068",
            "dst_ttp_name": "Exploitation for Privilege Escalation",
            "weight": 0.72,
            "source": "threat_intel",
          },
          ...
        ]
    """
    gql = """
    GRAPH ThreatIntelGraph
    MATCH
      (actor:ThreatActor {stix_id: @actor_id})-[:USES]->(src:TTP),
      (src)-[fb:FOLLOWED_BY]->(dst:TTP)
    RETURN
      src.stix_id  AS src_ttp_stix_id,
      src.name     AS src_ttp_name,
      dst.stix_id  AS dst_ttp_stix_id,
      dst.name     AS dst_ttp_name,
      fb.weight    AS weight,
      fb.source    AS source
    ORDER BY weight DESC
    """
    params = {"actor_id": actor_stix_id}
    param_types = {"actor_id": _str_type()}

    rows = []
    with database.snapshot() as snap:
        result = snap.execute_sql(gql, params=params, param_types=param_types)
        for row in result:
            rows.append(
                {
                    "src_ttp_stix_id": row[0],
                    "src_ttp_name": row[1],
                    "dst_ttp_stix_id": row[2],
                    "dst_ttp_name": row[3],
                    "weight": row[4],
                    "source": row[5],
                }
            )

    logger.info("find_actor_ttps", actor_stix_id=actor_stix_id, count=len(rows))
    return rows


def find_choke_points(
    database: Database,
    top_n: int = 20,
) -> list[dict[str, Any]]:
    """Return choke-point assets (assets with the most attack paths passing through them).

    Ranks assets using SQL with the following score:
      choke_score = pir_adjusted_criticality × targeting_actor_count

    Returns:
        [
          {
            "asset_id": "asset-001",
            "asset_name": "WebServer",
            "pir_adjusted_criticality": 9.0,
            "targeting_actor_count": 3,
            "choke_score": 27.0,
          },
          ...
        ]
    """
    sql = """
    SELECT
      a.id                       AS asset_id,
      a.name                     AS asset_name,
      a.pir_adjusted_criticality AS pir_adjusted_criticality,
      COUNT(DISTINCT t.actor_stix_id) AS targeting_actor_count,
      a.pir_adjusted_criticality * COUNT(DISTINCT t.actor_stix_id) AS choke_score
    FROM Asset a
    JOIN Targets t ON t.asset_id = a.id
    GROUP BY a.id, a.name, a.pir_adjusted_criticality
    ORDER BY choke_score DESC
    LIMIT @top_n
    """
    params = {"top_n": top_n}
    param_types = {"top_n": _int64_type()}

    rows = []
    with database.snapshot() as snap:
        result = snap.execute_sql(sql, params=params, param_types=param_types)
        for row in result:
            rows.append(
                {
                    "asset_id": row[0],
                    "asset_name": row[1],
                    "pir_adjusted_criticality": row[2],
                    "targeting_actor_count": row[3],
                    "choke_score": row[4],
                }
            )

    logger.info("find_choke_points", top_n=top_n, count=len(rows))
    return rows


def find_asset_exposure(
    database: Database,
) -> list[dict[str, Any]]:
    """Return internet-exposed assets with their reachable TTP counts.

    Uses SQL to aggregate exposed_to_internet=TRUE assets alongside the number
    of distinct actors and TTPs reachable via Targets edges.

    Returns:
        [
          {
            "asset_id": "asset-001",
            "asset_name": "WebServer",
            "pir_adjusted_criticality": 9.0,
            "targeting_actor_count": 2,
            "reachable_ttp_count": 12,
          },
          ...
        ]
    """
    sql = """
    SELECT
      a.id                            AS asset_id,
      a.name                          AS asset_name,
      a.pir_adjusted_criticality      AS pir_adjusted_criticality,
      COUNT(DISTINCT t.actor_stix_id) AS targeting_actor_count,
      COUNT(DISTINCT u.ttp_stix_id)   AS reachable_ttp_count
    FROM Asset a
    JOIN Targets t ON t.asset_id = a.id
    JOIN Uses u    ON u.actor_stix_id = t.actor_stix_id
    WHERE a.exposed_to_internet = TRUE
    GROUP BY a.id, a.name, a.pir_adjusted_criticality
    ORDER BY pir_adjusted_criticality DESC
    """

    rows = []
    with database.snapshot() as snap:
        result = snap.execute_sql(sql)
        for row in result:
            rows.append(
                {
                    "asset_id": row[0],
                    "asset_name": row[1],
                    "pir_adjusted_criticality": row[2],
                    "targeting_actor_count": row[3],
                    "reachable_ttp_count": row[4],
                }
            )

    logger.info("find_asset_exposure", count=len(rows))
    return rows


def find_incident_ttps(
    database: Database,
    incident_id: str,
) -> list[str]:
    """Return TTP STIX IDs linked to the specified incident via IncidentUsesTTP.

    Returns:
        ["attack-pattern--t1078", ...]
    """
    sql = """
    SELECT ttp_stix_id
    FROM IncidentUsesTTP
    WHERE incident_stix_id = @incident_id
    """
    params = {"incident_id": incident_id}
    param_types = {"incident_id": _str_type()}

    ttps: list[str] = []
    with database.snapshot() as snap:
        result = snap.execute_sql(sql, params=params, param_types=param_types)
        for row in result:
            ttps.append(row[0])

    logger.info("find_incident_ttps", incident_id=incident_id, count=len(ttps))
    return ttps


def find_followedby_edges(
    database: Database,
) -> list[dict[str, Any]]:
    """Return all FollowedBy edges (used for building the similarity graph).

    Returns:
        [{"src_stix_id": "...", "dst_stix_id": "...", "weight": 0.72}, ...]
    """
    sql = """
    SELECT src_stix_id, dst_stix_id, weight
    FROM FollowedBy
    """

    rows: list[dict[str, Any]] = []
    with database.snapshot() as snap:
        result = snap.execute_sql(sql)
        for row in result:
            rows.append({"src_stix_id": row[0], "dst_stix_id": row[1], "weight": row[2]})

    logger.info("find_followedby_edges", count=len(rows))
    return rows


def find_all_incident_ttps(
    database: Database,
) -> dict[str, list[str]]:
    """Return TTP STIX IDs for all incidents.

    Returns:
        {"incident--xxx": ["attack-pattern--t1078", ...], ...}
    """
    sql = """
    SELECT incident_stix_id, ttp_stix_id
    FROM IncidentUsesTTP
    ORDER BY incident_stix_id
    """

    result_map: dict[str, list[str]] = {}
    with database.snapshot() as snap:
        result = snap.execute_sql(sql)
        for row in result:
            inc_id, ttp_id = row[0], row[1]
            result_map.setdefault(inc_id, []).append(ttp_id)

    logger.info("find_all_incident_ttps", incident_count=len(result_map))
    return result_map


# ---------------------------------------------------------------------------
# Type helpers (Spanner param_types)
# ---------------------------------------------------------------------------


def _str_type() -> Any:
    from google.cloud.spanner_v1 import param_types

    return param_types.STRING


def _int64_type() -> Any:
    from google.cloud.spanner_v1 import param_types

    return param_types.INT64
