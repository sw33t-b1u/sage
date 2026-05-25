"""Spanner query functions.

Provides analytical queries for Attack Flow and Attack Graph sub-graphs.
All queries use standard SQL (no GQL / Property Graph dependency) so they
work on Spanner Standard edition and the local emulator.
"""

from __future__ import annotations

from datetime import date, datetime, time, timedelta
from typing import Any

import structlog
from google.cloud.spanner_v1.database import Database

logger = structlog.get_logger(__name__)


def _to_window_bounds(
    since: date | None, until: date | None
) -> tuple[datetime | None, datetime | None]:
    """Convert ``date`` window bounds to ``datetime`` for Spanner TIMESTAMP binds.

    ``since`` snaps to 00:00:00 (inclusive lower bound). ``until`` snaps
    to 00:00:00 on the day AFTER (exclusive upper bound) so the SQL
    ``last_observed < @until`` semantics treat ``since == until`` as a
    full calendar day match instead of a zero-width range. ``None``
    propagates through so callers can omit the filter entirely when
    both bounds are absent.
    """
    since_dt = datetime.combine(since, time.min) if since is not None else None
    until_dt = datetime.combine(until, time.min) + timedelta(days=1) if until is not None else None
    return since_dt, until_dt


def find_attack_paths(
    database: Database,
    asset_id: str,
    limit: int = 10,
) -> list[dict[str, Any]]:
    """Return attack paths reaching the specified asset, ordered by confidence.

    Joins ThreatActor → Targets → Asset and ThreatActor → Uses → TTP.

    Returns:
        [
          {
            "actor_stix_id": "intrusion-set--xxx",
            "actor_name": "APT99",
            "ttp_stix_id": "attack-pattern--t1078",
            "ttp_name": "Valid Accounts",
            "confidence": 90,
          },
          ...
        ]
    """
    sql = """
    SELECT
      a.stix_id    AS actor_stix_id,
      a.name       AS actor_name,
      t.stix_id    AS ttp_stix_id,
      t.name       AS ttp_name,
      u.confidence AS confidence
    FROM Targets tgt
    JOIN ThreatActor a ON a.stix_id = tgt.actor_stix_id
    JOIN Uses u        ON u.actor_stix_id = a.stix_id
    JOIN TTP t         ON t.stix_id = u.ttp_stix_id
    WHERE tgt.asset_id = @asset_id
    ORDER BY u.confidence DESC
    LIMIT @limit
    """
    params = {"asset_id": asset_id, "limit": limit}
    param_types = {
        "asset_id": _str_type(),
        "limit": _int64_type(),
    }

    rows = []
    with database.snapshot() as snap:
        result = snap.execute_sql(sql, params=params, param_types=param_types)
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
    *,
    since: date | None = None,
    until: date | None = None,
) -> list[dict[str, Any]]:
    """Return the TTP attack flow for the specified actor, ordered by FollowedBy weight.

    Joins Uses → TTP (src) → FollowedBy → TTP (dst) for the given actor.

    When ``since`` / ``until`` are supplied, the Uses edges are restricted
    to those with ``last_observed`` in ``[since, until]`` (inclusive of
    full calendar days). When both are ``None`` no temporal filter is
    applied and behaviour matches the pre-Initiative-F semantics.

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
    since_dt, until_dt = _to_window_bounds(since, until)
    window_clause = ""
    params: dict[str, Any] = {"actor_id": actor_stix_id}
    param_types: dict[str, Any] = {"actor_id": _str_type()}
    if since_dt is not None:
        window_clause += " AND u.last_observed >= @since"
        params["since"] = since_dt
        param_types["since"] = _timestamp_type()
    if until_dt is not None:
        window_clause += " AND u.last_observed < @until"
        params["until"] = until_dt
        param_types["until"] = _timestamp_type()

    sql = f"""
    SELECT
      src.stix_id  AS src_ttp_stix_id,
      src.name     AS src_ttp_name,
      dst.stix_id  AS dst_ttp_stix_id,
      dst.name     AS dst_ttp_name,
      fb.weight    AS weight,
      fb.source    AS source
    FROM Uses u
    JOIN TTP src        ON src.stix_id = u.ttp_stix_id
    JOIN FollowedBy fb  ON fb.src_ttp_stix_id = src.stix_id
    JOIN TTP dst        ON dst.stix_id = fb.dst_ttp_stix_id
    WHERE u.actor_stix_id = @actor_id{window_clause}
    ORDER BY fb.weight DESC
    """

    rows = []
    with database.snapshot() as snap:
        result = snap.execute_sql(sql, params=params, param_types=param_types)
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

    logger.info(
        "find_actor_ttps",
        actor_stix_id=actor_stix_id,
        count=len(rows),
        since=since.isoformat() if since else None,
        until=until.isoformat() if until else None,
    )
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
    *,
    since: date | None = None,
    until: date | None = None,
) -> list[dict[str, Any]]:
    """Return internet-exposed assets with their reachable TTP counts.

    Aggregates ``exposed_to_internet=TRUE`` assets along the
    ``Asset ← Targets ← ThreatActor → Uses → TTP`` join, counting
    distinct targeting actors and distinct reachable TTPs.

    When ``since`` / ``until`` are supplied, Uses edges are restricted to
    those with ``last_observed`` in ``[since, until]`` per
    Initiative F §2.6. The plan's "∪ Incident.occurred_at" combined view
    is consumed by Phase 8's ``/threat-summary`` endpoint; this query
    keeps the Uses-only counts so the response shape stays
    backward-compatible.

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
    since_dt, until_dt = _to_window_bounds(since, until)
    window_clause = ""
    params: dict[str, Any] = {}
    param_types: dict[str, Any] = {}
    if since_dt is not None:
        window_clause += " AND u.last_observed >= @since"
        params["since"] = since_dt
        param_types["since"] = _timestamp_type()
    if until_dt is not None:
        window_clause += " AND u.last_observed < @until"
        params["until"] = until_dt
        param_types["until"] = _timestamp_type()

    sql = f"""
    SELECT
      a.id                            AS asset_id,
      a.name                          AS asset_name,
      a.pir_adjusted_criticality      AS pir_adjusted_criticality,
      COUNT(DISTINCT t.actor_stix_id) AS targeting_actor_count,
      COUNT(DISTINCT u.ttp_stix_id)   AS reachable_ttp_count
    FROM Asset a
    JOIN Targets t ON t.asset_id = a.id
    JOIN Uses u    ON u.actor_stix_id = t.actor_stix_id
    WHERE a.exposed_to_internet = TRUE{window_clause}
    GROUP BY a.id, a.name, a.pir_adjusted_criticality
    ORDER BY pir_adjusted_criticality DESC
    """

    rows = []
    with database.snapshot() as snap:
        if params:
            result = snap.execute_sql(sql, params=params, param_types=param_types)
        else:
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

    logger.info(
        "find_asset_exposure",
        count=len(rows),
        since=since.isoformat() if since else None,
        until=until.isoformat() if until else None,
    )
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


def load_pirs(database: Database) -> list[dict[str, Any]]:
    """Return all PIR rows for visualizers and analysis tooling."""
    sql = """
    SELECT pir_id, intelligence_level, organizational_scope, decision_point,
           description, rationale, recommended_action, threat_actor_tags,
           risk_composite, valid_from, valid_until
    FROM PIR
    ORDER BY pir_id
    """
    rows: list[dict[str, Any]] = []
    with database.snapshot() as snap:
        for row in snap.execute_sql(sql):
            rows.append(
                {
                    "pir_id": row[0],
                    "intelligence_level": row[1],
                    "organizational_scope": row[2],
                    "decision_point": row[3],
                    "description": row[4],
                    "rationale": row[5],
                    "recommended_action": row[6],
                    "threat_actor_tags": list(row[7] or []),
                    "risk_composite": row[8],
                    "valid_from": row[9],
                    "valid_until": row[10],
                }
            )
    logger.info("load_pirs", count=len(rows))
    return rows


def load_pir_edges(database: Database) -> dict[str, list[dict[str, Any]]]:
    """Return PIR cascade edges keyed by edge-table name.

    Keys: "PirPrioritizesActor", "PirPrioritizesTTP", "PirWeightsAsset".
    """
    actor_sql = "SELECT pir_id, actor_stix_id, overlap_ratio FROM PirPrioritizesActor"
    ttp_sql = "SELECT pir_id, ttp_stix_id FROM PirPrioritizesTTP"
    asset_sql = "SELECT pir_id, asset_id, matched_tag, criticality_multiplier FROM PirWeightsAsset"

    result: dict[str, list[dict[str, Any]]] = {
        "PirPrioritizesActor": [],
        "PirPrioritizesTTP": [],
        "PirWeightsAsset": [],
    }
    with database.snapshot(multi_use=True) as snap:
        for row in snap.execute_sql(actor_sql):
            result["PirPrioritizesActor"].append(
                {"pir_id": row[0], "actor_stix_id": row[1], "overlap_ratio": row[2]}
            )
        for row in snap.execute_sql(ttp_sql):
            result["PirPrioritizesTTP"].append({"pir_id": row[0], "ttp_stix_id": row[1]})
        for row in snap.execute_sql(asset_sql):
            result["PirWeightsAsset"].append(
                {
                    "pir_id": row[0],
                    "asset_id": row[1],
                    "matched_tag": row[2],
                    "criticality_multiplier": row[3],
                }
            )
    logger.info(
        "load_pir_edges",
        actors=len(result["PirPrioritizesActor"]),
        ttps=len(result["PirPrioritizesTTP"]),
        assets=len(result["PirWeightsAsset"]),
    )
    return result


# ---------------------------------------------------------------------------
# Actor name search (Initiative I Phase 3 — GET /actors)
# ---------------------------------------------------------------------------


def find_actors_by_name(
    database: Database,
    name_query: str,
    limit: int = 20,
) -> list[dict[str, Any]]:
    """Return ThreatActors whose name contains ``name_query`` (case-insensitive).

    Sorted by ``last_seen`` DESC (most recently active first).

    Returns:
        [
          {
            "stix_id": "intrusion-set--xxx",
            "name": "APT99",
            "description": None,
            "aliases": ["Fancy Bear"],
            "first_seen": <datetime>,
            "last_seen": <datetime>,
            "sophistication_level": "advanced",
          },
          ...
        ]
    """
    sql = """
    SELECT
      stix_id,
      name,
      aliases,
      first_seen,
      last_seen,
      sophistication
    FROM ThreatActor
    WHERE LOWER(name) LIKE LOWER(@pattern)
    ORDER BY last_seen DESC
    LIMIT @limit
    """
    params = {
        "pattern": f"%{name_query}%",
        "limit": limit,
    }
    param_types = {
        "pattern": _str_type(),
        "limit": _int64_type(),
    }

    rows: list[dict[str, Any]] = []
    with database.snapshot() as snap:
        result = snap.execute_sql(sql, params=params, param_types=param_types)
        for row in result:
            rows.append(
                {
                    "stix_id": row[0],
                    "name": row[1],
                    "description": None,
                    "aliases": list(row[2] or []),
                    "first_seen": row[3],
                    "last_seen": row[4],
                    "sophistication_level": row[5],
                }
            )

    logger.info("find_actors_by_name", name_query=name_query, count=len(rows))
    return rows


# ---------------------------------------------------------------------------
# Threat summary (Initiative F Phase 8 — GET /threat-summary)
# ---------------------------------------------------------------------------


def find_prioritized_actors_for_asset(
    database: Database,
    asset_id: str,
    *,
    since: date,
    until: date,
    limit: int,
) -> list[dict[str, Any]]:
    """Return prioritized actors targeting ``asset_id`` from PIRs valid in window.

    Joins ``Targets`` (actor → asset) × ``PirPrioritizesActor`` (PIR ↔
    actor) × ``PIR`` (validity window). The PIR validity intersection
    follows plan §2.6: a PIR is counted when its
    ``[valid_from, valid_until]`` interval covers the requested
    ``[since, until]`` window — i.e. the PIR was authoritative for the
    entire request range. ``rationale_json`` is returned as the raw
    JSON string from Initiative D's persisted score breakdown; the
    response builder inline-expands it to a dict before serialisation.
    """
    sql = """
    SELECT DISTINCT
      ta.stix_id          AS actor_stix_id,
      ta.name             AS actor_name,
      ppa.pir_id          AS pir_id,
      ppa.overlap_ratio   AS overlap_ratio,
      ppa.likelihood      AS likelihood,
      ppa.rationale_json  AS rationale_json
    FROM Targets t
    JOIN ThreatActor ta        ON ta.stix_id = t.actor_stix_id
    JOIN PirPrioritizesActor ppa ON ppa.actor_stix_id = ta.stix_id
    JOIN PIR p                 ON p.pir_id = ppa.pir_id
    WHERE t.asset_id  = @asset_id
      AND p.valid_from  <= @since
      AND p.valid_until >= @until
    ORDER BY COALESCE(ppa.likelihood, 0) DESC, COALESCE(ppa.overlap_ratio, 0) DESC
    LIMIT @limit
    """
    params = {
        "asset_id": asset_id,
        "since": since,
        "until": until,
        "limit": limit,
    }
    param_types = {
        "asset_id": _str_type(),
        "since": _date_type(),
        "until": _date_type(),
        "limit": _int64_type(),
    }

    rows: list[dict[str, Any]] = []
    with database.snapshot() as snap:
        for row in snap.execute_sql(sql, params=params, param_types=param_types):
            rows.append(
                {
                    "actor_stix_id": row[0],
                    "actor_name": row[1],
                    "pir_id": row[2],
                    "overlap_ratio": row[3],
                    "likelihood": row[4],
                    "rationale_json": row[5],
                }
            )
    logger.info(
        "find_prioritized_actors_for_asset",
        asset_id=asset_id,
        count=len(rows),
        since=since.isoformat(),
        until=until.isoformat(),
    )
    return rows


def find_vulnerabilities_for_asset(
    database: Database,
    asset_id: str,
    *,
    since: date,
    until: date,
    limit: int,
) -> list[dict[str, Any]]:
    """Return vulnerabilities attached to ``asset_id`` with publication date in window.

    Joins ``HasVulnerability`` × ``Vulnerability`` and filters
    ``Vulnerability.published_date`` to ``[since, until]`` per plan §2.6
    (vulns block anchored on publication date).
    """
    since_dt, until_dt = _to_window_bounds(since, until)
    sql = """
    SELECT
      v.stix_id           AS vuln_stix_id,
      v.cve_id            AS cve_id,
      v.description       AS description,
      v.cvss_score        AS cvss_score,
      v.epss_score        AS epss_score,
      v.published_date    AS published_date
    FROM HasVulnerability hv
    JOIN Vulnerability v ON v.stix_id = hv.vuln_stix_id
    WHERE hv.asset_id = @asset_id
      AND v.published_date >= @since
      AND v.published_date <  @until
    ORDER BY COALESCE(v.cvss_score, 0) DESC, v.published_date DESC
    LIMIT @limit
    """
    params = {
        "asset_id": asset_id,
        "since": since_dt,
        "until": until_dt,
        "limit": limit,
    }
    param_types = {
        "asset_id": _str_type(),
        "since": _timestamp_type(),
        "until": _timestamp_type(),
        "limit": _int64_type(),
    }

    rows: list[dict[str, Any]] = []
    with database.snapshot() as snap:
        for row in snap.execute_sql(sql, params=params, param_types=param_types):
            rows.append(
                {
                    "vuln_stix_id": row[0],
                    "cve_id": row[1],
                    "description": row[2],
                    "cvss_score": row[3],
                    "epss_score": row[4],
                    "published_date": row[5],
                }
            )
    logger.info(
        "find_vulnerabilities_for_asset",
        asset_id=asset_id,
        count=len(rows),
        since=since.isoformat(),
        until=until.isoformat(),
    )
    return rows


def find_incidents_for_asset(
    database: Database,
    asset_id: str,
    *,
    since: date,
    until: date,
    limit: int,
) -> list[dict[str, Any]]:
    """Return incidents whose TTPs target ``asset_id`` with occurred_at in window.

    Per plan §2.6 + §10 Q2: the time anchor is
    ``Incident.occurred_at`` **only**. ``resolved_at`` is NOT consulted,
    so an incident that started before the window but was resolved
    inside it is correctly excluded (occurred_at is the attack-time
    anchor; resolved_at is the IR-closure time).

    Path: ``Incident → IncidentUsesTTP → TTP → TargetsAsset → Asset``.
    """
    since_dt, until_dt = _to_window_bounds(since, until)
    sql = """
    SELECT DISTINCT
      i.stix_id      AS incident_stix_id,
      i.name         AS incident_name,
      i.occurred_at  AS occurred_at,
      i.severity     AS severity,
      i.source       AS source
    FROM Incident i
    JOIN IncidentUsesTTP iut ON iut.incident_stix_id = i.stix_id
    JOIN TargetsAsset ta     ON ta.ttp_stix_id = iut.ttp_stix_id
    WHERE ta.asset_id = @asset_id
      AND i.occurred_at >= @since
      AND i.occurred_at <  @until
    ORDER BY i.occurred_at DESC
    LIMIT @limit
    """
    params = {
        "asset_id": asset_id,
        "since": since_dt,
        "until": until_dt,
        "limit": limit,
    }
    param_types = {
        "asset_id": _str_type(),
        "since": _timestamp_type(),
        "until": _timestamp_type(),
        "limit": _int64_type(),
    }

    rows: list[dict[str, Any]] = []
    with database.snapshot() as snap:
        for row in snap.execute_sql(sql, params=params, param_types=param_types):
            rows.append(
                {
                    "incident_stix_id": row[0],
                    "incident_name": row[1],
                    "occurred_at": row[2],
                    "severity": row[3],
                    "source": row[4],
                }
            )
    logger.info(
        "find_incidents_for_asset",
        asset_id=asset_id,
        count=len(rows),
        since=since.isoformat(),
        until=until.isoformat(),
    )
    return rows


# ---------------------------------------------------------------------------
# Type helpers (Spanner param_types)
# ---------------------------------------------------------------------------


def _str_type() -> Any:
    from google.cloud.spanner_v1 import param_types

    return param_types.STRING


def _int64_type() -> Any:
    from google.cloud.spanner_v1 import param_types

    return param_types.INT64


def _timestamp_type() -> Any:
    from google.cloud.spanner_v1 import param_types

    return param_types.TIMESTAMP


def _date_type() -> Any:
    from google.cloud.spanner_v1 import param_types

    return param_types.DATE
