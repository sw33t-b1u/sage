"""SQLite query functions — mirror of sage.spanner.query.

Every public function here has the same name, signature, and return
shape as its sage.spanner.query counterpart, but takes an
``sqlite3.Connection`` instead of a Spanner ``Database``. The sage.db
dispatch layer routes calls to the right implementation by backend.

Dialect translation (Decision D-3):
  * ``@param`` placeholders -> ``:param`` (named style).
  * TIMESTAMP / DATE comparisons operate on ISO 8601 UTC TEXT.
    Lexicographic ordering of ISO 8601 strings matches chronological
    ordering as long as every stored value uses the same UTC offset
    notation; the upsert layer's canonical format is
    ``datetime.now(UTC).isoformat()`` (``...+00:00``), and window
    bounds are bound in that exact format so boundary comparisons stay
    byte-exact.
  * ARRAY<STRING> columns come back as JSON TEXT and are decoded with
    ``json.loads`` so callers receive ``list[str]`` — identical to the
    Spanner client's list materialisation.
  * TIMESTAMP columns the Spanner client yields as ``datetime`` are
    parsed back from TEXT with ``datetime.fromisoformat`` (DATE columns
    likewise to ``date``) so the per-row value types match the Spanner
    backend byte-for-byte.
"""

from __future__ import annotations

import json
import sqlite3
from datetime import UTC, date, datetime, time, timedelta
from typing import Any

import structlog

logger = structlog.get_logger(__name__)


def _to_window_bounds(since: date | None, until: date | None) -> tuple[str | None, str | None]:
    """Convert ``date`` window bounds to ISO 8601 UTC TEXT bind values.

    Mirrors ``sage.spanner.query._to_window_bounds`` semantics:
    ``since`` snaps to 00:00:00 (inclusive lower bound), ``until`` snaps
    to 00:00:00 on the day AFTER (exclusive upper bound) so
    ``ts < :until`` treats ``since == until`` as a full calendar day.
    The Spanner version returns ``datetime`` objects for TIMESTAMP
    binds; SQLite stores TIMESTAMP as TEXT, so this version returns the
    canonical ``+00:00`` ISO strings the upsert layer writes.
    """
    since_s = datetime.combine(since, time.min, tzinfo=UTC).isoformat() if since else None
    until_s = (
        (datetime.combine(until, time.min, tzinfo=UTC) + timedelta(days=1)).isoformat()
        if until
        else None
    )
    return since_s, until_s


def _decode_json_array(raw: Any) -> list[str]:
    """Decode a JSON-array TEXT column to ``list[str]`` ([] for NULL)."""
    if raw is None:
        return []
    if isinstance(raw, list):
        return [str(item) for item in raw]
    return [str(item) for item in json.loads(raw)]


def _parse_ts(raw: Any) -> datetime | None:
    """Parse an ISO 8601 TEXT timestamp back to ``datetime`` (None-safe).

    The Spanner client returns TIMESTAMP columns as timezone-aware
    ``datetime`` objects; this restores the same type from the TEXT
    storage so return shapes stay identical across backends.
    """
    if raw is None or isinstance(raw, datetime):
        return raw
    return datetime.fromisoformat(raw)


def _parse_date(raw: Any) -> date | None:
    """Parse an ISO 8601 TEXT date back to ``date`` (None-safe).

    Mirrors the Spanner client's ``date`` materialisation for DATE
    columns. Accepts full timestamps defensively by truncating to the
    date part.
    """
    if raw is None:
        return raw
    if isinstance(raw, datetime):
        return raw.date()
    if isinstance(raw, date):
        return raw
    return date.fromisoformat(str(raw)[:10])


def find_attack_paths(
    conn: sqlite3.Connection,
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
    WHERE tgt.asset_id = :asset_id
    ORDER BY u.confidence DESC
    LIMIT :limit
    """
    rows = [
        {
            "actor_stix_id": rec["actor_stix_id"],
            "actor_name": rec["actor_name"],
            "ttp_stix_id": rec["ttp_stix_id"],
            "ttp_name": rec["ttp_name"],
            "confidence": rec["confidence"],
        }
        for rec in conn.execute(sql, {"asset_id": asset_id, "limit": limit})
    ]
    logger.info("find_attack_paths", asset_id=asset_id, count=len(rows))
    return rows


def find_actor_ttps(
    conn: sqlite3.Connection,
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
    applied.

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
    since_s, until_s = _to_window_bounds(since, until)
    window_clause = ""
    params: dict[str, Any] = {"actor_id": actor_stix_id}
    if since_s is not None:
        window_clause += " AND u.last_observed >= :since"
        params["since"] = since_s
    if until_s is not None:
        window_clause += " AND u.last_observed < :until"
        params["until"] = until_s

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
    WHERE u.actor_stix_id = :actor_id{window_clause}
    ORDER BY fb.weight DESC
    """
    rows = [
        {
            "src_ttp_stix_id": rec["src_ttp_stix_id"],
            "src_ttp_name": rec["src_ttp_name"],
            "dst_ttp_stix_id": rec["dst_ttp_stix_id"],
            "dst_ttp_name": rec["dst_ttp_name"],
            "weight": rec["weight"],
            "source": rec["source"],
        }
        for rec in conn.execute(sql, params)
    ]
    logger.info(
        "find_actor_ttps",
        actor_stix_id=actor_stix_id,
        count=len(rows),
        since=since.isoformat() if since else None,
        until=until.isoformat() if until else None,
    )
    return rows


def find_choke_points(
    conn: sqlite3.Connection,
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
    LIMIT :top_n
    """
    rows = [
        {
            "asset_id": rec["asset_id"],
            "asset_name": rec["asset_name"],
            "pir_adjusted_criticality": rec["pir_adjusted_criticality"],
            "targeting_actor_count": rec["targeting_actor_count"],
            "choke_score": rec["choke_score"],
        }
        for rec in conn.execute(sql, {"top_n": top_n})
    ]
    logger.info("find_choke_points", top_n=top_n, count=len(rows))
    return rows


def find_asset_exposure(
    conn: sqlite3.Connection,
    *,
    since: date | None = None,
    until: date | None = None,
) -> list[dict[str, Any]]:
    """Return internet-exposed assets with their reachable TTP counts.

    Aggregates ``exposed_to_internet=TRUE`` (stored as 1) assets along
    the ``Asset ← Targets ← ThreatActor → Uses → TTP`` join, counting
    distinct targeting actors and distinct reachable TTPs.

    When ``since`` / ``until`` are supplied, Uses edges are restricted to
    those with ``last_observed`` in ``[since, until]``.

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
    since_s, until_s = _to_window_bounds(since, until)
    window_clause = ""
    params: dict[str, Any] = {}
    if since_s is not None:
        window_clause += " AND u.last_observed >= :since"
        params["since"] = since_s
    if until_s is not None:
        window_clause += " AND u.last_observed < :until"
        params["until"] = until_s

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
    WHERE a.exposed_to_internet = 1{window_clause}
    GROUP BY a.id, a.name, a.pir_adjusted_criticality
    ORDER BY pir_adjusted_criticality DESC
    """
    rows = [
        {
            "asset_id": rec["asset_id"],
            "asset_name": rec["asset_name"],
            "pir_adjusted_criticality": rec["pir_adjusted_criticality"],
            "targeting_actor_count": rec["targeting_actor_count"],
            "reachable_ttp_count": rec["reachable_ttp_count"],
        }
        for rec in conn.execute(sql, params)
    ]
    logger.info(
        "find_asset_exposure",
        count=len(rows),
        since=since.isoformat() if since else None,
        until=until.isoformat() if until else None,
    )
    return rows


def find_incident_ttps(
    conn: sqlite3.Connection,
    incident_id: str,
) -> list[str]:
    """Return TTP STIX IDs linked to the specified incident via IncidentUsesTTP.

    Returns:
        ["attack-pattern--t1078", ...]
    """
    sql = """
    SELECT ttp_stix_id
    FROM IncidentUsesTTP
    WHERE incident_stix_id = :incident_id
    """
    ttps = [rec["ttp_stix_id"] for rec in conn.execute(sql, {"incident_id": incident_id})]
    logger.info("find_incident_ttps", incident_id=incident_id, count=len(ttps))
    return ttps


def find_followedby_edges(
    conn: sqlite3.Connection,
) -> list[dict[str, Any]]:
    """Return all FollowedBy edges (used for building the similarity graph).

    Returns:
        [{"src_stix_id": "...", "dst_stix_id": "...", "weight": 0.72}, ...]
    """
    sql = """
    SELECT src_ttp_stix_id, dst_ttp_stix_id, weight
    FROM FollowedBy
    """
    rows = [
        {
            "src_stix_id": rec["src_ttp_stix_id"],
            "dst_stix_id": rec["dst_ttp_stix_id"],
            "weight": rec["weight"],
        }
        for rec in conn.execute(sql)
    ]
    logger.info("find_followedby_edges", count=len(rows))
    return rows


def find_all_incident_ttps(
    conn: sqlite3.Connection,
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
    for rec in conn.execute(sql):
        result_map.setdefault(rec["incident_stix_id"], []).append(rec["ttp_stix_id"])
    logger.info("find_all_incident_ttps", incident_count=len(result_map))
    return result_map


def load_pirs(conn: sqlite3.Connection) -> list[dict[str, Any]]:
    """Return all PIR rows for visualizers and analysis tooling."""
    sql = """
    SELECT pir_id, intelligence_level, organizational_scope, decision_point,
           description, rationale, recommended_action, threat_actor_tags,
           risk_composite, valid_from, valid_until
    FROM PIR
    ORDER BY pir_id
    """
    rows = [
        {
            "pir_id": rec["pir_id"],
            "intelligence_level": rec["intelligence_level"],
            "organizational_scope": rec["organizational_scope"],
            "decision_point": rec["decision_point"],
            "description": rec["description"],
            "rationale": rec["rationale"],
            "recommended_action": rec["recommended_action"],
            "threat_actor_tags": _decode_json_array(rec["threat_actor_tags"]),
            "risk_composite": rec["risk_composite"],
            "valid_from": _parse_date(rec["valid_from"]),
            "valid_until": _parse_date(rec["valid_until"]),
        }
        for rec in conn.execute(sql)
    ]
    logger.info("load_pirs", count=len(rows))
    return rows


def load_pir_edges(conn: sqlite3.Connection) -> dict[str, list[dict[str, Any]]]:
    """Return PIR cascade edges keyed by edge-table name.

    Keys: "PirPrioritizesActor", "PirPrioritizesTTP", "PirWeightsAsset".
    """
    actor_sql = "SELECT pir_id, actor_stix_id, overlap_ratio FROM PirPrioritizesActor"
    ttp_sql = "SELECT pir_id, ttp_stix_id FROM PirPrioritizesTTP"
    asset_sql = "SELECT pir_id, asset_id, matched_tag, criticality_multiplier FROM PirWeightsAsset"

    result: dict[str, list[dict[str, Any]]] = {
        "PirPrioritizesActor": [
            {
                "pir_id": rec["pir_id"],
                "actor_stix_id": rec["actor_stix_id"],
                "overlap_ratio": rec["overlap_ratio"],
            }
            for rec in conn.execute(actor_sql)
        ],
        "PirPrioritizesTTP": [
            {"pir_id": rec["pir_id"], "ttp_stix_id": rec["ttp_stix_id"]}
            for rec in conn.execute(ttp_sql)
        ],
        "PirWeightsAsset": [
            {
                "pir_id": rec["pir_id"],
                "asset_id": rec["asset_id"],
                "matched_tag": rec["matched_tag"],
                "criticality_multiplier": rec["criticality_multiplier"],
            }
            for rec in conn.execute(asset_sql)
        ],
    }
    logger.info(
        "load_pir_edges",
        actors=len(result["PirPrioritizesActor"]),
        ttps=len(result["PirPrioritizesTTP"]),
        assets=len(result["PirWeightsAsset"]),
    )
    return result


# ---------------------------------------------------------------------------
# Actor name search (GET /actors)
# ---------------------------------------------------------------------------


def find_actors_by_name(
    conn: sqlite3.Connection,
    name_query: str,
    limit: int = 20,
) -> list[dict[str, Any]]:
    """Return ThreatActors whose name contains ``name_query`` (case-insensitive).

    Sorted by ``last_seen`` DESC (most recently active first). SQLite's
    ``LOWER`` folds ASCII only (Spanner folds full Unicode); actor names
    in the corpus are ASCII so behaviour matches in practice.

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
    WHERE LOWER(name) LIKE LOWER(:pattern)
    ORDER BY last_seen DESC
    LIMIT :limit
    """
    rows = [
        {
            "stix_id": rec["stix_id"],
            "name": rec["name"],
            "description": None,
            "aliases": _decode_json_array(rec["aliases"]),
            "first_seen": _parse_ts(rec["first_seen"]),
            "last_seen": _parse_ts(rec["last_seen"]),
            "sophistication_level": rec["sophistication"],
        }
        for rec in conn.execute(sql, {"pattern": f"%{name_query}%", "limit": limit})
    ]
    logger.info("find_actors_by_name", name_query=name_query, count=len(rows))
    return rows


# ---------------------------------------------------------------------------
# Threat summary (GET /threat-summary)
# ---------------------------------------------------------------------------


def find_prioritized_actors_for_asset(
    conn: sqlite3.Connection,
    asset_id: str,
    *,
    since: date,
    until: date,
    limit: int,
) -> list[dict[str, Any]]:
    """Return prioritized actors targeting ``asset_id`` from PIRs valid in window.

    Joins ``Targets`` (actor → asset) × ``PirPrioritizesActor`` (PIR ↔
    actor) × ``PIR`` (validity window). A PIR is counted when its
    ``[valid_from, valid_until]`` interval covers the requested
    ``[since, until]`` window — i.e. the PIR was authoritative for the
    entire request range. ``rationale_json`` is returned as the raw
    JSON string from the persisted score breakdown; the response
    builder inline-expands it to a dict before serialisation.
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
    WHERE t.asset_id  = :asset_id
      AND p.valid_from  <= :since
      AND p.valid_until >= :until
    ORDER BY COALESCE(ppa.likelihood, 0) DESC, COALESCE(ppa.overlap_ratio, 0) DESC
    LIMIT :limit
    """
    params = {
        "asset_id": asset_id,
        "since": since.isoformat(),
        "until": until.isoformat(),
        "limit": limit,
    }
    rows = [
        {
            "actor_stix_id": rec["actor_stix_id"],
            "actor_name": rec["actor_name"],
            "pir_id": rec["pir_id"],
            "overlap_ratio": rec["overlap_ratio"],
            "likelihood": rec["likelihood"],
            "rationale_json": rec["rationale_json"],
        }
        for rec in conn.execute(sql, params)
    ]
    logger.info(
        "find_prioritized_actors_for_asset",
        asset_id=asset_id,
        count=len(rows),
        since=since.isoformat(),
        until=until.isoformat(),
    )
    return rows


def find_vulnerabilities_for_asset(
    conn: sqlite3.Connection,
    asset_id: str,
    *,
    since: date,
    until: date,
    limit: int,
) -> list[dict[str, Any]]:
    """Return vulnerabilities attached to ``asset_id`` with publication date in window.

    Joins ``HasVulnerability`` × ``Vulnerability`` and filters
    ``Vulnerability.published_date`` to ``[since, until]`` (vulns block
    anchored on publication date).
    """
    since_s, until_s = _to_window_bounds(since, until)
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
    WHERE hv.asset_id = :asset_id
      AND v.published_date >= :since
      AND v.published_date <  :until
    ORDER BY COALESCE(v.cvss_score, 0) DESC, v.published_date DESC
    LIMIT :limit
    """
    params = {
        "asset_id": asset_id,
        "since": since_s,
        "until": until_s,
        "limit": limit,
    }
    rows = [
        {
            "vuln_stix_id": rec["vuln_stix_id"],
            "cve_id": rec["cve_id"],
            "description": rec["description"],
            "cvss_score": rec["cvss_score"],
            "epss_score": rec["epss_score"],
            "published_date": _parse_ts(rec["published_date"]),
        }
        for rec in conn.execute(sql, params)
    ]
    logger.info(
        "find_vulnerabilities_for_asset",
        asset_id=asset_id,
        count=len(rows),
        since=since.isoformat(),
        until=until.isoformat(),
    )
    return rows


def find_incidents_for_asset(
    conn: sqlite3.Connection,
    asset_id: str,
    *,
    since: date,
    until: date,
    limit: int,
) -> list[dict[str, Any]]:
    """Return incidents whose TTPs target ``asset_id`` with occurred_at in window.

    The time anchor is ``Incident.occurred_at`` **only**. ``resolved_at``
    is NOT consulted, so an incident that started before the window but
    was resolved inside it is correctly excluded (occurred_at is the
    attack-time anchor; resolved_at is the IR-closure time).

    Path: ``Incident → IncidentUsesTTP → TTP → TargetsAsset → Asset``.
    """
    since_s, until_s = _to_window_bounds(since, until)
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
    WHERE ta.asset_id = :asset_id
      AND i.occurred_at >= :since
      AND i.occurred_at <  :until
    ORDER BY i.occurred_at DESC
    LIMIT :limit
    """
    params = {
        "asset_id": asset_id,
        "since": since_s,
        "until": until_s,
        "limit": limit,
    }
    rows = [
        {
            "incident_stix_id": rec["incident_stix_id"],
            "incident_name": rec["incident_name"],
            "occurred_at": _parse_ts(rec["occurred_at"]),
            "severity": rec["severity"],
            "source": rec["source"],
        }
        for rec in conn.execute(sql, params)
    ]
    logger.info(
        "find_incidents_for_asset",
        asset_id=asset_id,
        count=len(rows),
        since=since.isoformat(),
        until=until.isoformat(),
    )
    return rows
