"""Response builder for ``GET /threat-summary`` (Initiative F Phase 8).

Stitches five per-asset sections from the graph database into one
verbose response (queries dispatch through ``sage.db``):

- ``prioritized_actors`` — ``PirPrioritizesActor`` rows for PIRs whose
  validity covers the requested window, restricted to actors that
  ``Targets`` the asset. ``rationale_json`` is inline-expanded to a dict
  via :func:`_decode_rationale`.
- ``attack_paths`` — ``find_attack_paths(asset)`` rows (unchanged from
  Phase 7).
- ``choke_points`` — ``find_choke_points`` rows (asset-related; the
  table itself is global since choke-point ranking is a graph-wide
  property).
- ``vulnerabilities`` — ``HasVulnerability`` × ``Vulnerability`` for
  the asset with ``published_date`` in window.
- ``incidents`` — ``Incident`` rows for incidents whose TTPs target the
  asset, anchored on ``Incident.occurred_at`` ONLY (plan §10 Q2).

Per-section caps default to 5 (Initiative E top-5 parity); ``?limit=N``
overrides for 1-100 inclusive. Pagination beyond ``limit`` is
intentionally deferred — see plan §2.5.
"""

from __future__ import annotations

import json
from datetime import date
from typing import Any

import structlog

from sage.api.models import (
    AttackPathEntry,
    ChokePointEntry,
    IncidentEntry,
    PrioritizedActorEntry,
    ThreatSummaryResponse,
    ThreatSummaryWindow,
    VulnerabilityEntry,
)
from sage.db import (
    find_attack_paths,
    find_choke_points,
    find_incidents_for_asset,
    find_prioritized_actors_for_asset,
    find_vulnerabilities_for_asset,
)

logger = structlog.get_logger(__name__)


def build_threat_summary(
    database: Any,
    *,
    asset_id: str,
    since: date,
    until: date,
    limit: int,
) -> ThreatSummaryResponse:
    """Assemble the five-section response for one asset.

    Each section query runs in its own snapshot; the response builder
    does not require cross-section transactional consistency since the
    underlying graph rows are append-mostly (PIR validity, vuln
    publication dates, incident occurrence dates).
    """
    actors_raw = find_prioritized_actors_for_asset(
        database, asset_id, since=since, until=until, limit=limit
    )
    attack_paths_raw = find_attack_paths(database, asset_id, limit=limit)
    choke_points_raw = find_choke_points(database, top_n=limit)
    vulns_raw = find_vulnerabilities_for_asset(
        database, asset_id, since=since, until=until, limit=limit
    )
    incidents_raw = find_incidents_for_asset(
        database, asset_id, since=since, until=until, limit=limit
    )

    response = ThreatSummaryResponse(
        asset_id=asset_id,
        window=ThreatSummaryWindow(since=since, until=until),
        limit=limit,
        prioritized_actors=[
            PrioritizedActorEntry(
                actor_stix_id=row["actor_stix_id"],
                actor_name=row.get("actor_name"),
                pir_id=row["pir_id"],
                overlap_ratio=row.get("overlap_ratio"),
                likelihood=row.get("likelihood"),
                rationale=_decode_rationale(row.get("rationale_json")),
            )
            for row in actors_raw
        ],
        attack_paths=[AttackPathEntry(**row) for row in attack_paths_raw],
        choke_points=[ChokePointEntry(**row) for row in choke_points_raw],
        vulnerabilities=[VulnerabilityEntry(**row) for row in vulns_raw],
        incidents=[IncidentEntry(**row) for row in incidents_raw],
    )
    logger.info(
        "threat_summary_built",
        asset_id=asset_id,
        actors=len(response.prioritized_actors),
        attack_paths=len(response.attack_paths),
        choke_points=len(response.choke_points),
        vulnerabilities=len(response.vulnerabilities),
        incidents=len(response.incidents),
        since=since.isoformat(),
        until=until.isoformat(),
        limit=limit,
    )
    return response


def _decode_rationale(raw: str | None) -> dict[str, Any] | None:
    """Inline-expand the ``PirPrioritizesActor.rationale_json`` payload.

    Returns ``None`` when the column is empty (legacy rows from before
    Initiative D wired the rationale field) or when the stored value
    cannot be parsed as a JSON object. Parse failures are logged so
    operators can find producer-side corruption; the request still
    succeeds (rationale falls back to ``None``).
    """
    if not raw:
        return None
    try:
        decoded = json.loads(raw)
    except json.JSONDecodeError as exc:
        logger.warning("rationale_json_decode_failed", error=str(exc))
        return None
    if not isinstance(decoded, dict):
        logger.warning("rationale_json_not_object", actual_type=type(decoded).__name__)
        return None
    return decoded
