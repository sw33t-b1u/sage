"""``/api/incidents`` — direct IR intake + read endpoints (Initiative G).

POST (Phase 1) — bypasses OpenCTI's 24h polling latency so IR teams
can register an incident the same day it occurs. The endpoint is plan
§2.1's "direct IR intake API"; the resulting ``Incident.source`` row
carries the ``direct_api`` discriminator (plan §2.2).

GET (Phase 2) — BEACON consumption path per plan §2.4. Filter scope
is ``since`` / ``until`` / ``actor_stix_id`` only (no severity / source
/ asset filters in G). Pagination is ``?limit=N`` only (default 50,
range 1-100; no offset / cursor). Response is "full" — the
``diamond_model`` JSON column is inline-expanded and ``ttps[]`` rows
are joined in, so BEACON gets the whole incident in one round-trip.

Auth (plan §2.10 / Decision 10):
  * POST — write API foot-gun gate. Token unset → 503, missing → 401,
    wrong → 403. Configured with ``enforce_when_unset=True``.
  * GET — permissive when ``SAGE_API_AUTH_TOKEN`` is unset
    (backwards-compatible with existing read endpoints); Bearer
    enforced when the token is set. Configured with
    ``enforce_when_unset=False``.

Out of scope here (deferred to later G phases): the
``cmd/register_incident.py`` Diamond Model CLI (Phase 3).
"""

from __future__ import annotations

from datetime import date
from typing import Any

import structlog
from fastapi import APIRouter, Depends, HTTPException, Query, Request
from pydantic import BaseModel, ConfigDict

from sage.api.auth import verify_auth
from sage.api.models import (
    GetIncidentsResponse,
    IncidentReadEntry,
    IncidentReadTTP,
    IncidentWindow,
)
from sage.api.windows import resolve_window
from sage.config import Config
from sage.models.incident_request import IncidentRequest
from sage.spanner.incidents import read_incidents, upsert_incident

# Accept the two STIX object types that map to ThreatActor rows
# (mirror of the pattern used by ``/api/annotate``).
_ACTOR_STIX_ID_PATTERN = r"^intrusion-set--[0-9a-f-]{36}$|^threat-actor--[0-9a-f-]{36}$"

logger = structlog.get_logger(__name__)

router = APIRouter()


class IncidentWarning(BaseModel):
    model_config = ConfigDict(extra="forbid")
    code: str
    message: str


class IncidentResponse(BaseModel):
    """Response body of ``POST /api/incidents`` (plan §2.1)."""

    model_config = ConfigDict(extra="forbid")
    incident_stix_id: str
    accepted: bool
    created: bool
    updated: bool
    warnings: list[IncidentWarning]


@router.post(
    "/incidents",
    response_model=IncidentResponse,
    dependencies=[Depends(verify_auth(enforce_when_unset=True))],
)
def post_incident(req: IncidentRequest, request: Request) -> IncidentResponse:
    """Register or replace one Incident + its IncidentUsesTTP rows.

    PUT-like semantics — re-POST with the same ``incident_stix_id``
    fully replaces both the parent row and its TTP children inside one
    Spanner transaction (plan §2.1, Decision 1, last bullet).
    """
    try:
        result: dict[str, Any] = upsert_incident(
            database=request.app.state.database,
            req=req,
        )
    except Exception as exc:
        logger.error(
            "incident_upsert_failed",
            incident_stix_id=req.incident_stix_id,
            error=str(exc),
        )
        raise HTTPException(
            status_code=500,
            detail="Failed to write incident",
        ) from exc

    return IncidentResponse(
        incident_stix_id=result["incident_stix_id"],
        accepted=result["accepted"],
        created=result["created"],
        updated=result["updated"],
        warnings=[IncidentWarning(**w) for w in result["warnings"]],
    )


@router.get(
    "/incidents",
    response_model=GetIncidentsResponse,
    dependencies=[Depends(verify_auth(enforce_when_unset=False))],
)
def get_incidents(
    request: Request,
    since: date | None = Query(
        None,
        description=(
            "Inclusive lower bound (YYYY-MM-DD) on ``Incident.occurred_at``. "
            "Defaults to ``until - SAGE_ACTIVITY_WINDOW_DAYS``."
        ),
    ),
    until: date | None = Query(
        None,
        description=(
            "Inclusive upper bound (YYYY-MM-DD) on ``Incident.occurred_at``. "
            "Defaults to today (UTC). Treated as full-day inclusive."
        ),
    ),
    actor_stix_id: str | None = Query(
        None,
        pattern=_ACTOR_STIX_ID_PATTERN,
        description=(
            "Restrict to incidents whose TTPs are used by this actor "
            "(``EXISTS`` join through ``IncidentUsesTTP → Uses``)."
        ),
    ),
    limit: int = Query(
        50,
        ge=1,
        le=100,
        description=(
            "Maximum number of incidents to return. Plan §2.4 fixes pagination "
            "at limit-only (no offset / cursor in G)."
        ),
    ),
) -> GetIncidentsResponse:
    """List incidents whose ``occurred_at`` falls in ``[since, until]``.

    No TLP filter is applied (plan §2.4 Q6=NO — TLP is enforced
    upstream at ETL; a Bearer-authed caller may read any stored
    incident). Spanner snapshot reads are strong by default so a POST
    /incidents followed by a GET on the same ``incident_stix_id`` will
    reflect the upserted state immediately (plan §2.4 read
    consistency: strong).
    """
    config: Config = request.app.state.config
    since_d, until_d = resolve_window(config, since, until)
    try:
        rows = read_incidents(
            request.app.state.database,
            since=since_d,
            until=until_d,
            actor_stix_id=actor_stix_id,
            limit=limit,
        )
    except Exception as exc:
        logger.error(
            "incident_read_failed",
            since=since_d.isoformat(),
            until=until_d.isoformat(),
            actor_stix_id=actor_stix_id,
            limit=limit,
            error=str(exc),
        )
        raise HTTPException(
            status_code=500,
            detail="Failed to read incidents",
        ) from exc

    entries = [
        IncidentReadEntry(
            incident_stix_id=row["incident_stix_id"],
            name=row["name"],
            occurred_at=row["occurred_at"],
            severity=row["severity"],
            source=row["source"],
            description=row["description"],
            kill_chain_phases=row["kill_chain_phases"],
            diamond_model=row["diamond_model"],
            ttps=[
                IncidentReadTTP(
                    ttp_stix_id=t["ttp_stix_id"],
                    sequence_order=t["sequence_order"],
                )
                for t in row["ttps"]
            ],
        )
        for row in rows
    ]
    return GetIncidentsResponse(
        count=len(entries),
        window=IncidentWindow(since=since_d, until=until_d),
        incidents=entries,
    )
