"""``POST /api/incidents`` — direct IR intake endpoint (Initiative G Phase 1).

Bypasses OpenCTI's 24h polling latency so IR teams can register an
incident the same day it occurs. The endpoint is plan §2.1's "direct
IR intake API" — supplements (does NOT replace) the existing OpenCTI
flow; the resulting ``Incident.source`` row carries the
``direct_api`` discriminator (plan §2.2).

Auth (plan §2.10 / Decision 10): write API foot-gun gate. Token unset
→ 503; token set + missing header → 401; token set + wrong value → 403.
Configured via :func:`sage.api.auth.verify_auth` with
``enforce_when_unset=True``.

Out of scope here (deferred to later G phases): GET /incidents (Phase
2) and the ``cmd/register_incident.py`` Diamond Model CLI (Phase 3).
"""

from __future__ import annotations

from typing import Any

import structlog
from fastapi import APIRouter, Depends, HTTPException, Request
from pydantic import BaseModel, ConfigDict

from sage.api.auth import verify_auth
from sage.models.incident_request import IncidentRequest
from sage.spanner.incidents import upsert_incident

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
