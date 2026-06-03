"""FastAPI Analysis API — Cloud Run entry point.

Exposes Spanner query results as a REST API.
The Spanner Database instance is initialised at startup and stored in
app.state so that all endpoints can share a single connection.

Authentication:
  Set SAGE_API_AUTH_TOKEN to require a Bearer token on every request.
  When unset, a warning is logged at startup but no auth is enforced.

Environment variables (loaded via Config.from_env()):
  GCP_PROJECT_ID, SPANNER_INSTANCE, SPANNER_DB, etc.
"""

from __future__ import annotations

from contextlib import asynccontextmanager
from datetime import date
from typing import Any

import structlog
from fastapi import Depends, FastAPI, HTTPException, Query
from google.cloud import spanner

from sage.analysis.similarity import find_similar_incidents
from sage.api.annotation import router as annotation_router
from sage.api.auth import verify_auth
from sage.api.incidents import router as incidents_router
from sage.api.models import ThreatSummaryResponse
from sage.api.threat_summary import build_threat_summary
from sage.api.windows import resolve_window
from sage.caldera.client import sync_actor_ttps
from sage.config import Config
from sage.spanner.query import (
    find_actor_ttps,
    find_actors_by_name,
    find_asset_exposure,
    find_attack_paths,
    find_choke_points,
)

logger = structlog.get_logger(__name__)


@asynccontextmanager
async def lifespan(app: FastAPI):  # type: ignore[type-arg]
    config = Config.from_env()
    spanner_client = spanner.Client(project=config.gcp_project_id)
    instance = spanner_client.instance(config.spanner_instance_id)
    app.state.database = instance.database(config.spanner_database_id)
    app.state.config = config
    if not config.api_auth_token:
        logger.warning("api_auth_disabled", reason="SAGE_API_AUTH_TOKEN not set")
    logger.info("api_started", database=config.spanner_database_id)
    yield
    logger.info("api_stopped")


app = FastAPI(title="SAGE Analysis API", version="0.1.0", lifespan=lifespan)


# ---------------------------------------------------------------------------
# Authentication
# ---------------------------------------------------------------------------
# Read endpoints stay permissive when ``SAGE_API_AUTH_TOKEN`` is unset
# (backwards-compatible with existing deployments). Write endpoints —
# ``POST /api/annotate`` (Initiative E, retroactively per Decision 10)
# and ``POST /api/incidents`` (Initiative G Phase 1) — reject with 503
# when the token is unset so we cannot accept poisoned data from an
# unauthenticated caller.

_verify_auth = verify_auth(enforce_when_unset=False)
_verify_auth_write = verify_auth(enforce_when_unset=True)


# ---------------------------------------------------------------------------
# Attack Path endpoints
# ---------------------------------------------------------------------------


@app.get("/attack-paths", dependencies=[Depends(_verify_auth)])
def get_attack_paths(
    asset_id: str = Query(..., description="Asset ID"),
    limit: int = Query(10, ge=1, le=100),
) -> list[dict[str, Any]]:
    """Return attack paths reaching the specified asset, ordered by confidence."""
    try:
        return find_attack_paths(app.state.database, asset_id, limit)
    except Exception as exc:
        logger.error("api_error", endpoint="attack-paths", error=str(exc))
        raise HTTPException(status_code=500, detail="Internal server error") from exc


@app.get("/choke-points", dependencies=[Depends(_verify_auth)])
def get_choke_points(
    top_n: int = Query(20, ge=1, le=100),
) -> list[dict[str, Any]]:
    """Return choke-point assets ordered by score descending."""
    try:
        return find_choke_points(app.state.database, top_n)
    except Exception as exc:
        logger.error("api_error", endpoint="choke-points", error=str(exc))
        raise HTTPException(status_code=500, detail="Internal server error") from exc


# ``_resolve_window`` was moved to ``sage.api.windows.resolve_window``
# in Initiative G Phase 2 so the GET /api/incidents handler can share
# the same defaulting logic without creating an import cycle. The local
# alias is kept so existing references in this module read the same.
_resolve_window = resolve_window


@app.get("/actor-ttps", dependencies=[Depends(_verify_auth)])
def get_actor_ttps(
    actor_id: str = Query(..., description="ThreatActor STIX ID"),
    since: date | None = Query(
        None,
        description=(
            "Inclusive lower bound (YYYY-MM-DD) on Uses.last_observed. "
            "Defaults to until - SAGE_ACTIVITY_WINDOW_DAYS."
        ),
    ),
    until: date | None = Query(
        None,
        description=(
            "Inclusive upper bound (YYYY-MM-DD) on Uses.last_observed. Defaults to today (UTC)."
        ),
    ),
) -> list[dict[str, Any]]:
    """Return the TTP attack flow for the specified actor, ordered by FollowedBy weight."""
    config: Config = app.state.config
    since_d, until_d = _resolve_window(config, since, until)
    try:
        return find_actor_ttps(app.state.database, actor_id, since=since_d, until=until_d)
    except Exception as exc:
        logger.error("api_error", endpoint="actor-ttps", error=str(exc))
        raise HTTPException(status_code=500, detail="Internal server error") from exc


@app.get("/actors", dependencies=[Depends(_verify_auth)])
def get_actors(
    name: str = Query(
        ...,
        min_length=2,
        description="Name substring to search (case-insensitive, min 2 chars)",
    ),
    limit: int = Query(
        20,
        ge=1,
        le=100,
        description="Maximum number of results to return (1-100)",
    ),
) -> dict[str, Any]:
    """Return ThreatActors whose name contains the given substring.

    Returns ``{"actors": [...], "count": N}`` sorted by last_seen DESC.
    """
    try:
        actors = find_actors_by_name(app.state.database, name, limit)
        return {"actors": actors, "count": len(actors)}
    except Exception as exc:
        logger.error("api_error", endpoint="actors", error=str(exc))
        raise HTTPException(status_code=500, detail="Internal server error") from exc


@app.get(
    "/threat-summary",
    dependencies=[Depends(_verify_auth)],
    response_model=ThreatSummaryResponse,
)
def get_threat_summary(
    asset: str = Query(..., description="Asset ID to summarise"),
    since: date | None = Query(
        None,
        description=(
            "Inclusive lower bound (YYYY-MM-DD) on the per-section time anchor. "
            "Defaults to until - SAGE_ACTIVITY_WINDOW_DAYS."
        ),
    ),
    until: date | None = Query(
        None,
        description=(
            "Exclusive upper bound (YYYY-MM-DD) on the per-section time anchor. "
            "Defaults to today (UTC)."
        ),
    ),
    limit: int = Query(
        5,
        ge=1,
        le=100,
        description=(
            "Per-section row cap. Default 5 mirrors BEACON's Initiative E top-5 "
            "prioritized_actors view; range 1-100, pagination beyond limit is "
            "intentionally deferred (Initiative F)."
        ),
    ),
) -> ThreatSummaryResponse:
    """Return a five-section per-asset threat summary.

    Sections:
      * ``prioritized_actors`` — from PIRs valid in window, restricted
        to actors that ``Targets`` the asset; ``rationale_json`` is
        inline-expanded.
      * ``attack_paths`` — TTP attack flow toward the asset.
      * ``choke_points`` — graph-wide ranking (helps the analyst place
        the asset against the broader topology).
      * ``vulnerabilities`` — CVEs with ``published_date`` in window.
      * ``incidents`` — Incidents with ``occurred_at`` in window (the
        ``resolved_at`` column is intentionally not consulted —
        plan §10 Q2).
    """
    config: Config = app.state.config
    since_d, until_d = _resolve_window(config, since, until)
    try:
        return build_threat_summary(
            app.state.database,
            asset_id=asset,
            since=since_d,
            until=until_d,
            limit=limit,
        )
    except Exception as exc:
        logger.error("api_error", endpoint="threat-summary", error=str(exc))
        raise HTTPException(status_code=500, detail="Internal server error") from exc


@app.get("/asset-exposure", dependencies=[Depends(_verify_auth)])
def get_asset_exposure(
    since: date | None = Query(
        None,
        description=(
            "Inclusive lower bound (YYYY-MM-DD) on Uses.last_observed. "
            "Defaults to until - SAGE_ACTIVITY_WINDOW_DAYS."
        ),
    ),
    until: date | None = Query(
        None,
        description=(
            "Inclusive upper bound (YYYY-MM-DD) on Uses.last_observed. Defaults to today (UTC)."
        ),
    ),
) -> list[dict[str, Any]]:
    """Return externally-exposed assets and their reachable TTP counts."""
    config: Config = app.state.config
    since_d, until_d = _resolve_window(config, since, until)
    try:
        return find_asset_exposure(app.state.database, since=since_d, until=until_d)
    except Exception as exc:
        logger.error("api_error", endpoint="asset-exposure", error=str(exc))
        raise HTTPException(status_code=500, detail="Internal server error") from exc


# ---------------------------------------------------------------------------
# IR Feedback: similar incident search
# ---------------------------------------------------------------------------


@app.get("/similar-incidents", dependencies=[Depends(_verify_auth)])
def get_similar_incidents(
    incident_id: str = Query(..., description="Incident STIX ID"),
    top_k: int = Query(5, ge=1, le=20),
    alpha: float = Query(
        0.5,
        ge=0.0,
        le=1.0,
        description="Weight for jaccard_ttp score (remainder goes to transition_coverage)",
    ),
    max_hops: int = Query(2, ge=1, le=4),
) -> list[dict[str, Any]]:
    """Return past incidents most similar to the given incident, ordered by hybrid score.

    hybrid_score = alpha × jaccard_ttp + (1 - alpha) × transition_coverage
    """
    try:
        return find_similar_incidents(
            app.state.database,
            incident_id,
            top_k=top_k,
            alpha=alpha,
            max_hops=max_hops,
        )
    except Exception as exc:
        logger.error("api_error", endpoint="similar-incidents", error=str(exc))
        raise HTTPException(status_code=500, detail="Internal server error") from exc


# ---------------------------------------------------------------------------
# Caldera integration
# ---------------------------------------------------------------------------


@app.post("/caldera/adversary", dependencies=[Depends(_verify_auth)])
def post_caldera_adversary(
    actor_id: str = Query(..., description="ThreatActor STIX ID"),
) -> dict[str, Any]:
    """Generate and sync a Caldera Adversary profile from the actor's TTPs.

    Returns 503 if CALDERA_URL or CALDERA_API_KEY is not configured.
    """
    config: Config = app.state.config
    if not config.caldera_url or not config.caldera_api_key:
        raise HTTPException(status_code=503, detail="CALDERA_URL / CALDERA_API_KEY not configured")

    try:
        ttp_rows = find_actor_ttps(app.state.database, actor_id)
        result = sync_actor_ttps(
            caldera_url=config.caldera_url,
            api_key=config.caldera_api_key,
            actor_stix_id=actor_id,
            ttp_rows=ttp_rows,
        )
        return result
    except Exception as exc:
        logger.error("api_error", endpoint="caldera/adversary", error=str(exc))
        raise HTTPException(status_code=500, detail="Internal server error") from exc


# ---------------------------------------------------------------------------
# Annotation router (POST /api/annotate)
# ---------------------------------------------------------------------------
# Initiative G Decision 10: write endpoint joins POST /api/incidents
# under ``enforce_when_unset=True`` so the auth policy is uniform across
# all write APIs (token unset → 503 instead of silently allowing writes).

app.include_router(
    annotation_router,
    prefix="/api",
    dependencies=[Depends(_verify_auth_write)],
)


# ---------------------------------------------------------------------------
# Incidents router (POST /api/incidents)
# ---------------------------------------------------------------------------
# Auth gate is declared inside the router (router-level Depends would
# stack with the route-level Depends and confuse OpenAPI). The router
# wires its own ``verify_auth(enforce_when_unset=True)``.

app.include_router(
    incidents_router,
    prefix="/api",
)
