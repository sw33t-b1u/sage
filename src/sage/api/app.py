"""FastAPI Analysis API — Cloud Run entry point.

Exposes Spanner query results as a REST API.
The Spanner Database instance is initialised at startup and stored in
app.state so that all endpoints can share a single connection.

Authentication:
  Set SAGE_API_AUTH_TOKEN to require a Bearer token on every request.
  When unset, a warning is logged at startup but no auth is enforced.

Environment variables (loaded via Config.from_env()):
  PROJECT_ID, SPANNER_INSTANCE, SPANNER_DB, etc.
"""

from __future__ import annotations

import secrets
from contextlib import asynccontextmanager
from typing import Any

import structlog
from fastapi import Depends, FastAPI, HTTPException, Query, Request
from google.cloud import spanner

from sage.analysis.similarity import find_similar_incidents
from sage.caldera.client import sync_actor_ttps
from sage.config import Config
from sage.spanner.query import (
    find_actor_ttps,
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


async def _verify_auth(request: Request) -> None:
    """Verify Bearer token if SAGE_API_AUTH_TOKEN is configured."""
    config: Config = request.app.state.config
    if not config.api_auth_token:
        return
    auth_header = request.headers.get("Authorization", "")
    if not auth_header.startswith("Bearer "):
        raise HTTPException(status_code=401, detail="Missing or invalid Authorization header")
    token = auth_header[7:]
    if not secrets.compare_digest(token, config.api_auth_token):
        raise HTTPException(status_code=403, detail="Invalid API token")


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


@app.get("/actor-ttps", dependencies=[Depends(_verify_auth)])
def get_actor_ttps(
    actor_id: str = Query(..., description="ThreatActor STIX ID"),
) -> list[dict[str, Any]]:
    """Return the TTP attack flow for the specified actor, ordered by FollowedBy weight."""
    try:
        return find_actor_ttps(app.state.database, actor_id)
    except Exception as exc:
        logger.error("api_error", endpoint="actor-ttps", error=str(exc))
        raise HTTPException(status_code=500, detail="Internal server error") from exc


@app.get("/asset-exposure", dependencies=[Depends(_verify_auth)])
def get_asset_exposure() -> list[dict[str, Any]]:
    """Return externally-exposed assets and their reachable TTP counts."""
    try:
        return find_asset_exposure(app.state.database)
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
