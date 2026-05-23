"""REST endpoint for the AnnotatesActor edge table (Initiative E Phase 6).

Mirrors the CLI from Phase 5 (``cmd/annotate_actor.py``) over HTTP. The
router is mounted under ``/api`` by :mod:`sage.api.app` with Bearer-token
auth applied at the router level via ``_verify_auth``.

Request handling steps:
  1. FastAPI parses the body into ``AnnotateRequest`` (rejects malformed
     ``actor_stix_id``, unknown ``annotation_type``, missing fields with
     a 422 from the framework).
  2. The endpoint re-validates ``payload`` against the type-specific
     Pydantic model from :mod:`sage.models.annotation` and returns 422
     on field-level failures.
  3. On success, ``write_annotation`` buffers one Spanner mutation and
     the endpoint returns 200 with the row metadata.
"""

from __future__ import annotations

from typing import Any

import structlog
from fastapi import APIRouter, HTTPException, Request
from pydantic import BaseModel, Field, HttpUrl, ValidationError

from sage.models.annotation import AnnotationType, validate_payload
from sage.spanner.annotations import write_annotation

logger = structlog.get_logger(__name__)

router = APIRouter()

# Accept the two STIX object types that map to ThreatActor rows.
_ACTOR_STIX_ID_PATTERN = r"^intrusion-set--[0-9a-f-]{36}$|^threat-actor--[0-9a-f-]{36}$"


class AnnotateRequest(BaseModel):
    """Inbound POST body for ``/api/annotate``."""

    annotator_id: str = Field(..., min_length=1)
    actor_stix_id: str = Field(..., pattern=_ACTOR_STIX_ID_PATTERN)
    annotation_type: AnnotationType
    payload: dict[str, Any]
    evidence_url: HttpUrl | None = None


class AnnotateResponse(BaseModel):
    """Response shape returned on a successful insert."""

    annotator_id: str
    actor_stix_id: str
    annotation_type: AnnotationType
    created_at_pending: bool
    evidence_url: HttpUrl | None = None


@router.post("/annotate", response_model=AnnotateResponse)
def post_annotate(req: AnnotateRequest, request: Request) -> AnnotateResponse:
    """Insert one ``AnnotatesActor`` row after re-validating the payload."""
    try:
        payload_model = validate_payload(req.annotation_type, req.payload)
    except ValidationError as exc:
        raise HTTPException(status_code=422, detail=exc.errors()) from exc

    evidence_url_str = str(req.evidence_url) if req.evidence_url else None

    try:
        result = write_annotation(
            database=request.app.state.database,
            annotator_id=req.annotator_id,
            actor_stix_id=req.actor_stix_id,
            annotation_type=req.annotation_type,
            payload=payload_model,
            evidence_url=evidence_url_str,
        )
    except Exception as exc:
        # The PK is (annotator_id, actor_stix_id, created_at) where
        # created_at is the server-assigned COMMIT_TIMESTAMP. Collisions
        # are effectively impossible within Spanner's microsecond
        # resolution, so the catch below is defensive: any write failure
        # is surfaced as 409 so the rare case is not silently masked as
        # a 500.
        logger.error(
            "annotation_write_failed",
            annotator_id=req.annotator_id,
            actor_stix_id=req.actor_stix_id,
            error=str(exc),
        )
        raise HTTPException(
            status_code=409,
            detail="Failed to write annotation (possible PK conflict)",
        ) from exc

    return AnnotateResponse(
        annotator_id=result["annotator_id"],
        actor_stix_id=result["actor_stix_id"],
        annotation_type=AnnotationType(result["annotation_type"]),
        created_at_pending=result["created_at_pending"],
        evidence_url=req.evidence_url,
    )
