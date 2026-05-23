"""Pydantic models for AnnotatesActor payloads (Initiative E Phase 5).

The ``AnnotatesActor`` edge table (introduced in SAGE 0.10.0) stores
analyst-supplied annotations against ``ThreatActor`` rows. Each annotation
carries an ``annotation_type`` from a controlled vocabulary plus a typed
payload serialised as JSON. The per-type Pydantic models below enforce
schema integrity *before* the Spanner write so invalid payloads are
rejected at the CLI / API boundary rather than persisted.
"""

from __future__ import annotations

from enum import StrEnum

from pydantic import BaseModel, Field, HttpUrl


class AnnotationType(StrEnum):
    """Controlled vocabulary for AnnotatesActor.annotation_type."""

    FALSE_POSITIVE = "false-positive"
    SCOPE_EXCLUSION = "scope-exclusion"
    ANALYST_NOTE = "analyst-note"
    CONFIDENCE_OVERRIDE = "confidence-override"


class FalsePositivePayload(BaseModel):
    """Analyst rejects the actor as relevant to this org."""

    reason: str = Field(..., min_length=1)
    evidence_url: HttpUrl | None = None


class ScopeExclusionPayload(BaseModel):
    """Actor is relevant but explicitly out-of-scope for this org."""

    reason: str = Field(..., min_length=1)
    evidence_url: HttpUrl | None = None


class AnalystNotePayload(BaseModel):
    """Free-text comment; no scoring effect."""

    note: str = Field(..., min_length=1)


class ConfidenceOverridePayload(BaseModel):
    """Analyst replaces the computed Likelihood with a manual value."""

    original_likelihood: float = Field(..., ge=0.0, le=1.0)
    overridden_likelihood: float = Field(..., ge=0.0, le=1.0)
    reason: str = Field(..., min_length=1)


_PAYLOAD_MODELS: dict[AnnotationType, type[BaseModel]] = {
    AnnotationType.FALSE_POSITIVE: FalsePositivePayload,
    AnnotationType.SCOPE_EXCLUSION: ScopeExclusionPayload,
    AnnotationType.ANALYST_NOTE: AnalystNotePayload,
    AnnotationType.CONFIDENCE_OVERRIDE: ConfidenceOverridePayload,
}


def validate_payload(
    annotation_type: AnnotationType,
    payload_dict: dict,
) -> BaseModel:
    """Dispatch ``payload_dict`` to the model that matches ``annotation_type``.

    Raises ``pydantic.ValidationError`` on field-level mismatch and
    ``KeyError`` when called with an annotation_type that has no
    registered payload model (which is a programming error — the
    AnnotationType enum and ``_PAYLOAD_MODELS`` must stay in sync).
    """
    model_cls = _PAYLOAD_MODELS[annotation_type]
    return model_cls.model_validate(payload_dict)
