"""Pydantic models for the SAGE Analysis API responses.

Currently holds the ``ThreatSummaryResponse`` shape returned by the
Initiative F Phase 8 ``GET /threat-summary`` endpoint. Earlier endpoints
return raw ``list[dict]`` payloads — they were authored before Pydantic
response models were standardised in the API layer.
"""

from __future__ import annotations

from datetime import date, datetime
from typing import Any

from pydantic import BaseModel, ConfigDict, Field


class PrioritizedActorEntry(BaseModel):
    """One actor row in ``ThreatSummaryResponse.prioritized_actors``.

    ``rationale`` carries Initiative D's persisted score breakdown
    (intent/capability/opportunity factors + free-text text), inline-
    expanded from the ``rationale_json`` STRING(MAX) column. ``None``
    when the PIR row was written before Initiative D wired the
    rationale column.
    """

    model_config = ConfigDict(extra="forbid")
    actor_stix_id: str
    actor_name: str | None = None
    pir_id: str
    overlap_ratio: float | None = None
    likelihood: float | None = None
    rationale: dict[str, Any] | None = None


class AttackPathEntry(BaseModel):
    """One row from ``find_attack_paths``."""

    model_config = ConfigDict(extra="forbid")
    actor_stix_id: str
    actor_name: str | None = None
    ttp_stix_id: str
    ttp_name: str | None = None
    confidence: int | None = None


class ChokePointEntry(BaseModel):
    """One row from ``find_choke_points``."""

    model_config = ConfigDict(extra="forbid")
    asset_id: str
    asset_name: str | None = None
    pir_adjusted_criticality: float | None = None
    targeting_actor_count: int
    choke_score: float | None = None


class VulnerabilityEntry(BaseModel):
    """One row joining ``HasVulnerability`` × ``Vulnerability``."""

    model_config = ConfigDict(extra="forbid")
    vuln_stix_id: str
    cve_id: str | None = None
    description: str | None = None
    cvss_score: float | None = None
    epss_score: float | None = None
    published_date: datetime | None = None


class IncidentEntry(BaseModel):
    """One ``Incident`` row anchored on ``occurred_at`` (NOT ``resolved_at``).

    The exclusion of ``resolved_at`` is plan §10 Q2's authoritative
    decision: ``occurred_at`` is the attack-time anchor; ``resolved_at``
    represents IR-closure time and is intentionally not used by the
    summary endpoint.
    """

    model_config = ConfigDict(extra="forbid")
    incident_stix_id: str
    incident_name: str | None = None
    occurred_at: datetime | None = None
    severity: str | None = None
    source: str | None = None


class ThreatSummaryWindow(BaseModel):
    """The resolved [since, until] window applied to this response.

    Returned echo so callers can confirm which window was used when
    defaults filled in via ``activity_window_days``.
    """

    model_config = ConfigDict(extra="forbid")
    since: date
    until: date


class ThreatSummaryResponse(BaseModel):
    """Verbose single-asset threat summary.

    Five top-N sections; per-section default cap is 5 (aligned with
    Initiative E's top-5 prioritized_actors view) and each is bounded
    by the ``?limit=N`` query param (1-100). Sections that produce no
    rows return ``[]``; the endpoint never 404s on a known asset.
    """

    model_config = ConfigDict(extra="forbid")
    asset_id: str
    window: ThreatSummaryWindow
    limit: int = Field(ge=1, le=100)
    prioritized_actors: list[PrioritizedActorEntry]
    attack_paths: list[AttackPathEntry]
    choke_points: list[ChokePointEntry]
    vulnerabilities: list[VulnerabilityEntry]
    incidents: list[IncidentEntry]
