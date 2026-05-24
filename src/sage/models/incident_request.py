"""Pydantic request model for ``POST /api/incidents`` (Initiative G Phase 1).

The endpoint accepts direct IR-team submissions that bypass OpenCTI's
24h polling latency (plan §2.1). Required vs optional fields follow the
plan exactly:

* **Required** — ``incident_stix_id``, ``name``, ``occurred_at``,
  ``severity`` (controlled vocab: low/medium/high/critical).
* **Optional** — ``kill_chain_phases[]``, ``ttps[]`` (with
  ``sequence_order``), ``diamond_model`` (4-key dict), ``iocs[]``,
  ``description``.

The Diamond Model is enforced as a 4-key dict (adversary / capability /
infrastructure / victim) per Caltagirone, Pendergast & Betz (2013) —
see ``ref/diamondmodel.md`` and plan §5. Quadrant **values** are free
text (may be empty strings) so operators can register an incident with
partial knowledge; **keys** must all be present so the column always
round-trips with a complete shape.
"""

from __future__ import annotations

from datetime import datetime
from enum import StrEnum

from pydantic import BaseModel, ConfigDict, Field, field_validator

INCIDENT_STIX_ID_PATTERN = (
    r"^incident--[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$"
)
TTP_STIX_ID_PATTERN = (
    r"^attack-pattern--[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$"
)

DIAMOND_MODEL_KEYS: tuple[str, ...] = (
    "adversary",
    "capability",
    "infrastructure",
    "victim",
)


class IncidentSeverity(StrEnum):
    """Controlled vocabulary for ``Incident.severity`` (plan §2.1)."""

    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"


class KillChainPhase(BaseModel):
    """One ATT&CK / Lockheed-style kill-chain phase entry.

    ``x_ttp_stix_id`` is an optional STIX custom property — when set
    the upsert helper derives an ``IncidentUsesTTP`` row from this entry
    too (plan §2.1 calls out that ``kill_chain_phases`` carries
    ``x_ttp_stix_id`` per entry).
    """

    model_config = ConfigDict(extra="forbid")
    kill_chain_name: str = Field(..., min_length=1)
    phase_name: str = Field(..., min_length=1)
    x_ttp_stix_id: str | None = Field(default=None, pattern=TTP_STIX_ID_PATTERN)


class IncidentTTP(BaseModel):
    """One IR-attested TTP referenced by the incident.

    ``sequence_order`` is **optional** — when ``None`` the upsert path
    emits a ``sequence_order_null`` warning and the row is still
    persisted but ``FollowedBy(ir_feedback)`` derivation is skipped
    downstream per HLD §5.2.
    """

    model_config = ConfigDict(extra="forbid")
    ttp_stix_id: str = Field(..., pattern=TTP_STIX_ID_PATTERN)
    sequence_order: int | None = Field(default=None, ge=0)


class IncidentRequest(BaseModel):
    """Body of ``POST /api/incidents``."""

    model_config = ConfigDict(extra="forbid")

    incident_stix_id: str = Field(..., pattern=INCIDENT_STIX_ID_PATTERN)
    name: str = Field(..., min_length=1)
    occurred_at: datetime
    severity: IncidentSeverity
    description: str | None = None
    kill_chain_phases: list[KillChainPhase] = Field(default_factory=list)
    ttps: list[IncidentTTP] = Field(default_factory=list)
    diamond_model: dict[str, str] | None = None
    iocs: list[str] = Field(default_factory=list)

    @field_validator("diamond_model")
    @classmethod
    def _validate_diamond_model(cls, value: dict[str, str] | None) -> dict[str, str] | None:
        if value is None:
            return None
        missing = [k for k in DIAMOND_MODEL_KEYS if k not in value]
        if missing:
            raise ValueError(
                f"diamond_model must contain all four quadrants (missing: {', '.join(missing)})"
            )
        extra = [k for k in value if k not in DIAMOND_MODEL_KEYS]
        if extra:
            raise ValueError("diamond_model contains unknown keys: " + ", ".join(extra))
        return value
