"""Direct-API Incident upsert for ``POST /api/incidents`` (Initiative G Phase 1).

Implements the PUT-like full-replace semantics decided in plan §2.1
(Decision 1, last bullet): re-POST with the same ``incident_stix_id``
fully replaces the Incident row AND its child ``IncidentUsesTTP`` rows
inside a single Spanner transaction. The existing
``sage.spanner.upsert.upsert_rows`` path is intentionally not reused
here because it cannot run a delete + upsert + insert in one atomic
transaction (it uses ``database.batch``, which Spanner treats as a
sequence of independent commits with no rollback semantics).

Warnings (plan §2.1 / §6 Phase 1 acceptance):
  * ``kcp_missing`` — emitted when ``kill_chain_phases`` is absent /
    empty. Operator should populate it so downstream code can derive
    ATT&CK kill-chain phase ordering.
  * ``sequence_order_null`` — emitted when any of ``ttps[]`` is missing
    a ``sequence_order``. Downstream ``FollowedBy(ir_feedback)``
    derivation skips rows with NULL sequence_order (SAGE HLD §5.2).

Each warning increments the ``sage_incident_warnings_total{code=...}``
counter — currently emitted as a structured log record because SAGE
does not yet expose a Prometheus endpoint. The log key + label format
matches the planned counter so a future ``prometheus_client.Counter``
adoption is a drop-in (see ``_emit_warning_counter`` below).
"""

from __future__ import annotations

import json
from datetime import UTC, datetime
from typing import Any

import google.cloud.spanner as spanner
import structlog
from google.cloud.spanner_v1.database import Database

from sage.models.incident_request import IncidentRequest

logger = structlog.get_logger(__name__)

# Plan §2.2: ``Incident.source`` discriminator value for rows written
# via the direct API (vs ``ir_feedback`` for OpenCTI-relayed rows).
DIRECT_API_SOURCE = "direct_api"

WARNING_KCP_MISSING = "kcp_missing"
WARNING_SEQUENCE_ORDER_NULL = "sequence_order_null"

# Mirror of ``sage.spanner.upsert._TABLE_COLUMNS["Incident"]`` — kept
# local so this module does not import a private symbol and so a future
# Incident DDL change is surfaced via test failures here as well as in
# the upsert path.
_INCIDENT_COLUMNS: list[str] = [
    "stix_id",
    "name",
    "description",
    "occurred_at",
    "resolved_at",
    "severity",
    "kill_chain_phases",
    "diamond_model",
    "source",
    "stix_modified",
]

_IUT_COLUMNS: list[str] = ["incident_stix_id", "ttp_stix_id", "sequence_order"]


def _emit_warning_counter(code: str, *, incident_stix_id: str) -> None:
    """Stand-in for ``sage_incident_warnings_total{code=...}``.

    Plan §3 requires a Prometheus counter; SAGE has no metrics endpoint
    today so we log with the canonical metric name + label so log-based
    aggregation reproduces the counter, and the eventual swap to a real
    ``prometheus_client.Counter`` is a one-line change.
    """
    logger.warning(
        "sage_incident_warnings_total",
        code=code,
        incident_stix_id=incident_stix_id,
    )


def _collect_warnings(req: IncidentRequest) -> list[dict[str, str]]:
    """Build the response ``warnings[]`` list and emit metric records."""
    warnings: list[dict[str, str]] = []
    if not req.kill_chain_phases:
        warnings.append(
            {
                "code": WARNING_KCP_MISSING,
                "message": (
                    "kill_chain_phases is empty; no IncidentUsesTTP rows "
                    "will be derived from kill chain entries."
                ),
            }
        )
        _emit_warning_counter(WARNING_KCP_MISSING, incident_stix_id=req.incident_stix_id)
    if any(t.sequence_order is None for t in req.ttps):
        warnings.append(
            {
                "code": WARNING_SEQUENCE_ORDER_NULL,
                "message": (
                    "One or more ttps[] entries have sequence_order=null; "
                    "FollowedBy(ir_feedback) derivation will skip those rows."
                ),
            }
        )
        _emit_warning_counter(WARNING_SEQUENCE_ORDER_NULL, incident_stix_id=req.incident_stix_id)
    return warnings


def _build_iut_rows(req: IncidentRequest) -> list[list[Any]]:
    """Materialise ``IncidentUsesTTP`` rows from the request.

    Deduplicates ``(incident_stix_id, ttp_stix_id)`` because that pair is
    the IncidentUsesTTP PK. When both the ``ttps[]`` block and a
    ``kill_chain_phases[].x_ttp_stix_id`` reference the same TTP, the
    ``ttps[]`` entry wins (it carries the explicit sequence_order).
    """
    rows: dict[str, list[Any]] = {}
    for kcp in req.kill_chain_phases:
        if kcp.x_ttp_stix_id is None:
            continue
        rows.setdefault(
            kcp.x_ttp_stix_id,
            [req.incident_stix_id, kcp.x_ttp_stix_id, None],
        )
    for ttp in req.ttps:
        rows[ttp.ttp_stix_id] = [
            req.incident_stix_id,
            ttp.ttp_stix_id,
            ttp.sequence_order,
        ]
    return list(rows.values())


def _serialise_diamond_model(req: IncidentRequest) -> str | None:
    """Persist Diamond Model as JSON (matches ``Incident.diamond_model JSON``)."""
    if req.diamond_model is None:
        return None
    return json.dumps(req.diamond_model, sort_keys=True)


def _build_incident_row(req: IncidentRequest, *, stix_modified: datetime) -> list[Any]:
    """Materialise the ``Incident`` row.

    ``kill_chain_phases`` is persisted as the structured list (Spanner
    ARRAY<STRUCT>) — the column already exists; we just pass the JSON
    serialisation that the Spanner client accepts.
    """
    kcp_payload = (
        json.dumps([p.model_dump() for p in req.kill_chain_phases])
        if req.kill_chain_phases
        else None
    )
    return [
        req.incident_stix_id,
        req.name,
        req.description,
        req.occurred_at,
        None,  # resolved_at — direct API never sets this (plan §2.1)
        req.severity.value,
        kcp_payload,
        _serialise_diamond_model(req),
        DIRECT_API_SOURCE,
        stix_modified,
    ]


def upsert_incident(
    database: Database,
    req: IncidentRequest,
    *,
    now: datetime | None = None,
) -> dict[str, Any]:
    """PUT-like upsert: replace Incident + child IncidentUsesTTP atomically.

    Returns a dict with:
      * ``incident_stix_id`` — echo of the PK.
      * ``accepted`` — always True (validation rejects upstream return
        the request before reaching this helper).
      * ``created`` / ``updated`` — exactly one is True. ``updated``
        reflects pre-existence in the same transaction (no read-then-
        write race because the existence check runs inside the upsert
        transaction).
      * ``warnings`` — per ``_collect_warnings``.
    """
    stix_modified = now or datetime.now(tz=UTC)
    incident_row = _build_incident_row(req, stix_modified=stix_modified)
    iut_rows = _build_iut_rows(req)

    def _txn(transaction) -> bool:  # type: ignore[no-untyped-def]
        existing = list(
            transaction.read(
                table="Incident",
                columns=["stix_id"],
                keyset=spanner.KeySet(keys=[[req.incident_stix_id]]),
            )
        )
        existed = bool(existing)

        transaction.execute_update(
            "DELETE FROM IncidentUsesTTP WHERE incident_stix_id = @id",
            params={"id": req.incident_stix_id},
            param_types={"id": spanner.param_types.STRING},
        )

        transaction.insert_or_update(
            table="Incident",
            columns=_INCIDENT_COLUMNS,
            values=[incident_row],
        )

        if iut_rows:
            transaction.insert_or_update(
                table="IncidentUsesTTP",
                columns=_IUT_COLUMNS,
                values=iut_rows,
            )
        return existed

    existed = database.run_in_transaction(_txn)
    warnings = _collect_warnings(req)
    logger.info(
        "incident_upserted",
        incident_stix_id=req.incident_stix_id,
        existed=existed,
        ttp_row_count=len(iut_rows),
        source=DIRECT_API_SOURCE,
    )
    return {
        "incident_stix_id": req.incident_stix_id,
        "accepted": True,
        "created": not existed,
        "updated": existed,
        "warnings": warnings,
    }
