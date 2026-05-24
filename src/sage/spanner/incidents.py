"""Direct-API Incident upsert + read helpers (Initiative G Phases 1 / 2).

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
from datetime import UTC, date, datetime, time, timedelta
from typing import Any

import google.cloud.spanner as spanner
import structlog
from google.cloud.spanner_v1 import param_types
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

    ``kill_chain_phases`` is declared ``ARRAY<STRING(64)>`` in
    ``schema/spanner_ddl.sql`` (line 74), so the column accepts a plain
    Python ``list[str]`` — one ``phase_name`` per entry, matching the
    convention already used by the OpenCTI relay path in
    ``sage.stix.mapper.map_incident``. ``kill_chain_name`` and the
    optional ``x_ttp_stix_id`` metadata are NOT lost: they flow into
    ``IncidentUsesTTP`` rows via :func:`_build_iut_rows`.

    A previous revision serialised ``kill_chain_phases`` as a JSON
    string — that satisfied the unit mocks but would crash a real
    Spanner mutation with a STRING → ARRAY<STRING> type mismatch.
    Each ``phase_name`` is truncated to 64 chars as a defensive bound
    so a stray long string never trips the column-length check at
    commit time.
    """
    kcp_payload = (
        [p.phase_name[:64] for p in req.kill_chain_phases] if req.kill_chain_phases else None
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


# ---------------------------------------------------------------------------
# Read side (Initiative G Phase 2)
# ---------------------------------------------------------------------------


def _to_timestamp_bounds(since: date, until: date) -> tuple[datetime, datetime]:
    """Convert ``date`` bounds into TIMESTAMP bind values.

    ``since`` snaps to 00:00:00 (inclusive lower bound). ``until`` snaps
    to 00:00:00 on the next day (exclusive upper bound) so the SQL
    ``occurred_at < @until`` semantics treat ``since == until`` as a
    full calendar day — matches the convention adopted by
    ``sage.spanner.query._to_window_bounds`` for the existing
    ``/actor-ttps`` and ``/asset-exposure`` endpoints (Phase 7).
    """
    since_dt = datetime.combine(since, time.min)
    until_dt = datetime.combine(until, time.min) + timedelta(days=1)
    return since_dt, until_dt


def _decode_diamond_model(raw: Any) -> dict[str, Any] | None:
    """Best-effort decode of the ``Incident.diamond_model`` JSON column.

    Spanner's Python client returns JSON columns as either a ``dict``
    (newer ``google-cloud-spanner`` versions) or a raw JSON string
    (older versions, or when the row was written as a literal string).
    Both shapes are tolerated; an unparseable payload falls back to
    ``None`` rather than poisoning the response.
    """
    if raw is None:
        return None
    if isinstance(raw, dict):
        return raw
    if isinstance(raw, str):
        try:
            decoded = json.loads(raw)
        except (json.JSONDecodeError, ValueError):
            logger.warning("diamond_model_unparseable", raw_preview=raw[:120])
            return None
        if isinstance(decoded, dict):
            return decoded
        logger.warning("diamond_model_not_object", decoded_type=type(decoded).__name__)
        return None
    logger.warning("diamond_model_unexpected_type", value_type=type(raw).__name__)
    return None


def _decode_kill_chain_phases(raw: Any) -> list[str]:
    """Normalise the Spanner ``ARRAY<STRING(64)>`` column to ``list[str]``.

    Empty / NULL columns become ``[]`` so the response shape is stable
    even for OpenCTI-relayed rows that wrote ``NULL``. Non-string
    entries are coerced via ``str()`` defensively (mapper.py and the
    direct-API path both write strings, but a stray non-string would
    otherwise crash JSON serialisation downstream).
    """
    if not raw:
        return []
    if isinstance(raw, list):
        return [str(item) for item in raw]
    logger.warning("kill_chain_phases_unexpected_type", value_type=type(raw).__name__)
    return []


def read_incidents(
    database: Database,
    *,
    since: date,
    until: date,
    actor_stix_id: str | None,
    limit: int,
) -> list[dict[str, Any]]:
    """Return incidents whose ``occurred_at`` falls in ``[since, until]``.

    Plan §2.4 filter scope: ``since``, ``until``, ``actor_stix_id`` —
    no severity / source / asset filters in G. Pagination is
    ``limit`` only (no offset / cursor); default at the route layer.

    ``actor_stix_id`` joins through ``IncidentUsesTTP → Uses`` so the
    incident is only included when at least one of its TTPs was used
    by the given actor. Spanner ``EXISTS`` keeps the main row count
    deterministic (one row per incident regardless of TTP fan-out).

    Each returned dict carries the IUT child rows under ``ttps`` and
    the JSON column under ``diamond_model`` so the API layer can
    construct the response without a second round-trip. Spanner
    ``database.snapshot()`` provides strong reads by default — POST
    followed by GET on the same ``incident_stix_id`` reflects the
    upserted state immediately (plan §2.4 ``read consistency: strong``).
    """
    since_dt, until_dt = _to_timestamp_bounds(since, until)

    where_clauses = ["i.occurred_at >= @since", "i.occurred_at < @until"]
    params: dict[str, Any] = {
        "since": since_dt,
        "until": until_dt,
        "limit": limit,
    }
    ptypes: dict[str, Any] = {
        "since": param_types.TIMESTAMP,
        "until": param_types.TIMESTAMP,
        "limit": param_types.INT64,
    }

    if actor_stix_id is not None:
        where_clauses.append(
            "EXISTS ("
            "  SELECT 1"
            "  FROM IncidentUsesTTP iut2"
            "  JOIN Uses u2 ON u2.ttp_stix_id = iut2.ttp_stix_id"
            "  WHERE iut2.incident_stix_id = i.stix_id"
            "    AND u2.actor_stix_id = @actor_stix_id"
            ")"
        )
        params["actor_stix_id"] = actor_stix_id
        ptypes["actor_stix_id"] = param_types.STRING

    where_sql = " AND ".join(where_clauses)
    sql = f"""
    SELECT
      i.stix_id           AS incident_stix_id,
      i.name              AS name,
      i.description       AS description,
      i.occurred_at       AS occurred_at,
      i.severity          AS severity,
      i.source            AS source,
      i.kill_chain_phases AS kill_chain_phases,
      i.diamond_model     AS diamond_model
    FROM Incident i
    WHERE {where_sql}
    ORDER BY i.occurred_at DESC, i.stix_id ASC
    LIMIT @limit
    """

    incidents: list[dict[str, Any]] = []
    with database.snapshot() as snap:
        for row in snap.execute_sql(sql, params=params, param_types=ptypes):
            incidents.append(
                {
                    "incident_stix_id": row[0],
                    "name": row[1],
                    "description": row[2],
                    "occurred_at": row[3],
                    "severity": row[4],
                    "source": row[5],
                    "kill_chain_phases": _decode_kill_chain_phases(row[6]),
                    "diamond_model": _decode_diamond_model(row[7]),
                    "ttps": [],
                }
            )

    if not incidents:
        logger.info(
            "read_incidents",
            count=0,
            since=since.isoformat(),
            until=until.isoformat(),
            actor_stix_id=actor_stix_id,
        )
        return incidents

    # Fetch IUT rows for the returned incidents in one round-trip.
    # Using IN UNNEST(@ids) keeps the bind set bounded by ``limit`` so
    # the largest query is 100 ids.
    ids = [inc["incident_stix_id"] for inc in incidents]
    iut_sql = """
    SELECT incident_stix_id, ttp_stix_id, sequence_order
    FROM IncidentUsesTTP
    WHERE incident_stix_id IN UNNEST(@ids)
    ORDER BY incident_stix_id, sequence_order NULLS LAST, ttp_stix_id
    """
    iut_params = {"ids": ids}
    iut_ptypes = {"ids": param_types.Array(param_types.STRING)}

    by_id: dict[str, list[dict[str, Any]]] = {iid: [] for iid in ids}
    with database.snapshot() as snap:
        for row in snap.execute_sql(iut_sql, params=iut_params, param_types=iut_ptypes):
            by_id[row[0]].append({"ttp_stix_id": row[1], "sequence_order": row[2]})

    for inc in incidents:
        inc["ttps"] = by_id.get(inc["incident_stix_id"], [])

    logger.info(
        "read_incidents",
        count=len(incidents),
        since=since.isoformat(),
        until=until.isoformat(),
        actor_stix_id=actor_stix_id,
    )
    return incidents
