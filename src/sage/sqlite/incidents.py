"""Direct-API Incident upsert + read helpers — mirror of sage.spanner.incidents.

Every public function has the same name, signature, and return shape as
its sage.spanner.incidents counterpart, but takes an
``sqlite3.Connection`` instead of a Spanner ``Database``.

PUT-like full-replace semantics: re-POST with the same
``incident_stix_id`` fully replaces the Incident row AND its child
``IncidentUsesTTP`` rows inside a single SQLite transaction (the
existence check, child delete, and inserts share one implicit
transaction committed at the end; any failure rolls everything back).

Warnings:
  * ``kcp_missing`` — emitted when ``kill_chain_phases`` is absent /
    empty. Operator should populate it so downstream code can derive
    ATT&CK kill-chain phase ordering.
  * ``sequence_order_null`` — emitted when any of ``ttps[]`` is missing
    a ``sequence_order``. Downstream ``FollowedBy(ir_feedback)``
    derivation skips rows with NULL sequence_order.

Each warning increments the ``sage_incident_warnings_total{code=...}``
counter — emitted as a structured log record (same stand-in as the
Spanner module) because SAGE does not expose a Prometheus endpoint.

Dialect translation (Decision D-3):
  * TIMESTAMP values are stored as ISO 8601 UTC TEXT; the read side
    parses them back to ``datetime`` so return shapes match the Spanner
    client's materialisation.
  * ``kill_chain_phases ARRAY<STRING(64)>`` -> JSON-array TEXT, decoded
    to ``list[str]`` on read.
  * ``IN UNNEST(@ids)`` -> a dynamically expanded ``IN (?, ?, ...)``
    placeholder list, bounded by the caller's ``limit`` exactly like the
    Spanner bind array.
"""

from __future__ import annotations

import json
import sqlite3
from datetime import UTC, date, datetime, time, timedelta
from typing import Any

import structlog

from sage.models.incident_request import IncidentRequest

logger = structlog.get_logger(__name__)

# ``Incident.source`` discriminator value for rows written via the
# direct API (vs ``ir_feedback`` for OpenCTI-relayed rows).
DIRECT_API_SOURCE = "direct_api"

WARNING_KCP_MISSING = "kcp_missing"
WARNING_SEQUENCE_ORDER_NULL = "sequence_order_null"

# Mirror of ``sage.sqlite.upsert._TABLE_COLUMNS["Incident"]`` — kept
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

    Logs with the canonical metric name + label so log-based aggregation
    reproduces the counter, and the eventual swap to a real
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
    """Persist Diamond Model as a JSON TEXT column value."""
    if req.diamond_model is None:
        return None
    return json.dumps(req.diamond_model, sort_keys=True)


def _build_incident_row(req: IncidentRequest, *, stix_modified: datetime) -> list[Any]:
    """Materialise the ``Incident`` row (SQLite TEXT encodings).

    ``kill_chain_phases`` is stored as a JSON array TEXT — one
    ``phase_name`` per entry, matching the upsert layer's ARRAY -> JSON
    encoding. Each ``phase_name`` is truncated to 64 chars for parity
    with the Spanner ``ARRAY<STRING(64)>`` column-length bound.
    Timestamps are stored as ISO 8601 UTC TEXT.
    """
    kcp_payload = (
        json.dumps([p.phase_name[:64] for p in req.kill_chain_phases])
        if req.kill_chain_phases
        else None
    )
    return [
        req.incident_stix_id,
        req.name,
        req.description,
        req.occurred_at.isoformat(),
        None,  # resolved_at — direct API never sets this
        req.severity.value,
        kcp_payload,
        _serialise_diamond_model(req),
        DIRECT_API_SOURCE,
        stix_modified.isoformat(),
    ]


def upsert_incident(
    conn: sqlite3.Connection,
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
        reflects pre-existence checked in the same transaction (the
        single-writer operating model means no concurrent writer can
        race the check).
      * ``warnings`` — per ``_collect_warnings``.
    """
    stix_modified = now or datetime.now(tz=UTC)
    incident_row = _build_incident_row(req, stix_modified=stix_modified)
    iut_rows = _build_iut_rows(req)

    col_list = ", ".join(_INCIDENT_COLUMNS)
    placeholders = ", ".join("?" for _ in _INCIDENT_COLUMNS)
    set_clause = ", ".join(f"{c} = excluded.{c}" for c in _INCIDENT_COLUMNS if c != "stix_id")
    incident_sql = (
        f"INSERT INTO Incident ({col_list}) VALUES ({placeholders}) "  # noqa: S608
        f"ON CONFLICT(stix_id) DO UPDATE SET {set_clause}"
    )

    try:
        cur = conn.execute(
            "SELECT 1 FROM Incident WHERE stix_id = ?",
            (req.incident_stix_id,),
        )
        existed = cur.fetchone() is not None

        conn.execute(
            "DELETE FROM IncidentUsesTTP WHERE incident_stix_id = ?",
            (req.incident_stix_id,),
        )
        conn.execute(incident_sql, incident_row)
        if iut_rows:
            conn.executemany(
                "INSERT INTO IncidentUsesTTP (incident_stix_id, ttp_stix_id, sequence_order)"
                " VALUES (?, ?, ?)",
                iut_rows,
            )
        conn.commit()
    except Exception:
        conn.rollback()
        raise

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
# Read side
# ---------------------------------------------------------------------------


def _to_timestamp_bounds(since: date, until: date) -> tuple[str, str]:
    """Convert ``date`` bounds into ISO 8601 UTC TEXT bind values.

    ``since`` snaps to 00:00:00 (inclusive lower bound). ``until`` snaps
    to 00:00:00 on the next day (exclusive upper bound) so the SQL
    ``occurred_at < :until`` semantics treat ``since == until`` as a
    full calendar day — matches the convention of
    ``sage.sqlite.query._to_window_bounds``. The Spanner version returns
    ``datetime`` objects; SQLite compares TEXT, so the canonical
    ``+00:00`` ISO strings are returned instead.
    """
    since_dt = datetime.combine(since, time.min, tzinfo=UTC)
    until_dt = datetime.combine(until, time.min, tzinfo=UTC) + timedelta(days=1)
    return since_dt.isoformat(), until_dt.isoformat()


def _decode_diamond_model(raw: Any) -> dict[str, Any] | None:
    """Best-effort decode of the ``Incident.diamond_model`` JSON TEXT column.

    The column stores a raw JSON string (D-3: Spanner ``JSON`` -> TEXT);
    a ``dict`` is also tolerated for symmetry with the Spanner reader.
    An unparseable payload falls back to ``None`` rather than poisoning
    the response.
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
    """Normalise the JSON-array TEXT column to ``list[str]``.

    Empty / NULL columns become ``[]`` so the response shape is stable.
    Non-string entries are coerced via ``str()`` defensively (the write
    paths only store strings, but a stray non-string would otherwise
    crash JSON serialisation downstream).
    """
    if not raw:
        return []
    if isinstance(raw, str):
        try:
            raw = json.loads(raw)
        except (json.JSONDecodeError, ValueError):
            logger.warning("kill_chain_phases_unparseable", raw_preview=raw[:120])
            return []
    if isinstance(raw, list):
        return [str(item) for item in raw]
    logger.warning("kill_chain_phases_unexpected_type", value_type=type(raw).__name__)
    return []


def _parse_ts(raw: Any) -> datetime | None:
    """Parse an ISO 8601 TEXT timestamp back to ``datetime`` (None-safe)."""
    if raw is None or isinstance(raw, datetime):
        return raw
    return datetime.fromisoformat(raw)


def read_incidents(
    conn: sqlite3.Connection,
    *,
    since: date,
    until: date,
    actor_stix_id: str | None,
    limit: int,
) -> list[dict[str, Any]]:
    """Return incidents whose ``occurred_at`` falls in ``[since, until]``.

    Filter scope: ``since``, ``until``, ``actor_stix_id`` — no severity /
    source / asset filters. Pagination is ``limit`` only (no offset /
    cursor); default at the route layer.

    ``actor_stix_id`` joins through ``IncidentUsesTTP → Uses`` so the
    incident is only included when at least one of its TTPs was used
    by the given actor. ``EXISTS`` keeps the main row count
    deterministic (one row per incident regardless of TTP fan-out).

    Each returned dict carries the IUT child rows under ``ttps`` and
    the decoded JSON column under ``diamond_model`` so the API layer can
    construct the response without a second round-trip. SQLite reads
    are strongly consistent within a connection — POST followed by GET
    on the same ``incident_stix_id`` reflects the upserted state
    immediately.
    """
    since_s, until_s = _to_timestamp_bounds(since, until)

    where_clauses = ["i.occurred_at >= :since", "i.occurred_at < :until"]
    params: dict[str, Any] = {
        "since": since_s,
        "until": until_s,
        "limit": limit,
    }
    if actor_stix_id is not None:
        where_clauses.append(
            "EXISTS ("
            "  SELECT 1"
            "  FROM IncidentUsesTTP iut2"
            "  JOIN Uses u2 ON u2.ttp_stix_id = iut2.ttp_stix_id"
            "  WHERE iut2.incident_stix_id = i.stix_id"
            "    AND u2.actor_stix_id = :actor_stix_id"
            ")"
        )
        params["actor_stix_id"] = actor_stix_id

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
    LIMIT :limit
    """

    incidents: list[dict[str, Any]] = [
        {
            "incident_stix_id": rec["incident_stix_id"],
            "name": rec["name"],
            "description": rec["description"],
            "occurred_at": _parse_ts(rec["occurred_at"]),
            "severity": rec["severity"],
            "source": rec["source"],
            "kill_chain_phases": _decode_kill_chain_phases(rec["kill_chain_phases"]),
            "diamond_model": _decode_diamond_model(rec["diamond_model"]),
            "ttps": [],
        }
        for rec in conn.execute(sql, params)
    ]

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
    # The Spanner version binds IN UNNEST(@ids); SQLite expands the
    # placeholder list dynamically — still bounded by ``limit`` so the
    # largest query is 100 ids.
    ids = [inc["incident_stix_id"] for inc in incidents]
    id_placeholders = ", ".join("?" for _ in ids)
    iut_sql = (
        "SELECT incident_stix_id, ttp_stix_id, sequence_order"
        " FROM IncidentUsesTTP"
        f" WHERE incident_stix_id IN ({id_placeholders})"  # noqa: S608
        " ORDER BY incident_stix_id, COALESCE(sequence_order, 9999), ttp_stix_id"
    )

    by_id: dict[str, list[dict[str, Any]]] = {iid: [] for iid in ids}
    for rec in conn.execute(iut_sql, ids):
        by_id[rec["incident_stix_id"]].append(
            {"ttp_stix_id": rec["ttp_stix_id"], "sequence_order": rec["sequence_order"]}
        )

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
