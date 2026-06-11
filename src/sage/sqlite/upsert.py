"""SQLite upsert operations — mirror of sage.spanner.upsert.

Every public function here has the same name, signature, and return type
as its sage.spanner.upsert counterpart, but takes an ``sqlite3.Connection``
instead of a Spanner ``Database``. The sage.db dispatch layer routes calls
to the right implementation by backend.

Dialect translation (Decision D-3):
  * Spanner's INSERT OR UPDATE mutation -> ``INSERT INTO t (cols)
    VALUES (...) ON CONFLICT(<pk cols>) DO UPDATE SET <non-pk>=excluded....``
  * ARRAY<...> columns are JSON-encoded with ``json.dumps`` on write.
  * ALLOW_COMMIT_TIMESTAMP columns receive ``datetime.now(UTC).isoformat()``
    when the row provides no explicit value.

The ``_TABLE_COLUMNS`` registry and the precedence rules are kept in lock
step with sage.spanner.upsert so reviewers can diff the two side by side.
"""

from __future__ import annotations

import json
import sqlite3
from datetime import UTC, datetime
from typing import Any

import structlog

from sage.spanner.constants import effective_priority as _effective_priority

logger = structlog.get_logger(__name__)

# Column definitions per table (order mirrors sage.spanner.upsert / the DDL).
_TABLE_COLUMNS: dict[str, list[str]] = {
    "ThreatActor": [
        "stix_id",
        "stix_type",
        "name",
        "aliases",
        "sophistication",
        "motivation",
        "tags",
        "first_seen",
        "last_seen",
        "stix_modified",
    ],
    "TTP": [
        "stix_id",
        "attack_technique_id",
        "tactic",
        "name",
        "description",
        "platforms",
        "detection_difficulty",
        "stix_modified",
    ],
    "Vulnerability": [
        "stix_id",
        "cve_id",
        "description",
        "cvss_score",
        "epss_score",
        "affected_platforms",
        "published_date",
        "stix_modified",
    ],
    "MalwareTool": [
        "stix_id",
        "stix_type",
        "name",
        "description",
        "capabilities",
        "stix_modified",
    ],
    "Observable": [
        "stix_id",
        "obs_type",
        "value",
        "confidence",
        "tlp",
        "first_seen",
        "last_seen",
        "stix_modified",
    ],
    "Incident": [
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
    ],
    "Identity": [
        "stix_id",
        "name",
        "identity_class",
        "sectors",
        "description",
        "contact_information",
        "roles",
        "deleted_at",
        "stix_modified",
        "is_high_value_impersonation_target",
        "impersonation_risk_factors",
    ],
    "Asset": [
        "id",
        "name",
        "asset_type",
        "environment",
        "criticality",
        "pir_adjusted_criticality",
        "owner",
        "network_segment",
        "network_cidr",
        "network_zone",
        "exposed_to_internet",
        "tags",
        "last_updated",
    ],
    "SecurityControl": ["id", "name", "control_type", "coverage"],
    "Uses": [
        "actor_stix_id",
        "ttp_stix_id",
        "confidence",
        "first_observed",
        "last_observed",
        "stix_id",
    ],
    "UsesTool": [
        "actor_stix_id",
        "tool_stix_id",
        "confidence",
        "first_observed",
        "last_observed",
        "stix_id",
    ],
    "Exploits": ["ttp_stix_id", "vuln_stix_id", "stix_id"],
    "MalwareUsesTTP": [
        "malware_stix_id",
        "ttp_stix_id",
        "confidence",
        "first_observed",
        "last_observed",
        "stix_id",
    ],
    "Targets": ["actor_stix_id", "asset_id", "confidence", "source"],
    "TargetsAsset": ["ttp_stix_id", "asset_id", "match_reason"],
    "HasVulnerability": [
        "asset_id",
        "vuln_stix_id",
        "remediation_status",
        "detected_at",
    ],
    "ConnectedTo": [
        "src_asset_id",
        "dst_asset_id",
        "protocol",
        "port",
        "direction",
        "allowed",
    ],
    "ProtectedBy": ["asset_id", "control_id"],
    "IndicatesTTP": ["observable_stix_id", "ttp_stix_id", "confidence", "stix_id"],
    "IndicatesActor": ["observable_stix_id", "actor_stix_id", "confidence", "stix_id"],
    "ActorTargetsIdentity": [
        "actor_stix_id",
        "identity_stix_id",
        "confidence",
        "description",
        "first_observed",
        "stix_id",
    ],
    "HasAccess": [
        "identity_stix_id",
        "asset_id",
        "access_level",
        "role",
        "granted_at",
        "revoked_at",
        "source",
        "confidence",
        "stix_modified",
    ],
    "UserAccount": [
        "stix_id",
        "account_login",
        "display_name",
        "account_type",
        "is_privileged",
        "is_service_account",
        "identity_stix_id",
        "source",
        "confidence",
        "stix_modified",
    ],
    "AccountOnAsset": [
        "user_account_stix_id",
        "asset_id",
        "first_seen",
        "last_seen",
        "source",
    ],
    "UserAccountBelongsTo": [
        "identity_stix_id",
        "user_account_stix_id",
        "source",
    ],
    "FollowedBy": [
        "src_ttp_stix_id",
        "dst_ttp_stix_id",
        "source",
        "weight",
        "actor_stix_id",
        "evidence_stix_ids",
        "last_calculated",
    ],
    "IncidentUsesTTP": ["incident_stix_id", "ttp_stix_id", "sequence_order"],
    "PIR": [
        "pir_id",
        "intelligence_level",
        "organizational_scope",
        "decision_point",
        "description",
        "rationale",
        "recommended_action",
        "threat_actor_tags",
        "risk_composite",
        "valid_from",
        "valid_until",
        "last_updated",
    ],
    "PirPrioritizesActor": [
        "pir_id",
        "actor_stix_id",
        "overlap_ratio",
        "likelihood",
        "rationale_json",
    ],
    "AnnotatesActor": [
        "annotator_id",
        "actor_stix_id",
        "annotation_type",
        "payload_json",
        "created_at",
        "evidence_url",
    ],
    "PirPrioritizesTTP": ["pir_id", "ttp_stix_id"],
    "PirWeightsAsset": [
        "pir_id",
        "asset_id",
        "matched_tag",
        "criticality_multiplier",
    ],
    "PirPrioritizesImpersonationTarget": [
        "pir_id",
        "identity_stix_id",
        "source_stix_id",
        "effective_priority",
        "derived_at",
    ],
    "AttributedToActor": [
        "source_stix_id",
        "target_actor_stix_id",
        "source_type",
        "target_type",
        "confidence",
        "description",
        "first_observed",
        "stix_id",
        "source",
    ],
    "AttributedToIdentity": [
        "source_stix_id",
        "identity_stix_id",
        "source_type",
        "confidence",
        "description",
        "first_observed",
        "stix_id",
        "source",
    ],
    "ImpersonatesIdentity": [
        "source_stix_id",
        "identity_stix_id",
        "source_type",
        "confidence",
        "description",
        "first_observed",
        "stix_id",
        "effective_priority",
        "source",
    ],
}

# Primary-key columns per table (drives the ON CONFLICT target). Mirrors the
# PRIMARY KEY clauses in schema/sqlite_ddl.sql / schema/spanner_ddl.sql.
_PRIMARY_KEYS: dict[str, list[str]] = {
    "ThreatActor": ["stix_id"],
    "TTP": ["stix_id"],
    "Vulnerability": ["stix_id"],
    "MalwareTool": ["stix_id"],
    "Observable": ["stix_id"],
    "Incident": ["stix_id"],
    "Identity": ["stix_id"],
    "SecurityControl": ["id"],
    "Asset": ["id"],
    "Uses": ["actor_stix_id", "ttp_stix_id"],
    "UsesTool": ["actor_stix_id", "tool_stix_id"],
    "Exploits": ["ttp_stix_id", "vuln_stix_id"],
    "MalwareUsesTTP": ["malware_stix_id", "ttp_stix_id"],
    "Targets": ["actor_stix_id", "asset_id"],
    "TargetsAsset": ["ttp_stix_id", "asset_id"],
    "HasVulnerability": ["asset_id", "vuln_stix_id"],
    "ConnectedTo": ["src_asset_id", "dst_asset_id"],
    "ProtectedBy": ["asset_id", "control_id"],
    "IndicatesTTP": ["observable_stix_id", "ttp_stix_id"],
    "IndicatesActor": ["observable_stix_id", "actor_stix_id"],
    "ActorTargetsIdentity": ["actor_stix_id", "identity_stix_id"],
    "HasAccess": ["identity_stix_id", "asset_id"],
    "UserAccount": ["stix_id"],
    "AccountOnAsset": ["user_account_stix_id", "asset_id"],
    "UserAccountBelongsTo": ["identity_stix_id", "user_account_stix_id"],
    "FollowedBy": ["src_ttp_stix_id", "dst_ttp_stix_id", "source"],
    "IncidentUsesTTP": ["incident_stix_id", "ttp_stix_id"],
    "PIR": ["pir_id"],
    "PirPrioritizesActor": ["pir_id", "actor_stix_id"],
    "AnnotatesActor": ["annotator_id", "actor_stix_id", "created_at"],
    "PirPrioritizesTTP": ["pir_id", "ttp_stix_id"],
    "PirWeightsAsset": ["pir_id", "asset_id"],
    "PirPrioritizesImpersonationTarget": ["pir_id", "identity_stix_id", "source_stix_id"],
    "AttributedToActor": ["source_stix_id", "target_actor_stix_id"],
    "AttributedToIdentity": ["source_stix_id", "identity_stix_id"],
    "ImpersonatesIdentity": ["source_stix_id", "identity_stix_id"],
}

# ARRAY<...> columns (Spanner) -> JSON-encoded TEXT (SQLite). Read-side
# decoding (json.loads) lives in the query layer (Phase 2).
_JSON_ARRAY_COLUMNS: dict[str, set[str]] = {
    "ThreatActor": {"aliases", "tags"},
    "TTP": {"platforms"},
    "Vulnerability": {"affected_platforms"},
    "MalwareTool": {"capabilities"},
    "Observable": set(),
    "Incident": {"kill_chain_phases"},
    "Identity": {"sectors", "roles", "impersonation_risk_factors"},
    "Asset": {"tags"},
    "SecurityControl": {"coverage"},
    "FollowedBy": {"evidence_stix_ids"},
    "PIR": {"threat_actor_tags"},
}

# Columns that take datetime.now(UTC).isoformat() when the row provides no
# value (the SQLite analogue of Spanner's ALLOW_COMMIT_TIMESTAMP / COMMIT_TIMESTAMP).
_COMMIT_TIMESTAMP_COLUMNS: dict[str, set[str]] = {
    "PIR": {"last_updated"},
    "PirPrioritizesImpersonationTarget": {"derived_at"},
}

# NOT NULL DEFAULT (...) columns from the DDL. Unlike Spanner (which applies
# defaults for NULL on its upsert mutation), SQLite rejects an explicit NULL even
# when a column DEFAULT exists — because we always list every column in the
# INSERT. So the upsert layer substitutes the DDL default when the row omits
# the value, preserving Spanner-parity semantics. Booleans use 0/1.
_NOT_NULL_DEFAULTS: dict[str, dict[str, Any]] = {
    "Incident": {"source": "ir_feedback"},
    "Asset": {"criticality": 5.0, "exposed_to_internet": 0},
    "FollowedBy": {"weight": 0.0},
    "HasVulnerability": {"remediation_status": "open"},
    "ConnectedTo": {"direction": "bidirectional", "allowed": 1},
    "UserAccount": {"is_privileged": 0, "is_service_account": 0},
    "AttributedToActor": {"source": "trace"},
    "AttributedToIdentity": {"source": "trace"},
    "ImpersonatesIdentity": {"source": "trace"},
}

# Batch size for executemany chunking (kept for parity with the Spanner path).
_BATCH_SIZE = 500


def upsert_rows(
    conn: sqlite3.Connection,
    table: str,
    rows: list[dict[str, Any]],
) -> int:
    """Bulk upsert rows into the specified table. Returns the number of rows written."""
    if not rows:
        return 0

    columns = _TABLE_COLUMNS[table]
    ct_cols = _COMMIT_TIMESTAMP_COLUMNS.get(table, set())
    json_cols = _JSON_ARRAY_COLUMNS.get(table, set())
    defaults = _NOT_NULL_DEFAULTS.get(table, {})
    sql = _build_upsert_sql(table, columns)
    total = 0

    for batch in _chunk(rows, _BATCH_SIZE):
        params = []
        for r in batch:
            row_vals = _row_to_values(r, columns, json_cols, ct_cols, defaults)
            params.append(row_vals)
        conn.executemany(sql, params)
        total += len(batch)

    conn.commit()
    logger.info("upserted", table=table, count=total)
    return total


def upsert_followed_by(
    conn: sqlite3.Connection,
    rows: list[dict[str, Any]],
) -> int:
    """Upsert FollowedBy rows, using the current UTC timestamp for last_calculated."""
    if not rows:
        return 0

    table = "FollowedBy"
    columns = _TABLE_COLUMNS[table]
    json_cols = _JSON_ARRAY_COLUMNS.get(table, set())
    defaults = _NOT_NULL_DEFAULTS.get(table, {})
    sql = _build_upsert_sql(table, columns)
    now = datetime.now(UTC).isoformat()
    total = 0

    for batch in _chunk(rows, _BATCH_SIZE):
        params = []
        for r in batch:
            row_vals = _row_to_values(r, columns, json_cols, set(), defaults)
            # last_calculated (final column) is always set to commit timestamp.
            row_vals[-1] = now
            params.append(row_vals)
        conn.executemany(sql, params)
        total += len(batch)

    conn.commit()
    logger.info("upserted_followed_by", count=total)
    return total


def update_pir_criticality(
    conn: sqlite3.Connection,
    asset_rows: list[dict],
) -> int:
    """Partially update Asset.pir_adjusted_criticality without touching other columns."""
    if not asset_rows:
        return 0

    total = 0
    for batch_rows in _chunk(asset_rows, _BATCH_SIZE):
        params = [(r.get("pir_adjusted_criticality"), r["id"]) for r in batch_rows]
        conn.executemany(
            "UPDATE Asset SET pir_adjusted_criticality = ? WHERE id = ?",
            params,
        )
        total += len(batch_rows)

    conn.commit()
    logger.info("updated_pir_criticality", count=total)
    return total


def upsert_has_access(conn: sqlite3.Connection, rows: list[dict]) -> int:
    """Precedence-aware upsert for ``HasAccess`` (manual > beacon > trace)."""
    if not rows:
        return 0
    return _precedence_upsert(conn, "HasAccess", rows, ["identity_stix_id", "asset_id"])


def _precedence_upsert(
    conn: sqlite3.Connection,
    table: str,
    rows: list[dict],
    key_columns: list[str],
) -> int:
    """Generic precedence-aware upsert (manual > beacon > trace).

    Reads the existing ``source`` for each row's PK and accepts the incoming
    row only when its source is equal-or-higher precedence. Lower-precedence
    rows are skipped with a structured-log entry, so analyst manual overrides
    survive BEACON regeneration.
    """
    if not rows:
        return 0
    precedence: dict[str, int] = {"trace": 1, "beacon": 2, "manual": 3}

    placeholders = " AND ".join(f"{col} = ?" for col in key_columns)
    select_cols = ", ".join([*key_columns, "source"])
    existing: dict[tuple, str] = {}
    for row in rows:
        key = tuple(row[col] for col in key_columns)
        cur = conn.execute(
            f"SELECT {select_cols} FROM {table} WHERE {placeholders}",  # noqa: S608
            key,
        )
        record = cur.fetchone()
        if record is not None:
            existing[key] = record["source"]

    accepted: list[dict] = []
    skipped = 0
    for row in rows:
        key = tuple(row[col] for col in key_columns)
        incoming_rank = precedence.get(row.get("source", "trace"), 0)
        existing_src = existing.get(key)
        if existing_src is None:
            accepted.append(row)
            continue
        existing_rank = precedence.get(existing_src, 0)
        if incoming_rank >= existing_rank:
            accepted.append(row)
        else:
            skipped += 1
            logger.info(
                f"{table.lower()}_upsert_skipped",
                key=key,
                existing_source=existing_src,
                incoming_source=row.get("source"),
            )
    written = upsert_rows(conn, table, accepted)
    if skipped:
        logger.info(f"{table.lower()}_upsert_skipped_total", count=skipped)
    return written


def upsert_user_account(conn: sqlite3.Connection, rows: list[dict]) -> int:
    """Precedence-aware UserAccount upsert."""
    return _precedence_upsert(conn, "UserAccount", rows, ["stix_id"])


def upsert_account_on_asset(conn: sqlite3.Connection, rows: list[dict]) -> int:
    """Precedence-aware AccountOnAsset upsert."""
    return _precedence_upsert(conn, "AccountOnAsset", rows, ["user_account_stix_id", "asset_id"])


def upsert_user_account_belongs_to(conn: sqlite3.Connection, rows: list[dict]) -> int:
    """Precedence-aware UserAccountBelongsTo upsert."""
    return _precedence_upsert(
        conn,
        "UserAccountBelongsTo",
        rows,
        ["identity_stix_id", "user_account_stix_id"],
    )


def upsert_attributed_to_actor(conn: sqlite3.Connection, rows: list[dict]) -> int:
    """Precedence-aware upsert for AttributedToActor."""
    return _precedence_upsert(
        conn, "AttributedToActor", rows, ["source_stix_id", "target_actor_stix_id"]
    )


def upsert_attributed_to_identity(conn: sqlite3.Connection, rows: list[dict]) -> int:
    """Precedence-aware upsert for AttributedToIdentity."""
    return _precedence_upsert(
        conn, "AttributedToIdentity", rows, ["source_stix_id", "identity_stix_id"]
    )


def upsert_impersonates_identity(conn: sqlite3.Connection, rows: list[dict]) -> int:
    """Precedence-aware upsert for ImpersonatesIdentity.

    effective_priority is already embedded in each row by the mapper; this
    function delegates to the generic precedence upsert without recomputing.
    Use recompute_effective_priority_for_identity when an Identity's flag changes.
    """
    return _precedence_upsert(
        conn, "ImpersonatesIdentity", rows, ["source_stix_id", "identity_stix_id"]
    )


def recompute_effective_priority_for_identity(
    conn: sqlite3.Connection,
    identity_stix_id: str,
    is_high_value_impersonation_target: bool,
) -> int:
    """Recompute ``effective_priority`` for all ImpersonatesIdentity rows targeting this identity.

    Returns the number of rows updated.
    """
    cur = conn.execute(
        "SELECT source_stix_id, confidence FROM ImpersonatesIdentity WHERE identity_stix_id = ?",
        (identity_stix_id,),
    )
    existing_rows = [
        {"source_stix_id": rec["source_stix_id"], "confidence": rec["confidence"]}
        for rec in cur.fetchall()
    ]

    if not existing_rows:
        return 0

    params = [
        (
            _effective_priority(row["confidence"], is_high_value_impersonation_target),
            row["source_stix_id"],
            identity_stix_id,
        )
        for row in existing_rows
    ]
    conn.executemany(
        "UPDATE ImpersonatesIdentity SET effective_priority = ?"
        " WHERE source_stix_id = ? AND identity_stix_id = ?",
        params,
    )
    conn.commit()

    count = len(existing_rows)
    logger.info(
        "effective_priority_recomputed",
        identity_stix_id=identity_stix_id,
        affected_row_count=count,
        is_high_value_impersonation_target=is_high_value_impersonation_target,
    )
    return count


def upsert_pir_prioritizes_impersonation_target(
    conn: sqlite3.Connection,
    rows: list[dict],
) -> int:
    """Upsert PirPrioritizesImpersonationTarget rows.

    derived_at is always overwritten with the current UTC timestamp,
    matching the Spanner implementation (which substitutes COMMIT_TIMESTAMP
    unconditionally for that column).
    """
    if not rows:
        return 0
    stamped = [{**r, "derived_at": None} for r in rows]
    return upsert_rows(conn, "PirPrioritizesImpersonationTarget", stamped)


def derive_pir_prioritizes_impersonation_target_for_identity(
    conn: sqlite3.Connection,
    identity_stix_id: str,
) -> int:
    """Derive (or re-derive) PirPrioritizesImpersonationTarget rows for one identity.

    Returns the number of rows written (0 when there are no ImpersonatesIdentity
    rows for the identity or no PIR tag intersection).
    """
    cur = conn.execute(
        "SELECT source_stix_id, effective_priority FROM ImpersonatesIdentity"
        " WHERE identity_stix_id = ?",
        (identity_stix_id,),
    )
    imp_rows = [
        {"source_stix_id": rec["source_stix_id"], "effective_priority": rec["effective_priority"]}
        for rec in cur.fetchall()
    ]
    if not imp_rows:
        return 0

    actor_ids = [r["source_stix_id"] for r in imp_rows]
    actor_tags_map: dict[str, list[str]] = {}
    placeholders = ",".join("?" for _ in actor_ids)
    cur = conn.execute(
        f"SELECT stix_id, tags FROM ThreatActor WHERE stix_id IN ({placeholders})",  # noqa: S608
        actor_ids,
    )
    for rec in cur.fetchall():
        actor_tags_map[rec["stix_id"]] = _decode_json_array(rec["tags"])

    pir_rows: list[dict] = []
    cur = conn.execute("SELECT pir_id, threat_actor_tags FROM PIR")
    for rec in cur.fetchall():
        pir_rows.append(
            {
                "pir_id": rec["pir_id"],
                "threat_actor_tags": _decode_json_array(rec["threat_actor_tags"]),
            }
        )
    if not pir_rows:
        return 0

    ppt_rows: list[dict] = []
    for imp in imp_rows:
        actor_id = imp["source_stix_id"]
        actor_tags = set(actor_tags_map.get(actor_id, []))
        if not actor_tags:
            continue
        for pir in pir_rows:
            pir_tags = set(pir["threat_actor_tags"])
            if actor_tags & pir_tags:
                ppt_rows.append(
                    {
                        "pir_id": pir["pir_id"],
                        "identity_stix_id": identity_stix_id,
                        "source_stix_id": actor_id,
                        "effective_priority": imp["effective_priority"],
                    }
                )

    return upsert_pir_prioritizes_impersonation_target(conn, ppt_rows)


def fetch_asset_rows(conn: sqlite3.Connection) -> list[dict]:
    """Fetch all Asset rows as a list of dicts (tags decoded to list[str])."""
    columns = _TABLE_COLUMNS["Asset"]
    cur = conn.execute(f"SELECT {', '.join(columns)} FROM Asset")  # noqa: S608
    rows = []
    for rec in cur.fetchall():
        row = dict(zip(columns, rec, strict=True))
        row["tags"] = _decode_json_array(row["tags"])
        rows.append(row)
    return rows


# ---------------------------------------------------------------------------
# Utilities
# ---------------------------------------------------------------------------


def _build_upsert_sql(table: str, columns: list[str]) -> str:
    """Build ``INSERT ... ON CONFLICT(pk) DO UPDATE SET ...`` for *table*."""
    pk_cols = _PRIMARY_KEYS[table]
    col_list = ", ".join(columns)
    placeholders = ", ".join("?" for _ in columns)
    conflict_target = ", ".join(pk_cols)
    non_pk = [c for c in columns if c not in pk_cols]
    if non_pk:
        set_clause = ", ".join(f"{c} = excluded.{c}" for c in non_pk)
        do_update = f"DO UPDATE SET {set_clause}"
    else:
        # All columns are part of the PK (e.g. ProtectedBy, PirPrioritizesTTP);
        # an upsert with nothing to update becomes DO NOTHING.
        do_update = "DO NOTHING"
    return (
        f"INSERT INTO {table} ({col_list}) VALUES ({placeholders}) "  # noqa: S608
        f"ON CONFLICT({conflict_target}) {do_update}"
    )


def _row_to_values(
    row: dict,
    columns: list[str],
    json_cols: set[str],
    ct_cols: set[str],
    defaults: dict[str, Any],
) -> list:
    """Build the positional value list for *columns*.

    Encodes ARRAY columns as JSON, fills commit-timestamp columns and
    NOT NULL DEFAULT columns when the row omits them (Spanner applies DDL
    defaults server-side on its upsert mutation; SQLite needs the substitution
    here because every column is listed explicitly in the INSERT).
    """
    now: str | None = None
    values: list = []
    for col in columns:
        val = row.get(col)
        if col in json_cols and val is not None:
            val = json.dumps(list(val))
        elif val is None and col in ct_cols:
            if now is None:
                now = datetime.now(UTC).isoformat()
            val = now
        elif val is None and col in defaults:
            val = defaults[col]
        values.append(val)
    return values


def _decode_json_array(raw: Any) -> list:
    """Decode a JSON-array TEXT column back to a Python list ([] for NULL)."""
    if raw is None:
        return []
    if isinstance(raw, list):
        return raw
    return json.loads(raw)


def _chunk(lst: list, size: int):
    for i in range(0, len(lst), size):
        yield lst[i : i + size]
