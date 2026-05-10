"""Spanner Graph upsert operations.

Uses INSERT OR UPDATE (insert_or_update mutation) to ensure idempotency.
Re-running the ETL for the same stix_id does not produce duplicate rows.
"""

from __future__ import annotations

from typing import Any

import google.cloud.spanner as spanner
import structlog
from google.cloud.spanner_v1.database import Database

logger = structlog.get_logger(__name__)

# Column definitions per table (order must match the Spanner DDL)
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
    # SAGE 0.5.3: column mapping for the Identity SDO node added in 0.5.0.
    # The 0.5.0 release added the schema and mapper but missed both the
    # worker dispatch (filed in 0.5.3) and this column registration. Order
    # must match `schema/spanner_ddl.sql` exactly — Spanner mutations are
    # positional.
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
    # SAGE 0.5.3: column mapping for the actor → identity edge added in 0.5.0.
    # Same release omission as the Identity table; restored together.
    "ActorTargetsIdentity": [
        "actor_stix_id",
        "identity_stix_id",
        "confidence",
        "description",
        "first_observed",
        "stix_id",
    ],
    # SAGE 0.6.0 / Initiative A — identity → asset access edge.
    # Precedence-aware upsert is handled by ``upsert_has_access`` (below);
    # the ordinary ``upsert_rows`` path overwrites unconditionally and
    # should not be used directly for HasAccess rows in production code.
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
    "PirPrioritizesActor": ["pir_id", "actor_stix_id", "overlap_ratio"],
    "PirPrioritizesTTP": ["pir_id", "ttp_stix_id"],
    "PirWeightsAsset": [
        "pir_id",
        "asset_id",
        "matched_tag",
        "criticality_multiplier",
    ],
}

# Columns that must be written with spanner.COMMIT_TIMESTAMP when a row does
# not provide an explicit value (matches ALLOW_COMMIT_TIMESTAMP in the DDL).
_COMMIT_TIMESTAMP_COLUMNS: dict[str, set[str]] = {
    "PIR": {"last_updated"},
}

# Batch size (Spanner mutation limit is 20,000 mutations/transaction)
_BATCH_SIZE = 500


def upsert_rows(
    database: Database,
    table: str,
    rows: list[dict[str, Any]],
) -> int:
    """Bulk upsert rows into the specified table. Returns the number of rows written."""
    if not rows:
        return 0

    columns = _TABLE_COLUMNS[table]
    ct_cols = _COMMIT_TIMESTAMP_COLUMNS.get(table, set())
    total = 0

    for batch in _chunk(rows, _BATCH_SIZE):
        values = []
        for r in batch:
            row_vals = _row_to_values(r, columns)
            for i, col in enumerate(columns):
                if col in ct_cols and row_vals[i] is None:
                    row_vals[i] = spanner.COMMIT_TIMESTAMP
            values.append(row_vals)
        with database.batch() as b:
            b.insert_or_update(table=table, columns=columns, values=values)
        total += len(batch)

    logger.info("upserted", table=table, count=total)
    return total


def upsert_followed_by(
    database: Database,
    rows: list[dict[str, Any]],
) -> int:
    """Upsert FollowedBy rows, using commit_timestamp for last_calculated."""
    if not rows:
        return 0

    columns = _TABLE_COLUMNS["FollowedBy"]
    total = 0

    for batch in _chunk(rows, _BATCH_SIZE):
        # last_calculated uses ALLOW_COMMIT_TIMESTAMP
        values = []
        for r in batch:
            row_vals = _row_to_values(r, columns)
            # Replace last_calculated (final column) with commit timestamp
            row_vals[-1] = spanner.COMMIT_TIMESTAMP
            values.append(row_vals)

        with database.batch() as b:
            b.insert_or_update(table="FollowedBy", columns=columns, values=values)
        total += len(batch)

    logger.info("upserted_followed_by", count=total)
    return total


# ---------------------------------------------------------------------------
# Queries (read operations)
# ---------------------------------------------------------------------------


def update_pir_criticality(
    database: Database,
    asset_rows: list[dict],
) -> int:
    """Partially update Asset.pir_adjusted_criticality without touching other columns.

    Uses batch.update() to write only the pir_adjusted_criticality column.
    """
    if not asset_rows:
        return 0

    columns = ["id", "pir_adjusted_criticality"]
    total = 0
    for batch_rows in _chunk(asset_rows, _BATCH_SIZE):
        values = [[r["id"], r.get("pir_adjusted_criticality")] for r in batch_rows]
        with database.batch() as b:
            b.update(table="Asset", columns=columns, values=values)
        total += len(batch_rows)

    logger.info("updated_pir_criticality", count=total)
    return total


def upsert_has_access(database: Database, rows: list[dict]) -> int:
    """Precedence-aware upsert for ``HasAccess`` (Initiative A §7.4).

    Rules: ``manual > beacon > trace``. An incoming row writes only when
    its ``source`` has equal-or-higher precedence than the existing
    ``source`` for the same ``(identity_stix_id, asset_id)`` pair.
    Lower-precedence incoming rows are skipped with a structured-log
    entry so analyst manual overrides survive BEACON regeneration
    cycles.

    The function is used by ``cmd/load_identity_assets.py`` (beacon
    source) and the ETL worker (trace source). Manual rows arrive via
    ad-hoc SQL or a future analyst CLI; this path treats them like any
    other upsert with the correct ``source`` value.
    """
    if not rows:
        return 0

    precedence: dict[str, int] = {"trace": 1, "beacon": 2, "manual": 3}

    # Read existing rows for the keys we are about to write so we can
    # apply precedence at the row level. Spanner has no conditional
    # mutation so the read-then-write race is acceptable here — the
    # ETL is a single writer per run.
    keys = [(r["identity_stix_id"], r["asset_id"]) for r in rows]
    keyset = spanner.KeySet(keys=keys)
    existing: dict[tuple[str, str], str] = {}
    with database.snapshot() as snap:
        result = snap.read(
            table="HasAccess",
            columns=["identity_stix_id", "asset_id", "source"],
            keyset=keyset,
        )
        for ident_id, asset_id, src in result:
            existing[(ident_id, asset_id)] = src

    accepted: list[dict] = []
    skipped = 0
    for row in rows:
        incoming_src = row.get("source", "trace")
        incoming_rank = precedence.get(incoming_src, 0)
        key = (row["identity_stix_id"], row["asset_id"])
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
                "has_access_upsert_skipped",
                identity_stix_id=key[0],
                asset_id=key[1],
                existing_source=existing_src,
                incoming_source=incoming_src,
            )

    written = upsert_rows(database, "HasAccess", accepted)
    if skipped:
        logger.info("has_access_upsert_skipped_total", count=skipped)
    return written


def fetch_asset_rows(database: Database) -> list[dict]:
    """Fetch all rows from the Asset table and return them as a list of dicts.

    Called before ETL to supply the asset_rows argument to process_bundle().
    The returned dicts include the id and tags fields required by PIRFilter.build_targets().
    """
    columns = _TABLE_COLUMNS["Asset"]
    rows = []
    with database.snapshot() as snap:
        result = snap.read(table="Asset", columns=columns, keyset=spanner.KeySet(all_=True))
        for r in result:
            rows.append(dict(zip(columns, r)))
    return rows


# ---------------------------------------------------------------------------
# Utilities
# ---------------------------------------------------------------------------


def _row_to_values(row: dict, columns: list[str]) -> list:
    return [row.get(col) for col in columns]


def _chunk(lst: list, size: int):
    for i in range(0, len(lst), size):
        yield lst[i : i + size]
