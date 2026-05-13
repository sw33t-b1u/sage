"""Spanner Graph upsert operations.

Uses INSERT OR UPDATE (insert_or_update mutation) to ensure idempotency.
Re-running the ETL for the same stix_id does not produce duplicate rows.
"""

from __future__ import annotations

from typing import Any

import google.cloud.spanner as spanner
import structlog
from google.cloud.spanner_v1.database import Database

from sage.spanner.constants import effective_priority as _effective_priority

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
    # SAGE 0.9.0 / Initiative C Phase 2: two new columns appended at the end
    # (Spanner ALTER TABLE ADD COLUMN appends; positional order preserved).
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
    # SAGE 0.7.0 / Initiative B — User-account SCO and its edges.
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
    "PirPrioritizesActor": ["pir_id", "actor_stix_id", "overlap_ratio"],
    "PirPrioritizesTTP": ["pir_id", "ttp_stix_id"],
    "PirWeightsAsset": [
        "pir_id",
        "asset_id",
        "matched_tag",
        "criticality_multiplier",
    ],
    # SAGE 0.9.0 / Initiative C Phase 2 — PIR → impersonation-target cascade.
    # derived_at uses ALLOW_COMMIT_TIMESTAMP (see upsert_pir_prioritizes_impersonation_target).
    "PirPrioritizesImpersonationTarget": [
        "pir_id",
        "identity_stix_id",
        "source_stix_id",
        "effective_priority",
        "derived_at",
    ],
    # SAGE 0.8.0 / Initiative C Phase 1 — Attribution & Impersonation edges.
    # source column enables precedence-aware upsert (manual > beacon > trace)
    # consistent with HasAccess, UserAccount, AccountOnAsset.
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

# Columns that must be written with spanner.COMMIT_TIMESTAMP when a row does
# not provide an explicit value (matches ALLOW_COMMIT_TIMESTAMP in the DDL).
_COMMIT_TIMESTAMP_COLUMNS: dict[str, set[str]] = {
    "PIR": {"last_updated"},
    "PirPrioritizesImpersonationTarget": {"derived_at"},
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


def _precedence_upsert(
    database: Database,
    table: str,
    rows: list[dict],
    key_columns: list[str],
) -> int:
    """Generic precedence-aware upsert.

    Common implementation behind ``upsert_has_access`` (Initiative A) and
    Initiative B's ``upsert_user_account`` / ``upsert_account_on_asset`` /
    ``upsert_user_account_belongs_to``. Reads the existing ``source``
    column for each row's PK, accepts the incoming row only when its
    source is equal-or-higher precedence than the existing one.

    ``key_columns`` lists the PK columns in the same order as the table
    DDL.
    """
    if not rows:
        return 0
    precedence: dict[str, int] = {"trace": 1, "beacon": 2, "manual": 3}
    keys = [tuple(r[col] for col in key_columns) for r in rows]
    keyset = spanner.KeySet(keys=keys)
    existing: dict[tuple, str] = {}
    with database.snapshot() as snap:
        result = snap.read(
            table=table,
            columns=[*key_columns, "source"],
            keyset=keyset,
        )
        for record in result:
            key = tuple(record[: len(key_columns)])
            existing[key] = record[len(key_columns)]

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
    written = upsert_rows(database, table, accepted)
    if skipped:
        logger.info(f"{table.lower()}_upsert_skipped_total", count=skipped)
    return written


def upsert_user_account(database: Database, rows: list[dict]) -> int:
    """Precedence-aware UserAccount upsert (Initiative B §7.3)."""
    return _precedence_upsert(database, "UserAccount", rows, ["stix_id"])


def upsert_account_on_asset(database: Database, rows: list[dict]) -> int:
    """Precedence-aware AccountOnAsset upsert (Initiative B §7.3)."""
    return _precedence_upsert(
        database, "AccountOnAsset", rows, ["user_account_stix_id", "asset_id"]
    )


def upsert_user_account_belongs_to(database: Database, rows: list[dict]) -> int:
    """Precedence-aware UserAccountBelongsTo upsert (Initiative B §7.3)."""
    return _precedence_upsert(
        database,
        "UserAccountBelongsTo",
        rows,
        ["identity_stix_id", "user_account_stix_id"],
    )


def upsert_attributed_to_actor(database: Database, rows: list[dict]) -> int:
    """Precedence-aware upsert for AttributedToActor (Initiative C §6.4)."""
    return _precedence_upsert(
        database, "AttributedToActor", rows, ["source_stix_id", "target_actor_stix_id"]
    )


def upsert_attributed_to_identity(database: Database, rows: list[dict]) -> int:
    """Precedence-aware upsert for AttributedToIdentity (Initiative C §6.4)."""
    return _precedence_upsert(
        database, "AttributedToIdentity", rows, ["source_stix_id", "identity_stix_id"]
    )


def upsert_impersonates_identity(database: Database, rows: list[dict]) -> int:
    """Precedence-aware upsert for ImpersonatesIdentity (Initiative C §6.4).

    effective_priority is already embedded in each row by the mapper; this
    function delegates to the generic precedence upsert without recomputing.
    Use recompute_effective_priority_for_identity when an Identity's roles change.
    """
    return _precedence_upsert(
        database, "ImpersonatesIdentity", rows, ["source_stix_id", "identity_stix_id"]
    )


def recompute_effective_priority_for_identity(
    database: Database,
    identity_stix_id: str,
    identity_roles: list[str],
    is_high_value_impersonation_target: bool = False,
) -> int:
    """Recompute effective_priority for all ImpersonatesIdentity rows that target this identity.

    Phase 2 extension: `is_high_value_impersonation_target` flag takes precedence
    over role-tag intersection when computing the multiplier. Default False preserves
    backward compat with existing call sites (BEACON 0.12.x / Phase 1 cascade).

    Called from the Identity upsert path whenever a row's roles or flag changes.
    Walks ImpersonatesIdentity WHERE identity_stix_id = ? and rewrites
    effective_priority. Returns the number of rows updated.
    """
    # Fetch all impersonates rows for this identity
    existing_rows: list[dict] = []
    with database.snapshot() as snap:
        result = snap.execute_sql(
            "SELECT source_stix_id, confidence FROM ImpersonatesIdentity"
            " WHERE identity_stix_id = @id",
            params={"id": identity_stix_id},
            param_types={"id": spanner.param_types.STRING},
        )
        for src_id, conf in result:
            existing_rows.append({"source_stix_id": src_id, "confidence": conf})

    if not existing_rows:
        return 0

    columns = ["source_stix_id", "identity_stix_id", "effective_priority"]
    values = [
        [
            row["source_stix_id"],
            identity_stix_id,
            _effective_priority(
                row["confidence"],
                identity_roles,
                is_high_value_impersonation_target,
            ),
        ]
        for row in existing_rows
    ]

    with database.batch() as b:
        b.update(table="ImpersonatesIdentity", columns=columns, values=values)

    count = len(existing_rows)
    logger.info(
        "effective_priority_recomputed",
        identity_stix_id=identity_stix_id,
        affected_row_count=count,
        is_high_value_impersonation_target=is_high_value_impersonation_target,
    )
    return count


def upsert_pir_prioritizes_impersonation_target(
    database: Database,
    rows: list[dict],
) -> int:
    """Upsert PirPrioritizesImpersonationTarget rows (Initiative C Phase 2).

    Uses commit_timestamp for derived_at. Called from the ETL worker after
    ImpersonatesIdentity upsert and from the recompute cascade in
    load_identity_assets.py when an Identity flag changes.
    """
    if not rows:
        return 0

    columns = _TABLE_COLUMNS["PirPrioritizesImpersonationTarget"]
    total = 0

    for batch in _chunk(rows, _BATCH_SIZE):
        values = []
        for r in batch:
            row_vals = _row_to_values(r, columns)
            # Replace derived_at with commit timestamp
            derived_at_idx = columns.index("derived_at")
            row_vals[derived_at_idx] = spanner.COMMIT_TIMESTAMP
            values.append(row_vals)
        with database.batch() as b:
            b.insert_or_update(
                table="PirPrioritizesImpersonationTarget",
                columns=columns,
                values=values,
            )
        total += len(batch)

    logger.info("upserted_pir_prioritizes_impersonation_target", count=total)
    return total


def derive_pir_prioritizes_impersonation_target_for_identity(
    database: Database,
    identity_stix_id: str,
) -> int:
    """Derive (or re-derive) PirPrioritizesImpersonationTarget rows for one identity.

    Called from the recompute cascade (load_identity_assets.py) when an Identity
    row's `is_high_value_impersonation_target` flag becomes True. Queries:
      1. ImpersonatesIdentity for all actors that impersonate this identity.
      2. ThreatActor.tags for each such actor.
      3. All PIR rows with their threat_actor_tags.
    Then derives and upserts the intersection rows.

    Returns the number of rows written (0 when there are no ImpersonatesIdentity
    rows for the identity or no PIR tag intersection).
    """
    # Step 1: read ImpersonatesIdentity rows for this identity
    imp_rows: list[dict] = []
    with database.snapshot() as snap:
        result = snap.execute_sql(
            "SELECT source_stix_id, effective_priority FROM ImpersonatesIdentity"
            " WHERE identity_stix_id = @id",
            params={"id": identity_stix_id},
            param_types={"id": spanner.param_types.STRING},
        )
        for src_id, eff_pri in result:
            imp_rows.append({"source_stix_id": src_id, "effective_priority": eff_pri})

    if not imp_rows:
        return 0

    # Step 2: read ThreatActor.tags for each actor
    actor_ids = [r["source_stix_id"] for r in imp_rows]
    actor_tags_map: dict[str, list[str]] = {}
    with database.snapshot() as snap:
        result = snap.read(
            table="ThreatActor",
            columns=["stix_id", "tags"],
            keyset=spanner.KeySet(keys=[[aid] for aid in actor_ids]),
        )
        for stix_id, tags in result:
            actor_tags_map[stix_id] = list(tags or [])

    # Step 3: read PIR rows
    pir_rows: list[dict] = []
    with database.snapshot() as snap:
        result = snap.read(
            table="PIR",
            columns=["pir_id", "threat_actor_tags"],
            keyset=spanner.KeySet(all_=True),
        )
        for pir_id, threat_actor_tags in result:
            pir_rows.append({"pir_id": pir_id, "threat_actor_tags": list(threat_actor_tags or [])})

    if not pir_rows:
        return 0

    # Derive intersection rows
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

    return upsert_pir_prioritizes_impersonation_target(database, ppt_rows)


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
