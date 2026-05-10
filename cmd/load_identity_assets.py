"""Load BEACON's identity_assets.json into the SAGE Spanner Graph.

Initiative A — SAGE 0.6.0. Reads the artifact emitted by
``BEACON/cmd/generate_identity_assets.py`` and validated by
``TRACE/cmd/validate_identity_assets.py``, then upserts:

- ``Identity`` rows (one per ``identities[*]``).
- ``HasAccess`` rows (one per ``has_access[*]``) with
  ``source = "beacon"``. Precedence-aware upsert via
  ``upsert_has_access`` ensures analyst-manual rows survive.

Identity STIX ids are deterministic from the BEACON-supplied id —
``identity--<sha1(id)>`` so re-loads idempotently update the same
row even when BEACON regenerates the artifact.

Usage:
    export SPANNER_EMULATOR_HOST=localhost:9010  # for local emulator
    uv run python cmd/load_identity_assets.py \\
        --file ../BEACON/output/identity_assets.json
"""

from __future__ import annotations

import argparse
import json
import sys
import uuid
from datetime import UTC, datetime
from pathlib import Path

import structlog
from google.cloud import spanner

sys.path.insert(0, str(Path(__file__).parent.parent / "src"))

from sage.config import Config
from sage.spanner.upsert import upsert_has_access, upsert_rows

structlog.configure(
    processors=[
        structlog.processors.TimeStamper(fmt="iso"),
        structlog.processors.JSONRenderer(),
    ]
)
logger = structlog.get_logger(__name__)

DEFAULT_FILE = Path(__file__).parent.parent / "input" / "identity_assets.json"

# Deterministic UUID v5 namespace for BEACON-supplied identity ids — keeps
# Identity.stix_id stable across regenerations of identity_assets.json so
# the precedence-aware upsert recognizes "same identity, beacon-source".
_BEACON_IDENTITY_NAMESPACE = uuid.UUID("d41d8cd9-8f00-b204-e980-0998ecf8427e")


def _now() -> datetime:
    return datetime.now(tz=UTC)


def _to_ts(value: str | None) -> datetime | None:
    if not value:
        return None
    try:
        return datetime.fromisoformat(value).replace(tzinfo=UTC)
    except ValueError:
        return None


def _identity_stix_id(beacon_id: str) -> str:
    """Stable ``identity--<uuid>`` from a BEACON-supplied identifier.

    Hash-based UUID v5 ensures identical input always produces the same
    STIX id, so subsequent loads upsert into the same row.
    """
    return f"identity--{uuid.uuid5(_BEACON_IDENTITY_NAMESPACE, beacon_id)}"


def _normalize_asset_id(value: str) -> str:
    """Mirror BEACON's ``_normalize_asset_id`` so cross-file refs match.

    BEACON's ``assets_generator`` prefixes ids with ``asset-`` when the
    LLM output omits it. ``identity_assets.json`` also passes the LLM's
    raw id through, so this function applies the same normalization
    here for the cross-file lookup.
    """
    return value if value.startswith("asset-") else f"asset-{value}"


def load_identity_assets(database: spanner.Database, data: dict) -> dict[str, int]:
    """Upsert identities + has_access rows from a parsed
    ``identity_assets.json`` payload. Returns ingestion counts.
    """
    identities_in = data.get("identities", []) or []
    has_access_in = data.get("has_access", []) or []
    now = _now()
    stats: dict[str, int] = {}

    # --- Identity rows ---
    id_map: dict[str, str] = {}
    identity_rows = []
    for ident in identities_in:
        beacon_id = ident.get("id")
        if not beacon_id:
            continue
        stix_id = _identity_stix_id(beacon_id)
        id_map[beacon_id] = stix_id
        identity_rows.append(
            {
                "stix_id": stix_id,
                "name": ident.get("name", beacon_id),
                "identity_class": ident.get("identity_class") or None,
                "sectors": list(ident.get("sectors") or []),
                "description": ident.get("description") or None,
                "contact_information": None,
                "roles": list(ident.get("roles") or []),
                "deleted_at": None,
                "stix_modified": now,
            }
        )
    stats["identities"] = upsert_rows(database, "Identity", identity_rows)

    # --- HasAccess rows ---
    has_access_rows = []
    for ha in has_access_in:
        beacon_identity_id = ha.get("identity_id")
        beacon_asset_id = ha.get("asset_id")
        if not beacon_identity_id or not beacon_asset_id:
            continue
        identity_stix_id = id_map.get(beacon_identity_id)
        if identity_stix_id is None:
            logger.warning(
                "has_access_skipped_unknown_identity",
                identity_id=beacon_identity_id,
                hint="cross-ref should have been caught by TRACE validate_identity_assets",
            )
            continue
        has_access_rows.append(
            {
                "identity_stix_id": identity_stix_id,
                "asset_id": _normalize_asset_id(beacon_asset_id),
                "access_level": ha.get("access_level") or None,
                "role": ha.get("role") or None,
                "granted_at": _to_ts(ha.get("granted_at")),
                "revoked_at": _to_ts(ha.get("revoked_at")),
                "source": "beacon",
                "confidence": 100,
                "stix_modified": now,
            }
        )
    stats["has_access"] = upsert_has_access(database, has_access_rows)

    logger.info("load_identity_assets_complete", **stats)
    return stats


def main() -> None:
    parser = argparse.ArgumentParser(description="Load identity_assets.json into Spanner")
    parser.add_argument(
        "--file",
        type=Path,
        default=DEFAULT_FILE,
        help=f"identity_assets JSON path (default: {DEFAULT_FILE})",
    )
    args = parser.parse_args()

    if not args.file.exists():
        logger.error("file_not_found", path=str(args.file))
        sys.exit(1)

    config = Config.from_env()
    spanner_client = spanner.Client(project=config.gcp_project_id)
    instance = spanner_client.instance(config.spanner_instance_id)
    database = instance.database(config.spanner_database_id)

    with args.file.open() as f:
        data = json.load(f)

    logger.info(
        "loading_identity_assets",
        file=str(args.file),
        identities=len(data.get("identities", [])),
        has_access=len(data.get("has_access", [])),
    )
    load_identity_assets(database, data)


if __name__ == "__main__":
    main()
