"""Load BEACON's user_accounts.json into the SAGE Spanner Graph.

Initiative B — SAGE 0.7.0. Reads the artifact emitted by
``BEACON/cmd/generate_user_accounts.py`` and validated by
``TRACE/cmd/validate_user_accounts.py``, then upserts:

- ``UserAccount`` rows (one per ``user_accounts[*]``).
- ``AccountOnAsset`` rows (one per ``account_on_asset[*]``) with
  ``source = "beacon"``.
- ``UserAccountBelongsTo`` rows for entries with non-empty
  ``identity_id`` (linking to Identity).

Identity STIX ids and UserAccount STIX ids are deterministic UUID5
hashes of the BEACON-supplied ids so re-loads idempotently update
the same rows. The Identity namespace is shared with
``load_identity_assets.py`` (same namespace UUID).

Usage:
    export SPANNER_EMULATOR_HOST=localhost:9010  # for local emulator
    uv run python cmd/load_user_accounts.py \\
        --file ../BEACON/output/user_accounts.json
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
from sage.spanner.upsert import (
    upsert_account_on_asset,
    upsert_user_account,
    upsert_user_account_belongs_to,
)

structlog.configure(
    processors=[
        structlog.processors.TimeStamper(fmt="iso"),
        structlog.processors.JSONRenderer(),
    ]
)
logger = structlog.get_logger(__name__)

DEFAULT_FILE = Path(__file__).parent.parent / "input" / "user_accounts.json"

# Same namespace as load_identity_assets — keeps Identity STIX ids
# stable across the two BEACON-side loaders.
_BEACON_IDENTITY_NAMESPACE = uuid.UUID("d41d8cd9-8f00-b204-e980-0998ecf8427e")
# Distinct namespace so user-account ids don't collide with identity ids.
_BEACON_USER_ACCOUNT_NAMESPACE = uuid.UUID("c41d8cd9-8f00-b204-e980-0998ecf8427e")


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
    return f"identity--{uuid.uuid5(_BEACON_IDENTITY_NAMESPACE, beacon_id)}"


def _user_account_stix_id(beacon_id: str) -> str:
    return f"user-account--{uuid.uuid5(_BEACON_USER_ACCOUNT_NAMESPACE, beacon_id)}"


def _normalize_asset_id(value: str) -> str:
    return value if value.startswith("asset-") else f"asset-{value}"


def load_user_accounts(database: spanner.Database, data: dict) -> dict[str, int]:
    """Upsert user-accounts + edges from a parsed user_accounts.json
    payload. Returns ingestion counts.
    """
    user_accounts_in = data.get("user_accounts", []) or []
    edges_in = data.get("account_on_asset", []) or []
    now = _now()
    stats: dict[str, int] = {}

    # --- UserAccount rows ---
    ua_id_map: dict[str, str] = {}
    user_account_rows = []
    belongs_to_rows = []
    for ua in user_accounts_in:
        beacon_id = ua.get("id")
        if not beacon_id:
            continue
        stix_id = _user_account_stix_id(beacon_id)
        ua_id_map[beacon_id] = stix_id
        identity_id_field = ua.get("identity_id") or None
        identity_stix_id = _identity_stix_id(identity_id_field) if identity_id_field else None
        user_account_rows.append(
            {
                "stix_id": stix_id,
                "account_login": ua.get("account_login", beacon_id),
                "display_name": ua.get("display_name") or None,
                "account_type": ua.get("account_type") or None,
                "is_privileged": bool(ua.get("is_privileged", False)),
                "is_service_account": bool(ua.get("is_service_account", False)),
                "identity_stix_id": identity_stix_id,
                "source": "beacon",
                "confidence": 100,
                "stix_modified": now,
            }
        )
        if identity_stix_id is not None:
            belongs_to_rows.append(
                {
                    "identity_stix_id": identity_stix_id,
                    "user_account_stix_id": stix_id,
                    "source": "beacon",
                }
            )
    stats["user_accounts"] = upsert_user_account(database, user_account_rows)
    stats["user_account_belongs_to"] = upsert_user_account_belongs_to(database, belongs_to_rows)

    # --- AccountOnAsset rows ---
    edge_rows = []
    for edge in edges_in:
        beacon_ua_id = edge.get("user_account_id")
        beacon_asset_id = edge.get("asset_id")
        if not beacon_ua_id or not beacon_asset_id:
            continue
        ua_stix_id = ua_id_map.get(beacon_ua_id)
        if ua_stix_id is None:
            logger.warning(
                "account_on_asset_skipped_unknown_user_account",
                user_account_id=beacon_ua_id,
                hint="cross-ref should have been caught by TRACE validate_user_accounts",
            )
            continue
        edge_rows.append(
            {
                "user_account_stix_id": ua_stix_id,
                "asset_id": _normalize_asset_id(beacon_asset_id),
                "first_seen": _to_ts(edge.get("first_seen")),
                "last_seen": _to_ts(edge.get("last_seen")),
                "source": "beacon",
            }
        )
    stats["account_on_asset"] = upsert_account_on_asset(database, edge_rows)

    logger.info("load_user_accounts_complete", **stats)
    return stats


def main() -> None:
    parser = argparse.ArgumentParser(description="Load user_accounts.json into Spanner")
    parser.add_argument(
        "--file",
        type=Path,
        default=DEFAULT_FILE,
        help=f"user_accounts JSON path (default: {DEFAULT_FILE})",
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
        "loading_user_accounts",
        file=str(args.file),
        user_accounts=len(data.get("user_accounts", [])),
        account_on_asset=len(data.get("account_on_asset", [])),
    )
    load_user_accounts(database, data)


if __name__ == "__main__":
    main()
