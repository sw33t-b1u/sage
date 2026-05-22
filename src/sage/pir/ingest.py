"""Ingest BEACON 0.15.0 actor_triage entries into PirPrioritizesActor.

Phase 6 follow-ups honored (from Phase 5 review):
  1. Sub-factors missing from ScoreComponent → default 0.0 (not raised).
  2. rationale_json serialises the FULL Rationale: text + intent_factors +
     capability_factors + opportunity_factors.
  3. likelihood stored as raw float [0,1]; no rescale.
  4. data_quality assumed present (no defensive None handling needed).
"""

from __future__ import annotations

import json
from typing import Any

import structlog
from google.cloud.spanner_v1.database import Database

from sage.spanner.upsert import upsert_rows

logger = structlog.get_logger(__name__)


def ingest_prioritized_actors(
    database: Database,
    pir_id: str,
    prioritized_actors: list[dict[str, Any]],
) -> int:
    """Write prioritized_actors[] entries from a BEACON PIR to PirPrioritizesActor.

    Each entry is upserted as one PirPrioritizesActor row:
      - actor_stix_id  = entry["actor_id"]  (BEACON slug or STIX id)
      - likelihood     = raw float [0,1], no rescale
      - rationale_json = JSON-serialized Rationale (text + 3 factor dicts)
      - overlap_ratio  = NULL  (not applicable for triage-sourced rows)

    Missing sub-factors in ScoreComponent default to 0.0 (graceful fallback;
    never raise). Empty or missing rationale fields default to {} / "".

    Args:
        database: Spanner database instance.
        pir_id: PIR identifier (pir_output.json[*].pir_id).
        prioritized_actors: list from pir_output.json[*].prioritized_actors.

    Returns:
        Number of rows written to PirPrioritizesActor.
    """
    rows: list[dict[str, Any]] = []

    for entry in prioritized_actors:
        actor_id: str = entry.get("actor_id") or ""
        if not actor_id:
            logger.warning("ingest_actor_missing_id", pir_id=pir_id)
            continue

        likelihood: float = float(entry.get("likelihood") or 0.0)

        rationale: dict = entry.get("rationale") or {}
        rationale_json: str = json.dumps(
            {
                "text": rationale.get("text") or "",
                "intent_factors": rationale.get("intent_factors") or {},
                "capability_factors": rationale.get("capability_factors") or {},
                "opportunity_factors": rationale.get("opportunity_factors") or {},
            }
        )

        rows.append(
            {
                "pir_id": pir_id,
                "actor_stix_id": actor_id,
                "overlap_ratio": None,  # not applicable for triage-sourced rows
                "likelihood": likelihood,
                "rationale_json": rationale_json,
            }
        )

    if not rows:
        return 0

    written = upsert_rows(database, "PirPrioritizesActor", rows)
    logger.info("ingest_prioritized_actors", pir_id=pir_id, count=written)
    return written
