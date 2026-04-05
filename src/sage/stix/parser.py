"""STIX 2.1 bundle parsing and pre-processing.

Uses the stix2 library for validation and converts objects to plain dicts
for easier handling in the ETL pipeline.
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

import stix2
import structlog

logger = structlog.get_logger(__name__)

# Object types processed by the ETL pipeline
SUPPORTED_TYPES = frozenset(
    {
        "threat-actor",
        "intrusion-set",
        "attack-pattern",
        "vulnerability",
        "malware",
        "tool",
        "indicator",
        "relationship",
        "incident",  # IR feedback
        "sighting",  # reserved for future use
    }
)


def parse_bundle(bundle_dict: dict[str, Any]) -> list[dict[str, Any]]:
    """Parse a STIX 2.1 bundle and return a list of supported objects.

    - Each object is individually validated by the stix2 library
    - Objects that fail validation are skipped with a warning log
    - Unsupported types are skipped silently
    """
    raw_objects = bundle_dict.get("objects", [])
    result: list[dict[str, Any]] = []

    for raw in raw_objects:
        obj_type = raw.get("type", "")
        obj_id = raw.get("id", "unknown")

        if obj_type not in SUPPORTED_TYPES:
            continue

        try:
            parsed = _parse_object(raw)
            result.append(parsed)
        except Exception as exc:
            logger.warning("parse_failed", stix_id=obj_id, error=str(exc))

    logger.info("parsed", total=len(raw_objects), accepted=len(result))
    return result


def load_bundle_from_file(path: Path) -> list[dict[str, Any]]:
    """Load and parse a STIX bundle from a JSON file."""
    with path.open() as f:
        bundle = json.load(f)
    return parse_bundle(bundle)


def _parse_object(raw: dict[str, Any]) -> dict[str, Any]:
    """Parse a raw dict through the stix2 library and return a plain dict.

    The stix2 library validates the object during parsing.
    On failure it raises stix2.exceptions.STIXError or a subclass.
    """
    parsed = stix2.parse(json.dumps(raw), allow_custom=True)
    # Return as a plain dict (easier to handle in Spanner upsert code)
    return json.loads(parsed.serialize())
