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
        "identity",  # SAGE 0.5.0 — credential / org-targeting graph node
        "incident",  # IR feedback
        "sighting",  # reserved for future use
        # SAGE 0.6.2 / Initiative A: TRACE 1.2.1+ synthesizes one
        # ``x-asset-internal`` object per resolved internal asset and
        # references it from ``x-trace-has-access`` relationships. The
        # object carries an ``asset_id`` property; the worker builds a
        # stix_id → asset_id map at ETL time so the mapper can resolve.
        "x-asset-internal",
        # SAGE 0.7.0 / Initiative B: STIX 2.1 §6.4 user-account SCO and
        # §4.10 observed-data SDO. TRACE 1.4.0+ emits these for CTI-
        # extracted account observations.
        "user-account",
        "observed-data",
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

    SAGE 0.6.2: ``x-asset-internal`` is a TRACE-internal custom type with
    a bespoke ``asset_id`` property. ``stix2.parse(...)`` with
    ``allow_custom=True`` returns it as a plain dict (no STIX class
    binding), which then breaks ``parsed.serialize()`` with
    ``AttributeError: 'dict' object has no attribute 'serialize'``. We
    own the format, so bypass the stix2 round-trip and pass the raw dict
    through unchanged. The worker then reads ``asset_id`` directly to
    build the resolution map.

    SAGE 0.7.0: same treatment for ``observed-data`` SDOs that wrap
    user-account SCOs. The stix2 library validates observed-data
    strictly (object_refs must resolve), but TRACE bundles include the
    referenced user-account SCO inline; the worker doesn't need the
    SDO at all (only its inner user-account ids matter), so we keep
    the dict round-trip-free.
    """
    if raw.get("type") in ("x-asset-internal", "observed-data"):
        return dict(raw)
    parsed = stix2.parse(json.dumps(raw), allow_custom=True)
    # Return as a plain dict (easier to handle in Spanner upsert code)
    return json.loads(parsed.serialize())
