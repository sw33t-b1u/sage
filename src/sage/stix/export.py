"""Build a STIX 2.1 bundle subset for manual SIEM threat hunting.

Given Observable rows linked to selected actors (see
``sage.db.find_indicators_for_actors``), assemble a self-contained STIX 2.1
bundle of:

* ``indicator`` SDOs — reconstructed from the stored ``obs_type`` / ``value``;
* ``threat-actor`` / ``intrusion-set`` SDOs — the selected actors;
* ``relationship`` SROs — ``indicator --indicates--> actor`` for each link;
* ``marking-definition`` objects — canonical TLP markings referenced by the
  indicators.

The original STIX ``pattern`` string is not stored by SAGE, so it is
reconstructed in the canonical ``[<obs-path> = '<value>']`` form. Single-value
IOCs round-trip exactly; the algorithm for hashes is inferred from the digest
length (md5/sha-1/sha-256), defaulting to SHA-256.
"""

from __future__ import annotations

import uuid
from datetime import UTC, datetime
from typing import Any

# Canonical STIX 2.x TLP marking-definition ids (spec-fixed UUIDs).
_TLP_MARKING_IDS: dict[str, str] = {
    "white": "marking-definition--613f2e26-407d-48c7-9eca-b8e91df99dc9",
    "green": "marking-definition--34098fce-860f-48ae-8e50-ebd3cc5e41da",
    "amber": "marking-definition--f88d31f6-486f-44da-b317-01333bde0b82",
}

# Deterministic namespace for relationship ids derived from (indicator, actor).
_REL_NAMESPACE = uuid.UUID("6e2f1d3a-2b4c-4f6a-9b1e-2c3d4e5f6a7b")

_HASH_ALG_BY_LEN: dict[int, str] = {32: "MD5", 40: "SHA-1", 64: "SHA-256"}


def observable_to_pattern(obs_type: str, value: str) -> str:
    """Reconstruct a canonical STIX 2.1 pattern from a stored observable."""
    escaped = value.replace("\\", "\\\\").replace("'", "\\'")
    if obs_type == "ip":
        path = "ipv6-addr:value" if ":" in value else "ipv4-addr:value"
        return f"[{path} = '{escaped}']"
    if obs_type == "domain":
        return f"[domain-name:value = '{escaped}']"
    if obs_type == "email":
        return f"[email-addr:value = '{escaped}']"
    if obs_type == "url":
        return f"[url:value = '{escaped}']"
    if obs_type == "hash":
        alg = _HASH_ALG_BY_LEN.get(len(value), "SHA-256")
        return f"[file:hashes.'{alg}' = '{escaped}']"
    # Unknown observable type: emit a best-effort artifact pattern so the
    # bundle stays valid and the value is still searchable by an analyst.
    return f"[x-sage-observable:value = '{escaped}']"


def _ts(value: Any, *, default: datetime) -> str:
    if isinstance(value, datetime):
        dt = value if value.tzinfo else value.replace(tzinfo=UTC)
        return dt.astimezone(UTC).strftime("%Y-%m-%dT%H:%M:%S.000Z")
    return default.strftime("%Y-%m-%dT%H:%M:%S.000Z")


def _actor_type(actor_stix_id: str, actor_stix_type: str | None) -> str:
    if actor_stix_type in ("threat-actor", "intrusion-set"):
        return actor_stix_type
    return "intrusion-set" if actor_stix_id.startswith("intrusion-set--") else "threat-actor"


def build_indicator_bundle(rows: list[dict[str, Any]]) -> dict[str, Any]:
    """Assemble a STIX 2.1 bundle subset from ``find_indicators_for_actors`` rows.

    Returns a bundle dict (``type: bundle``) with deterministic, de-duplicated
    indicator / actor / relationship / marking-definition objects. An empty
    input yields a bundle with an empty ``objects`` list.
    """
    now = datetime.now(UTC)
    indicators: dict[str, dict[str, Any]] = {}
    actors: dict[str, dict[str, Any]] = {}
    relationships: dict[str, dict[str, Any]] = {}
    markings: dict[str, dict[str, Any]] = {}

    for row in rows:
        obs_id = row["observable_stix_id"]
        actor_id = row["actor_stix_id"]
        tlp = (row.get("tlp") or "").lower()
        marking_ref = _TLP_MARKING_IDS.get(tlp)

        if obs_id not in indicators:
            created = _ts(row.get("first_seen"), default=now)
            indicator: dict[str, Any] = {
                "type": "indicator",
                "spec_version": "2.1",
                "id": obs_id,
                "created": created,
                "modified": _ts(row.get("last_seen"), default=now),
                "pattern": observable_to_pattern(row["obs_type"], row["value"]),
                "pattern_type": "stix",
                "valid_from": created,
            }
            if row.get("confidence") is not None:
                indicator["confidence"] = row["confidence"]
            if marking_ref:
                indicator["object_marking_refs"] = [marking_ref]
            indicators[obs_id] = indicator
        elif marking_ref:
            refs = indicators[obs_id].setdefault("object_marking_refs", [])
            if marking_ref not in refs:
                refs.append(marking_ref)

        if actor_id not in actors:
            actors[actor_id] = {
                "type": _actor_type(actor_id, row.get("actor_stix_type")),
                "spec_version": "2.1",
                "id": actor_id,
                "created": now.strftime("%Y-%m-%dT%H:%M:%S.000Z"),
                "modified": now.strftime("%Y-%m-%dT%H:%M:%S.000Z"),
                "name": row.get("actor_name") or actor_id,
            }

        rel_id = "relationship--" + str(uuid.uuid5(_REL_NAMESPACE, f"{obs_id}|{actor_id}"))
        if rel_id not in relationships:
            relationships[rel_id] = {
                "type": "relationship",
                "spec_version": "2.1",
                "id": rel_id,
                "created": now.strftime("%Y-%m-%dT%H:%M:%S.000Z"),
                "modified": now.strftime("%Y-%m-%dT%H:%M:%S.000Z"),
                "relationship_type": "indicates",
                "source_ref": obs_id,
                "target_ref": actor_id,
            }

        if marking_ref and marking_ref not in markings:
            markings[marking_ref] = _marking_definition(marking_ref, tlp)

    objects: list[dict[str, Any]] = [
        *markings.values(),
        *indicators.values(),
        *actors.values(),
        *relationships.values(),
    ]
    return {
        "type": "bundle",
        "id": "bundle--" + str(uuid.uuid4()),
        "objects": objects,
    }


def _marking_definition(marking_id: str, tlp: str) -> dict[str, Any]:
    return {
        "type": "marking-definition",
        "spec_version": "2.1",
        "id": marking_id,
        "created": "2017-01-20T00:00:00.000Z",
        "definition_type": "tlp",
        "name": f"TLP:{tlp.upper()}",
        "definition": {"tlp": tlp},
    }
