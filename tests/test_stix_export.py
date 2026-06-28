"""Tests for the STIX 2.1 indicator-subset export builder."""

from __future__ import annotations

from datetime import UTC, datetime

from sage.stix.export import build_indicator_bundle, observable_to_pattern

ACTOR_1 = "intrusion-set--11111111-1111-1111-1111-111111111111"
OBS_1 = "indicator--dddddddd-dddd-dddd-dddd-ddddddddddd1"
OBS_2 = "indicator--dddddddd-dddd-dddd-dddd-ddddddddddd2"


def _row(obs_id, obs_type, value, tlp="amber", actor=ACTOR_1):
    return {
        "observable_stix_id": obs_id,
        "obs_type": obs_type,
        "value": value,
        "confidence": 80,
        "tlp": tlp,
        "first_seen": datetime(2026, 6, 10, tzinfo=UTC),
        "last_seen": datetime(2026, 6, 20, tzinfo=UTC),
        "actor_stix_id": actor,
        "actor_stix_type": "intrusion-set",
        "actor_name": "APT99",
        "rel_confidence": 70,
    }


def test_pattern_reconstruction_by_type() -> None:
    assert observable_to_pattern("ip", "203.0.113.10") == "[ipv4-addr:value = '203.0.113.10']"
    assert observable_to_pattern("ip", "2001:db8::1") == "[ipv6-addr:value = '2001:db8::1']"
    assert observable_to_pattern("domain", "evil.example.com") == (
        "[domain-name:value = 'evil.example.com']"
    )
    assert observable_to_pattern("url", "https://e.example/x") == (
        "[url:value = 'https://e.example/x']"
    )
    assert observable_to_pattern("hash", "a" * 64) == f"[file:hashes.'SHA-256' = '{'a' * 64}']"
    assert observable_to_pattern("hash", "b" * 32) == f"[file:hashes.'MD5' = '{'b' * 32}']"


def test_build_bundle_shape_and_relationships() -> None:
    rows = [
        _row(OBS_1, "ip", "203.0.113.10"),
        _row(OBS_2, "domain", "evil.example.com"),
    ]

    bundle = build_indicator_bundle(rows)

    assert bundle["type"] == "bundle"
    assert bundle["id"].startswith("bundle--")
    by_type: dict[str, list] = {}
    for obj in bundle["objects"]:
        by_type.setdefault(obj["type"], []).append(obj)

    assert len(by_type["indicator"]) == 2
    assert len(by_type["intrusion-set"]) == 1
    assert len(by_type["relationship"]) == 2
    assert by_type["marking-definition"]  # amber marking present

    for ind in by_type["indicator"]:
        assert ind["spec_version"] == "2.1"
        assert ind["pattern_type"] == "stix"
        assert ind["object_marking_refs"]

    for rel in by_type["relationship"]:
        assert rel["relationship_type"] == "indicates"
        assert rel["target_ref"] == ACTOR_1
        assert rel["source_ref"] in {OBS_1, OBS_2}


def test_relationship_ids_are_deterministic() -> None:
    rows = [_row(OBS_1, "ip", "203.0.113.10")]
    b1 = build_indicator_bundle(rows)
    b2 = build_indicator_bundle(rows)

    rid1 = next(o["id"] for o in b1["objects"] if o["type"] == "relationship")
    rid2 = next(o["id"] for o in b2["objects"] if o["type"] == "relationship")
    assert rid1 == rid2


def test_empty_rows_yield_empty_objects() -> None:
    bundle = build_indicator_bundle([])
    assert bundle["objects"] == []
