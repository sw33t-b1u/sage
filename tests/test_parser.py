"""Tests for stix/parser.py.

Specifically guards the SAGE 0.6.2 fix: ``x-asset-internal`` objects
must pass through with their ``asset_id`` property preserved, since
the stix2 library's ``allow_custom=True`` path returns a plain dict
that doesn't survive ``parsed.serialize()``.
"""

from __future__ import annotations

from sage.stix.parser import parse_bundle


def _ts() -> str:
    return "2026-05-10T08:00:00.000Z"


class TestXAssetInternalPassthrough:
    def test_asset_id_property_preserved(self):
        bundle = {
            "type": "bundle",
            "id": "bundle--00000000-0000-4000-8000-000000000001",
            "objects": [
                {
                    "type": "x-asset-internal",
                    "id": "x-asset-internal--f6761eb5-ab89-5503-9f5f-ccfc7bf3ed22",
                    "spec_version": "2.1",
                    "created": _ts(),
                    "modified": _ts(),
                    "asset_id": "asset-CA-001",
                }
            ],
        }
        objects = parse_bundle(bundle)
        assert len(objects) == 1
        assert objects[0]["type"] == "x-asset-internal"
        assert objects[0]["asset_id"] == "asset-CA-001"
        assert objects[0]["id"] == "x-asset-internal--f6761eb5-ab89-5503-9f5f-ccfc7bf3ed22"

    def test_extension_definition_silently_skipped(self):
        # Sanity check: TRACE bundles include extension-definition objects
        # that SAGE doesn't ingest. They should be silently dropped, not
        # raise.
        bundle = {
            "type": "bundle",
            "id": "bundle--00000000-0000-4000-8000-000000000002",
            "objects": [
                {
                    "type": "extension-definition",
                    "id": "extension-definition--11111111-1111-4111-8111-111111111111",
                    "spec_version": "2.1",
                    "created": _ts(),
                    "modified": _ts(),
                    "name": "TRACE",
                    "description": "test",
                    "schema": "https://example.com/schema",
                    "version": "1.0.0",
                    "extension_types": ["toplevel-property-extension"],
                }
            ],
        }
        # No exception, no objects accepted (extension-definition is not in
        # SUPPORTED_TYPES).
        assert parse_bundle(bundle) == []

    def test_x_trace_has_access_relationship_passes_through(self):
        # 1.2.1 / 0.6.2: target_ref is now a valid STIX identifier
        # (UUIDv5-form), so the stix2 library accepts it. Verify the
        # relationship survives parse and the target_ref string matches
        # the synthesized x-asset-internal id.
        bundle = {
            "type": "bundle",
            "id": "bundle--00000000-0000-4000-8000-000000000003",
            "objects": [
                {
                    "type": "x-asset-internal",
                    "id": "x-asset-internal--f6761eb5-ab89-5503-9f5f-ccfc7bf3ed22",
                    "spec_version": "2.1",
                    "created": _ts(),
                    "modified": _ts(),
                    "asset_id": "asset-CA-001",
                },
                {
                    "type": "identity",
                    "id": "identity--22222222-2222-4222-8222-222222222222",
                    "spec_version": "2.1",
                    "created": _ts(),
                    "modified": _ts(),
                    "name": "Auditor",
                    "identity_class": "group",
                },
                {
                    "type": "relationship",
                    "id": "relationship--33333333-3333-4333-8333-333333333333",
                    "spec_version": "2.1",
                    "created": _ts(),
                    "modified": _ts(),
                    "relationship_type": "x-trace-has-access",
                    "source_ref": "identity--22222222-2222-4222-8222-222222222222",
                    "target_ref": "x-asset-internal--f6761eb5-ab89-5503-9f5f-ccfc7bf3ed22",
                },
            ],
        }
        objects = parse_bundle(bundle)
        types = [o["type"] for o in objects]
        assert "x-asset-internal" in types
        assert "identity" in types
        assert "relationship" in types
        rel = next(o for o in objects if o["type"] == "relationship")
        assert rel["target_ref"] == "x-asset-internal--f6761eb5-ab89-5503-9f5f-ccfc7bf3ed22"
