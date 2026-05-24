"""Tests for ``sage.cli.navigator_loader`` (Initiative G Phase 3)."""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from sage.cli.navigator_loader import (
    NavigatorEntry,
    NavigatorLayerError,
    load_navigator_layer,
    parse_navigator_payload,
)

FIXTURE = Path(__file__).parent / "fixtures" / "navigator_layer_sample.json"


class TestLoadNavigatorLayer:
    def test_fixture_round_trips(self):
        entries = load_navigator_layer(FIXTURE)
        assert len(entries) == 3
        assert entries[0] == NavigatorEntry(
            technique_id="T1566",
            tactic="initial-access",
            sequence_order=0,
            score=1.0,
            comment="Phishing — initial entry vector",
        )
        # ``sequence_order`` is the index in the source array
        assert [e.sequence_order for e in entries] == [0, 1, 2]
        # Score / comment are optional — the third entry omits comment
        assert entries[2].comment is None
        assert entries[2].score == 0.5

    def test_missing_file_raises(self, tmp_path):
        missing = tmp_path / "does-not-exist.json"
        with pytest.raises(NavigatorLayerError):
            load_navigator_layer(missing)

    def test_invalid_json_raises(self, tmp_path):
        bad = tmp_path / "bad.json"
        bad.write_text("{not valid json")
        with pytest.raises(NavigatorLayerError):
            load_navigator_layer(bad)


class TestParseNavigatorPayload:
    def test_rejects_non_object_payload(self):
        with pytest.raises(NavigatorLayerError):
            parse_navigator_payload([])

    def test_rejects_missing_techniques_array(self):
        with pytest.raises(NavigatorLayerError):
            parse_navigator_payload({"name": "x"})

    def test_rejects_non_list_techniques(self):
        with pytest.raises(NavigatorLayerError):
            parse_navigator_payload({"techniques": "T1078"})

    def test_rejects_non_object_entry(self):
        with pytest.raises(NavigatorLayerError) as exc_info:
            parse_navigator_payload({"techniques": ["T1078"]})
        assert "techniques[0]" in str(exc_info.value)

    def test_rejects_missing_technique_id(self):
        with pytest.raises(NavigatorLayerError) as exc_info:
            parse_navigator_payload({"techniques": [{"tactic": "initial-access"}]})
        assert "techniqueID" in str(exc_info.value)

    def test_rejects_empty_technique_id(self):
        with pytest.raises(NavigatorLayerError):
            parse_navigator_payload(
                {"techniques": [{"techniqueID": "   ", "tactic": "initial-access"}]}
            )

    def test_rejects_missing_tactic(self):
        with pytest.raises(NavigatorLayerError) as exc_info:
            parse_navigator_payload({"techniques": [{"techniqueID": "T1078"}]})
        assert "tactic" in str(exc_info.value)

    def test_rejects_non_numeric_score(self):
        with pytest.raises(NavigatorLayerError) as exc_info:
            parse_navigator_payload(
                {
                    "techniques": [
                        {
                            "techniqueID": "T1078",
                            "tactic": "initial-access",
                            "score": "high",
                        }
                    ]
                }
            )
        assert "score" in str(exc_info.value)

    def test_rejects_non_string_comment(self):
        with pytest.raises(NavigatorLayerError) as exc_info:
            parse_navigator_payload(
                {
                    "techniques": [
                        {
                            "techniqueID": "T1078",
                            "tactic": "initial-access",
                            "comment": ["multi", "line"],
                        }
                    ]
                }
            )
        assert "comment" in str(exc_info.value)

    def test_score_accepts_int(self):
        """JSON ``score: 1`` should land as ``1.0`` for downstream consumers."""
        entries = parse_navigator_payload(
            {
                "techniques": [
                    {
                        "techniqueID": "T1078",
                        "tactic": "initial-access",
                        "score": 1,
                    }
                ]
            }
        )
        assert entries[0].score == 1.0

    def test_score_rejects_bool(self):
        """``isinstance(True, int)`` is true but ``score: true`` is not numeric."""
        with pytest.raises(NavigatorLayerError):
            parse_navigator_payload(
                {
                    "techniques": [
                        {
                            "techniqueID": "T1078",
                            "tactic": "initial-access",
                            "score": True,
                        }
                    ]
                }
            )

    def test_round_trip_via_json_string(self, tmp_path):
        """Smoke test: write a layer, load it, get the same entries."""
        payload = {
            "techniques": [
                {"techniqueID": "T1003", "tactic": "credential-access"},
            ]
        }
        path = tmp_path / "layer.json"
        path.write_text(json.dumps(payload))
        entries = load_navigator_layer(path)
        assert entries == [
            NavigatorEntry(
                technique_id="T1003",
                tactic="credential-access",
                sequence_order=0,
                score=None,
                comment=None,
            )
        ]
