"""Tests for AnnotatesActor write surface (Initiative E Phase 5).

Coverage:
  * Pydantic models per annotation_type — happy path + edge cases.
  * ``validate_payload`` dispatcher returns the correct model class.
  * ``write_annotation`` buffers a single Spanner mutation with the
    expected columns and ``COMMIT_TIMESTAMP`` for ``created_at``.
  * CLI argparse accepts the documented flags and rejects invalid
    payloads with exit code 2.

Spanner is mocked at the ``Database`` level; no emulator required.
"""

from __future__ import annotations

import json
from unittest.mock import MagicMock, patch

import google.cloud.spanner as spanner
import pytest
from pydantic import BaseModel, ValidationError

from sage.models.annotation import (  # noqa: E402
    AnalystNotePayload,
    AnnotationType,
    ConfidenceOverridePayload,
    FalsePositivePayload,
    ScopeExclusionPayload,
    validate_payload,
)
from sage.spanner.annotations import write_annotation  # noqa: E402

# ---------------------------------------------------------------------------
# Spanner mock helpers
# ---------------------------------------------------------------------------


def _mock_database():
    """Return (mock Database, list capturing insert_or_update calls)."""
    inserts: list[tuple[str, list[str], list[list]]] = []

    def _record(table, columns, values):
        inserts.append((table, list(columns), [list(v) for v in values]))

    batch = MagicMock()
    batch.insert_or_update.side_effect = _record
    batch_ctx = MagicMock()
    batch_ctx.__enter__.return_value = batch
    batch_ctx.__exit__.return_value = None

    db = MagicMock()
    db.batch.return_value = batch_ctx
    return db, inserts


# ---------------------------------------------------------------------------
# Pydantic model coverage
# ---------------------------------------------------------------------------


class TestPydanticModels:
    def test_false_positive_happy_path(self):
        m = FalsePositivePayload(reason="Mis-tagged by upstream feed")
        assert m.reason == "Mis-tagged by upstream feed"
        assert m.evidence_url is None

    def test_false_positive_accepts_evidence_url(self):
        m = FalsePositivePayload(
            reason="Mis-tagged",
            evidence_url="https://example.com/report",
        )
        assert str(m.evidence_url).startswith("https://example.com/report")

    def test_scope_exclusion_happy_path(self):
        m = ScopeExclusionPayload(reason="Out of scope for this org")
        assert m.reason == "Out of scope for this org"

    def test_analyst_note_happy_path(self):
        m = AnalystNotePayload(note="Track campaign activity in Q3")
        assert m.note == "Track campaign activity in Q3"

    def test_confidence_override_happy_path(self):
        m = ConfidenceOverridePayload(
            original_likelihood=0.42,
            overridden_likelihood=0.85,
            reason="Recent intrusion attempt confirmed",
        )
        assert m.original_likelihood == pytest.approx(0.42)
        assert m.overridden_likelihood == pytest.approx(0.85)

    def test_confidence_override_rejects_above_one(self):
        with pytest.raises(ValidationError):
            ConfidenceOverridePayload(
                original_likelihood=0.5,
                overridden_likelihood=1.5,
                reason="invalid",
            )

    def test_confidence_override_rejects_below_zero(self):
        with pytest.raises(ValidationError):
            ConfidenceOverridePayload(
                original_likelihood=-0.1,
                overridden_likelihood=0.5,
                reason="invalid",
            )

    def test_empty_reason_rejected(self):
        with pytest.raises(ValidationError):
            FalsePositivePayload(reason="")

    def test_empty_note_rejected(self):
        with pytest.raises(ValidationError):
            AnalystNotePayload(note="")


# ---------------------------------------------------------------------------
# validate_payload dispatcher
# ---------------------------------------------------------------------------


class TestValidatePayloadDispatcher:
    def test_false_positive_dispatch(self):
        m = validate_payload(AnnotationType.FALSE_POSITIVE, {"reason": "x"})
        assert isinstance(m, FalsePositivePayload)

    def test_scope_exclusion_dispatch(self):
        m = validate_payload(AnnotationType.SCOPE_EXCLUSION, {"reason": "x"})
        assert isinstance(m, ScopeExclusionPayload)

    def test_analyst_note_dispatch(self):
        m = validate_payload(AnnotationType.ANALYST_NOTE, {"note": "x"})
        assert isinstance(m, AnalystNotePayload)

    def test_confidence_override_dispatch(self):
        m = validate_payload(
            AnnotationType.CONFIDENCE_OVERRIDE,
            {
                "original_likelihood": 0.3,
                "overridden_likelihood": 0.7,
                "reason": "x",
            },
        )
        assert isinstance(m, ConfidenceOverridePayload)

    def test_dispatcher_propagates_validation_error(self):
        with pytest.raises(ValidationError):
            validate_payload(
                AnnotationType.CONFIDENCE_OVERRIDE,
                {
                    "original_likelihood": 0.3,
                    "overridden_likelihood": 1.5,
                    "reason": "x",
                },
            )


# ---------------------------------------------------------------------------
# write_annotation — Spanner mutation shape
# ---------------------------------------------------------------------------


class TestWriteAnnotation:
    def test_writes_one_row_with_expected_columns(self):
        db, inserts = _mock_database()
        payload = AnalystNotePayload(note="hello")
        result = write_annotation(
            database=db,
            annotator_id="alice@example.com",
            actor_stix_id="intrusion-set--abc",
            annotation_type=AnnotationType.ANALYST_NOTE,
            payload=payload,
        )
        assert len(inserts) == 1
        table, columns, values = inserts[0]
        assert table == "AnnotatesActor"
        assert columns == [
            "annotator_id",
            "actor_stix_id",
            "annotation_type",
            "payload_json",
            "created_at",
            "evidence_url",
        ]
        assert len(values) == 1
        row = values[0]
        assert row[0] == "alice@example.com"
        assert row[1] == "intrusion-set--abc"
        assert row[2] == "analyst-note"
        assert json.loads(row[3]) == {"note": "hello"}
        # created_at must be the commit_timestamp sentinel
        assert row[4] is spanner.COMMIT_TIMESTAMP
        assert row[5] is None
        assert result == {
            "annotator_id": "alice@example.com",
            "actor_stix_id": "intrusion-set--abc",
            "annotation_type": "analyst-note",
            "created_at_pending": True,
        }

    @pytest.mark.parametrize(
        "annotation_type, payload",
        [
            (AnnotationType.FALSE_POSITIVE, FalsePositivePayload(reason="r")),
            (AnnotationType.SCOPE_EXCLUSION, ScopeExclusionPayload(reason="r")),
            (AnnotationType.ANALYST_NOTE, AnalystNotePayload(note="n")),
            (
                AnnotationType.CONFIDENCE_OVERRIDE,
                ConfidenceOverridePayload(
                    original_likelihood=0.2,
                    overridden_likelihood=0.8,
                    reason="r",
                ),
            ),
        ],
    )
    def test_each_annotation_type_writes_once(
        self,
        annotation_type: AnnotationType,
        payload: BaseModel,
    ):
        db, inserts = _mock_database()
        write_annotation(
            database=db,
            annotator_id="alice@example.com",
            actor_stix_id="intrusion-set--abc",
            annotation_type=annotation_type,
            payload=payload,
        )
        assert len(inserts) == 1
        _, _, values = inserts[0]
        assert values[0][2] == annotation_type.value
        assert json.loads(values[0][3]) == payload.model_dump(mode="json")

    def test_evidence_url_propagated(self):
        db, inserts = _mock_database()
        write_annotation(
            database=db,
            annotator_id="alice@example.com",
            actor_stix_id="intrusion-set--abc",
            annotation_type=AnnotationType.FALSE_POSITIVE,
            payload=FalsePositivePayload(reason="r"),
            evidence_url="https://example.com/evidence",
        )
        _, _, values = inserts[0]
        assert values[0][5] == "https://example.com/evidence"


# ---------------------------------------------------------------------------
# CLI behaviour
# ---------------------------------------------------------------------------


class TestCLI:
    def _write_payload(self, tmp_path, body: dict):
        p = tmp_path / "payload.json"
        p.write_text(json.dumps(body))
        return p

    def test_argparse_accepts_required_flags(self, tmp_path):
        from sage.cli.annotate_actor import _build_parser

        parser = _build_parser()
        args = parser.parse_args(
            [
                "--annotator",
                "alice@example.com",
                "--actor-stix-id",
                "intrusion-set--abc",
                "--type",
                "analyst-note",
                "--payload-file",
                "payload.json",
            ]
        )
        assert args.annotator == "alice@example.com"
        assert args.actor_stix_id == "intrusion-set--abc"
        assert args.annotation_type == "analyst-note"
        assert args.evidence_url is None

    def test_argparse_rejects_unknown_type(self):
        from sage.cli.annotate_actor import _build_parser

        parser = _build_parser()
        with pytest.raises(SystemExit):
            parser.parse_args(
                [
                    "--annotator",
                    "alice@example.com",
                    "--actor-stix-id",
                    "intrusion-set--abc",
                    "--type",
                    "not-a-real-type",
                    "--payload-file",
                    "payload.json",
                ]
            )

    def test_cli_calls_write_once_on_happy_path(self, tmp_path):
        import sage.cli.annotate_actor as cli_mod

        payload_path = self._write_payload(
            tmp_path,
            {"note": "Track this actor next quarter"},
        )

        fake_db = MagicMock()
        fake_config = MagicMock()
        fake_config.gcp_project_id = "p"
        fake_config.spanner_instance_id = "i"
        fake_config.spanner_database_id = "d"

        with (
            patch.object(cli_mod, "Config") as config_mock,
            patch.object(cli_mod, "get_database", return_value=fake_db) as gd_mock,
            patch.object(cli_mod, "write_annotation") as write_mock,
        ):
            config_mock.from_env.return_value = fake_config
            write_mock.return_value = {
                "annotator_id": "alice@example.com",
                "actor_stix_id": "intrusion-set--abc",
                "annotation_type": "analyst-note",
                "created_at_pending": True,
            }
            rc = cli_mod.main(
                [
                    "--annotator",
                    "alice@example.com",
                    "--actor-stix-id",
                    "intrusion-set--abc",
                    "--type",
                    "analyst-note",
                    "--payload-file",
                    str(payload_path),
                ]
            )

        assert rc == 0
        gd_mock.assert_called_once_with("p", "i", "d")
        write_mock.assert_called_once()
        kwargs = write_mock.call_args.kwargs
        assert kwargs["annotator_id"] == "alice@example.com"
        assert kwargs["actor_stix_id"] == "intrusion-set--abc"
        assert kwargs["annotation_type"] == AnnotationType.ANALYST_NOTE
        assert isinstance(kwargs["payload"], AnalystNotePayload)
        assert kwargs["evidence_url"] is None

    def test_cli_passes_evidence_url_through(self, tmp_path):
        import sage.cli.annotate_actor as cli_mod

        payload_path = self._write_payload(tmp_path, {"reason": "Mis-tagged"})

        with (
            patch.object(cli_mod, "Config") as config_mock,
            patch.object(cli_mod, "get_database", return_value=MagicMock()),
            patch.object(cli_mod, "write_annotation") as write_mock,
        ):
            config_mock.from_env.return_value = MagicMock(
                gcp_project_id="p",
                spanner_instance_id="i",
                spanner_database_id="d",
            )
            write_mock.return_value = {
                "annotator_id": "a",
                "actor_stix_id": "intrusion-set--abc",
                "annotation_type": "false-positive",
                "created_at_pending": True,
            }
            rc = cli_mod.main(
                [
                    "--annotator",
                    "a",
                    "--actor-stix-id",
                    "intrusion-set--abc",
                    "--type",
                    "false-positive",
                    "--payload-file",
                    str(payload_path),
                    "--evidence-url",
                    "https://example.com/evidence",
                ]
            )
        assert rc == 0
        assert write_mock.call_args.kwargs["evidence_url"] == "https://example.com/evidence"

    def test_cli_invalid_payload_exits_with_code_two(self, tmp_path, capsys):
        import sage.cli.annotate_actor as cli_mod

        # overridden_likelihood out of range — fails Pydantic before any
        # Config / Spanner code runs.
        payload_path = self._write_payload(
            tmp_path,
            {
                "original_likelihood": 0.3,
                "overridden_likelihood": 1.5,
                "reason": "bogus",
            },
        )

        with (
            patch.object(cli_mod, "Config") as config_mock,
            patch.object(cli_mod, "get_database") as gd_mock,
            patch.object(cli_mod, "write_annotation") as write_mock,
        ):
            rc = cli_mod.main(
                [
                    "--annotator",
                    "alice@example.com",
                    "--actor-stix-id",
                    "intrusion-set--abc",
                    "--type",
                    "confidence-override",
                    "--payload-file",
                    str(payload_path),
                ]
            )
            assert rc == 2
            # Confirms validation aborted before any Spanner work.
            config_mock.from_env.assert_not_called()
            gd_mock.assert_not_called()
            write_mock.assert_not_called()

        captured = capsys.readouterr()
        assert "validation" in (captured.out + captured.err).lower()

    def test_cli_missing_required_field_exits_with_code_two(self, tmp_path):
        import sage.cli.annotate_actor as cli_mod

        # confidence-override missing "reason"
        payload_path = self._write_payload(
            tmp_path,
            {"original_likelihood": 0.3, "overridden_likelihood": 0.5},
        )

        with (
            patch.object(cli_mod, "Config") as config_mock,
            patch.object(cli_mod, "get_database") as gd_mock,
            patch.object(cli_mod, "write_annotation") as write_mock,
        ):
            rc = cli_mod.main(
                [
                    "--annotator",
                    "alice@example.com",
                    "--actor-stix-id",
                    "intrusion-set--abc",
                    "--type",
                    "confidence-override",
                    "--payload-file",
                    str(payload_path),
                ]
            )

        assert rc == 2
        config_mock.from_env.assert_not_called()
        gd_mock.assert_not_called()
        write_mock.assert_not_called()

    def test_cli_unreadable_payload_file_exits_with_code_two(self, tmp_path):
        import sage.cli.annotate_actor as cli_mod

        missing = tmp_path / "does-not-exist.json"
        rc = cli_mod.main(
            [
                "--annotator",
                "alice@example.com",
                "--actor-stix-id",
                "intrusion-set--abc",
                "--type",
                "analyst-note",
                "--payload-file",
                str(missing),
            ]
        )
        assert rc == 2
