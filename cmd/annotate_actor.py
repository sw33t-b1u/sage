"""CLI for writing AnnotatesActor rows (Initiative E Phase 5).

Usage:
    uv run python -m cmd.annotate_actor \\
        --annotator alice@example.com \\
        --actor-stix-id intrusion-set--<uuid> \\
        --type confidence-override \\
        --payload-file payload.json \\
        [--evidence-url https://example.com/evidence]

Exit codes:
    0 — annotation accepted and Spanner mutation buffered.
    2 — payload validation failed (Pydantic) or argparse rejected args.

.. deprecated:: SAGE 1.0.0

    Direct invocation as ``python -m cmd.annotate_actor`` /
    ``python cmd/annotate_actor.py`` is deprecated. Use the unified
    ``sage actor-annotate`` entry (Initiative H Phase 6). Removal is
    scheduled for SAGE 2.0.
"""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

import structlog
from pydantic import ValidationError

# Match sibling CLIs that put src/ on sys.path before importing sage.*
sys.path.insert(0, str(Path(__file__).parent.parent / "src"))

from sage.config import Config  # noqa: E402
from sage.models.annotation import AnnotationType, validate_payload  # noqa: E402
from sage.spanner.annotations import write_annotation  # noqa: E402
from sage.spanner.client import get_database  # noqa: E402

structlog.configure(
    processors=[
        structlog.processors.TimeStamper(fmt="iso"),
        structlog.processors.JSONRenderer(),
    ]
)
logger = structlog.get_logger(__name__)


def _build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description="Write an AnnotatesActor row backed by a typed Pydantic payload.",
    )
    parser.add_argument(
        "--annotator",
        required=True,
        help="Identifier of the analyst writing the annotation (e.g. email).",
    )
    parser.add_argument(
        "--actor-stix-id",
        required=True,
        help="STIX id of the target ThreatActor (e.g. intrusion-set--<uuid>).",
    )
    parser.add_argument(
        "--type",
        required=True,
        dest="annotation_type",
        choices=[t.value for t in AnnotationType],
        help="Annotation type from the controlled vocabulary.",
    )
    parser.add_argument(
        "--payload-file",
        required=True,
        type=Path,
        help="Path to a JSON file containing the annotation_type-specific payload.",
    )
    parser.add_argument(
        "--evidence-url",
        default=None,
        help="Optional URL recorded on the row alongside the payload.",
    )
    return parser


def main(argv: list[str] | None = None) -> int:
    parser = _build_parser()
    args = parser.parse_args(argv)

    annotation_type = AnnotationType(args.annotation_type)

    try:
        payload_dict = json.loads(args.payload_file.read_text())
    except (OSError, json.JSONDecodeError) as exc:
        print(f"error: failed to read payload file: {exc}", file=sys.stderr)
        return 2

    try:
        payload = validate_payload(annotation_type, payload_dict)
    except ValidationError as exc:
        print(f"error: payload failed validation for type {annotation_type.value}:")
        print(str(exc), file=sys.stderr)
        return 2

    config = Config.from_env()
    database = get_database(
        config.gcp_project_id,
        config.spanner_instance_id,
        config.spanner_database_id,
    )

    result = write_annotation(
        database=database,
        annotator_id=args.annotator,
        actor_stix_id=args.actor_stix_id,
        annotation_type=annotation_type,
        payload=payload,
        evidence_url=args.evidence_url,
    )
    print(
        "annotation written: "
        f"annotator_id={result['annotator_id']} "
        f"actor_stix_id={result['actor_stix_id']} "
        f"annotation_type={result['annotation_type']} "
        f"created_at_pending={result['created_at_pending']}"
    )
    return 0


if __name__ == "__main__":
    sys.stderr.write(
        "DeprecationWarning: 'python -m cmd.annotate_actor' / "
        "'python cmd/annotate_actor.py' is deprecated as of "
        "SAGE 1.0.0. Use 'sage actor-annotate' instead; cmd/* "
        "invocations are scheduled for removal in SAGE 2.0.\n"
    )
    raise SystemExit(main())
