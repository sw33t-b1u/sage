"""MITRE ATT&CK Navigator layer JSON parser (Initiative G Phase 3).

The CLI ``cmd/register_incident.py`` accepts a Navigator ``layer.json``
file so IR analysts can express a TTP sequence visually in the
Navigator UI and then hand the exported layer to the SAGE registration
helper. This module is the parser; it returns the ``techniques`` array
in source order so the caller can derive ``sequence_order`` from the
list index (plan §2.3).

The Navigator JSON schema is large and versioned, but for the IR
workflow we only need a minimal subset: every entry under
``techniques[]`` must carry ``techniqueID`` and ``tactic``; ``score``
and ``comment`` are passed through verbatim when present so a future
caller can use the score as a confidence hint.

The parser is intentionally strict — a missing ``techniques`` array or
a malformed entry raises :class:`NavigatorLayerError` rather than
returning a partial list. The IR registration path is operator-driven
so a silent half-import is worse than a hard error.
"""

from __future__ import annotations

import json
from dataclasses import dataclass
from pathlib import Path
from typing import Any


class NavigatorLayerError(ValueError):
    """Raised when a Navigator layer JSON file cannot be parsed."""


@dataclass(frozen=True)
class NavigatorEntry:
    """One parsed ``techniques[]`` row.

    ``sequence_order`` is the 0-based index in the source array; the
    caller writes it onto the corresponding ``IncidentUsesTTP`` row.
    """

    technique_id: str
    tactic: str
    sequence_order: int
    score: float | None = None
    comment: str | None = None


def load_navigator_layer(path: Path | str) -> list[NavigatorEntry]:
    """Parse a Navigator layer file and return its techniques in order.

    Raises:
        NavigatorLayerError: file missing, unreadable, not valid JSON,
            or schema-incompatible (no ``techniques`` array, or any
            entry missing ``techniqueID`` / ``tactic``).
    """
    layer_path = Path(path)
    try:
        raw = layer_path.read_text()
    except OSError as exc:
        raise NavigatorLayerError(f"failed to read navigator layer: {exc}") from exc

    try:
        payload = json.loads(raw)
    except json.JSONDecodeError as exc:
        raise NavigatorLayerError(f"navigator layer is not valid JSON: {exc}") from exc

    return parse_navigator_payload(payload)


def parse_navigator_payload(payload: Any) -> list[NavigatorEntry]:
    """Validate an already-loaded payload and return ordered entries.

    Split from :func:`load_navigator_layer` so tests can drive
    parsing without touching the filesystem.
    """
    if not isinstance(payload, dict):
        raise NavigatorLayerError("navigator layer must be a JSON object")
    techniques = payload.get("techniques")
    if not isinstance(techniques, list):
        raise NavigatorLayerError("navigator layer is missing the required 'techniques' array")
    entries: list[NavigatorEntry] = []
    for index, item in enumerate(techniques):
        if not isinstance(item, dict):
            raise NavigatorLayerError(
                f"techniques[{index}] must be an object, got {type(item).__name__}"
            )
        technique_id = item.get("techniqueID")
        if not isinstance(technique_id, str) or not technique_id.strip():
            raise NavigatorLayerError(
                f"techniques[{index}] is missing a non-empty 'techniqueID' field"
            )
        tactic = item.get("tactic")
        if not isinstance(tactic, str) or not tactic.strip():
            raise NavigatorLayerError(f"techniques[{index}] is missing a non-empty 'tactic' field")
        raw_score = item.get("score")
        score: float | None
        if raw_score is None:
            score = None
        elif isinstance(raw_score, int | float) and not isinstance(raw_score, bool):
            score = float(raw_score)
        else:
            raise NavigatorLayerError(
                f"techniques[{index}].score must be numeric, got {type(raw_score).__name__}"
            )
        raw_comment = item.get("comment")
        comment: str | None
        if raw_comment is None:
            comment = None
        elif isinstance(raw_comment, str):
            comment = raw_comment
        else:
            raise NavigatorLayerError(
                f"techniques[{index}].comment must be a string, got {type(raw_comment).__name__}"
            )
        entries.append(
            NavigatorEntry(
                technique_id=technique_id.strip(),
                tactic=tactic.strip(),
                sequence_order=index,
                score=score,
                comment=comment,
            )
        )
    return entries
