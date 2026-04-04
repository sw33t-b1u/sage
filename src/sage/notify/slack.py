"""Slack webhook notifications.

Detects changes in choke-point scores since the last ETL run and sends
a Slack notification. If SLACK_WEBHOOK_URL is not set, this module is a no-op.
"""

from __future__ import annotations

import json
from typing import Any

import structlog

logger = structlog.get_logger(__name__)

# Minimum relative change required to trigger a notification (10%)
_CHANGE_THRESHOLD = 0.10


def _post(webhook_url: str, payload: dict[str, Any]) -> bool:
    """POST payload to the Slack Incoming Webhook. Returns True on success.

    requests is an optional dependency and is imported lazily.
    """
    try:
        import requests  # noqa: PLC0415
    except ImportError:
        logger.error("slack_notify_failed", reason="requests not installed")
        return False

    try:
        resp = requests.post(
            webhook_url,
            data=json.dumps(payload),
            headers={"Content-Type": "application/json"},
            timeout=10,
        )
        resp.raise_for_status()
        return True
    except Exception as exc:
        logger.error("slack_notify_failed", error=str(exc))
        return False


def notify_etl_complete(
    webhook_url: str,
    stats: dict[str, int],
    choke_rows: list[dict],
    prev_choke_rows: list[dict],
) -> bool:
    """Send a Slack notification about choke-point score changes after ETL completion.

    A notification is sent only when at least one asset's score has changed
    by _CHANGE_THRESHOLD or more relative to the previous run.

    Args:
        webhook_url: Slack Incoming Webhook URL
        stats: return value of ETLWorker.process_bundle()
        choke_rows: current find_choke_points() results
        prev_choke_rows: previous find_choke_points() results (loaded from GCS etc.)

    Returns:
        True if a notification was sent, False if skipped
    """
    if not webhook_url:
        return False

    changed = _detect_changes(choke_rows, prev_choke_rows)
    if not changed:
        logger.info("slack_notify_skipped", reason="no significant choke score change")
        return False

    blocks = _build_etl_blocks(stats, changed)
    return _post(webhook_url, {"blocks": blocks})


def _detect_changes(
    current: list[dict],
    previous: list[dict],
) -> list[dict]:
    """Return assets whose choke score changed by _CHANGE_THRESHOLD or more vs. previous run."""
    prev_map = {r["asset_id"]: r["choke_score"] for r in previous}
    changed = []

    for row in current:
        asset_id = row["asset_id"]
        prev_score = prev_map.get(asset_id)

        if prev_score is None:
            # Newly observed asset
            changed.append({**row, "change": "new", "prev_score": None})
        elif prev_score == 0:
            if row["choke_score"] > 0:
                changed.append({**row, "change": "increased", "prev_score": prev_score})
        else:
            ratio = abs(row["choke_score"] - prev_score) / prev_score
            if ratio >= _CHANGE_THRESHOLD:
                direction = "increased" if row["choke_score"] > prev_score else "decreased"
                changed.append({**row, "change": direction, "prev_score": prev_score})

    return changed


def _build_etl_blocks(stats: dict[str, int], changed: list[dict]) -> list[dict]:
    """Build a Slack Block Kit message payload."""
    new_count = stats.get("threat_actors", 0)
    ttp_count = stats.get("ttps", 0)

    header = (
        f":rotating_light: *SAGE — Choke-Point Score Change Detected*\n"
        f"ETL complete: *{new_count}* new actor(s), *{ttp_count}* new TTP(s)"
    )

    lines = []
    for row in changed[:5]:  # show top 5 only
        icon = ":new:" if row["change"] == "new" else (
            ":arrow_up:" if row["change"] == "increased" else ":arrow_down:"
        )
        prev = f"(prev: {row['prev_score']:.1f})" if row["prev_score"] is not None else "(new)"
        lines.append(
            f"{icon} *{row['asset_name']}*  "
            f"score: {row['choke_score']:.1f} {prev}  "
            f"targeting actors: {row['targeting_actor_count']}"
        )

    if len(changed) > 5:
        lines.append(f"_…and {len(changed) - 5} more_")

    return [
        {"type": "section", "text": {"type": "mrkdwn", "text": header}},
        {"type": "divider"},
        {"type": "section", "text": {"type": "mrkdwn", "text": "\n".join(lines)}},
    ]
