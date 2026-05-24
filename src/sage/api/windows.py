"""Shared time-window helpers for the Analysis API.

Originally defined inline in :mod:`sage.api.app` (Initiative F Phase 7).
Extracted in Initiative G Phase 2 so the new ``GET /api/incidents``
handler in :mod:`sage.api.incidents` can reuse the same defaulting
logic without creating an import cycle through ``app.py`` (which
already imports ``incidents.router``).
"""

from __future__ import annotations

from datetime import UTC, date, datetime, timedelta

from sage.config import Config


def resolve_window(
    config: Config,
    since: date | None,
    until: date | None,
) -> tuple[date, date]:
    """Fill in absent since/until bounds from config.

    Default ``until`` is today (UTC); default ``since`` is
    ``until - activity_window_days`` so the response always carries a
    bounded window. When the client passes only one bound, the other is
    derived consistently from it.
    """
    if until is None:
        until = datetime.now(tz=UTC).date()
    if since is None:
        since = until - timedelta(days=config.activity_window_days)
    return since, until
