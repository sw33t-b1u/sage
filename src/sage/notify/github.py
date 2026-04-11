"""GitHub REST API client for GHE Issue creation and updates.

Creates or updates a weekly choke-point report as a GitHub/GHE Issue.
If an Issue with the same title (same week number) already exists and is open,
its body is updated instead of creating a new one.

Required environment variables:
  GHE_TOKEN: GitHub Personal Access Token (repo scope)
  GHE_REPO:  "owner/repo" format (e.g. "security-team/sage-reports")
"""

from __future__ import annotations

import structlog

try:
    import requests
except ImportError:
    requests = None  # type: ignore[assignment]

logger = structlog.get_logger(__name__)

# Base URL for GitHub.com API (override with https://{host}/api/v3 for GHE Server)
_GITHUB_API_BASE = "https://api.github.com"
_ISSUE_LABEL = "sage-report"


def post_choke_point_issue(
    token: str,
    repo: str,
    title: str,
    body: str,
    api_base: str = _GITHUB_API_BASE,
) -> str | None:
    """Post or update a choke-point report as a GHE Issue.

    If an open Issue with the same title exists, its body is updated.
    Otherwise a new Issue is created.

    Args:
        token: GitHub Personal Access Token
        repo: "owner/repo" format
        title: Issue title (should include the week number)
        body: Issue body in Markdown
        api_base: API base URL (override for GHE Server instances)

    Returns:
        URL of the created or updated Issue, or None on failure
    """
    if not token or not repo:
        logger.warning("github_notify_skipped", reason="GHE_TOKEN or GHE_REPO not set")
        return None

    if requests is None:
        logger.error("github_notify_failed", reason="requests not installed")
        return None

    headers = {
        "Authorization": f"Bearer {token}",
        "Accept": "application/vnd.github+json",
        "X-GitHub-Api-Version": "2022-11-28",
    }

    existing = _find_existing_issue(headers, api_base, repo, title)

    try:
        if existing:
            # Update existing Issue body
            issue_number = existing["number"]
            url = f"{api_base}/repos/{repo}/issues/{issue_number}"
            resp = requests.patch(  # type: ignore[union-attr]
                url,
                json={"body": body},
                headers=headers,
                timeout=15,
            )
            resp.raise_for_status()
            issue_url = resp.json()["html_url"]
            logger.info("github_issue_updated", url=issue_url, number=issue_number)
            return issue_url
        else:
            # Create a new Issue
            _ensure_label(headers, api_base, repo)
            url = f"{api_base}/repos/{repo}/issues"
            resp = requests.post(  # type: ignore[union-attr]
                url,
                json={"title": title, "body": body, "labels": [_ISSUE_LABEL]},
                headers=headers,
                timeout=15,
            )
            resp.raise_for_status()
            issue_url = resp.json()["html_url"]
            logger.info("github_issue_created", url=issue_url)
            return issue_url
    except Exception as exc:
        logger.error("github_notify_failed", error=str(exc))
        return None


def _find_existing_issue(
    headers: dict,
    api_base: str,
    repo: str,
    title: str,
) -> dict | None:
    """Search for an open Issue with the same title."""
    try:
        url = f"{api_base}/repos/{repo}/issues"
        resp = requests.get(  # type: ignore[union-attr]
            url,
            params={"state": "open", "labels": _ISSUE_LABEL, "per_page": 50},
            headers=headers,
            timeout=10,
        )
        resp.raise_for_status()
        for issue in resp.json():
            if issue.get("title") == title:
                return issue
    except Exception as exc:
        logger.warning("github_search_failed", error=str(exc))
    return None


def _ensure_label(
    headers: dict,
    api_base: str,
    repo: str,
) -> None:
    """Create _ISSUE_LABEL in the repository if it does not already exist."""
    try:
        url = f"{api_base}/repos/{repo}/labels"
        resp = requests.post(  # type: ignore[union-attr]
            url,
            json={
                "name": _ISSUE_LABEL,
                "color": "d93f0b",
                "description": "SAGE auto-generated report",
            },
            headers=headers,
            timeout=10,
        )
        # 422 = label already exists (expected on subsequent runs)
        if resp.status_code not in (201, 422):
            resp.raise_for_status()
    except Exception as exc:
        logger.warning("github_label_ensure_failed", error=str(exc))
