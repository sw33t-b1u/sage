"""sage.notify.slack / sage.notify.github のユニットテスト。

requests をモックして HTTP リクエストを実際には送らない。
"""

from __future__ import annotations

from unittest.mock import MagicMock, patch

from sage.notify.github import post_choke_point_issue
from sage.notify.slack import _detect_changes, notify_etl_complete

# ---------------------------------------------------------------------------
# Slack
# ---------------------------------------------------------------------------


class TestDetectChanges:
    def _row(self, asset_id: str, score: float, count: int = 1) -> dict:
        return {
            "asset_id": asset_id,
            "asset_name": f"Asset-{asset_id}",
            "choke_score": score,
            "pir_adjusted_criticality": 5.0,
            "targeting_actor_count": count,
        }

    def test_new_asset_detected(self):
        current = [self._row("asset-new", 10.0)]
        changed = _detect_changes(current, [])
        assert len(changed) == 1
        assert changed[0]["change"] == "new"

    def test_score_increase_above_threshold(self):
        current = [self._row("asset-001", 11.0)]
        previous = [self._row("asset-001", 10.0)]
        changed = _detect_changes(current, previous)
        assert len(changed) == 1
        assert changed[0]["change"] == "increased"

    def test_score_decrease_above_threshold(self):
        current = [self._row("asset-001", 8.0)]
        previous = [self._row("asset-001", 10.0)]
        changed = _detect_changes(current, previous)
        assert len(changed) == 1
        assert changed[0]["change"] == "decreased"

    def test_small_change_not_detected(self):
        # 5% 変化はしきい値 10% 未満 → 検知しない
        current = [self._row("asset-001", 10.5)]
        previous = [self._row("asset-001", 10.0)]
        changed = _detect_changes(current, previous)
        assert changed == []

    def test_unchanged_asset_not_detected(self):
        current = [self._row("asset-001", 10.0)]
        previous = [self._row("asset-001", 10.0)]
        changed = _detect_changes(current, previous)
        assert changed == []


class TestNotifyEtlComplete:
    def _choke_row(self, asset_id: str, score: float) -> dict:
        return {
            "asset_id": asset_id,
            "asset_name": f"Asset-{asset_id}",
            "choke_score": score,
            "pir_adjusted_criticality": 5.0,
            "targeting_actor_count": 2,
        }

    def test_no_webhook_url_returns_false(self):
        result = notify_etl_complete("", {}, [], [])
        assert result is False

    def test_no_changes_returns_false(self):
        rows = [self._choke_row("asset-001", 10.0)]
        result = notify_etl_complete("https://hooks.slack.com/x", {}, rows, rows)
        assert result is False

    def test_posts_when_changes_detected(self):
        mock_resp = MagicMock()
        mock_resp.raise_for_status.return_value = None

        with patch("sage.notify.slack._post", return_value=True) as mock_post:
            current = [self._choke_row("asset-new", 15.0)]
            result = notify_etl_complete(
                "https://hooks.slack.com/x",
                {"threat_actors": 2, "ttps": 5},
                current,
                [],
            )
        assert result is True
        mock_post.assert_called_once()


# ---------------------------------------------------------------------------
# GitHub
# ---------------------------------------------------------------------------


class TestPostChokePointIssue:
    def test_no_token_returns_none(self):
        result = post_choke_point_issue("", "owner/repo", "title", "body")
        assert result is None

    def test_no_repo_returns_none(self):
        result = post_choke_point_issue("token", "", "title", "body")
        assert result is None

    def test_creates_new_issue_when_none_exists(self):
        mock_get = MagicMock()
        mock_get.raise_for_status.return_value = None
        mock_get.json.return_value = []  # 既存 Issue なし

        mock_post_label = MagicMock()
        mock_post_label.status_code = 201
        mock_post_label.raise_for_status.return_value = None

        mock_post_issue = MagicMock()
        mock_post_issue.raise_for_status.return_value = None
        mock_post_issue.json.return_value = {"html_url": "https://github.com/owner/repo/issues/1"}

        with patch("sage.notify.github.requests") as mock_requests:
            mock_requests.get.return_value = mock_get
            mock_requests.post.side_effect = [mock_post_label, mock_post_issue]

            result = post_choke_point_issue(
                "token", "owner/repo", "title", "body",
                api_base="https://api.github.com",
            )

        assert result == "https://github.com/owner/repo/issues/1"

    def test_updates_existing_issue(self):
        mock_get = MagicMock()
        mock_get.raise_for_status.return_value = None
        mock_get.json.return_value = [{"number": 42, "title": "title"}]

        mock_patch = MagicMock()
        mock_patch.raise_for_status.return_value = None
        mock_patch.json.return_value = {"html_url": "https://github.com/owner/repo/issues/42"}

        with patch("sage.notify.github.requests") as mock_requests:
            mock_requests.get.return_value = mock_get
            mock_requests.patch.return_value = mock_patch

            result = post_choke_point_issue(
                "token", "owner/repo", "title", "body",
                api_base="https://api.github.com",
            )

        assert result == "https://github.com/owner/repo/issues/42"
        mock_requests.patch.assert_called_once()
