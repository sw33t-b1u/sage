"""tests/test_caldera.py — Caldera クライアントのユニットテスト。"""

from __future__ import annotations

from unittest.mock import MagicMock, patch

import sage.caldera.client as caldera_module
from sage.caldera.client import (
    create_adversary,
    get_adversaries,
    sync_actor_ttps,
    update_adversary,
)

_URL = "http://caldera.internal:8888"
_KEY = "test-api-key"


class TestGetAdversaries:
    def test_returns_list(self):
        mock_resp = MagicMock()
        mock_resp.json.return_value = [{"name": "SAGE-apt99", "adversary_id": "aaa"}]
        mock_resp.raise_for_status.return_value = None

        with patch.object(caldera_module.requests, "get", return_value=mock_resp) as mock_get:
            result = get_adversaries(_URL, _KEY)

        mock_get.assert_called_once()
        assert len(result) == 1
        assert result[0]["name"] == "SAGE-apt99"

    def test_returns_empty_on_error(self):
        with patch.object(caldera_module.requests, "get", side_effect=Exception("timeout")):
            result = get_adversaries(_URL, _KEY)
        assert result == []


class TestCreateAdversary:
    def test_success(self):
        mock_resp = MagicMock()
        mock_resp.json.return_value = {"adversary_id": "new-id", "name": "SAGE-apt99"}
        mock_resp.raise_for_status.return_value = None

        with patch.object(caldera_module.requests, "post", return_value=mock_resp):
            result = create_adversary(_URL, _KEY, "SAGE-apt99", "desc", ["ability-1"])

        assert result is not None
        assert result["adversary_id"] == "new-id"

    def test_returns_none_on_error(self):
        with patch.object(caldera_module.requests, "post", side_effect=Exception("refused")):
            result = create_adversary(_URL, _KEY, "SAGE-apt99", "desc", [])
        assert result is None


class TestUpdateAdversary:
    def test_success(self):
        mock_resp = MagicMock()
        mock_resp.raise_for_status.return_value = None

        with patch.object(caldera_module.requests, "patch", return_value=mock_resp):
            ok = update_adversary(_URL, _KEY, "adv-id", ["ability-1", "ability-2"])

        assert ok is True

    def test_failure(self):
        with patch.object(caldera_module.requests, "patch", side_effect=Exception("not found")):
            ok = update_adversary(_URL, _KEY, "adv-id", [])
        assert ok is False


class TestSyncActorTtps:
    _ttp_rows = [
        {"src_ttp_stix_id": "attack-pattern--t1078", "dst_ttp_stix_id": "attack-pattern--t1068"},
        {"src_ttp_stix_id": "attack-pattern--t1068", "dst_ttp_stix_id": "attack-pattern--t1021"},
    ]

    def test_creates_when_not_exists(self):
        with (
            patch.object(
                caldera_module,
                "get_adversaries",
                return_value=[],
            ),
            patch.object(
                caldera_module,
                "create_adversary",
                return_value={"adversary_id": "new-id"},
            ) as mock_create,
        ):
            result = sync_actor_ttps(_URL, _KEY, "intrusion-set--apt99", self._ttp_rows)

        assert result["action"] == "created"
        assert result["adversary_id"] == "new-id"
        assert result["ability_count"] == 3  # 3 unique TTPs
        mock_create.assert_called_once()

    def test_updates_when_exists(self):
        existing = [{"name": "SAGE-intrusion-set--apt99", "adversary_id": "existing-id"}]

        with (
            patch.object(caldera_module, "get_adversaries", return_value=existing),
            patch.object(caldera_module, "update_adversary", return_value=True) as mock_update,
        ):
            result = sync_actor_ttps(_URL, _KEY, "intrusion-set--apt99", self._ttp_rows)

        assert result["action"] == "updated"
        assert result["adversary_id"] == "existing-id"
        mock_update.assert_called_once()

    def test_skipped_on_create_failure(self):
        with (
            patch.object(caldera_module, "get_adversaries", return_value=[]),
            patch.object(caldera_module, "create_adversary", return_value=None),
        ):
            result = sync_actor_ttps(_URL, _KEY, "intrusion-set--apt99", self._ttp_rows)

        assert result["action"] == "skipped"

    def test_deduplicates_ttps(self):
        ttp_rows = [
            {"src_ttp_stix_id": "A", "dst_ttp_stix_id": "B"},
            {"src_ttp_stix_id": "A", "dst_ttp_stix_id": "C"},  # A is duplicate
        ]
        with (
            patch.object(caldera_module, "get_adversaries", return_value=[]),
            patch.object(
                caldera_module,
                "create_adversary",
                return_value={"adversary_id": "x"},
            ) as mock_create,
        ):
            result = sync_actor_ttps(_URL, _KEY, "intrusion-set--test", ttp_rows)

        assert result["ability_count"] == 3  # A, B, C (no duplicate)
        _, kwargs = mock_create.call_args
        # atomic_ordering は位置引数で渡されるため args を確認
        call_args = mock_create.call_args[0]
        assert len(call_args[4]) == 3  # atomic_ordering
