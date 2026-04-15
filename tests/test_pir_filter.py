"""PIRFilter のユニットテスト。"""

from pathlib import Path

import pytest

from sage.pir.filter import PIRFilter

FIXTURES = Path(__file__).parent / "fixtures"


@pytest.fixture
def pir_filter():
    return PIRFilter.from_file(FIXTURES / "sample_pir.json")


@pytest.fixture
def empty_pir_filter():
    return PIRFilter([])


# ---------------------------------------------------------------------------
# ThreatActor フィルタリング
# ---------------------------------------------------------------------------


class TestIsRelevantActor:
    def test_actor_with_matching_tag_is_relevant(self, pir_filter):
        actor = {"stix_id": "x", "name": "APT99", "tags": ["apt", "targets-japan"]}
        assert pir_filter.is_relevant_actor(actor) is True

    def test_ransomware_actor_is_relevant(self, pir_filter):
        actor = {"stix_id": "x", "name": "LockBit", "tags": ["ransomware", "financially-motivated"]}
        assert pir_filter.is_relevant_actor(actor) is True

    def test_unrelated_actor_is_not_relevant(self, pir_filter):
        actor = {"stix_id": "x", "name": "GenericBot", "tags": ["botnet"]}
        assert pir_filter.is_relevant_actor(actor) is False

    def test_empty_pir_accepts_all(self, empty_pir_filter):
        actor = {"stix_id": "x", "name": "Anyone", "tags": []}
        assert empty_pir_filter.is_relevant_actor(actor) is True

    def test_actor_with_no_tags_is_not_relevant(self, pir_filter):
        actor = {"stix_id": "x", "name": "Unknown", "tags": []}
        assert pir_filter.is_relevant_actor(actor) is False


class TestActorRelevanceScore:
    def test_full_tag_overlap_scores_high(self, pir_filter):
        actor = {"tags": ["ransomware", "apt", "targets-japan"]}
        score = pir_filter.actor_relevance_score(actor)
        # pir_filter の threat_actor_tags は3件、全一致なら 1.0
        assert score == pytest.approx(1.0)

    def test_partial_overlap_scores_between_0_and_1(self, pir_filter):
        actor = {"tags": ["apt"]}  # 3件中1件一致 → 1/3
        score = pir_filter.actor_relevance_score(actor)
        assert 0.0 < score < 1.0

    def test_no_overlap_scores_zero(self, pir_filter):
        actor = {"tags": ["botnet"]}
        score = pir_filter.actor_relevance_score(actor)
        assert score == pytest.approx(0.0)


# ---------------------------------------------------------------------------
# 資産重み付け
# ---------------------------------------------------------------------------


class TestAdjustAssetCriticality:
    def test_external_facing_asset_is_boosted(self, pir_filter):
        asset = {"id": "a1", "name": "WebServer", "criticality": 5.0, "tags": ["external-facing"]}
        result = pir_filter.adjust_asset_criticality(asset)
        # multiplier=2.0 → 5.0 * 2.0 = 10.0
        assert result["pir_adjusted_criticality"] == pytest.approx(10.0)

    def test_s3_asset_multiplier(self, pir_filter):
        asset = {"id": "a2", "name": "S3Bucket", "criticality": 4.0, "tags": ["s3"]}
        result = pir_filter.adjust_asset_criticality(asset)
        # multiplier=1.8 → 4.0 * 1.8 = 7.2
        assert result["pir_adjusted_criticality"] == pytest.approx(7.2)

    def test_max_multiplier_applied_for_multiple_tags(self, pir_filter):
        # external-facing(2.0) と s3(1.8) の両方にマッチ → max=2.0 を適用
        asset = {
            "id": "a3",
            "name": "ExposedS3",
            "criticality": 5.0,
            "tags": ["external-facing", "s3"],
        }
        result = pir_filter.adjust_asset_criticality(asset)
        assert result["pir_adjusted_criticality"] == pytest.approx(10.0)

    def test_untagged_asset_unchanged(self, pir_filter):
        asset = {"id": "a4", "name": "InternalDB", "criticality": 5.0, "tags": ["database"]}
        result = pir_filter.adjust_asset_criticality(asset)
        assert result["pir_adjusted_criticality"] == pytest.approx(5.0)

    def test_criticality_capped_at_10(self, pir_filter):
        asset = {
            "id": "a5",
            "name": "CriticalServer",
            "criticality": 9.0,
            "tags": ["external-facing"],
        }
        result = pir_filter.adjust_asset_criticality(asset)
        assert result["pir_adjusted_criticality"] == pytest.approx(10.0)

    def test_original_row_not_mutated(self, pir_filter):
        asset = {"id": "a6", "name": "Server", "criticality": 5.0, "tags": ["external-facing"]}
        original_criticality = asset["criticality"]
        pir_filter.adjust_asset_criticality(asset)
        assert asset["criticality"] == original_criticality  # 元の dict を変更しない

    def test_adjust_assets_processes_all(self, pir_filter):
        assets = [
            {"id": "a1", "name": "Web", "criticality": 5.0, "tags": ["external-facing"]},
            {"id": "a2", "name": "DB", "criticality": 5.0, "tags": ["database"]},
        ]
        results = pir_filter.adjust_assets(assets)
        assert len(results) == 2
        assert results[0]["pir_adjusted_criticality"] == pytest.approx(10.0)
        assert results[1]["pir_adjusted_criticality"] == pytest.approx(5.0)


class TestBuildTargets:
    def test_generates_targets_for_matching_actor_and_asset(self, pir_filter):
        actors = [
            {"stix_id": "intrusion-set--apt99", "name": "APT99", "tags": ["apt", "targets-japan"]}
        ]
        assets = [{"id": "asset-001", "name": "WebServer", "tags": ["external-facing"]}]
        targets = pir_filter.build_targets(actors, assets)
        assert len(targets) == 1
        assert targets[0]["actor_stix_id"] == "intrusion-set--apt99"
        assert targets[0]["asset_id"] == "asset-001"
        assert targets[0]["source"] == "pir_auto"
        assert 0 < targets[0]["confidence"] <= 100

    def test_no_match_returns_empty(self, pir_filter):
        actors = [{"stix_id": "intrusion-set--apt99", "name": "APT99", "tags": ["apt"]}]
        assets = [{"id": "asset-001", "name": "InternalDB", "tags": ["database"]}]
        # assets の tags が PIR の asset_weight_rules にマッチしない
        targets = pir_filter.build_targets(actors, assets)
        assert targets == []

    def test_actor_not_in_pir_returns_empty(self, pir_filter):
        actors = [{"stix_id": "intrusion-set--unknown", "name": "Unknown", "tags": ["cybercrime"]}]
        assets = [{"id": "asset-001", "name": "WebServer", "tags": ["external-facing"]}]
        targets = pir_filter.build_targets(actors, assets)
        assert targets == []

    def test_deduplicates_same_pair_keeps_highest_confidence(self, pir_filter):
        # 同一ペアが複数 PIR からマッチする場合: デフォルト fixture は1PIR なので
        # 同一アクターが複数アセットにマッチするケースをテスト
        actors = [
            {"stix_id": "intrusion-set--apt99", "name": "APT99", "tags": ["apt", "targets-japan"]}
        ]
        assets = [
            {"id": "asset-001", "name": "Web", "tags": ["external-facing"]},
            {"id": "asset-002", "name": "Backup", "tags": ["backup"]},
        ]
        targets = pir_filter.build_targets(actors, assets)
        assert len(targets) == 2
        asset_ids = {t["asset_id"] for t in targets}
        assert "asset-001" in asset_ids
        assert "asset-002" in asset_ids

    def test_empty_pir_returns_empty(self, empty_pir_filter):
        actors = [{"stix_id": "actor-1", "tags": ["apt"]}]
        assets = [{"id": "asset-1", "tags": ["external-facing"]}]
        assert empty_pir_filter.build_targets(actors, assets) == []


# ---------------------------------------------------------------------------
# pir_adjusted_criticality 更新（Targets エッジ考慮）
# ---------------------------------------------------------------------------


class TestUpdateAssetCriticality:
    """PIRFilter.update_asset_criticality() のテスト。

    HLD 5.4 の計算式:
      adjusted = base × max_multiplier × targets_multiplier (上限 10.0)
      targets_multiplier = 1.5 if PIR-matched actor → asset の Targets エッジあり
    """

    def _actor(self, stix_id: str, tags: list[str]) -> dict:
        return {"stix_id": stix_id, "name": "TestActor", "tags": tags}

    def _asset(self, asset_id: str, tags: list[str], criticality: float = 5.0) -> dict:
        return {"id": asset_id, "name": "TestAsset", "tags": tags, "criticality": criticality}

    def _target(self, actor_id: str, asset_id: str) -> dict:
        return {"actor_stix_id": actor_id, "asset_id": asset_id, "confidence": 80}

    def test_targets_multiplier_applied_for_pir_matched_actor(self, pir_filter):
        # external-facing: 2.0 × Targets(PIR actor): 1.5 = 3.0 → 5.0 × 3.0 = 10.0 (上限)
        actors = [self._actor("actor-apt", ["apt", "targets-japan"])]
        assets = [self._asset("asset-001", ["external-facing"], criticality=3.0)]
        targets = [self._target("actor-apt", "asset-001")]

        result = pir_filter.update_asset_criticality(assets, actors, targets)

        assert len(result) == 1
        # 3.0 × 2.0 × 1.5 = 9.0
        assert result[0]["pir_adjusted_criticality"] == pytest.approx(9.0)

    def test_no_targets_edge_gives_no_extra_multiplier(self, pir_filter):
        actors = [self._actor("actor-apt", ["apt"])]
        assets = [self._asset("asset-001", ["external-facing"], criticality=3.0)]
        targets: list[dict] = []  # Targets エッジなし

        result = pir_filter.update_asset_criticality(assets, actors, targets)

        # 3.0 × 2.0 × 1.0 = 6.0
        assert result[0]["pir_adjusted_criticality"] == pytest.approx(6.0)

    def test_non_pir_actor_in_targets_gives_no_extra_multiplier(self, pir_filter):
        # Targets エッジはあるが、そのアクターが PIR にマッチしない
        actors = [self._actor("actor-unknown", ["cybercrime"])]
        assets = [self._asset("asset-001", ["external-facing"], criticality=3.0)]
        targets = [self._target("actor-unknown", "asset-001")]

        result = pir_filter.update_asset_criticality(assets, actors, targets)

        # 3.0 × 2.0 × 1.0 = 6.0
        assert result[0]["pir_adjusted_criticality"] == pytest.approx(6.0)

    def test_criticality_capped_at_10(self, pir_filter):
        actors = [self._actor("actor-apt", ["apt"])]
        assets = [self._asset("asset-001", ["external-facing"], criticality=5.0)]
        targets = [self._target("actor-apt", "asset-001")]

        result = pir_filter.update_asset_criticality(assets, actors, targets)

        # 5.0 × 2.0 × 1.5 = 15.0 → 上限 10.0
        assert result[0]["pir_adjusted_criticality"] == pytest.approx(10.0)

    def test_original_asset_row_not_mutated(self, pir_filter):
        asset = self._asset("asset-001", ["external-facing"])
        original_adjusted = asset.get("pir_adjusted_criticality")
        result = pir_filter.update_asset_criticality([asset], [], [])
        assert asset.get("pir_adjusted_criticality") == original_adjusted
        assert result[0] is not asset

    def test_empty_assets_returns_empty(self, pir_filter):
        result = pir_filter.update_asset_criticality([], [], [])
        assert result == []


# ---------------------------------------------------------------------------
# PIR ノード／カスケードエッジ生成
# ---------------------------------------------------------------------------


class TestBuildPirNodes:
    def test_emits_one_row_per_pir(self, pir_filter):
        rows = pir_filter.build_pir_nodes()
        assert len(rows) == 1
        row = rows[0]
        assert row["pir_id"] == "PIR-2025-001"
        assert row["intelligence_level"] == "operational"
        assert row["threat_actor_tags"] == ["ransomware", "apt", "targets-japan"]

    def test_empty_pir_returns_empty(self, empty_pir_filter):
        assert empty_pir_filter.build_pir_nodes() == []


class TestBuildPirActorEdges:
    def test_emits_edge_for_overlapping_actor(self, pir_filter):
        actors = [
            {"stix_id": "actor-1", "tags": ["ransomware", "apt", "targets-japan"]},
            {"stix_id": "actor-2", "tags": ["botnet"]},
        ]
        edges = pir_filter.build_pir_actor_edges(actors)
        assert len(edges) == 1
        assert edges[0]["pir_id"] == "PIR-2025-001"
        assert edges[0]["actor_stix_id"] == "actor-1"
        assert edges[0]["overlap_ratio"] == pytest.approx(1.0)

    def test_partial_overlap(self, pir_filter):
        actors = [{"stix_id": "actor-1", "tags": ["apt"]}]
        edges = pir_filter.build_pir_actor_edges(actors)
        assert edges[0]["overlap_ratio"] == pytest.approx(round(1 / 3, 4))


class TestBuildPirTtpEdges:
    def test_transitive_ttp_edges_from_uses(self, pir_filter):
        actors = [{"stix_id": "actor-1", "tags": ["apt"]}]
        pir_actor_edges = pir_filter.build_pir_actor_edges(actors)
        uses = [
            {"actor_stix_id": "actor-1", "ttp_stix_id": "ttp-A"},
            {"actor_stix_id": "actor-1", "ttp_stix_id": "ttp-B"},
            {"actor_stix_id": "actor-2", "ttp_stix_id": "ttp-C"},
        ]
        edges = pir_filter.build_pir_ttp_edges(uses, pir_actor_edges)
        ttp_ids = {e["ttp_stix_id"] for e in edges}
        assert ttp_ids == {"ttp-A", "ttp-B"}
        assert all(e["pir_id"] == "PIR-2025-001" for e in edges)

    def test_dedupes_same_pair(self, pir_filter):
        actors = [
            {"stix_id": "actor-1", "tags": ["apt"]},
            {"stix_id": "actor-2", "tags": ["ransomware"]},
        ]
        pir_actor_edges = pir_filter.build_pir_actor_edges(actors)
        uses = [
            {"actor_stix_id": "actor-1", "ttp_stix_id": "ttp-A"},
            {"actor_stix_id": "actor-2", "ttp_stix_id": "ttp-A"},
        ]
        edges = pir_filter.build_pir_ttp_edges(uses, pir_actor_edges)
        assert len(edges) == 1


class TestBuildPirAssetEdges:
    def test_picks_max_multiplier(self, pir_filter):
        assets = [{"id": "a1", "tags": ["external-facing", "s3"]}]
        edges = pir_filter.build_pir_asset_edges(assets)
        assert len(edges) == 1
        assert edges[0]["criticality_multiplier"] == pytest.approx(2.0)
        assert edges[0]["matched_tag"] == "external-facing"

    def test_no_matching_tag_skipped(self, pir_filter):
        assets = [{"id": "a1", "tags": ["database"]}]
        assert pir_filter.build_pir_asset_edges(assets) == []
