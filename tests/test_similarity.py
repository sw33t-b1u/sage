"""tests/test_similarity.py — 類似インシデント検索のユニットテスト。"""

from __future__ import annotations

from unittest.mock import MagicMock, patch

from sage.analysis.similarity import (
    bfs_reachable,
    build_followedby_graph,
    find_similar_incidents,
    hybrid_score,
    jaccard_ttp,
    transition_coverage,
)

# ---------------------------------------------------------------------------
# FollowedBy グラフ構築
# ---------------------------------------------------------------------------


class TestBuildFollowedbyGraph:
    def test_basic(self):
        rows = [
            {"src_stix_id": "A", "dst_stix_id": "B", "weight": 0.8},
            {"src_stix_id": "B", "dst_stix_id": "C", "weight": 0.6},
        ]
        graph = build_followedby_graph(rows)
        assert graph == {"A": {"B"}, "B": {"C"}}

    def test_multi_dst(self):
        rows = [
            {"src_stix_id": "A", "dst_stix_id": "B", "weight": 0.5},
            {"src_stix_id": "A", "dst_stix_id": "C", "weight": 0.3},
        ]
        graph = build_followedby_graph(rows)
        assert graph["A"] == {"B", "C"}

    def test_empty(self):
        assert build_followedby_graph([]) == {}


# ---------------------------------------------------------------------------
# BFS 到達可能ノード
# ---------------------------------------------------------------------------


class TestBfsReachable:
    def _graph(self):
        return {"A": {"B"}, "B": {"C"}, "C": {"D"}}

    def test_zero_hops(self):
        result = bfs_reachable(self._graph(), {"A"}, max_hops=0)
        assert result == {"A"}

    def test_one_hop(self):
        result = bfs_reachable(self._graph(), {"A"}, max_hops=1)
        assert result == {"A", "B"}

    def test_two_hops(self):
        result = bfs_reachable(self._graph(), {"A"}, max_hops=2)
        assert result == {"A", "B", "C"}

    def test_multiple_start_nodes(self):
        result = bfs_reachable(self._graph(), {"A", "C"}, max_hops=1)
        assert "B" in result and "D" in result

    def test_cycle_safe(self):
        graph = {"A": {"B"}, "B": {"A"}}
        result = bfs_reachable(graph, {"A"}, max_hops=5)
        assert result == {"A", "B"}


# ---------------------------------------------------------------------------
# Jaccard 類似度
# ---------------------------------------------------------------------------


class TestJaccardTtp:
    def test_identical(self):
        assert jaccard_ttp({"A", "B"}, {"A", "B"}) == 1.0

    def test_disjoint(self):
        assert jaccard_ttp({"A"}, {"B"}) == 0.0

    def test_partial(self):
        j = jaccard_ttp({"A", "B"}, {"B", "C"})
        assert abs(j - 1 / 3) < 1e-9

    def test_both_empty(self):
        assert jaccard_ttp(set(), set()) == 1.0

    def test_one_empty(self):
        assert jaccard_ttp(set(), {"A"}) == 0.0


# ---------------------------------------------------------------------------
# transition_coverage
# ---------------------------------------------------------------------------


class TestTransitionCoverage:
    def _graph(self):
        # A → B → C
        return {"A": {"B"}, "B": {"C"}}

    def test_direct_match(self):
        score = transition_coverage({"A", "C"}, {"A", "C"}, self._graph())
        assert score == 1.0

    def test_missing_middle_covered_by_bfs(self):
        """HLD の worked example: incident=[A,C] vs reference=[A,B,C]"""
        score = transition_coverage({"A", "C"}, {"A", "B", "C"}, self._graph())
        assert score == 1.0

    def test_unreachable(self):
        """incident=[A] vs reference=[D] — D は到達不可"""
        graph = {"A": {"B"}}
        score = transition_coverage({"A"}, {"D"}, graph)
        assert score == 0.0

    def test_partial_coverage(self):
        graph = {"A": {"B"}}
        # A→B は到達可能、C は不可
        score = transition_coverage({"A"}, {"B", "C"}, graph, max_hops=1)
        assert abs(score - 0.5) < 1e-9

    def test_empty_ref(self):
        assert transition_coverage({"A"}, set(), {}) == 1.0


# ---------------------------------------------------------------------------
# ハイブリッドスコア
# ---------------------------------------------------------------------------


class TestHybridScore:
    def _graph(self):
        return {"A": {"B"}, "B": {"C"}}

    def test_worked_example(self):
        """HLD 7.3 worked example: jaccard=2/3, transition_coverage=1.0 → 0.83"""
        score = hybrid_score({"A", "C"}, {"A", "B", "C"}, self._graph())
        expected = 0.5 * (2 / 3) + 0.5 * 1.0
        assert abs(score - expected) < 1e-9

    def test_alpha_zero(self):
        """alpha=0 → transition_coverage のみ"""
        score = hybrid_score({"A"}, {"A", "B"}, self._graph(), alpha=0.0)
        # A→B は 1 ホップで到達可能 → coverage=1.0
        assert abs(score - 1.0) < 1e-9

    def test_alpha_one(self):
        """alpha=1 → jaccard のみ"""
        score = hybrid_score({"A", "B"}, {"A", "B", "C"}, self._graph(), alpha=1.0)
        j = jaccard_ttp({"A", "B"}, {"A", "B", "C"})
        assert abs(score - j) < 1e-9


# ---------------------------------------------------------------------------
# find_similar_incidents (Spanner モック)
# ---------------------------------------------------------------------------


class TestFindSimilarIncidents:
    def _make_db(self, query_ttps, all_ttps, followedby):
        """Spanner クエリをモックした database を返す。"""
        db = MagicMock()

        with (
            patch("sage.analysis.similarity.find_incident_ttps", return_value=query_ttps),
            patch("sage.analysis.similarity.find_followedby_edges", return_value=followedby),
            patch("sage.analysis.similarity.find_all_incident_ttps", return_value=all_ttps),
        ):
            yield db

    def test_returns_top_k(self):
        graph_rows = [
            {"src_stix_id": "A", "dst_stix_id": "B", "weight": 0.8},
        ]
        all_ttps = {
            "incident--ref-1": ["A", "B"],
            "incident--ref-2": ["C", "D"],
            "incident--ref-3": ["A", "X"],
        }

        db = MagicMock()
        with (
            patch("sage.analysis.similarity.find_incident_ttps", return_value=["A", "B"]),
            patch("sage.analysis.similarity.find_followedby_edges", return_value=graph_rows),
            patch("sage.analysis.similarity.find_all_incident_ttps", return_value=all_ttps),
        ):
            results = find_similar_incidents(db, "incident--query", top_k=2)

        assert len(results) == 2
        assert results[0]["hybrid_score"] >= results[1]["hybrid_score"]

    def test_excludes_self(self):
        all_ttps = {"incident--query": ["A", "B"], "incident--ref": ["A"]}

        db = MagicMock()
        with (
            patch("sage.analysis.similarity.find_incident_ttps", return_value=["A", "B"]),
            patch("sage.analysis.similarity.find_followedby_edges", return_value=[]),
            patch("sage.analysis.similarity.find_all_incident_ttps", return_value=all_ttps),
        ):
            results = find_similar_incidents(db, "incident--query")

        assert all(r["incident_id"] != "incident--query" for r in results)

    def test_empty_query_ttps_returns_empty(self):
        db = MagicMock()
        with (
            patch("sage.analysis.similarity.find_incident_ttps", return_value=[]),
            patch("sage.analysis.similarity.find_followedby_edges", return_value=[]),
            patch("sage.analysis.similarity.find_all_incident_ttps", return_value={}),
        ):
            results = find_similar_incidents(db, "incident--query")

        assert results == []

    def test_result_structure(self):
        all_ttps = {"incident--ref": ["A", "B"]}

        db = MagicMock()
        with (
            patch("sage.analysis.similarity.find_incident_ttps", return_value=["A"]),
            patch("sage.analysis.similarity.find_followedby_edges", return_value=[]),
            patch("sage.analysis.similarity.find_all_incident_ttps", return_value=all_ttps),
        ):
            results = find_similar_incidents(db, "incident--query")

        assert len(results) == 1
        r = results[0]
        assert "incident_id" in r
        assert "hybrid_score" in r
        assert "jaccard_ttp" in r
        assert "transition_coverage" in r
        assert "shared_ttps" in r
