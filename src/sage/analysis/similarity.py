"""IR Feedback — 類似インシデント検索。

ハイブリッド類似度スコアを計算してインシデントをランキングする。

  hybrid_score = alpha × jaccard_ttp + (1 - alpha) × transition_coverage

- jaccard_ttp: 2つのインシデントの TTP 集合の Jaccard 類似度
- transition_coverage: FollowedBy グラフ上で参照インシデントの TTP が
  クエリインシデントから最大 max_hops ホップで到達可能な割合
"""

from __future__ import annotations

from collections import deque
from typing import Any

import structlog
from google.cloud.spanner_v1.database import Database

from sage.spanner.query import find_all_incident_ttps, find_followedby_edges, find_incident_ttps

logger = structlog.get_logger(__name__)


# ---------------------------------------------------------------------------
# グラフ構築ユーティリティ
# ---------------------------------------------------------------------------


def build_followedby_graph(
    followedby_rows: list[dict[str, Any]],
) -> dict[str, set[str]]:
    """FollowedBy エッジ一覧から有向グラフを構築する。

    Returns:
        {src_stix_id: {dst_stix_id, ...}, ...}
    """
    graph: dict[str, set[str]] = {}
    for row in followedby_rows:
        src = row["src_stix_id"]
        dst = row["dst_stix_id"]
        graph.setdefault(src, set()).add(dst)
    return graph


def bfs_reachable(
    graph: dict[str, set[str]],
    start_nodes: set[str],
    max_hops: int,
) -> set[str]:
    """BFS で start_nodes から max_hops 以内に到達可能なノードを返す。

    start_nodes 自身も含む。
    """
    visited: set[str] = set(start_nodes)
    frontier: deque[tuple[str, int]] = deque((n, 0) for n in start_nodes)

    while frontier:
        node, depth = frontier.popleft()
        if depth >= max_hops:
            continue
        for neighbor in graph.get(node, set()):
            if neighbor not in visited:
                visited.add(neighbor)
                frontier.append((neighbor, depth + 1))

    return visited


# ---------------------------------------------------------------------------
# スコア計算
# ---------------------------------------------------------------------------


def jaccard_ttp(set_a: set[str], set_b: set[str]) -> float:
    """2 つの TTP 集合の Jaccard 類似度を返す。"""
    if not set_a and not set_b:
        return 1.0
    union = set_a | set_b
    if not union:
        return 0.0
    return len(set_a & set_b) / len(union)


def transition_coverage(
    incident_ttps: set[str],
    ref_ttps: set[str],
    followedby_graph: dict[str, set[str]],
    max_hops: int = 2,
) -> float:
    """参照インシデントの TTP がクエリインシデントから到達可能な割合。

    到達可能: クエリの TTP に直接含まれるか、FollowedBy グラフ上で
    max_hops 以内に辿り着けるか。

    Returns:
        0.0〜1.0 の float
    """
    if not ref_ttps:
        return 1.0

    reachable = bfs_reachable(followedby_graph, incident_ttps, max_hops)
    covered = len(ref_ttps & reachable)
    return covered / len(ref_ttps)


def hybrid_score(
    incident_ttps: set[str],
    ref_ttps: set[str],
    followedby_graph: dict[str, set[str]],
    alpha: float = 0.5,
    max_hops: int = 2,
) -> float:
    """ハイブリッド類似度スコアを計算する。

    hybrid_score = alpha × jaccard_ttp + (1 - alpha) × transition_coverage
    """
    j = jaccard_ttp(incident_ttps, ref_ttps)
    t = transition_coverage(incident_ttps, ref_ttps, followedby_graph, max_hops)
    return alpha * j + (1.0 - alpha) * t


# ---------------------------------------------------------------------------
# Spanner 連携: 類似インシデント検索
# ---------------------------------------------------------------------------


def find_similar_incidents(
    database: Database,
    incident_id: str,
    top_k: int = 5,
    alpha: float = 0.5,
    max_hops: int = 2,
) -> list[dict[str, Any]]:
    """指定インシデントに類似した過去インシデントをスコア順で返す。

    Args:
        database: Spanner Database インスタンス
        incident_id: クエリインシデントの STIX ID
        top_k: 返す上位件数
        alpha: jaccard_ttp の重み
        max_hops: FollowedBy BFS の最大ホップ数

    Returns:
        [
          {
            "incident_id": "incident--xxx",
            "hybrid_score": 0.83,
            "jaccard_ttp": 0.67,
            "transition_coverage": 1.0,
            "shared_ttps": ["attack-pattern--t1078", ...],
          },
          ...
        ]
    """
    query_ttps = set(find_incident_ttps(database, incident_id))
    if not query_ttps:
        logger.warning("find_similar_incidents_empty", incident_id=incident_id)
        return []

    followedby_rows = find_followedby_edges(database)
    graph = build_followedby_graph(followedby_rows)

    all_ttps = find_all_incident_ttps(database)

    results = []
    for ref_id, ref_ttp_list in all_ttps.items():
        if ref_id == incident_id:
            continue
        ref_ttps = set(ref_ttp_list)
        j = jaccard_ttp(query_ttps, ref_ttps)
        t = transition_coverage(query_ttps, ref_ttps, graph, max_hops)
        score = alpha * j + (1.0 - alpha) * t
        results.append({
            "incident_id": ref_id,
            "hybrid_score": round(score, 4),
            "jaccard_ttp": round(j, 4),
            "transition_coverage": round(t, 4),
            "shared_ttps": sorted(query_ttps & ref_ttps),
        })

    results.sort(key=lambda x: x["hybrid_score"], reverse=True)
    logger.info(
        "find_similar_incidents",
        incident_id=incident_id,
        candidates=len(results),
        top_k=top_k,
    )
    return results[:top_k]
