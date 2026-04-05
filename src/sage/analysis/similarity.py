"""IR Feedback — similar incident search.

Computes a hybrid similarity score to rank incidents.

  hybrid_score = alpha × jaccard_ttp + (1 - alpha) × transition_coverage

- jaccard_ttp: Jaccard similarity of the TTP sets of two incidents
- transition_coverage: fraction of the reference incident's TTPs that are
  reachable from the query incident within max_hops hops on the FollowedBy graph
"""

from __future__ import annotations

from collections import deque
from typing import Any

import structlog
from google.cloud.spanner_v1.database import Database

from sage.spanner.query import find_all_incident_ttps, find_followedby_edges, find_incident_ttps

logger = structlog.get_logger(__name__)


# ---------------------------------------------------------------------------
# Graph construction utilities
# ---------------------------------------------------------------------------


def build_followedby_graph(
    followedby_rows: list[dict[str, Any]],
) -> dict[str, set[str]]:
    """Build a directed graph from a list of FollowedBy edges.

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
    """Return all nodes reachable from start_nodes within max_hops via BFS.

    Includes start_nodes themselves.
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
# Score calculation
# ---------------------------------------------------------------------------


def jaccard_ttp(set_a: set[str], set_b: set[str]) -> float:
    """Return the Jaccard similarity of two TTP sets."""
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
    """Return the fraction of ref_ttps reachable from incident_ttps.

    Reachable means: directly contained in incident_ttps, or reachable within
    max_hops hops on the FollowedBy graph.

    Returns:
        float in range 0.0–1.0
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
    """Compute the hybrid similarity score.

    hybrid_score = alpha × jaccard_ttp + (1 - alpha) × transition_coverage
    """
    j = jaccard_ttp(incident_ttps, ref_ttps)
    t = transition_coverage(incident_ttps, ref_ttps, followedby_graph, max_hops)
    return alpha * j + (1.0 - alpha) * t


# ---------------------------------------------------------------------------
# Spanner integration: similar incident search
# ---------------------------------------------------------------------------


def find_similar_incidents(
    database: Database,
    incident_id: str,
    top_k: int = 5,
    alpha: float = 0.5,
    max_hops: int = 2,
) -> list[dict[str, Any]]:
    """Return historical incidents most similar to the specified incident, ordered by score.

    Args:
        database: Spanner Database instance
        incident_id: STIX ID of the query incident
        top_k: Number of top results to return
        alpha: Weight for jaccard_ttp component
        max_hops: Maximum BFS hops on the FollowedBy graph

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
