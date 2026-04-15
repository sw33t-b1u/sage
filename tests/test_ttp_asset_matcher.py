"""Unit tests for TTP → Asset derivation."""

from __future__ import annotations

from sage.analysis.ttp_asset_matcher import build_ttp_asset_edges


def _ttp(tech_id: str, stix_id: str | None = None) -> dict:
    return {
        "stix_id": stix_id or f"attack-pattern--{tech_id}",
        "attack_technique_id": tech_id,
    }


def _asset(asset_id: str, tags: list[str], asset_type: str = "server") -> dict:
    return {"id": asset_id, "tags": tags, "asset_type": asset_type}


def test_technique_matches_asset_tag():
    edges = build_ttp_asset_edges(
        ttp_rows=[_ttp("T1078")],
        asset_rows=[_asset("asset-A", ["identity", "database"])],
    )
    assert len(edges) == 1
    assert edges[0]["ttp_stix_id"].endswith("T1078")
    assert edges[0]["asset_id"] == "asset-A"
    assert edges[0]["match_reason"] in {"identity", "ad", "sso"}


def test_sub_technique_falls_through_to_parent():
    # T1566.004 should match the T1566 rule.
    edges = build_ttp_asset_edges(
        ttp_rows=[_ttp("T1566.004")],
        asset_rows=[_asset("asset-EP", ["endpoint"], asset_type="endpoint")],
    )
    assert len(edges) == 1
    assert edges[0]["match_reason"] == "endpoint"


def test_no_match_emits_no_edge():
    # T1190 needs "external-facing"; asset has none.
    edges = build_ttp_asset_edges(
        ttp_rows=[_ttp("T1190")],
        asset_rows=[_asset("asset-internal", ["database"])],
    )
    assert edges == []


def test_unknown_technique_skipped():
    edges = build_ttp_asset_edges(
        ttp_rows=[_ttp("T9999")],
        asset_rows=[_asset("asset-any", ["identity"])],
    )
    assert edges == []


def test_asset_type_contributes_to_match():
    # T1543 targets "server" or "endpoint"; tag list is empty but asset_type matches.
    edges = build_ttp_asset_edges(
        ttp_rows=[_ttp("T1543")],
        asset_rows=[_asset("asset-srv", [], asset_type="server")],
    )
    assert len(edges) == 1
    assert edges[0]["match_reason"] == "server"


def test_many_to_many_expansion():
    ttps = [_ttp("T1078"), _ttp("T1486")]
    assets = [
        _asset("a1", ["identity"]),
        _asset("a2", ["database"]),
        _asset("a3", ["backup"]),
    ]
    edges = build_ttp_asset_edges(ttps, assets)
    pairs = {(e["ttp_stix_id"].split("--")[1], e["asset_id"]) for e in edges}
    assert ("T1078", "a1") in pairs
    assert ("T1486", "a2") in pairs
    assert ("T1486", "a3") in pairs
    assert ("T1078", "a2") not in pairs
