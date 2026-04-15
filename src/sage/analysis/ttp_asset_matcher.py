"""TTP → Asset derivation via ATT&CK technique and asset-tag matching.

Purpose
-------
Most STIX feeds do not link attack-patterns to specific CVEs, and asset
inventories rarely enumerate CVEs at the row level.  To close the gap
between "which TTPs does this actor use" and "which of my assets are
exposed to those TTPs", we derive TTP → Asset edges from two stable
signals that already live in the graph:

* ATT&CK technique ID prefix (e.g. T1078 = Valid Accounts).
* Asset tags (e.g. "identity", "database", "external-facing").

The mapping below is a small, auditable dictionary.  It is intentionally
coarse — the goal is "this TTP can hit this class of asset", not a
vulnerability-level claim.  For TTPs not covered here, no edge is
emitted (fail-closed).
"""

from __future__ import annotations

# ATT&CK technique-ID prefix → asset-tag categories the TTP plausibly targets.
# Prefix is matched against the first five chars of attack_technique_id
# (e.g. "T1190").  Sub-techniques (T1566.001) fall through to the parent.
TECHNIQUE_TAG_MAP: dict[str, set[str]] = {
    # Initial access
    "T1190": {"external-facing"},
    "T1566": {"endpoint", "email"},
    "T1133": {"external-facing", "remote-access"},
    "T1199": {"saas", "cloud"},
    # Credential access / identity
    "T1078": {"identity", "ad", "sso"},
    "T1110": {"identity", "ad", "sso"},
    "T1003": {"identity", "ad"},
    "T1552": {"identity"},
    "T1550": {"identity", "ad"},
    "T1098": {"identity", "ad"},
    "T1482": {"ad"},
    "T1484": {"ad"},
    # Remote access / lateral movement
    "T1021": {"remote-access", "ad", "file-server"},
    "T1572": {"remote-access", "network-device"},
    "T1090": {"network-device"},
    # Data / exfil / impact
    "T1486": {"database", "file-server", "backup", "endpoint"},
    "T1490": {"backup"},
    "T1491": {"external-facing"},
    "T1213": {"database", "file-server"},
    "T1530": {"cloud", "cloud-storage"},
    "T1560": {"database", "file-server"},
    "T1567": {"external-facing"},
    "T1041": {"external-facing"},
    "T1048": {"external-facing"},
    # Discovery
    "T1083": {"file-server"},
    "T1018": {"ad"},
    "T1087": {"ad", "identity"},
    # Server-side execution / persistence
    "T1505": {"server", "file-server"},
    "T1543": {"server", "endpoint"},
    "T1547": {"endpoint"},
    # Cloud admin
    "T1651": {"cloud"},
    # OT / firmware / physical
    "T0801": {"ot"},
    "T0886": {"ot"},
}


def build_ttp_asset_edges(
    ttp_rows: list[dict],
    asset_rows: list[dict],
) -> list[dict]:
    """Derive TTP → Asset edges from technique-ID → asset-tag matching.

    For each TTP row with an ``attack_technique_id`` whose prefix is in
    ``TECHNIQUE_TAG_MAP``, emit one edge per asset whose ``tags`` or
    ``asset_type`` intersects the mapped tag set.

    The returned dicts map to the TargetsAsset table columns:
    ``ttp_stix_id``, ``asset_id``, ``match_reason``.
    ``match_reason`` records the tag that matched, so analysts can audit
    why a TTP was linked to a given asset.
    """
    edges: list[dict] = []
    for ttp in ttp_rows:
        tech_id = (ttp.get("attack_technique_id") or "").split(".")[0][:5]
        targets = TECHNIQUE_TAG_MAP.get(tech_id)
        if not targets:
            continue
        for asset in asset_rows:
            asset_signals = set(asset.get("tags") or [])
            if asset.get("asset_type"):
                asset_signals.add(asset["asset_type"])
            matched = targets & asset_signals
            if not matched:
                continue
            edges.append(
                {
                    "ttp_stix_id": ttp["stix_id"],
                    "asset_id": asset["id"],
                    "match_reason": sorted(matched)[0],
                }
            )
    return edges
