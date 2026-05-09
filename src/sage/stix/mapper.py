"""STIX 2.1 objects → Spanner node/edge row conversion.

Each map_* method returns a dict suitable for Spanner INSERT OR UPDATE.
Objects outside the target scope return None (caller skips them).
"""

from __future__ import annotations

import re
from collections import defaultdict
from datetime import UTC, datetime, timedelta
from typing import Any

# ATT&CK kill chain phase order (used for FollowedBy weight calculation)
PHASE_ORDER: dict[str, int] = {
    "reconnaissance": 0,
    "resource-development": 1,
    "initial-access": 2,
    "execution": 3,
    "persistence": 4,
    "privilege-escalation": 5,
    "defense-evasion": 6,
    "credential-access": 7,
    "discovery": 8,
    "lateral-movement": 9,
    "collection": 10,
    "command-and-control": 11,
    "exfiltration": 12,
    "impact": 13,
}

# Extraction rules for STIX Indicator patterns: (obs_type, regex)
_INDICATOR_PATTERNS: list[tuple[str, str]] = [
    ("ip", r"\[ipv4-addr:value\s*=\s*'([^']+)'\]"),
    ("ip", r"\[ipv6-addr:value\s*=\s*'([^']+)'\]"),
    ("domain", r"\[domain-name:value\s*=\s*'([^']+)'\]"),
    ("hash", r"\[file:hashes\.'[^']+'\s*=\s*'([^']+)'\]"),
    ("email", r"\[email-addr:value\s*=\s*'([^']+)'\]"),
    ("url", r"\[url:value\s*=\s*'([^']+)'\]"),
]


class StixMapper:
    """Maps STIX 2.1 objects to the Spanner schema."""

    # -----------------------------------------------------------------------
    # Node mappers
    # -----------------------------------------------------------------------

    def map_threat_actor(self, obj: dict) -> dict | None:
        if obj["type"] not in ("threat-actor", "intrusion-set"):
            return None
        return {
            "stix_id": obj["id"],
            "stix_type": obj["type"],
            "name": obj["name"],
            "aliases": obj.get("aliases", []),
            "sophistication": obj.get("sophistication"),
            "motivation": obj.get("primary_motivation"),
            "tags": list(obj.get("labels", [])),
            "first_seen": _to_ts(obj.get("first_seen")),
            "last_seen": _to_ts(obj.get("last_seen")),
            "stix_modified": _to_ts(obj.get("modified")) or _now(),
        }

    def map_ttp(self, obj: dict) -> dict | None:
        if obj["type"] != "attack-pattern":
            return None
        return {
            "stix_id": obj["id"],
            "attack_technique_id": _mitre_technique_id(obj),
            "tactic": _kill_chain_phase(obj),
            "name": obj["name"],
            "description": obj.get("description"),
            "platforms": obj.get("x_mitre_platforms", []),
            "detection_difficulty": None,  # Set when Summiting the Pyramid integration is enabled
            "stix_modified": _to_ts(obj.get("modified")) or _now(),
        }

    def map_vulnerability(self, obj: dict) -> dict | None:
        if obj["type"] != "vulnerability":
            return None
        return {
            "stix_id": obj["id"],
            "cve_id": obj.get("name"),
            "description": obj.get("description"),
            "cvss_score": _cvss_score(obj),
            "epss_score": None,  # Set when EPSS API integration is enabled
            "affected_platforms": obj.get("x_affected_platforms", []),
            "published_date": _to_ts(obj.get("created")),
            "stix_modified": _to_ts(obj.get("modified")) or _now(),
        }

    def map_malware_tool(self, obj: dict) -> dict | None:
        if obj["type"] not in ("malware", "tool"):
            return None
        return {
            "stix_id": obj["id"],
            "stix_type": obj["type"],
            "name": obj["name"],
            "description": obj.get("description"),
            "capabilities": obj.get("capabilities", []),
            "stix_modified": _to_ts(obj.get("modified")) or _now(),
        }

    def map_observable(self, obj: dict) -> dict | None:
        """Generate an Observable row from an indicator object."""
        if obj["type"] != "indicator":
            return None
        extracted = _extract_indicator(obj.get("pattern", ""))
        if not extracted:
            return None
        obs_type, value = extracted
        return {
            "stix_id": obj["id"],
            "obs_type": obs_type,
            "value": value,
            "confidence": obj.get("confidence"),
            "tlp": _tlp(obj),
            "first_seen": _to_ts(obj.get("valid_from")),
            "last_seen": _to_ts(obj.get("valid_until")),
            "stix_modified": _to_ts(obj.get("modified")) or _now(),
        }

    def map_identity(self, obj: dict) -> dict | None:
        """Map a STIX 2.1 §4.4 ``identity`` SDO to an Identity row.

        Added in SAGE 0.5.0 alongside TRACE 1.0.0's identity extraction.
        ``deleted_at`` defaults to NULL — SAGE-internal soft-delete is
        managed by HR-side workflows, not by the upstream STIX object.
        """
        if obj["type"] != "identity":
            return None
        return {
            "stix_id": obj["id"],
            "name": obj["name"],
            "identity_class": obj.get("identity_class"),
            "sectors": list(obj.get("sectors", [])),
            "description": obj.get("description"),
            "contact_information": obj.get("contact_information"),
            "roles": list(obj.get("roles", [])),
            "deleted_at": None,
            "stix_modified": _to_ts(obj.get("modified")) or _now(),
        }

    def map_incident(self, obj: dict) -> dict | None:
        if obj["type"] != "incident":
            return None
        return {
            "stix_id": obj["id"],
            "name": obj["name"],
            "description": obj.get("description"),
            "occurred_at": _to_ts(obj.get("first_seen")),
            "resolved_at": _to_ts(obj.get("last_seen")),
            "severity": obj.get("severity"),
            "kill_chain_phases": [
                p.get("phase_name", "") for p in obj.get("kill_chain_phases", [])
            ],
            "diamond_model": obj.get("x_diamond_model"),
            "source": "ir_feedback",
            "stix_modified": _to_ts(obj.get("modified")) or _now(),
        }

    def map_incident_ttp_edges(self, obj: dict) -> list[dict]:
        """Generate IncidentUsesTTP rows from an incident object.

        Uses the kill_chain_phases order as sequence_order.
        """
        if obj["type"] != "incident":
            return []
        incident_id = obj["id"]
        rows = []
        for order, phase in enumerate(obj.get("kill_chain_phases", [])):
            ttp_id = phase.get("x_ttp_stix_id")
            if ttp_id:
                rows.append(
                    {
                        "incident_stix_id": incident_id,
                        "ttp_stix_id": ttp_id,
                        "sequence_order": order,
                    }
                )
        return rows

    # -----------------------------------------------------------------------
    # Edge mappers
    # -----------------------------------------------------------------------

    def map_relationship(self, obj: dict) -> tuple[str, dict] | None:
        """Map a STIX relationship to (table_name, row dict). Returns None if not applicable."""
        if obj["type"] != "relationship":
            return None

        rel_type = obj["relationship_type"]
        src = obj["source_ref"]
        dst = obj["target_ref"]
        stix_id = obj["id"]
        confidence = obj.get("confidence")

        if rel_type == "uses" and "attack-pattern--" in dst:
            if src.startswith(("malware--", "tool--")):
                return "MalwareUsesTTP", {
                    "malware_stix_id": src,
                    "ttp_stix_id": dst,
                    "confidence": confidence,
                    "first_observed": _to_ts(obj.get("start_time")),
                    "last_observed": _to_ts(obj.get("stop_time")),
                    "stix_id": stix_id,
                }
            return "Uses", {
                "actor_stix_id": src,
                "ttp_stix_id": dst,
                "confidence": confidence,
                "first_observed": _to_ts(obj.get("start_time")),
                "last_observed": _to_ts(obj.get("stop_time")),
                "stix_id": stix_id,
            }

        if rel_type == "uses" and dst.startswith(("malware--", "tool--")):
            return "UsesTool", {
                "actor_stix_id": src,
                "tool_stix_id": dst,
                "confidence": confidence,
                "first_observed": _to_ts(obj.get("start_time")),
                "last_observed": _to_ts(obj.get("stop_time")),
                "stix_id": stix_id,
            }

        if rel_type == "exploits" and "vulnerability--" in dst:
            return "Exploits", {
                "ttp_stix_id": src,
                "vuln_stix_id": dst,
                "stix_id": stix_id,
            }

        if rel_type == "indicates":
            if "attack-pattern--" in dst:
                return "IndicatesTTP", {
                    "observable_stix_id": src,
                    "ttp_stix_id": dst,
                    "confidence": confidence,
                    "stix_id": stix_id,
                }
            if dst.startswith(("threat-actor--", "intrusion-set--")):
                return "IndicatesActor", {
                    "observable_stix_id": src,
                    "actor_stix_id": dst,
                    "confidence": confidence,
                    "stix_id": stix_id,
                }

        # SAGE 0.5.0: actor → identity targeting from TRACE-emitted reports.
        # STIX 2.1 §4.13 permits other source types (attack-pattern, malware,
        # tool, campaign) but only actor sources are stored as graph edges
        # in 1.0.0 — other sources are dropped with a structured-log warning
        # at the caller (etl/worker.py).
        if rel_type == "targets" and dst.startswith("identity--"):
            if src.startswith(("threat-actor--", "intrusion-set--")):
                return "ActorTargetsIdentity", {
                    "actor_stix_id": src,
                    "identity_stix_id": dst,
                    "confidence": confidence,
                    "description": obj.get("description"),
                    "first_observed": _to_ts(obj.get("start_time")),
                    "stix_id": stix_id,
                }

        return None


# ---------------------------------------------------------------------------
# FollowedBy weight calculation
# ---------------------------------------------------------------------------


def build_followed_by_weights(
    uses_rows: list[dict],
    ttp_phases: dict[str, str],
    ttp_vuln_data: dict[str, dict] | None = None,
    ir_feedback_pairs: set[tuple[str, str]] | None = None,
) -> list[dict]:
    """Derive FollowedBy(threat_intel) edges from Uses edges and calculate weights.

    weight = base_prob × activity_score × exploit_ease × ir_multiplier

    Args:
        uses_rows: List of Uses rows produced by map_relationship()
        ttp_phases: {ttp_stix_id: phase_name} mapping
        ttp_vuln_data: {ttp_stix_id: {"cvss_score": float|None, "epss_score": float|None}}
                       Built from Exploits edges. When omitted, exploit_ease = 1.0 for all TTPs.
        ir_feedback_pairs: Set of (src, dst) pairs from build_ir_feedback_followed_by().
                           Matching transitions receive ir_multiplier = 1.5. Default: 1.0 for all.

    Returns:
        List of dicts ready for upsert into the FollowedBy table (source="threat_intel")
    """
    if ttp_vuln_data is None:
        ttp_vuln_data = {}
    if ir_feedback_pairs is None:
        ir_feedback_pairs = set()

    # Build actor → TTP set mapping
    actor_ttps: dict[str, set[str]] = defaultdict(set)
    for row in uses_rows:
        actor_ttps[row["actor_stix_id"]].add(row["ttp_stix_id"])

    transition_counts: dict[tuple[str, str], int] = defaultdict(int)
    transition_evidence: dict[tuple[str, str], list[str]] = defaultdict(list)

    for actor_id, ttp_ids in actor_ttps.items():
        sorted_ttps = sorted(
            ttp_ids,
            key=lambda t: PHASE_ORDER.get(ttp_phases.get(t, ""), 99),
        )
        for i in range(len(sorted_ttps) - 1):
            src, dst = sorted_ttps[i], sorted_ttps[i + 1]
            if src != dst:
                transition_counts[(src, dst)] += 1
                transition_evidence[(src, dst)].append(actor_id)

    total_actors = max(len(actor_ttps), 1)

    # activity_score: per-TTP observation rate in the last 90 days
    # (last_observed = None is treated as neutral 0.5)
    cutoff_dt = _now() - timedelta(days=90)

    ttp_activity: dict[str, float] = {}
    for ttp_id in {t for actor_id, ttps in actor_ttps.items() for t in ttps}:
        relevant = [r for r in uses_rows if r.get("ttp_stix_id") == ttp_id]
        dated = [r for r in relevant if r.get("last_observed") is not None]
        if not dated:
            ttp_activity[ttp_id] = 0.5  # unknown date → neutral (× 2.0 = 1.0)
        else:
            recent = sum(
                1
                for r in dated
                if _to_ts(r["last_observed"]) is not None
                and _to_ts(r["last_observed"]) >= cutoff_dt
            )
            ttp_activity[ttp_id] = recent / len(dated)

    now = _now()

    result = []
    for (src, dst), count in transition_counts.items():
        # base_prob: number of actors that make this transition / total actors
        base_prob = min(count / total_actors, 1.0)

        # activity_score: average observation rate of src+dst TTPs × 2.0 (range 0.0–2.0)
        src_ratio = ttp_activity.get(src, 0.5)
        dst_ratio = ttp_activity.get(dst, 0.5)
        activity_score = min((src_ratio + dst_ratio) / 2.0 * 2.0, 2.0)

        # exploit_ease: derived from src TTP vulnerability data (1.0 if no CVE)
        vuln = ttp_vuln_data.get(src, {})
        cvss = vuln.get("cvss_score")
        epss = vuln.get("epss_score")
        if cvss is not None and epss is not None:
            exploit_ease = float(cvss) / 10.0 * 0.5 + float(epss) * 0.5
        elif cvss is not None:
            exploit_ease = float(cvss) / 10.0
        elif epss is not None:
            exploit_ease = float(epss)
        else:
            exploit_ease = 1.0  # TTPs without CVEs (e.g. social engineering) are neutral

        # ir_multiplier: 1.5 if this transition was confirmed in IR feedback
        ir_multiplier = 1.5 if (src, dst) in ir_feedback_pairs else 1.0

        weight = min(base_prob * activity_score * exploit_ease * ir_multiplier, 1.0)

        result.append(
            {
                "src_ttp_stix_id": src,
                "dst_ttp_stix_id": dst,
                "source": "threat_intel",
                "weight": weight,
                "actor_stix_id": None,
                "evidence_stix_ids": transition_evidence[(src, dst)][:10],
                "last_calculated": now,
            }
        )

    return result


def build_ir_feedback_followed_by(
    incident_ttp_rows: list[dict],
) -> tuple[list[dict], set[tuple[str, str]]]:
    """Derive FollowedBy(ir_feedback) edges from IncidentUsesTTP rows.

    Records with a NULL sequence_order are skipped.

    Args:
        incident_ttp_rows: List of IncidentUsesTTP rows
                           ({incident_stix_id, ttp_stix_id, sequence_order})

    Returns:
        (followed_by_rows, ir_feedback_pairs)
        - followed_by_rows: List of dicts for FollowedBy upsert (source="ir_feedback")
        - ir_feedback_pairs: Set of (src_ttp_stix_id, dst_ttp_stix_id) for ir_multiplier calculation
    """
    if not incident_ttp_rows:
        return [], set()

    # Group TTPs per incident by sequence_order (skip NULL entries)
    incident_sequences: dict[str, list[tuple[int, str]]] = defaultdict(list)
    for row in incident_ttp_rows:
        if row.get("sequence_order") is None:
            continue
        incident_sequences[row["incident_stix_id"]].append(
            (row["sequence_order"], row["ttp_stix_id"])
        )

    transition_counts: dict[tuple[str, str], int] = defaultdict(int)
    transition_evidence: dict[tuple[str, str], list[str]] = defaultdict(list)

    for incident_id, seq in incident_sequences.items():
        sorted_ttps = [ttp for _, ttp in sorted(seq)]
        for i in range(len(sorted_ttps) - 1):
            src, dst = sorted_ttps[i], sorted_ttps[i + 1]
            if src != dst:
                transition_counts[(src, dst)] += 1
                transition_evidence[(src, dst)].append(incident_id)

    total_incidents = max(len(incident_sequences), 1)
    now = _now()

    rows = [
        {
            "src_ttp_stix_id": src,
            "dst_ttp_stix_id": dst,
            "source": "ir_feedback",
            "weight": min(count / total_incidents, 1.0),
            "actor_stix_id": None,
            "evidence_stix_ids": transition_evidence[(src, dst)][:10],
            "last_calculated": now,
        }
        for (src, dst), count in transition_counts.items()
    ]
    ir_pairs = set(transition_counts.keys())
    return rows, ir_pairs


# ---------------------------------------------------------------------------
# Utilities
# ---------------------------------------------------------------------------


def _to_ts(val: Any) -> datetime | None:
    if val is None:
        return None
    if isinstance(val, datetime):
        return val if val.tzinfo else val.replace(tzinfo=UTC)
    if isinstance(val, str):
        try:
            return datetime.fromisoformat(val.replace("Z", "+00:00"))
        except ValueError:
            return None
    return None


def _now() -> datetime:
    return datetime.now(tz=UTC)


def _mitre_technique_id(obj: dict) -> str | None:
    for ref in obj.get("external_references", []):
        if ref.get("source_name") in ("mitre-attack", "mitre-mobile-attack"):
            return ref.get("external_id")
    return None


def _kill_chain_phase(obj: dict) -> str | None:
    for phase in obj.get("kill_chain_phases", []):
        if phase.get("kill_chain_name") == "mitre-attack":
            return phase.get("phase_name")
    phases = obj.get("kill_chain_phases", [])
    return phases[0].get("phase_name") if phases else None


def _cvss_score(obj: dict) -> float | None:
    for ref in obj.get("external_references", []):
        metrics = ref.get("x_cvss", {})
        if metrics and "base_score" in metrics:
            return float(metrics["base_score"])
    return None


def _extract_indicator(pattern: str) -> tuple[str, str] | None:
    for obs_type, regex in _INDICATOR_PATTERNS:
        m = re.search(regex, pattern, re.IGNORECASE)
        if m:
            return obs_type, m.group(1)
    return None


def _tlp(obj: dict) -> str:
    for ref in obj.get("object_marking_refs", []):
        ref_lower = ref.lower()
        for level in ("red", "amber", "green", "white"):
            if level in ref_lower:
                return level
    return "white"
