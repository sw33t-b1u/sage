"""StixMapper と build_followed_by_weights のユニットテスト。"""

import json
from pathlib import Path

import pytest

from sage.stix.mapper import (
    StixMapper,
    build_followed_by_weights,
    build_ir_feedback_followed_by,
)

FIXTURES = Path(__file__).parent / "fixtures"


@pytest.fixture
def bundle_objects():
    with (FIXTURES / "sample_bundle.json").open() as f:
        bundle = json.load(f)
    return bundle["objects"]


@pytest.fixture
def mapper():
    return StixMapper()


# ---------------------------------------------------------------------------
# ThreatActor
# ---------------------------------------------------------------------------


class TestMapThreatActor:
    def test_intrusion_set(self, mapper, bundle_objects):
        obj = next(o for o in bundle_objects if o["type"] == "intrusion-set")
        row = mapper.map_threat_actor(obj)

        assert row is not None
        assert row["stix_id"] == "intrusion-set--apt99"
        assert row["stix_type"] == "intrusion-set"
        assert row["name"] == "APT99"
        assert "apt" in row["tags"]
        assert "targets-japan" in row["tags"]
        assert row["motivation"] == "espionage"

    def test_irrelevant_type_returns_none(self, mapper, bundle_objects):
        obj = next(o for o in bundle_objects if o["type"] == "attack-pattern")
        assert mapper.map_threat_actor(obj) is None


# ---------------------------------------------------------------------------
# TTP
# ---------------------------------------------------------------------------


class TestMapTTP:
    def test_attack_pattern(self, mapper, bundle_objects):
        obj = next(o for o in bundle_objects if o["id"] == "attack-pattern--t1078")
        row = mapper.map_ttp(obj)

        assert row is not None
        assert row["stix_id"] == "attack-pattern--t1078"
        assert row["attack_technique_id"] == "T1078"
        assert row["tactic"] == "initial-access"
        assert "Windows" in row["platforms"]

    def test_privilege_escalation_phase(self, mapper, bundle_objects):
        obj = next(o for o in bundle_objects if o["id"] == "attack-pattern--t1068")
        row = mapper.map_ttp(obj)
        assert row["tactic"] == "privilege-escalation"


# ---------------------------------------------------------------------------
# Vulnerability
# ---------------------------------------------------------------------------


class TestMapVulnerability:
    def test_cve(self, mapper, bundle_objects):
        obj = next(o for o in bundle_objects if o["type"] == "vulnerability")
        row = mapper.map_vulnerability(obj)

        assert row is not None
        assert row["stix_id"] == "vulnerability--cve-2025-55182"
        assert row["cve_id"] == "CVE-2025-55182"
        assert row["description"] == "権限昇格を可能にするカーネルの脆弱性"


# ---------------------------------------------------------------------------
# Observable
# ---------------------------------------------------------------------------


class TestMapObservable:
    def test_ip_indicator(self, mapper, bundle_objects):
        obj = next(o for o in bundle_objects if o["type"] == "indicator")
        row = mapper.map_observable(obj)

        assert row is not None
        assert row["obs_type"] == "ip"
        assert row["value"] == "198.51.100.1"
        assert row["confidence"] == 80
        assert row["tlp"] == "amber"

    def test_non_indicator_returns_none(self, mapper, bundle_objects):
        obj = next(o for o in bundle_objects if o["type"] == "intrusion-set")
        assert mapper.map_observable(obj) is None


# ---------------------------------------------------------------------------
# Relationship マッピング
# ---------------------------------------------------------------------------


class TestMapRelationship:
    def test_uses_maps_to_uses_table(self, mapper, bundle_objects):
        obj = next(
            o
            for o in bundle_objects
            if o["type"] == "relationship" and o["relationship_type"] == "uses"
        )
        result = mapper.map_relationship(obj)
        assert result is not None
        table, row = result
        assert table == "Uses"
        assert row["actor_stix_id"] == "intrusion-set--apt99"
        assert "attack-pattern--" in row["ttp_stix_id"]

    def test_exploits_maps_to_exploits_table(self, mapper, bundle_objects):
        obj = next(
            o
            for o in bundle_objects
            if o["type"] == "relationship" and o["relationship_type"] == "exploits"
        )
        result = mapper.map_relationship(obj)
        assert result is not None
        table, row = result
        assert table == "Exploits"
        assert row["vuln_stix_id"] == "vulnerability--cve-2025-55182"

    def test_indicates_actor_maps_to_indicates_actor_table(self, mapper, bundle_objects):
        obj = next(
            o
            for o in bundle_objects
            if o["type"] == "relationship" and o["relationship_type"] == "indicates"
        )
        result = mapper.map_relationship(obj)
        assert result is not None
        table, row = result
        assert table == "IndicatesActor"
        assert row["actor_stix_id"] == "intrusion-set--apt99"

    def test_non_relationship_returns_none(self, mapper, bundle_objects):
        obj = next(o for o in bundle_objects if o["type"] == "intrusion-set")
        assert mapper.map_relationship(obj) is None


# ---------------------------------------------------------------------------
# FollowedBy 重み計算
# ---------------------------------------------------------------------------


class TestBuildFollowedByWeights:
    def test_generates_transitions_across_phases(self):
        uses_rows = [
            {"actor_stix_id": "intrusion-set--apt99", "ttp_stix_id": "attack-pattern--t1078"},
            {"actor_stix_id": "intrusion-set--apt99", "ttp_stix_id": "attack-pattern--t1068"},
        ]
        ttp_phases = {
            "attack-pattern--t1078": "initial-access",
            "attack-pattern--t1068": "privilege-escalation",
        }
        rows = build_followed_by_weights(uses_rows, ttp_phases)

        assert len(rows) >= 1
        transition = next(
            (
                r
                for r in rows
                if r["src_ttp_stix_id"] == "attack-pattern--t1078"
                and r["dst_ttp_stix_id"] == "attack-pattern--t1068"
            ),
            None,
        )
        assert transition is not None
        assert 0.0 < transition["weight"] <= 1.0
        assert transition["source"] == "threat_intel"

    def test_weight_is_normalized(self):
        # 2アクター中1アクターが同じ遷移 → weight = 0.5
        uses_rows = [
            {"actor_stix_id": "actor-A", "ttp_stix_id": "ttp-1"},
            {"actor_stix_id": "actor-A", "ttp_stix_id": "ttp-2"},
            {"actor_stix_id": "actor-B", "ttp_stix_id": "ttp-3"},  # 別の遷移のみ
        ]
        ttp_phases = {
            "ttp-1": "initial-access",
            "ttp-2": "execution",
            "ttp-3": "persistence",
        }
        rows = build_followed_by_weights(uses_rows, ttp_phases)
        t = next(
            (
                r
                for r in rows
                if r["src_ttp_stix_id"] == "ttp-1" and r["dst_ttp_stix_id"] == "ttp-2"
            ),
            None,
        )
        assert t is not None
        assert t["weight"] == pytest.approx(0.5)

    def test_empty_uses_returns_empty(self):
        assert build_followed_by_weights([], {}) == []

    def test_exploit_ease_applied_when_vuln_data_present(self):
        uses_rows = [
            {"actor_stix_id": "actor-A", "ttp_stix_id": "ttp-1"},
            {"actor_stix_id": "actor-A", "ttp_stix_id": "ttp-2"},
        ]
        ttp_phases = {"ttp-1": "initial-access", "ttp-2": "execution"}
        ttp_vuln_data = {"ttp-1": {"cvss_score": 8.0, "epss_score": 0.6}}
        rows = build_followed_by_weights(uses_rows, ttp_phases, ttp_vuln_data=ttp_vuln_data)
        t = next(r for r in rows if r["src_ttp_stix_id"] == "ttp-1")
        # exploit_ease = 8.0/10 * 0.5 + 0.6 * 0.5 = 0.4 + 0.3 = 0.7
        # base_prob = 1.0, activity_score = 1.0 (no last_observed)
        assert t["weight"] == pytest.approx(0.7)

    def test_ir_multiplier_applied_for_confirmed_pairs(self):
        uses_rows = [
            {"actor_stix_id": "actor-A", "ttp_stix_id": "ttp-1"},
            {"actor_stix_id": "actor-A", "ttp_stix_id": "ttp-2"},
        ]
        ttp_phases = {"ttp-1": "initial-access", "ttp-2": "execution"}
        ir_pairs = {("ttp-1", "ttp-2")}
        rows = build_followed_by_weights(uses_rows, ttp_phases, ir_feedback_pairs=ir_pairs)
        t = next(r for r in rows if r["src_ttp_stix_id"] == "ttp-1")
        # base_prob=1.0, activity_score=1.0, exploit_ease=1.0, ir_multiplier=1.5 → capped at 1.0
        assert t["weight"] == pytest.approx(1.0)

    def test_malware_uses_ttp_relationship(self, mapper):
        obj = {
            "type": "relationship",
            "id": "relationship--m001",
            "spec_version": "2.1",
            "relationship_type": "uses",
            "source_ref": "malware--emotet",
            "target_ref": "attack-pattern--t1059",
            "modified": "2025-01-01T00:00:00Z",
            "created": "2025-01-01T00:00:00Z",
        }
        result = mapper.map_relationship(obj)
        assert result is not None
        table, row = result
        assert table == "MalwareUsesTTP"
        assert row["malware_stix_id"] == "malware--emotet"
        assert row["ttp_stix_id"] == "attack-pattern--t1059"


class TestBuildIrFeedbackFollowedBy:
    def test_generates_transitions_from_sequence(self):
        rows = [
            {"incident_stix_id": "incident--inc1", "ttp_stix_id": "ttp-A", "sequence_order": 0},
            {"incident_stix_id": "incident--inc1", "ttp_stix_id": "ttp-B", "sequence_order": 1},
            {"incident_stix_id": "incident--inc1", "ttp_stix_id": "ttp-C", "sequence_order": 2},
        ]
        fb_rows, ir_pairs = build_ir_feedback_followed_by(rows)

        assert len(fb_rows) == 2
        assert ("ttp-A", "ttp-B") in ir_pairs
        assert ("ttp-B", "ttp-C") in ir_pairs
        for r in fb_rows:
            assert r["source"] == "ir_feedback"
            assert r["weight"] == pytest.approx(1.0)

    def test_null_sequence_order_skipped(self):
        rows = [
            {"incident_stix_id": "incident--inc1", "ttp_stix_id": "ttp-A", "sequence_order": 0},
            {"incident_stix_id": "incident--inc1", "ttp_stix_id": "ttp-B", "sequence_order": None},
        ]
        fb_rows, ir_pairs = build_ir_feedback_followed_by(rows)
        assert fb_rows == []
        assert ir_pairs == set()

    def test_weight_normalized_across_incidents(self):
        rows = [
            {"incident_stix_id": "incident--inc1", "ttp_stix_id": "ttp-A", "sequence_order": 0},
            {"incident_stix_id": "incident--inc1", "ttp_stix_id": "ttp-B", "sequence_order": 1},
            {"incident_stix_id": "incident--inc2", "ttp_stix_id": "ttp-A", "sequence_order": 0},
            {"incident_stix_id": "incident--inc2", "ttp_stix_id": "ttp-C", "sequence_order": 1},
        ]
        fb_rows, _ = build_ir_feedback_followed_by(rows)
        ab = next(
            r
            for r in fb_rows
            if r["src_ttp_stix_id"] == "ttp-A" and r["dst_ttp_stix_id"] == "ttp-B"
        )
        ac = next(
            r
            for r in fb_rows
            if r["src_ttp_stix_id"] == "ttp-A" and r["dst_ttp_stix_id"] == "ttp-C"
        )
        # 各遷移は2インシデント中1回 → weight = 0.5
        assert ab["weight"] == pytest.approx(0.5)
        assert ac["weight"] == pytest.approx(0.5)

    def test_empty_input_returns_empty(self):
        fb_rows, ir_pairs = build_ir_feedback_followed_by([])
        assert fb_rows == []
        assert ir_pairs == set()


# ---------------------------------------------------------------------------
# IncidentUsesTTP 統合テスト (sample_bundle_inc.json)
# ---------------------------------------------------------------------------


@pytest.fixture
def bundle_inc_objects():
    with (FIXTURES / "sample_bundle_inc.json").open() as f:
        bundle = json.load(f)
    return bundle["objects"]


class TestMapIncidentTTPEdges:
    def test_generates_edges_from_kill_chain_phases(self, mapper, bundle_inc_objects):
        incident = next(o for o in bundle_inc_objects if o["type"] == "incident")
        rows = mapper.map_incident_ttp_edges(incident)

        assert len(rows) == 5
        assert rows[0]["incident_stix_id"] == "incident--inc-2026-001"
        assert rows[0]["ttp_stix_id"] == "attack-pattern--984230ee-46fe-420d-9eb0-52b6cd418e3e"
        assert rows[0]["sequence_order"] == 0

    def test_sequence_order_is_correct(self, mapper, bundle_inc_objects):
        incident = next(o for o in bundle_inc_objects if o["type"] == "incident")
        rows = mapper.map_incident_ttp_edges(incident)

        orders = [r["sequence_order"] for r in rows]
        assert orders == list(range(5))

    def test_last_phase_is_impact(self, mapper, bundle_inc_objects):
        incident = next(o for o in bundle_inc_objects if o["type"] == "incident")
        rows = mapper.map_incident_ttp_edges(incident)

        assert rows[-1]["ttp_stix_id"] == "attack-pattern--187b08d7-6be7-4bf2-876e-74118c4d19e8"
        assert rows[-1]["sequence_order"] == 4

    def test_non_incident_returns_empty(self, mapper, bundle_inc_objects):
        non_incident = next(o for o in bundle_inc_objects if o["type"] == "intrusion-set")
        rows = mapper.map_incident_ttp_edges(non_incident)
        assert rows == []

    def test_ir_feedback_followed_by_from_inc_bundle(self, mapper, bundle_inc_objects):
        """incident から IncidentUsesTTP を生成し IR feedback FollowedBy に変換する統合テスト。"""
        incident = next(o for o in bundle_inc_objects if o["type"] == "incident")
        incident_ttp_rows = mapper.map_incident_ttp_edges(incident)
        fb_rows, ir_pairs = build_ir_feedback_followed_by(incident_ttp_rows)

        # 5フェーズ → 4遷移
        assert len(fb_rows) == 4
        assert len(ir_pairs) == 4
        # 最初の遷移: initial-access → credential-access
        first_pair = (
            "attack-pattern--984230ee-46fe-420d-9eb0-52b6cd418e3e",
            "attack-pattern--ed03a1ef-3ba7-4a8f-9f30-3787d077f0f9",
        )
        assert first_pair in ir_pairs
        for r in fb_rows:
            assert r["source"] == "ir_feedback"
            assert r["weight"] == pytest.approx(1.0)
