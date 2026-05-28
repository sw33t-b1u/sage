"""Tests for cmd/load_assets.py — stub Vulnerability creation (SAGE 1.2.0).

Covers:
- CVE absent from Spanner → stub Vulnerability row with deterministic stix_id
  + HasVulnerability edge is emitted.
- Malformed CVE ref is skipped with a warning (no stub, no edge).
- CVE already present in Spanner → existing stix_id is reused (unchanged path).
- Idempotency: minting a stub and then "ETL-upserting" a fuller Vulnerability
  with the same stix_id results in a single row (enriched, same PK).
"""

from __future__ import annotations

import sys
import uuid
from collections.abc import Iterable
from pathlib import Path
from unittest.mock import MagicMock

sys.path.insert(0, str(Path(__file__).parent.parent / "src"))
# Match sibling tests that import CLI modules by name from cmd/.
sys.path.insert(0, str(Path(__file__).parent.parent / "cmd"))

from load_assets import load_assets

from sage.stix.mapper import (
    _DETERMINISTIC_ID_NAMESPACE,
    deterministic_vuln_stix_id,
)

# ---------------------------------------------------------------------------
# Mock database helpers
# ---------------------------------------------------------------------------


def _mock_db(existing_cve_map: dict[str, str] | None = None):
    """Return (mock Database, recorded mutations list).

    ``existing_cve_map`` maps cve_id → stix_id for rows already in the
    Vulnerability table. The snapshot.execute_sql mock returns these rows
    in the format used by _resolve_cve_ids (stix_id, cve_id) and
    _resolve_actor_names (stix_id, name).

    Recorded mutations are tuples of (table, list[columns], list[row_tuples]).
    """
    if existing_cve_map is None:
        existing_cve_map = {}

    recorded: list[tuple[str, list[str], list[tuple]]] = []

    def _record(table: str, columns: Iterable[str], values: Iterable[tuple]) -> None:
        recorded.append((table, list(columns), list(values)))

    batch = MagicMock()
    batch.insert_or_update.side_effect = _record

    batch_ctx = MagicMock()
    batch_ctx.__enter__.return_value = batch
    batch_ctx.__exit__.return_value = None

    # _resolve_cve_ids executes: SELECT stix_id, cve_id FROM Vulnerability
    # _resolve_actor_names executes: SELECT stix_id, name FROM ThreatActor
    def _sql_side_effect(sql, *args, **kwargs):
        if "Vulnerability" in sql:
            return [(stix_id, cve_id) for cve_id, stix_id in existing_cve_map.items()]
        # ThreatActor query — return empty list (actor resolution not under test here)
        return []

    snap = MagicMock()
    snap.execute_sql.side_effect = _sql_side_effect

    snap_ctx = MagicMock()
    snap_ctx.__enter__.return_value = snap
    snap_ctx.__exit__.return_value = None

    db = MagicMock()
    db.snapshot.return_value = snap_ctx
    db.batch.return_value = batch_ctx

    return db, recorded


def _rows_for_table(recorded: list[tuple], table: str) -> list[dict]:
    """Collect all rows written to ``table`` as dicts (column → value)."""
    result = []
    for tbl, cols, values in recorded:
        if tbl == table:
            for row_vals in values:
                result.append(dict(zip(cols, row_vals)))
    return result


# ---------------------------------------------------------------------------
# Test: CVE absent → stub created + HasVulnerability edge emitted
# ---------------------------------------------------------------------------


class TestVulnStubCreation:
    def test_absent_cve_creates_stub_vulnerability_row(self, capsys):
        db, recorded = _mock_db(existing_cve_map={})

        data = {
            "asset_vulnerabilities": [
                {"vuln_stix_id_ref": "CVE-2025-1234", "asset_id": "asset-001"},
            ]
        }
        load_assets(db, data)

        vuln_rows = _rows_for_table(recorded, "Vulnerability")
        assert len(vuln_rows) == 1, "Expected exactly one stub Vulnerability row"
        row = vuln_rows[0]
        assert row["cve_id"] == "CVE-2025-1234"
        expected_stix_id = deterministic_vuln_stix_id("CVE-2025-1234")
        assert row["stix_id"] == expected_stix_id
        assert row["stix_modified"] is not None

    def test_absent_cve_creates_has_vulnerability_edge(self):
        db, recorded = _mock_db(existing_cve_map={})

        data = {
            "asset_vulnerabilities": [
                {"vuln_stix_id_ref": "CVE-2025-1234", "asset_id": "asset-001"},
            ]
        }
        load_assets(db, data)

        hv_rows = _rows_for_table(recorded, "HasVulnerability")
        assert len(hv_rows) == 1
        row = hv_rows[0]
        assert row["asset_id"] == "asset-001"
        assert row["vuln_stix_id"] == deterministic_vuln_stix_id("CVE-2025-1234")
        assert row["remediation_status"] == "open"

    def test_absent_cve_logs_vuln_stub_created(self, capsys):
        db, _ = _mock_db(existing_cve_map={})

        data = {
            "asset_vulnerabilities": [
                {"vuln_stix_id_ref": "CVE-2025-9999", "asset_id": "asset-002"},
            ]
        }
        load_assets(db, data)

        captured = capsys.readouterr()
        assert "vuln_stub_created" in captured.out


# ---------------------------------------------------------------------------
# Test: malformed CVE ref is skipped
# ---------------------------------------------------------------------------


class TestMalformedCveRef:
    def test_malformed_cve_skipped_no_stub(self, capsys):
        db, recorded = _mock_db(existing_cve_map={})

        data = {
            "asset_vulnerabilities": [
                {"vuln_stix_id_ref": "NOT-A-CVE-ID", "asset_id": "asset-003"},
            ]
        }
        load_assets(db, data)

        vuln_rows = _rows_for_table(recorded, "Vulnerability")
        assert vuln_rows == [], "No stub should be created for malformed CVE ref"

    def test_malformed_cve_skipped_no_has_vulnerability_edge(self):
        db, recorded = _mock_db(existing_cve_map={})

        data = {
            "asset_vulnerabilities": [
                {"vuln_stix_id_ref": "NOT-A-CVE-ID", "asset_id": "asset-003"},
            ]
        }
        load_assets(db, data)

        hv_rows = _rows_for_table(recorded, "HasVulnerability")
        assert hv_rows == [], "No HasVulnerability edge should be emitted for malformed CVE"

    def test_malformed_cve_logs_warning(self, capsys):
        db, _ = _mock_db(existing_cve_map={})

        data = {
            "asset_vulnerabilities": [
                {"vuln_stix_id_ref": "BADFORMAT", "asset_id": "asset-004"},
            ]
        }
        load_assets(db, data)

        captured = capsys.readouterr()
        assert "cve_invalid_format" in captured.out


# ---------------------------------------------------------------------------
# Test: CVE already present in Spanner — existing stix_id reused
# ---------------------------------------------------------------------------


class TestCveAlreadyPresent:
    def test_existing_cve_reuses_stix_id_no_stub(self):
        existing_stix_id = "vulnerability--existing-stix-id-0001"
        db, recorded = _mock_db(existing_cve_map={"CVE-2024-5678": existing_stix_id})

        data = {
            "asset_vulnerabilities": [
                {"vuln_stix_id_ref": "CVE-2024-5678", "asset_id": "asset-005"},
            ]
        }
        load_assets(db, data)

        # No stub should have been created
        vuln_rows = _rows_for_table(recorded, "Vulnerability")
        assert vuln_rows == [], "No stub should be created when CVE already exists"

        # HasVulnerability should use the existing stix_id
        hv_rows = _rows_for_table(recorded, "HasVulnerability")
        assert len(hv_rows) == 1
        assert hv_rows[0]["vuln_stix_id"] == existing_stix_id


# ---------------------------------------------------------------------------
# Test: idempotency — same stix_id when enriching stub via "ETL upsert"
# ---------------------------------------------------------------------------


class TestStubIdempotency:
    def test_stub_and_full_vuln_have_same_stix_id(self):
        """The stub stix_id must equal the id a later CTI ETL would produce."""
        cve_id = "CVE-2025-1234"
        stub_id = deterministic_vuln_stix_id(cve_id)

        # Simulate what a TRACE-emitted full Vulnerability node would carry:
        # TRACE uses the same uuid5(namespace, cve_id) formula.
        full_trace_id = f"vulnerability--{uuid.uuid5(_DETERMINISTIC_ID_NAMESPACE, cve_id)}"

        assert stub_id == full_trace_id, (
            "Stub stix_id must match TRACE's deterministic id so INSERT OR UPDATE "
            "enriches the same row rather than creating a duplicate."
        )

    def test_multiple_absent_cves_all_get_stubs(self):
        db, recorded = _mock_db(existing_cve_map={})

        data = {
            "asset_vulnerabilities": [
                {"vuln_stix_id_ref": "CVE-2025-0001", "asset_id": "asset-A"},
                {"vuln_stix_id_ref": "CVE-2025-0002", "asset_id": "asset-B"},
            ]
        }
        load_assets(db, data)

        vuln_rows = _rows_for_table(recorded, "Vulnerability")
        assert len(vuln_rows) == 2
        stix_ids = {r["stix_id"] for r in vuln_rows}
        assert stix_ids == {
            deterministic_vuln_stix_id("CVE-2025-0001"),
            deterministic_vuln_stix_id("CVE-2025-0002"),
        }

        hv_rows = _rows_for_table(recorded, "HasVulnerability")
        assert len(hv_rows) == 2

    def test_mixed_present_absent_cves(self):
        """Half the CVEs exist in Spanner; the other half get stubs."""
        existing_stix_id = "vulnerability--existing-0000"
        db, recorded = _mock_db(existing_cve_map={"CVE-2024-0001": existing_stix_id})

        data = {
            "asset_vulnerabilities": [
                {"vuln_stix_id_ref": "CVE-2024-0001", "asset_id": "asset-X"},
                {"vuln_stix_id_ref": "CVE-2025-0099", "asset_id": "asset-Y"},
            ]
        }
        load_assets(db, data)

        vuln_rows = _rows_for_table(recorded, "Vulnerability")
        # Only one stub (for the absent CVE)
        assert len(vuln_rows) == 1
        assert vuln_rows[0]["cve_id"] == "CVE-2025-0099"

        hv_rows = _rows_for_table(recorded, "HasVulnerability")
        assert len(hv_rows) == 2
        vuln_ids = {r["vuln_stix_id"] for r in hv_rows}
        assert existing_stix_id in vuln_ids
        assert deterministic_vuln_stix_id("CVE-2025-0099") in vuln_ids
