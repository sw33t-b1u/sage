"""End-to-end roundtrip test for the SQLite backend (SAGE 4.0.0).

Drives the real pipeline in process — no mocks on the database path:

    init-schema -> load-assets --input <fixture>
                -> run-etl --input <bundle fixture> (with a PIR file)
                -> FastAPI queries via TestClient

with ``SAGE_DB=sqlite`` and ``SAGE_STORAGE=local`` rooted at a pytest
tmp directory, so the DB file lands at ``<base>/db/sage.db`` exactly as
in a local deployment. The module-scoped ``pipeline_base`` fixture
builds the database once; the API tests then exercise the read-only
Analysis API connection plus the short-lived read-write session used by
``POST /api/incidents``.

One incident is seeded through ``sage.db.upsert_rows`` with a STIX-style
``Z``-suffix timestamp to verify the write-boundary canonicalization to
``+00:00`` ISO 8601 TEXT (window queries compare TEXT lexicographically,
so an unnormalized ``...Z`` value would fall out of every window).
"""

from __future__ import annotations

import os
import sqlite3
import sys
import threading
from pathlib import Path

import pytest
from fastapi.testclient import TestClient

FIXTURES = Path(__file__).parent / "fixtures"
ASSETS_FILE = FIXTURES / "sample_assets.json"
BUNDLE_FILE = FIXTURES / "sample_bundle_roundtrip.json"
PIR_FILE = FIXTURES / "sample_pir.json"

# Known fixture contents: APT99 (tags apt / targets-japan) matches the
# sample PIR's threat_actor_tags; asset-001 carries the "external-facing"
# tag matched by the PIR's asset_weight_rules, so the ETL generates
# Targets edges between them. The bundle fixture mirrors
# sample_bundle.json (mapper unit-test data) but uses spec-valid STIX
# 2.1 UUID identifiers so the real parser accepts every object.
ASSET_VPN = "asset-001-vpn00-0000-000000000001"
ACTOR_APT99 = "intrusion-set--4a5c1f00-89aa-4b9e-9f04-1c2d3e4f5a01"

AUTH_TOKEN = "roundtrip-secret-token"
AUTH_HEADER = {"Authorization": f"Bearer {AUTH_TOKEN}"}

POSTED_INCIDENT = "incident--00000000-0000-0000-0000-00000000e2e1"
SEEDED_Z_INCIDENT = "incident--00000000-0000-0000-0000-00000000e2e2"
TTP_UUID_A = "attack-pattern--00000000-0000-0000-0000-0000000000aa"

_ENV_KEYS_TO_SCRUB = (
    "GCP_PROJECT_ID",
    "REGION",
    "PIR_FILE_PATH",
    "TLP_MAX_LEVEL",
    "ACTIVITY_WINDOW_DAYS",
)
_ENV_PREFIXES_TO_SCRUB = (
    "SAGE_",
    "SPANNER_",
    "OPENCTI_",
    "GHE_",
    "CALDERA_",
    "SLACK_",
)


def _set_sqlite_env(mp: pytest.MonkeyPatch, base_dir: Path) -> None:
    """Point SAGE at the sqlite backend with local storage under *base_dir*."""
    mp.setenv("SAGE_DB", "sqlite")
    mp.setenv("SAGE_STORAGE", "local")
    mp.setenv("SAGE_STORAGE_BASE_DIR", str(base_dir))
    mp.setenv("PIR_FILE_PATH", str(PIR_FILE))


@pytest.fixture(scope="module")
def pipeline_base(tmp_path_factory: pytest.TempPathFactory) -> Path:
    """Build the SQLite DB once: init-schema -> load-assets -> run-etl.

    The function-scoped hermetic-env conftest fixture cannot guard a
    module-scoped fixture, so ambient env scrubbing and the repo-root
    ``.env`` no-op are replicated here with a local MonkeyPatch that is
    undone before the first test runs.
    """
    base = tmp_path_factory.mktemp("sqlite-roundtrip")
    mp = pytest.MonkeyPatch()
    try:
        import sage.config as config_module

        mp.setattr(config_module, "_load_dotenv", lambda path=".env": None)
        for key in _ENV_KEYS_TO_SCRUB:
            mp.delenv(key, raising=False)
        for key in list(os.environ):
            if key.startswith(_ENV_PREFIXES_TO_SCRUB):
                mp.delenv(key, raising=False)
        _set_sqlite_env(mp, base)

        from sage.cli import init_schema, load_assets, run_etl

        init_schema.main()

        mp.setattr(sys, "argv", ["sage-load-assets", "--input", str(ASSETS_FILE)])
        load_assets.main()

        mp.setattr(sys, "argv", ["sage-run-etl", "--input", str(BUNDLE_FILE)])
        run_etl.main()

        # Seed one incident with a STIX ``Z``-suffix timestamp through the
        # regular write boundary (sage.db dispatch -> sqlite upsert) so the
        # canonicalization to +00:00 TEXT is exercised end-to-end.
        from sage.config import Config
        from sage.db import database_session, upsert_rows

        config = Config.from_env()
        with database_session(config) as conn:
            upsert_rows(
                conn,
                "Incident",
                [
                    {
                        "stix_id": SEEDED_Z_INCIDENT,
                        "name": "Z-suffix window incident",
                        "occurred_at": "2026-06-01T00:00:00Z",
                        "severity": "medium",
                        "source": "ir_feedback",
                        "stix_modified": "2026-06-01T00:00:00Z",
                    }
                ],
            )
    finally:
        mp.undo()
    return base


@pytest.fixture()
def client(pipeline_base: Path, monkeypatch: pytest.MonkeyPatch):
    """TestClient over the real FastAPI app, lifespan included.

    The lifespan handler calls ``Config.from_env()`` and opens a
    read-only sqlite connection to ``<base>/db/sage.db``.
    """
    _set_sqlite_env(monkeypatch, pipeline_base)
    monkeypatch.setenv("SAGE_API_AUTH_TOKEN", AUTH_TOKEN)

    from sage.api.app import app

    with TestClient(app, raise_server_exceptions=True) as c:
        yield c


# ---------------------------------------------------------------------------
# Pipeline-level assertions (no API)
# ---------------------------------------------------------------------------


def test_db_file_materialized_under_base_dir(pipeline_base: Path):
    assert (pipeline_base / "db" / "sage.db").is_file()


def test_z_suffix_timestamp_normalized_at_write_boundary(pipeline_base: Path):
    """The seeded ``...Z`` value must be stored in canonical ``+00:00`` form."""
    conn = sqlite3.connect(pipeline_base / "db" / "sage.db")
    try:
        row = conn.execute(
            "SELECT occurred_at FROM Incident WHERE stix_id = ?",
            (SEEDED_Z_INCIDENT,),
        ).fetchone()
    finally:
        conn.close()
    assert row is not None
    assert row[0] == "2026-06-01T00:00:00+00:00"


def test_read_only_connection_usable_from_another_thread(pipeline_base: Path):
    """``check_same_thread=False`` lets the API's single read-only handle
    serve FastAPI threadpool requests (sync endpoints run off the main
    thread); safe because the handle is read-only and Python's sqlite3
    serializes access.
    """
    from sage.sqlite.client import get_connection

    conn = get_connection(
        pipeline_base / "db" / "sage.db",
        read_only=True,
        check_same_thread=False,
    )
    results: list[int] = []
    errors: list[Exception] = []

    def _query() -> None:
        try:
            row = conn.execute("SELECT COUNT(*) AS n FROM Incident").fetchone()
            results.append(row["n"])
        except Exception as exc:  # noqa: BLE001 — assert on any cross-thread failure
            errors.append(exc)

    worker = threading.Thread(target=_query)
    worker.start()
    worker.join()
    conn.close()
    assert errors == []
    assert results and results[0] >= 1


# ---------------------------------------------------------------------------
# Read endpoints
# ---------------------------------------------------------------------------


def test_attack_paths_returns_etl_derived_rows(client: TestClient):
    resp = client.get(
        "/attack-paths",
        params={"asset_id": ASSET_VPN},
        headers=AUTH_HEADER,
    )
    assert resp.status_code == 200, resp.text
    rows = resp.json()
    assert isinstance(rows, list)
    assert rows, "expected ETL-derived attack paths toward the targeted asset"
    for row in rows:
        assert set(row) == {
            "actor_stix_id",
            "actor_name",
            "ttp_stix_id",
            "ttp_name",
            "confidence",
        }
        assert row["actor_stix_id"] == ACTOR_APT99
    confidences = [row["confidence"] for row in rows]
    assert confidences == sorted(confidences, reverse=True)


def test_choke_points_ranks_targeted_assets(client: TestClient):
    resp = client.get("/choke-points", headers=AUTH_HEADER)
    assert resp.status_code == 200, resp.text
    rows = resp.json()
    assert isinstance(rows, list)
    assert rows, "expected at least one choke-point asset"
    assert ASSET_VPN in {row["asset_id"] for row in rows}
    for row in rows:
        assert set(row) >= {"asset_id", "asset_name", "targeting_actor_count", "choke_score"}


def test_actors_search_finds_etl_ingested_actor(client: TestClient):
    resp = client.get("/actors", params={"name": "APT"}, headers=AUTH_HEADER)
    assert resp.status_code == 200, resp.text
    body = resp.json()
    assert body["count"] >= 1
    by_id = {a["stix_id"]: a for a in body["actors"]}
    assert ACTOR_APT99 in by_id
    assert by_id[ACTOR_APT99]["name"] == "APT99"


# ---------------------------------------------------------------------------
# Incident write/read roundtrip
# ---------------------------------------------------------------------------


def test_incident_post_then_get_roundtrip(client: TestClient):
    body = {
        "incident_stix_id": POSTED_INCIDENT,
        "name": "SQLite roundtrip incident",
        "occurred_at": "2026-06-05T10:00:00Z",
        "severity": "high",
        "ttps": [{"ttp_stix_id": TTP_UUID_A, "sequence_order": 0}],
        "description": "registered through the live sqlite write session",
    }
    resp = client.post("/api/incidents", json=body, headers=AUTH_HEADER)
    assert resp.status_code == 200, resp.text
    posted = resp.json()
    assert posted["incident_stix_id"] == POSTED_INCIDENT
    assert posted["accepted"] is True

    resp = client.get(
        "/api/incidents",
        params={"since": "2026-06-05", "until": "2026-06-05"},
        headers=AUTH_HEADER,
    )
    assert resp.status_code == 200, resp.text
    payload = resp.json()
    by_id = {inc["incident_stix_id"]: inc for inc in payload["incidents"]}
    assert POSTED_INCIDENT in by_id
    inc = by_id[POSTED_INCIDENT]
    assert inc["name"] == "SQLite roundtrip incident"
    assert inc["severity"] == "high"
    assert inc["source"] == "direct_api"
    assert inc["ttps"] == [{"ttp_stix_id": TTP_UUID_A, "sequence_order": 0}]


def test_z_suffix_incident_visible_in_window_query(client: TestClient):
    """The Z-seeded incident must be matched by a +00:00 window comparison."""
    resp = client.get(
        "/api/incidents",
        params={"since": "2026-06-01", "until": "2026-06-01"},
        headers=AUTH_HEADER,
    )
    assert resp.status_code == 200, resp.text
    payload = resp.json()
    ids = [inc["incident_stix_id"] for inc in payload["incidents"]]
    assert SEEDED_Z_INCIDENT in ids
