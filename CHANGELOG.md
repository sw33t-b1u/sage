# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).


## [0.4.0] - 2026-04-04

### Added

**Analysis API (FastAPI)**
- `src/sage/api/app.py` — FastAPI application serving all analysis endpoints on Cloud Run
- `cmd/analysis_api.py` — uvicorn entry point (`--host`, `--port`, `--reload`)
- Endpoints: `GET /attack-paths`, `GET /choke-points`, `GET /actor-ttps`, `GET /asset-exposure`, `GET /similar-incidents`, `POST /caldera/adversary`
- Validation via FastAPI `Query` parameters (range checks, required fields)

**IR Incident Similarity (P4-3a)**
- `src/sage/analysis/similarity.py` — Hybrid similarity engine
  - `jaccard_ttp`: TTP set Jaccard similarity
  - `transition_coverage`: BFS reachability on FollowedBy graph (max 2 hops) — handles missing intermediate TTPs
  - `hybrid_score = 0.5 × jaccard_ttp + 0.5 × transition_coverage` (α configurable)
  - `find_similar_incidents()`: loads FollowedBy graph into memory, ranks all candidate incidents
- `src/sage/spanner/query.py` — Added `find_incident_ttps()`, `find_followedby_edges()`, `find_all_incident_ttps()`

**Caldera Integration (P4-2)**
- `src/sage/caldera/client.py` — MITRE Caldera REST API client (`CALDERA_URL`, `CALDERA_API_KEY`)
  - `get_adversaries()`, `create_adversary()`, `update_adversary()`, `sync_actor_ttps()`
  - Upsert semantics: updates existing profile by name, creates new if absent
- `cmd/sync_caldera.py` — CLI to sync actor TTPs to Caldera adversary profiles (`--actor-id`, `--list-adversaries`)

**IR Template (P4-3b)**
- `cmd/create_ir_template.py` — Creates structured GHE Issue from IR incident metadata
  - `--dry-run` for local preview; fetches similar incidents from `SAGE_API_URL` when set
  - Template includes: summary table, timeline, affected assets, TTPs, similar incidents section

**Configuration**
- `src/sage/config.py` — Added `caldera_url`, `caldera_api_key` (env: `CALDERA_URL`, `CALDERA_API_KEY`)
- `pyproject.toml` — Added `fastapi>=0.115.0`, `uvicorn>=0.30.0`; dev: `httpx>=0.27.0`

**Tests**
- `tests/test_api.py` — 14 tests (TestClient for all endpoints, validation, error handling)
- `tests/test_similarity.py` — 25 tests (graph build, BFS, Jaccard, transition coverage, hybrid score, Spanner mock)
- `tests/test_caldera.py` — 10 tests (get/create/update/sync with mocked requests)

---

## [0.3.0] - 2026-04-03

### Added

**Attack Flow Visualization**
- `cmd/visualize_attack_flow.py` — Interactive HTML visualization of FollowedBy-weighted Attack Flow
  - Edge width and color gradient (red → yellow → green) encode `weight`
  - `source` field controls line style: `threat_intel` = solid, `ir_feedback`/`manual_analysis` = dashed
  - `--actor-id` filter, `--limit`, `--no-open`, `--output` options
  - Legend HTML injected into output file

**Slack Notifications**
- `src/sage/notify/slack.py` — ETL completion notifications via Slack Incoming Webhook
  - Detects ≥10% change in choke scores between runs
  - Block Kit message with stats and top choke point changes
- `cmd/run_etl.py` — Captures pre/post choke rows; calls `notify_etl_complete()` when `SLACK_WEBHOOK_URL` is set
- `src/sage/config.py` — Added `slack_webhook_url` (env: `SLACK_WEBHOOK_URL`)

**GitHub Enterprise Integration**
- `src/sage/notify/github.py` — GHE Issue creation/update via GitHub REST API
  - Finds existing open Issue by `sage-report` label within same ISO week; PATCHes if found, POSTs if not
  - `_ensure_label()` creates the `sage-report` label if absent
- `cmd/report_choke_points.py` — Added `--ghe` flag to post choke point report as GHE Issue

**Configuration**
- `src/sage/config.py` — Added `ghe_token`, `ghe_repo` (env: `GHE_TOKEN`, `GHE_REPO`)
- `pyproject.toml` — Added `requests>=2.32.0`

**Tests**
- `tests/test_notify.py` — 9 tests (Slack change detection, post logic; GHE create/update)

---

## [0.2.0] - 2026-04-02

### Added

**PIR-Adjusted Asset Criticality**
- `src/sage/pir/filter.py` — `update_asset_criticality()`: applies PIR tag matching and Targets-actor multiplier
  - `pir_adjusted_criticality = base × MAX(multiplier) × targets_multiplier` (1.5× if PIR actor targets the asset)
  - Capped at 10.0
- `src/sage/spanner/upsert.py` — `update_pir_criticality()`: partial `batch.update()` for `pir_adjusted_criticality`; `fetch_asset_rows()`: reads all Asset rows via `KeySet(all_=True)`
- `src/sage/etl/worker.py` — Calls `update_asset_criticality()` then `update_pir_criticality()` after Targets generation

**Spanner Query Module**
- `src/sage/spanner/query.py` — Analysis queries:
  - `find_attack_paths(asset_id, limit)`: GQL traversal ThreatActor → TTP path to asset
  - `find_actor_ttps(actor_stix_id)`: GQL actor → TTP → FollowedBy flow
  - `find_choke_points(top_n)`: SQL ranking by `pir_adjusted_criticality × actor_count`
  - `find_asset_exposure()`: SQL for internet-exposed assets with reachable TTP count

**CLI Reports**
- `cmd/report_choke_points.py` — Markdown choke point report (`--top N`, `--output FILE`)
- `cmd/query_attack_paths.py` — Attack path query by `--asset-id` or `--actor-id`
- `cmd/load_assets.py` — Loads internal asset + Targets data into Spanner
- `cmd/visualize_graph.py` — Generates Attack Graph HTML using pyvis

**Schema Fix**
- `schema/spanner_ddl.sql` — `Targets.stix_id` → `Targets.source STRING(32)` (values: `pir_auto`, `manual`, `stix`)
- `schema/spanner_ddl.sql` — Moved `MalwareUsesTTP` from Attack Graph section to Attack Flow section

**Tests**
- `tests/test_pir_filter.py` — Added `TestUpdateAssetCriticality` (6 tests), `TestBuildTargets`
- `tests/test_spanner_query.py` — 10 tests (MagicMock for Spanner snapshot)
- `tests/test_mapper.py` — Added `TestMapIncidentTTPEdges` (5 tests); extended fixture `sample_bundle_inc.json`

---

## [0.1.0] - 2026-04-02

### Added

**ETL Pipeline**
- `etl/worker.py` — Cloud Run ETL worker: STIX object ingestion from GCS landing zone, PIR filtering, FollowedBy weight calculation, Spanner Graph upsert
- `stix/parser.py` — STIX 2.1 JSON parser supporting all node types (ThreatActor, TTP, Vulnerability, MalwareTool, Observable, Incident)
- `stix/mapper.py` — STIX object → Spanner Graph schema mapper (nodes and edges)
- `pir/filter.py` — PIR-based relevance filtering and `pir_adjusted_criticality` calculation for assets

**Spanner Graph**
- `spanner/client.py` — Google Cloud Spanner client with connection management
- `spanner/upsert.py` — Upsert logic for all node and edge tables
- `schema/` — DDL definitions for all Spanner tables and `ThreatIntelGraph` property graph

**OpenCTI Integration**
- `opencti/client.py` — OpenCTI REST API polling client (STIX 2.1 bundle export)

**Commands**
- `cmd/init_schema.py` — Initialize Spanner schema (DDL execution)
- `cmd/run_etl.py` — Manual ETL trigger

**Configuration**
- `config.py` — Environment-based configuration (GCP project, Spanner instance/database, GCS buckets, OpenCTI endpoint)
- `pyproject.toml` — Project metadata, dependencies, ruff and pytest configuration

**Infrastructure**
- `Dockerfile` — Cloud Run container image for ETL worker
- `Makefile` — `check` (vet → lint → test), `format`, `audit`, `init-schema`, `run-etl`

**Tests**
- `tests/test_mapper.py` — Unit tests for STIX → Spanner schema mapping
- `tests/test_pir_filter.py` — Unit tests for PIR filtering and asset criticality adjustment
- `tests/fixtures/` — Test fixture data (STIX bundles, PIR JSON)

[0.4.0]: https://github.com/your-org/sage/releases/tag/v0.4.0
[0.3.0]: https://github.com/your-org/sage/releases/tag/v0.3.0
[0.2.0]: https://github.com/your-org/sage/releases/tag/v0.2.0
[0.1.0]: https://github.com/your-org/sage/releases/tag/v0.1.0
