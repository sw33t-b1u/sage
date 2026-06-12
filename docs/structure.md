# SAGE — Project Directory Structure

This document describes the top-level layout of the SAGE repository.

```
SAGE/
├── src/sage/                   # Core Python package
│   ├── config.py               # Environment-based configuration (Config dataclass)
│   ├── etl/
│   │   └── worker.py           # ETL pipeline orchestrator
│   ├── stix/
│   │   ├── parser.py           # STIX 2.1 bundle parsing and validation
│   │   └── mapper.py           # STIX objects → Spanner node/edge rows
│   ├── pir/
│   │   ├── filter.py           # PIR relevance filtering and asset criticality weighting
│   │   └── ingest.py           # Ingest PIR actor-triage entries into PirPrioritizesActor
│   ├── spanner/
│   │   ├── client.py           # Spanner Database client setup
│   │   ├── upsert.py           # Bulk upsert helpers (INSERT OR UPDATE)
│   │   ├── query.py            # Analytical query functions (GQL + SQL)
│   │   ├── incidents.py        # Incident upsert/read helpers
│   │   ├── annotations.py      # Actor annotation write helpers
│   │   ├── constants.py        # Spanner-layer shared constants
│   │   └── migrations/         # Incremental DDL migration scripts
│   ├── sqlite/
│   │   ├── client.py           # SQLite connection setup (read-only / read-write)
│   │   ├── upsert.py           # Bulk upsert helpers (INSERT ... ON CONFLICT)
│   │   ├── query.py            # Analytical query functions (SQL)
│   │   ├── incidents.py        # Incident upsert/read helpers
│   │   └── annotations.py      # Actor annotation write helpers
│   ├── db/
│   │   └── __init__.py         # Backend dispatch layer (SAGE_DB: sqlite | spanner)
│   ├── notify/
│   │   ├── slack.py            # Slack webhook notification
│   │   └── github.py           # GitHub / GHE Issue creation and update
│   ├── api/
│   │   ├── app.py              # FastAPI Analysis API application (internal REST endpoints)
│   │   ├── annotation.py       # POST /api/annotate — actor annotation endpoint
│   │   ├── auth.py             # Shared Bearer-token auth dependency
│   │   ├── incidents.py        # POST / GET /api/incidents — direct IR intake and reads
│   │   ├── models.py           # Pydantic response models for the Analysis API
│   │   ├── threat_summary.py   # GET /threat-summary response builder
│   │   └── windows.py          # Shared time-window helpers for API queries
│   ├── caldera/
│   │   └── client.py           # MITRE Caldera REST API client
│   ├── analysis/
│   │   ├── similarity.py       # Hybrid incident similarity scoring
│   │   └── ttp_asset_matcher.py # TTP → Asset edge derivation via technique / asset-tag matching
│   ├── cli/
│   │   ├── __init__.py              # Unified ``sage`` CLI entry point (click Group)
│   │   ├── analysis_api.py          # Start the Analysis API server
│   │   ├── annotate_actor.py        # Write operator annotations (AnnotatesActor rows)
│   │   ├── create_ir_template.py    # Create IR incident template as GHE Issue
│   │   ├── init_schema.py           # Initialize the database DDL (SQLite or Spanner)
│   │   ├── load_assets.py           # Load internal asset data into the graph database
│   │   ├── load_identity_assets.py  # Load BEACON identity_assets.json
│   │   ├── load_user_accounts.py    # Load BEACON user_accounts.json
│   │   ├── navigator_loader.py      # Parse ATT&CK Navigator layer JSON for incident input
│   │   ├── query_attack_paths.py    # Query attack paths or actor TTPs
│   │   ├── register_incident.py     # Register an incident via the direct-API path
│   │   ├── report_choke_points.py   # Print / export / post choke-point report
│   │   ├── run_etl.py               # Run the ETL pipeline
│   │   ├── setup_emulator.py        # Configure Spanner emulator for local testing
│   │   ├── sync_caldera.py          # Sync actor TTPs to Caldera adversary profile
│   │   ├── visualize_attack_flow.py # Generate interactive attack flow HTML
│   │   ├── visualize_combined.py    # Combined graph + flow visualization
│   │   └── visualize_graph.py       # Generate interactive attack graph HTML
│   ├── models/
│   │   ├── annotation.py       # Actor annotation request/response models
│   │   └── incident_request.py # Incident registration request model
│   ├── storage/
│   │   ├── backend.py          # StorageBackend ABC
│   │   ├── local.py            # LocalStorage implementation
│   │   └── gcs.py              # GCSStorage implementation (optional dep)
│   └── opencti/
│       └── client.py           # OpenCTI STIX 2.1 export client
│
├── schema/
│   ├── sqlite_ddl.sql          # SQLite DDL (default backend; same tables, dialect-mapped)
│   └── spanner_ddl.sql         # Spanner Graph DDL (optional backend)
│
├── tests/
│   ├── fixtures/               # Sample STIX bundles, asset JSON, PIR JSON
│   └── test_*.py               # pytest test files
│
├── docs/                       # English documentation (authoritative)
│   ├── high-level-design.md    # Authoritative system design (local-only; gitignored)
│   ├── setup.md                # Clone, install, configure, first run, testing
│   ├── deploy.md               # Cloud Run deployment and Cloud Scheduler
│   ├── usage.md                # CLI commands, workflows, operations, troubleshooting
│   ├── data-model.md           # Node/edge definitions, PIR formula, FollowedBy weights
│   ├── ir-feedback-flow.md     # IR feedback loop and scoring formulas
│   ├── dependencies.md         # Third-party dependency rationale and licenses
│   ├── api-stability.md        # API stability policy and BC guarantees
│   ├── structure.md            # This file — directory layout reference
│   └── *.ja.md                 # Japanese translations alongside each English doc
│
├── .githooks/                  # Git hooks (install with: make setup)
│   ├── pre-commit              # Runs make vet lint before every commit
│   └── pre-push                # Runs make check before every push
│
├── CHANGELOG.md                # Version history
├── Dockerfile                  # Container image for Cloud Run deployment
├── Makefile                    # Quality gate targets (check, vet, lint, test, audit, setup)
├── pyproject.toml              # Python project config (uv + ruff)
├── uv.lock                     # Locked dependency versions
└── .env.example                # Template for environment variable configuration
```

## Design criteria

- **`src/sage/`** contains all reusable library code. Each sub-package has a single responsibility.
- **`schema/`** is the single source of truth for the database DDL: `sqlite_ddl.sql` for the default SQLite backend and `spanner_ddl.sql` for the optional Spanner backend.
- **`docs/`** holds user-facing documentation. English files use the base name (e.g. `setup.md`); Japanese translations are siblings with the `.ja.md` suffix (e.g. `setup.ja.md`).
- **`docs/high-level-design.md`** must be updated before any architectural change is implemented (Rule 27). The file is gitignored per maintainer policy.
