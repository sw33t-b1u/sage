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
│   │   └── filter.py           # PIR relevance filtering and asset criticality weighting
│   ├── spanner/
│   │   ├── client.py           # Spanner Database client setup
│   │   ├── upsert.py           # Bulk upsert helpers (INSERT OR UPDATE)
│   │   └── query.py            # Analytical query functions (GQL + SQL)
│   ├── notify/
│   │   ├── slack.py            # Slack webhook notification
│   │   └── github.py           # GitHub / GHE Issue creation and update
│   ├── api/
│   │   └── app.py              # FastAPI Analysis API (internal REST endpoints)
│   ├── caldera/
│   │   └── client.py           # MITRE Caldera REST API client
│   ├── analysis/
│   │   └── similarity.py       # Hybrid incident similarity scoring
│   └── opencti/
│       └── client.py           # OpenCTI STIX 2.1 export client
│
├── cmd/                        # CLI entry points (one script per command)
│   ├── init_schema.py          # Initialize Spanner Graph DDL
│   ├── run_etl.py              # Run the ETL pipeline
│   ├── load_assets.py          # Load internal asset data into Spanner
│   ├── report_choke_points.py  # Print / export / post choke-point report
│   ├── query_attack_paths.py   # Query attack paths or actor TTPs
│   ├── visualize_graph.py      # Generate interactive attack graph HTML
│   ├── visualize_attack_flow.py# Generate interactive attack flow HTML
│   ├── analysis_api.py         # Start the Analysis API server
│   ├── sync_caldera.py         # Sync actor TTPs to Caldera adversary profile
│   ├── create_ir_template.py   # Create IR incident template as GHE Issue
│   └── setup_emulator.py       # Configure Spanner emulator for local testing
│
├── schema/
│   └── spanner_ddl.sql         # Spanner Graph DDL (nodes, edges, property graph)
│
├── tests/
│   ├── fixtures/               # Sample STIX bundles, asset JSON, PIR JSON
│   └── test_*.py               # pytest test files
│
├── docs/                       # English documentation (authoritative)
│   ├── setup.md                # GCP resource creation, deployment, scheduler setup
│   ├── analyst-guide.md        # Day-to-day usage guide for CTI analysts
│   ├── data-model.md           # Node/edge definitions, PIR formula, FollowedBy weights
│   ├── local-testing.md        # Spanner emulator setup and unit test instructions
│   ├── dependencies.md         # Third-party dependency rationale and licenses
│   ├── structure.md            # This file — directory layout reference
│   └── ja/                     # Japanese translations (kept in sync with English)
│
├── .githooks/                  # Git hooks (install with: make setup)
│   ├── pre-commit              # Runs make vet lint before every commit
│   └── pre-push                # Runs make check before every push
│
├── high-level-design.md        # Authoritative system design document
├── CHANGELOG.md                # Version history
├── Dockerfile                  # Container image for Cloud Run deployment
├── Makefile                    # Quality gate targets (check, vet, lint, test, audit, setup)
├── pyproject.toml              # Python project config (uv + ruff)
├── uv.lock                     # Locked dependency versions
└── .env.example                # Template for environment variable configuration
```

## Design criteria

- **`src/sage/`** contains all reusable library code. Each sub-package has a single responsibility.
- **`cmd/`** contains thin CLI scripts that parse arguments, load configuration, and delegate to `src/sage/` modules. No business logic lives here.
- **`schema/`** is the single source of truth for the Spanner Graph DDL.
- **`docs/`** holds user-facing documentation in English; `docs/ja/` holds Japanese translations.
- **`high-level-design.md`** must be updated before any architectural change is implemented (Rule 27).
