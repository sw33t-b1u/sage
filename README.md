# SAGE — Security Attack Graph Engine

A platform that operationalizes the threat intelligence cycle by integrating external CTI data (STIX 2.1) with internal asset and organizational information. It visualizes and weights attack paths, and delivers actionable outputs to Red, Blue, and IR teams.

[日本語版 README はこちら](README.ja.md)

## Out of scope

This system receives data from the following — it does not replace them:
real-time SIEM detection, endpoint protection, vulnerability scanning automation.

## Features

- **Multi-source ingestion** — OpenCTI (STIX 2.1), AWS Security Hub, GCP Security Command Center, and analyst manual input via API
- **Attack Graph** — Models asset connectivity and reachable attack paths. Asset criticality is dynamically adjusted per PIR at ETL time
- **Attack Flow** — Tracks TTP time-series transitions as weighted `FollowedBy` edges
- **Analysis API** — Internal REST API (Cloud Run, VPC-internal, IAP-protected) exposing attack paths, choke points, actor TTPs, and asset exposure queries
- **Team outputs** — GitHub Enterprise playbook issues, Slack priority alerts, Caldera adversary profiles for red team simulations
- **TLP enforcement** — TLP Red objects excluded from storage; only `white`/`green`/`amber` ingested
- **IR feedback loop** — Incident records feed back into `FollowedBy` weights over time

## Architecture

```
[OpenCTI]──STIX 2.1──┐
[Security Hub]────────┼──→ [GCS: Landing Zone]
[SCC]─────────────────┘
[Analyst Input API]──────→ (manual)

        │
        ▼
[ETL Worker — Cloud Run]
  ├── STIX parsing + deduplication
  ├── TLP enforcement
  ├── PIR relevance filtering
  ├── FollowedBy weight recalculation
  └── Spanner Graph upsert

        │
        ▼
[Spanner Graph: ThreatIntelGraph]

        │
        ▼
[Analysis API — Cloud Run, VPC-internal]
  GET /attack-paths  GET /choke-points
  GET /actor-ttps    GET /asset-exposure

        │
        ▼
[GHE Issues]  [Slack alerts]  [Caldera adversary profiles]
```

## Documentation

| Document | Description |
|----------|-------------|
| [docs/setup.md](docs/setup.md) | GCP resource creation, schema init, Cloud Run & Scheduler deployment |
| [docs/analyst-guide.md](docs/analyst-guide.md) | Day-to-day usage: ETL, choke points, graph visualization, PIR updates, IR workflow |
| [docs/data-model.md](docs/data-model.md) | Node/edge definitions, PIR weighting formula, FollowedBy weight calculation |
| [docs/local-testing.md](docs/local-testing.md) | Spanner emulator setup, unit tests, sample fixtures |
| [docs/dependencies.md](docs/dependencies.md) | Dependency rationale and license information |

## Quick start

```sh
git clone https://github.com/sw33t-b1u/sage.git
cd sage
uv sync --extra dev
cp .env.example .env   # fill in GCP_PROJECT_ID, SPANNER_*, GCS_*, OPENCTI_*
```

See [docs/setup.md](docs/setup.md) for the full setup procedure.

## Project Structure

```
sage/
├── src/sage/
│   ├── config.py
│   ├── etl/worker.py              # ETL pipeline
│   ├── stix/{parser,mapper}.py    # STIX 2.1 parsing
│   ├── pir/filter.py              # PIR filtering & criticality adjustment
│   ├── spanner/{client,upsert,query}.py
│   ├── notify/{slack,github}.py
│   ├── api/app.py                 # FastAPI Analysis API
│   ├── caldera/client.py
│   ├── analysis/similarity.py
│   └── opencti/client.py
├── cmd/
│   ├── init_schema.py
│   ├── run_etl.py
│   ├── load_assets.py
│   ├── report_choke_points.py
│   ├── query_attack_paths.py
│   ├── visualize_graph.py
│   ├── visualize_attack_flow.py
│   ├── analysis_api.py
│   ├── sync_caldera.py
│   └── create_ir_template.py
├── schema/spanner_ddl.sql
├── tests/fixtures/
├── Dockerfile
├── Makefile
└── pyproject.toml
```

## Development

```sh
make check     # lint + test + audit (full quality gate)
make vet       # ruff check
make lint      # ruff format --check
make format    # ruff format + fix
make test      # pytest
make audit     # pip-audit
```

## GCP Infrastructure

```
Spanner (us-central1)       — ThreatIntelGraph
Cloud Storage               — STIX landing zone (90-day TTL)
Cloud Run                   — ETL worker + Analysis API
Cloud Scheduler             — daily ETL trigger (03:00 JST)
Secret Manager              — API tokens and credentials
```

## Implementation Phases

| Phase | Scope | Status |
|-------|-------|--------|
| Phase 1 | Spanner Graph schema + OpenCTI → STIX ETL | Complete |
| Phase 2 | Internal asset data + PIR application + attack path queries | Complete |
| Phase 3 | FollowedBy weights + visualization + Slack/GHE notifications | Complete |
| Phase 4 | Caldera integration + IR feedback loop + Analysis API | Complete |

## License

Apache-2.0 — see [LICENSE](LICENSE)
