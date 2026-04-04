# SAGE — Security Attack Graph Engine

A platform that operationalizes the threat intelligence cycle by integrating external CTI data (STIX 2.1) with internal asset and organizational information. It visualizes and weights attack paths, and delivers actionable outputs to Red, Blue, and IR teams.

[日本語版 README はこちら](README.ja.md)

## Out of scope

This system receives data from the following — it does not replace them:
real-time SIEM detection, endpoint protection, vulnerability scanning automation.

## Features

- **Multi-source ingestion** — OpenCTI (STIX 2.1), AWS Security Hub (ASFF → STIX), GCP Security Command Center (SCC Finding → STIX), and analyst manual input via API
- **Attack Graph** — Models asset connectivity and reachable attack paths. Asset criticality is adjusted per PIR (Priority Intelligence Requirements) at query time
- **Attack Flow** — Tracks TTP time-series transitions as weighted `FollowedBy` edges. Weights combine base probability, recent activity score (90-day window), exploit ease (CVSS + EPSS), and IR feedback multiplier
- **Analysis API** — Internal REST API (Cloud Run, VPC-internal, IAP-protected) exposing attack paths, choke points, actor TTPs, and asset exposure queries
- **Team outputs** — GitHub Enterprise playbook issues and choke point reports, Slack priority alerts, Caldera adversary profiles for red team simulations
- **TLP enforcement** — TLP Red objects are excluded from Spanner storage; only `white` / `green` / `amber` data is ingested (configurable)
- **IR feedback loop** — Incident records feed back into `FollowedBy` weights, improving path probability over time

## Architecture

```
[OpenCTI]──STIX 2.1──┐
[Security Hub]────────┼──→ [GCS: Landing Zone (raw STIX JSON)]
[SCC]─────────────────┘         gs://threat-intel-landing/raw/stix/{date}/{source}/{uuid}.json
[Analyst Input API]─────────→  (manual, up to ~5×/day)

                │
                ▼
        [ETL Worker — Cloud Run]
          ├── STIX object type detection
          ├── Deduplication by stix_id (upsert)
          ├── TLP check (red → analyst alert only, not stored)
          ├── PIR relevance filtering
          ├── FollowedBy weight recalculation (affected nodes only)
          └── Spanner Graph upsert

                │
                ▼
        [Spanner Graph: ThreatIntelGraph]
          Nodes: ThreatActor, TTP, Vulnerability, MalwareTool,
                 Asset, SecurityControl, Observable, Incident
          Edges: Uses, MalwareUsesTTP, UsesTool, Exploits,
                 Targets, HasVulnerability, ConnectedTo, ProtectedBy,
                 FollowedBy, IncidentUsesTTP, IndicatesTTP, IndicatesActor

                │
                ▼
        [Analysis API — Cloud Run, VPC-internal]
          GET  /attack-paths?asset_id=&limit=
          GET  /choke-points?top_n=
          GET  /actor-ttps?actor_id=
          GET  /asset-exposure
          GET  /similar-incidents?incident_id=
          POST /caldera/adversary?actor_id=

                │
                ▼
[GHE Issues]  [Slack alerts]  [Caldera adversary profiles]
```

## Requirements

- Python 3.12+
- [uv](https://github.com/astral-sh/uv)
- Google Cloud project with Cloud Spanner and Cloud Storage enabled
- OpenCTI instance (for external CTI ingestion)

## Setup

### 1. Clone and install

```sh
git clone https://github.com/your-org/sage.git
cd sage
uv sync --extra dev
```

### 2. Configure environment variables

| Variable | Required | Default | Description |
|----------|----------|---------|-------------|
| `GCP_PROJECT_ID` | Yes | — | GCP project ID |
| `SPANNER_INSTANCE_ID` | Yes | — | Spanner instance ID |
| `SPANNER_DATABASE_ID` | Yes | — | Spanner database ID |
| `GCS_LANDING_BUCKET` | Yes | — | GCS bucket for raw STIX landing |
| `OPENCTI_URL` | Yes | — | OpenCTI base URL |
| `OPENCTI_TOKEN` | Yes | — | OpenCTI API token |
| `PIR_FILE_PATH` | No | `/config/pir.json` | Path to PIR JSON file |
| `TLP_MAX_LEVEL` | No | `amber` | Maximum TLP level to ingest (`white`/`green`/`amber`) |
| `ACTIVITY_WINDOW_DAYS` | No | `90` | Lookback window for FollowedBy activity score |
| `SLACK_WEBHOOK_URL` | No | — | Slack Incoming Webhook URL for ETL completion alerts |
| `GHE_TOKEN` | No | — | GitHub Enterprise Personal Access Token |
| `GHE_REPO` | No | — | GHE repository in `owner/repo` format |
| `GHE_API_BASE` | No | `https://api.github.com` | GHE API base URL (override for self-hosted) |
| `CALDERA_URL` | No | — | MITRE Caldera server URL (e.g. `http://caldera.internal:8888`) |
| `CALDERA_API_KEY` | No | — | Caldera REST API key |
| `SAGE_API_URL` | No | — | Base URL of the running Analysis API (used by `create_ir_template.py`) |

### 3. Initialize Spanner schema

```sh
make init-schema
```

## Local Testing

### Unit tests (no GCP required)

```sh
make test
```

Unit tests use fixture files under `tests/fixtures/` and do not require any GCP credentials or network access.

### Full local test with Spanner emulator

The complete workflow covers both Attack Flow (STIX threat intel) and Attack Graph (internal assets).

```sh
# 1. Start the emulator (Docker)
docker run -d --name spanner-emulator -p 9010:9010 -p 9020:9020 \
  gcr.io/cloud-spanner-emulator/emulator
export SPANNER_EMULATOR_HOST=localhost:9010

# 2. Create instance, database, and schema
uv run python cmd/setup_emulator.py
make init-schema

# 3. Load threat intelligence (Attack Flow)
uv run python cmd/run_etl.py --manual-bundle tests/fixtures/sample_bundle_mirrorface.json
uv run python cmd/run_etl.py --manual-bundle tests/fixtures/sample_bundle_inc.json

# 4. Load internal assets (Attack Graph)
make load-assets

# 5. Visualize — opens tests/output/graph.html in browser
make visualize

# Stop and remove the emulator when done
docker stop spanner-emulator && docker rm spanner-emulator
```

### Graph output

`make visualize` generates `tests/output/graph.html` (git-ignored) and opens it in your browser.
Nodes are color-coded by type, draggable, and the graph is zoomable.
Use `--no-open` to suppress auto-opening, `--limit N` to cap rows per table.

| Node type | Color | Connects to |
|-----------|-------|-------------|
| ThreatActor | Red | TTP (USES), MalwareTool (USES_TOOL), Asset (TARGETS) |
| TTP | Orange | Vulnerability (EXPLOITS), TTP (FOLLOWED_BY) |
| Vulnerability | Yellow | — |
| MalwareTool | Purple | TTP (MALWARE_USES_TTP) |
| Observable | Teal | TTP (INDICATES_TTP), ThreatActor (INDICATES_ACTOR) |
| Incident | Pink | TTP (INCIDENT_USES_TTP) |
| Asset | Blue | Vulnerability (HAS_VULN), Asset (CONNECTED_TO), SecurityControl (PROTECTED_BY) |
| SecurityControl | Gray | — |

### Sample fixtures

| File | Description |
|------|-------------|
| `tests/fixtures/sample_bundle_mirrorface.json` | MirrorFace / Earth Kasha APT (targets Japan, 2024–2025). TTPs: T1190, T1566.001, T1574.002, T1071.001, T1083, T1041. CVE-2023-28461, CVE-2024-21412. LODEINFO backdoor + C2 IoCs. |
| `tests/fixtures/sample_bundle_inc.json` | INC Ransomware (active 2023–, targets healthcare/manufacturing). TTPs: T1190, T1078, T1003.001, T1021.002, T1048.002, T1486. CVE-2023-3519, CVE-2023-4966 (Citrix). Tools: Cobalt Strike, AnyDesk, MegaSync. IoCs from Trend Micro report. |
| `tests/fixtures/sample_assets.json` | Japanese manufacturing enterprise assets: Citrix NetScaler ADC (DMZ, internet-exposed), Active Directory, File Server, Backup Server, ERP (SAP), Factory PLC, Workstations. Network topology and SecurityControl assignments included. |

## Development

```sh
# Full quality gate: vet → lint → test
make check

# Individual targets
make vet       # ruff check (linting)
make lint      # ruff format --check (formatting check)
make format    # ruff format + ruff check --fix (auto-fix)
make test      # pytest
make audit     # pip-audit (dependency vulnerability scan)

# Run ETL manually
make run-etl
```

## Project Structure

```
sage/
├── src/sage/
│   ├── config.py              # Environment-based configuration
│   ├── etl/
│   │   └── worker.py          # ETL pipeline worker (GCS → Spanner)
│   ├── stix/
│   │   ├── parser.py          # STIX 2.1 JSON parser
│   │   └── mapper.py          # STIX object → Spanner schema mapper
│   ├── pir/
│   │   └── filter.py          # PIR filtering & pir_adjusted_criticality calculation
│   ├── spanner/
│   │   ├── client.py          # Spanner client
│   │   ├── upsert.py          # Graph node/edge upsert logic
│   │   └── query.py           # Analysis queries (GQL + SQL)
│   ├── notify/
│   │   ├── slack.py           # Slack Incoming Webhook notifications
│   │   └── github.py          # GitHub Enterprise Issue creation
│   ├── api/
│   │   └── app.py             # FastAPI Analysis API (Cloud Run entry point)
│   ├── caldera/
│   │   └── client.py          # MITRE Caldera REST API client
│   ├── analysis/
│   │   └── similarity.py      # Hybrid IR incident similarity (Jaccard + BFS)
│   └── opencti/
│       └── client.py          # OpenCTI REST API polling client
├── cmd/
│   ├── init_schema.py         # Initialize Spanner schema (DDL)
│   ├── run_etl.py             # Manual ETL trigger (+ Slack notification)
│   ├── load_assets.py         # Load internal asset data into Spanner
│   ├── report_choke_points.py # Print/export choke point report (--ghe to post GHE Issue)
│   ├── query_attack_paths.py  # Query attack paths by asset or actor
│   ├── visualize_graph.py     # Generate Attack Graph HTML (pyvis)
│   ├── visualize_attack_flow.py  # Generate Attack Flow HTML with FollowedBy weights
│   ├── analysis_api.py        # Start Analysis API via uvicorn
│   ├── sync_caldera.py        # Sync actor TTPs to Caldera adversary profile
│   └── create_ir_template.py  # Create IR incident GHE Issue from template
├── schema/                    # Spanner DDL definitions
├── tests/
│   ├── fixtures/              # STIX bundles and PIR JSON for tests
│   ├── test_mapper.py
│   ├── test_pir_filter.py
│   ├── test_spanner_query.py
│   ├── test_notify.py
│   ├── test_api.py
│   ├── test_similarity.py
│   └── test_caldera.py
├── Dockerfile                 # Cloud Run container image
├── Makefile
└── pyproject.toml
```

## Data Model

The Spanner Graph (`ThreatIntelGraph`) contains the following node and edge types.

### Nodes

| Node | Description |
|------|-------------|
| `ThreatActor` | Threat actor groups and individuals (STIX identity, tags for PIR matching) |
| `TTP` | ATT&CK techniques/sub-techniques with detection difficulty level |
| `Vulnerability` | CVEs with CVSS score, EPSS score, and affected platforms |
| `MalwareTool` | Malware families and attacker tools |
| `Asset` | Internal assets (server, endpoint, SaaS, storage, network device) with PIR-adjusted criticality. Network segment info (name, CIDR, zone) is stored as properties on this node. |
| `SecurityControl` | Defensive controls: EDR, WAF, SIEM, firewall, IAM |
| `Observable` | IoCs — IPs, domains, hashes, emails, URLs with TLP and confidence |
| `Incident` | IR incidents including diamond model and kill chain phases |

### Edges

| Edge | Source → Destination | Description |
|------|----------------------|-------------|
| `Uses` | ThreatActor → TTP | Actor uses a technique |
| `MalwareUsesTTP` | MalwareTool → TTP | Malware/tool uses a technique |
| `UsesTool` | ThreatActor → MalwareTool | Actor uses a malware or tool |
| `Exploits` | TTP → Vulnerability | Technique exploits a CVE |
| `FollowedBy` | TTP → TTP | TTP time-series transition with probability weight |
| `IncidentUsesTTP` | Incident → TTP | IR incident observed using a technique |
| `Targets` | ThreatActor → Asset | Actor targets an internal asset (auto-generated via PIR tag matching) |
| `HasVulnerability` | Asset → Vulnerability | Asset has an unpatched CVE |
| `ConnectedTo` | Asset ↔ Asset | Network reachability between assets |
| `ProtectedBy` | Asset → SecurityControl | Asset is covered by a control |
| `IndicatesTTP` | Observable → TTP | IoC is attributed to a TTP |
| `IndicatesActor` | Observable → ThreatActor | IoC is attributed to a threat actor |

## PIR-Based Asset Weighting

Priority Intelligence Requirements (PIRs) drive dynamic asset criticality adjustments.

> **Generating PIRs:** Use [BEACON](../BEACON) to automatically generate PIR JSON from your organization's business context (crown jewels, strategic objectives, cloud projects). BEACON produces SAGE-compatible `pir_output.json` ready to place at `PIR_FILE_PATH`. See [BEACON/docs/sage_integration.md](../BEACON/docs/sage_integration.md) for the end-to-end deployment procedure.

```json
{
  "pir_id": "PIR-2025-001",
  "description": "Ransomware group resilience improvement",
  "threat_actor_tags": ["ransomware", "financially-motivated"],
  "asset_weight_rules": [
    { "tag": "external-facing", "criticality_multiplier": 2.0 },
    { "tag": "s3",              "criticality_multiplier": 1.8 },
    { "tag": "backup",          "criticality_multiplier": 1.5 }
  ],
  "valid_from": "2025-01-01",
  "valid_until": "2025-12-31"
}
```

```
pir_adjusted_criticality =
  criticality
  × MAX(matching PIR rules' criticality_multiplier)
  × 1.5  (if ThreatActor targets this asset AND actor.tags ∩ PIR.threat_actor_tags ≠ ∅)
```

## FollowedBy Weight Calculation

The `FollowedBy.weight` field represents the transition probability between two TTPs:

```
weight(src_ttp → dst_ttp) =
  base_prob        ×   -- transition frequency in ATT&CK kill chain (from STIX observations)
  activity_score   ×   -- OpenCTI observation frequency in last 90 days (0.0–2.0)
  exploit_ease     ×   -- CVSSv3 Exploitability + EPSS (where applicable)
  ir_multiplier        -- +adjustment for transitions observed in internal IR records
```

Weights from `ir_feedback` and `manual_analysis` sources are stored as separate records and can be queried independently or aggregated.

## ETL Schedule

| Trigger | Scope | Latency target |
|---------|-------|---------------|
| Cloud Scheduler (daily 03:00 JST) | Full weight recalculation for all nodes/edges | Within 2 hours |
| Analyst Input API (manual) | Incremental update for added data only | Within 5 minutes |
| IR Feedback (OpenCTI → GCS) | Incident + IncidentUsesTTP + FollowedBy ir_feedback | Within 30 minutes |

## GCP Infrastructure

```
Spanner (us-central1)
  └── ThreatIntelGraph (regional, 1000 PU)

Cloud Storage
  ├── threat-intel-landing    (TTL: raw data 90 days)
  └── threat-intel-processed  (TTL: processed 1 year)

Cloud Run
  ├── etl-worker              (shared for batch and manual triggers)
  ├── analysis-api            (VPC-internal, IAP-protected, no public IP)
  └── internal-data-api       (asset and PIR management)

Cloud Scheduler
  └── daily-etl-trigger       (03:00 JST → etl-worker)

Pub/Sub
  └── scc-findings-topic      (Security Command Center → ETL)

Secret Manager
  └── opencti-api-key, slack-token, ghe-token, caldera-token
```

> **Note:** `analysis-api` has no public IP. Access is via Cloud IAP + Internal Load Balancer only.

## Implementation Phases

| Phase | Scope | Deliverable | Status |
|-------|-------|-------------|--------|
| Phase 1 | Spanner Graph schema + OpenCTI → STIX ETL | Working graph DB | Complete |
| Phase 2 | Internal asset data + PIR application + attack path queries | Choke point visualization | Complete |
| Phase 3 | FollowedBy weight calculation + attack flow visualization + Slack/GHE notifications | Blue Team ready | Complete |
| Phase 4 | Caldera integration + IR feedback loop + Analysis API | Red/IR Team ready | Complete |

## License

Apache-2.0 — see [LICENSE](LICENSE)
