# SAGE — Setup Guide

## Prerequisites

- Python 3.12+
- [uv](https://github.com/astral-sh/uv)
- Google Cloud project with billing enabled
- OpenCTI instance (for live CTI ingestion; not required for manual STIX bundle mode)

---

## Step 1 — Clone and install

```sh
git clone https://github.com/sw33t-b1u/sage.git
cd sage
uv sync --extra dev
```

Install git hooks (pre-commit: `vet lint`; pre-push: `make check`):

```sh
make setup
```

---

## Step 2 — Configure environment variables

Copy `.env.example` to `.env` and fill in the values.

| Variable | Required | Default | Description |
|----------|----------|---------|-------------|
| `PROJECT_ID` | Yes | — | GCP project ID |
| `REGION` | Shell only | `us-central1` | GCP region for `gcloud` commands (not used in Python code) |
| `SPANNER_INSTANCE` | Yes | — | Spanner instance ID |
| `SPANNER_DB` | Yes | — | Spanner database ID |
| `GCS_BUCKET` | Yes | — | GCS bucket for raw STIX landing |
| `OPENCTI_URL` | Yes | — | OpenCTI base URL |
| `OPENCTI_TOKEN` | Yes | — | OpenCTI API token |
| `PIR_FILE_PATH` | No | `/config/pir.json` | Path to PIR JSON file |
| `TLP_MAX_LEVEL` | No | `amber` | Maximum TLP level to ingest (`white`/`green`/`amber`) |
| `ACTIVITY_WINDOW_DAYS` | No | `90` | Lookback window for FollowedBy activity score (overridden by `SAGE_ACTIVITY_WINDOW_DAYS` if set) |
| `SAGE_ACTIVITY_WINDOW_DAYS` | No | — | SAGE-specific override for `ACTIVITY_WINDOW_DAYS` |
| `SLACK_WEBHOOK_URL` | No | — | Slack Incoming Webhook URL for ETL completion alerts |
| `GHE_TOKEN` | No | — | GitHub Enterprise Personal Access Token |
| `GHE_REPO` | No | — | GHE repository in `owner/repo` format |
| `GHE_API_BASE` | No | `https://api.github.com` | GHE API base URL (override for self-hosted) |
| `CALDERA_URL` | No | — | MITRE Caldera server URL |
| `CALDERA_API_KEY` | No | — | Caldera REST API key |
| `SAGE_API_URL` | No | — | Base URL of the running Analysis API |
| `SAGE_API_AUTH_TOKEN` | API mode | — | Bearer token for Analysis API authentication |
| `SAGE_STORAGE` | No | `local` | Storage backend: `local` or `gcs` |
| `SAGE_STORAGE_BASE_DIR` | No | `output` | Base directory for `local` backend |
| `SAGE_GCS_BUCKET` | GCS mode | — | GCS bucket name (required when `SAGE_STORAGE=gcs`) |
| `SAGE_GCS_PREFIX` | No | (empty) | Key prefix within the GCS bucket |
| `OTEL_SDK_DISABLED` | No | — | Set `true` to suppress Spanner client metrics export errors |

---

## Step 3 — Create GCP resources

```sh
# Load .env (set in Step 2) — all variables including REGION are now available
source .env

# Enable required APIs
gcloud services enable spanner.googleapis.com storage.googleapis.com \
  --project=${PROJECT_ID}

# Create Spanner instance
gcloud spanner instances create ${SPANNER_INSTANCE} \
  --config=regional-${REGION} \
  --description="SAGE Threat Intelligence" \
  --nodes=1 \
  --project=${PROJECT_ID}

# Create Spanner database
gcloud spanner databases create ${SPANNER_DB} \
  --instance=${SPANNER_INSTANCE} \
  --project=${PROJECT_ID}

# Create GCS landing bucket
gcloud storage buckets create gs://${GCS_BUCKET} \
  --location=${REGION} \
  --project=${PROJECT_ID}
```

> **Cost note:** A 1-node Spanner instance costs ~$0.90/hour. Use `--processing-units=100` instead of `--nodes=1` to minimize cost during evaluation.

---

## Step 4 — Initialize Spanner schema

```sh
make init-schema
```

---

## Step 5 — Load initial asset data

Create the `input/` directory (gitignored — may contain sensitive data) and place your asset file:

```sh
mkdir input

# Generate assets.json with BEACON, or start from the sample fixture:
cp tests/fixtures/sample_assets.json input/assets.json
# Edit input/assets.json to reflect your actual asset inventory
```

> **Validate before loading.** Pass the file through TRACE first so SAGE
> never ingests an artifact that fails schema or semantic checks
> ([TRACE](https://github.com/sw33t-b1u/trace) is the single validation
> gate for `assets.json`, `pir_output.json`, and STIX bundles):
>
> ```sh
> cd ../TRACE && uv run python cmd/validate_assets.py --assets ../SAGE/input/assets.json
> ```

```sh
uv run python cmd/load_assets.py            # reads input/assets.json by default
uv run python cmd/load_assets.py --file path/to/assets.json   # custom path
```

---

## Step 5.1 — Load identity assets (Initiative A / Initiative C Phase 2)

BEACON also emits `identity_assets.json` (people / roles / groups granted
access on internal assets). Place it under `input/` and validate via TRACE
before loading — TRACE 1.6.0+ cross-checks each `has_access[].asset_id`
against `assets.json` and validates the Initiative C Phase 2 flag
`is_high_value_impersonation_target` plus `impersonation_risk_factors`:

```sh
cp /path/to/identity_assets.json input/identity_assets.json

cd ../TRACE && uv run python cmd/validate_identity_assets.py \
  --identity-assets ../SAGE/input/identity_assets.json \
  --assets          ../SAGE/input/assets.json

cd ../SAGE && uv run python cmd/load_identity_assets.py \
  --file input/identity_assets.json
```

SAGE upserts `Identity` rows, `HasAccess` edges, and — when the flag is
set — derives the `PirPrioritizesImpersonationTarget` cascade edge so
`effective_priority` on `ImpersonatesIdentity` switches to multiplier=1.5.

---

## Step 5.2 — Load user accounts (Initiative B)

BEACON `user_accounts.json` carries account-level granularity (individual
login identifiers like `alice@corp`, `svc-jenkins`) below the identity
layer. Validate via TRACE and load:

```sh
cp /path/to/user_accounts.json input/user_accounts.json

cd ../TRACE && uv run python cmd/validate_user_accounts.py \
  --user-accounts ../SAGE/input/user_accounts.json \
  --assets        ../SAGE/input/assets.json

cd ../SAGE && uv run python cmd/load_user_accounts.py \
  --file input/user_accounts.json
```

`UserAccount` rows link to `Identity` via optional `identity_id` and to
host `Asset` rows via `AccountOnAsset` edges (composite key
`(user_account_id, asset_id)`).

---

## Step 6 — Place PIR file

Generate a PIR JSON with [BEACON](https://github.com/sw33t-b1u/beacon) (`cmd/generate_pir.py`) and place it in `input/`:

```sh
cp /path/to/pir_output_<timestamp>.json input/pir.json
# PIR_FILE_PATH=input/pir.json is already set in .env.example
```

> **Validate via TRACE before ETL.** TRACE checks Pydantic schema,
> threat-taxonomy presence of every `threat_actor_tags[*]`, and that
> each `asset_weight_rules[*].tag` matches at least one tag in your
> assets file:
>
> ```sh
> cd ../TRACE && uv run python cmd/validate_pir.py \
>   --pir ../SAGE/input/pir.json --assets ../SAGE/input/assets.json
> ```

---

## Step 7 — Run ETL manually (first-time verification)

> **STIX bundle source.** SAGE accepts STIX bundles from OpenCTI,
> Security Hub, SCC, or [TRACE](https://github.com/sw33t-b1u/trace).
> When using TRACE-produced bundles, run `validate_stix.py` first —
> SAGE will silently skip dangling references but TRACE catches them
> upfront. TRACE-emitted bundles carry `x_trace_*` envelope metadata
> which the SAGE parser ignores (forward-compatible).

```sh
# No OpenCTI required — use a local STIX bundle
uv run python cmd/run_etl.py --manual-bundle tests/fixtures/sample_bundle_mirrorface.json

# Against live OpenCTI
make run-etl
```

---

---

## Testing

### Unit tests (no GCP required)

```sh
make test
```

Uses fixture files under `tests/fixtures/`. No GCP credentials or network access needed.

For coverage report:
```sh
uv run pytest --cov=src/sage --cov-report=term-missing
```

---

### Full local test with Spanner emulator

Covers the complete workflow: Attack Flow (STIX threat intel) + Attack Graph (internal assets).

**Requires Docker or Podman.**

```sh
# 1. Start the Spanner emulator
docker run -d --name spanner-emulator -p 9010:9010 -p 9020:9020 \
  gcr.io/cloud-spanner-emulator/emulator
export SPANNER_EMULATOR_HOST=localhost:9010

# 2. Create instance, database, and schema
uv run python cmd/setup_emulator.py
make init-schema

# 3. Load threat intelligence (Attack Flow)
# NOTE: external or hand-authored bundles must be enriched first so PIR filtering retains actors:
#   cd ../TRACE && uv run python cmd/enrich_bundle.py --input <bundle.json> --output enriched.json && cd ../SAGE
uv run python cmd/run_etl.py --manual-bundle tests/fixtures/sample_bundle_mirrorface.json
uv run python cmd/run_etl.py --manual-bundle tests/fixtures/sample_bundle_inc.json

# 4. Load internal assets (Attack Graph)
make load-assets

# 5. Visualize — generates tests/output/graph.html and opens in browser
make visualize

# 6. Stop and remove the emulator when done
docker stop spanner-emulator && docker rm spanner-emulator
```

#### Using Podman instead of Docker

Podman is a drop-in replacement — every `docker` subcommand above works identically with `podman`. No flags or image name changes.

On macOS, Podman requires a VM (one-time setup):

```sh
podman machine init
podman machine start
```

Then substitute `podman` for `docker` in steps 1 and 6:

```sh
# Step 1
podman run -d --name spanner-emulator -p 9010:9010 -p 9020:9020 \
  gcr.io/cloud-spanner-emulator/emulator
export SPANNER_EMULATOR_HOST=localhost:9010

# Step 6
podman stop spanner-emulator && podman rm spanner-emulator
```

Steps 2–5 (uv and `make` commands) are unchanged.

---

### Graph visualization

`make visualize` generates `tests/output/graph.html` (git-ignored) and opens it in your browser. Nodes are color-coded by type, draggable, and zoomable.

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

Options:
```sh
uv run python cmd/visualize_combined.py --no-open   # combined view, suppress auto-open
uv run python cmd/visualize_combined.py --limit 200 # cap rows per table
uv run python cmd/visualize_graph.py --no-open      # attack graph only
uv run python cmd/visualize_attack_flow.py --no-open # attack flow only
```

---

### Sample fixtures

| File | Description |
|------|-------------|
| `sample_bundle_mirrorface.json` | MirrorFace / Earth Kasha APT (targets Japan, 2024–2025). TTPs: T1190, T1566.001, T1574.002, T1071.001, T1083, T1041. CVE-2023-28461, CVE-2024-21412. LODEINFO backdoor + C2 IoCs. |
| `sample_bundle_inc.json` | INC Ransomware (active 2023–, targets healthcare/manufacturing). TTPs: T1190, T1078, T1003.001, T1021.002, T1048.002, T1486. CVE-2023-3519, CVE-2023-4966 (Citrix). Tools: Cobalt Strike, AnyDesk, MegaSync. |
| `sample_assets.json` | Japanese manufacturing enterprise: Citrix NetScaler ADC, Active Directory, File Server, Backup Server, ERP (SAP), Factory PLC, Workstations. |
| `sample_pir.json` | Minimal PIR for unit tests. |

---

## Deleting data from Spanner

There is no dedicated delete CLI. Use `gcloud spanner databases execute-sql` with DML statements.

**Delete a specific node by STIX ID:**

```sh
# Delete a ThreatActor
gcloud spanner databases execute-sql ${SPANNER_DB} \
  --instance=${SPANNER_INSTANCE} --project=${PROJECT_ID} \
  --sql="DELETE FROM ThreatActor WHERE stix_id = 'intrusion-set--xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx'"

# Delete a TTP (also removes downstream FollowedBy edges referencing it)
gcloud spanner databases execute-sql ${SPANNER_DB} \
  --instance=${SPANNER_INSTANCE} --project=${PROJECT_ID} \
  --sql="DELETE FROM TTP WHERE stix_id = 'attack-pattern--xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx'"

# Delete an Asset loaded by mistake
gcloud spanner databases execute-sql ${SPANNER_DB} \
  --instance=${SPANNER_INSTANCE} --project=${PROJECT_ID} \
  --sql="DELETE FROM Asset WHERE id = 'asset-001-xxxxx-xxxx-xxxxxxxxxxxx'"
```

**Delete edges only (keep nodes):**

```sh
# Remove all Targets edges for a specific actor
gcloud spanner databases execute-sql ${SPANNER_DB} \
  --instance=${SPANNER_INSTANCE} --project=${PROJECT_ID} \
  --sql="DELETE FROM Targets WHERE src_actor_stix_id = 'intrusion-set--xxxx'"

# Remove FollowedBy edges from a specific source
gcloud spanner databases execute-sql ${SPANNER_DB} \
  --instance=${SPANNER_INSTANCE} --project=${PROJECT_ID} \
  --sql="DELETE FROM FollowedBy WHERE source = 'manual'"
```

**Full schema reset (wipe all data, keep schema):**

```sh
# Run DDL again — drops and recreates all tables
make init-schema
```

> **Note:** Spanner DDL re-execution via `init_schema.py` drops all tables and recreates them empty. Use this only when a clean slate is needed.
