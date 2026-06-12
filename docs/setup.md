# SAGE — Setup Guide

## Prerequisites

- Python 3.12+
- [uv](https://github.com/astral-sh/uv)
- Google Cloud project with billing enabled — **only** for the optional
  Spanner backend (`SAGE_DB=spanner`) or GCS storage (`SAGE_STORAGE=gcs`).
  The default configuration (SQLite + local storage) needs no GCP account.
- OpenCTI instance (for live CTI ingestion; not required for manual STIX bundle mode)

SAGE 4.0.0 stores its graph in a **SQLite database file by default**
(`SAGE_DB=sqlite`). The file lives under the StorageBackend `db/`
category (`<base_dir>/db/sage.db` locally, or synced to GCS). Cloud
Spanner remains available as an optional backend via `SAGE_DB=spanner`.

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
| `SAGE_DB` | No | `sqlite` | Database backend: `sqlite` (default) or `spanner` |
| `GCP_PROJECT_ID` | Spanner only | — | GCP project ID (required when `SAGE_DB=spanner`) |
| `REGION` | Shell only | `us-central1` | GCP region for `gcloud` commands (not used in Python code) |
| `SPANNER_INSTANCE` | Spanner only | — | Spanner instance ID (required when `SAGE_DB=spanner`) |
| `SPANNER_DB` | Spanner only | — | Spanner database ID (required when `SAGE_DB=spanner`) |
| `SAGE_ETL_INPUT_BUCKET` | Spanner only | — | GCS bucket for raw STIX landing (required when `SAGE_DB=spanner`) |
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
| `SAGE_STORAGE_BUCKET` | GCS mode | — | GCS bucket name (required when `SAGE_STORAGE=gcs`) |
| `SAGE_STORAGE_PREFIX` | No | (empty) | Key prefix within the GCS bucket |
| `OTEL_SDK_DISABLED` | No | — | Set `true` to suppress Spanner client metrics export errors (Spanner backend only) |

With the default backend (`SAGE_DB=sqlite`) and default storage
(`SAGE_STORAGE=local`), no GCP variable is needed — the database file is
created at `output/db/sage.db` on first run. To sync the database via
GCS instead, set `SAGE_STORAGE=gcs` + `SAGE_STORAGE_BUCKET`.

---

## Step 3 — (Optional) Spanner backend — create GCP resources

**Skip this step on the default SQLite backend.** Only follow it when
you set `SAGE_DB=spanner`.

```sh
# Load .env (set in Step 2) — all variables including REGION are now available
source .env

# Enable required APIs
gcloud services enable spanner.googleapis.com storage.googleapis.com \
  --project=${GCP_PROJECT_ID}

# Create Spanner instance
gcloud spanner instances create ${SPANNER_INSTANCE} \
  --config=regional-${REGION} \
  --description="SAGE Threat Intelligence" \
  --nodes=1 \
  --project=${GCP_PROJECT_ID}

# Create Spanner database
gcloud spanner databases create ${SPANNER_DB} \
  --instance=${SPANNER_INSTANCE} \
  --project=${GCP_PROJECT_ID}

# Create GCS landing bucket
gcloud storage buckets create gs://${SAGE_ETL_INPUT_BUCKET} \
  --location=${REGION} \
  --project=${GCP_PROJECT_ID}
```

> **Cost note:** A 1-node Spanner instance costs ~$0.90/hour and cannot be stopped. Use `--processing-units=100` instead of `--nodes=1` to minimize cost during evaluation. The default SQLite backend exists precisely to avoid this always-on cost — choose Spanner only when data volume or concurrency demands it.

---

## Step 4 — Initialize the database schema

```sh
make init-schema
```

Applies `schema/sqlite_ddl.sql` on the default SQLite backend, or
`schema/spanner_ddl.sql` when `SAGE_DB=spanner`. On SQLite this step is
optional — every CLI entry point applies the schema automatically when
the database file does not exist yet.

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
> cd ../TRACE && uv run trace validate-assets --assets ../SAGE/input/assets.json
> ```

```sh
uv run sage load-assets            # reads input/assets.json by default
uv run sage load-assets --input path/to/assets.json  # custom path
```

---

## Step 5.1 — Load identity assets

BEACON also emits `identity_assets.json` (people / roles / groups granted
access on internal assets). Place it under `input/` and validate via TRACE
before loading — TRACE cross-checks each `has_access[].asset_id`
against `assets.json` and validates the flag
`is_high_value_impersonation_target` plus `impersonation_risk_factors`:

```sh
cp /path/to/identity_assets.json input/identity_assets.json

cd ../TRACE && uv run trace validate-identity \
  --identity-assets ../SAGE/input/identity_assets.json \
  --assets          ../SAGE/input/assets.json

cd ../SAGE && uv run sage load-identity-assets \
  --input input/identity_assets.json
```

SAGE upserts `Identity` rows, `HasAccess` edges, and — when the flag is
set — derives the `PirPrioritizesImpersonationTarget` cascade edge so
`effective_priority` on `ImpersonatesIdentity` switches to multiplier=1.5.

---

## Step 5.2 — Load user accounts

BEACON `user_accounts.json` carries account-level granularity (individual
login identifiers like `alice@corp`, `svc-jenkins`) below the identity
layer. Validate via TRACE and load:

```sh
cp /path/to/user_accounts.json input/user_accounts.json

cd ../TRACE && uv run trace validate-accounts \
  --user-accounts ../SAGE/input/user_accounts.json \
  --assets        ../SAGE/input/assets.json

cd ../SAGE && uv run sage load-user-accounts \
  --input input/user_accounts.json
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
> cd ../TRACE && uv run trace validate-pir \
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
uv run sage run-etl --input tests/fixtures/sample_bundle_mirrorface.json

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

### Full local test (SQLite default)

With the default backend the complete workflow — Attack Flow (STIX
threat intel) + Attack Graph (internal assets) — runs with no emulator,
no Docker, and no GCP credentials:

```sh
# Database file is created at output/db/sage.db automatically
uv run sage run-etl --input tests/fixtures/sample_bundle_mirrorface.json
uv run sage run-etl --input tests/fixtures/sample_bundle_inc.json
make load-assets
make visualize
```

---

### Full local test with Spanner emulator (`SAGE_DB=spanner`)

Same workflow against the optional Spanner backend.

**Requires Docker or Podman.**

```sh
# 0. Select the Spanner backend for this shell
export SAGE_DB=spanner

# 1. Start the Spanner emulator
docker run -d --name spanner-emulator -p 9010:9010 -p 9020:9020 \
  gcr.io/cloud-spanner-emulator/emulator
export SPANNER_EMULATOR_HOST=localhost:9010

# 2. Create instance, database, and schema
uv run sage setup-emulator
make init-schema

# 3. Load threat intelligence (Attack Flow)
# NOTE: external or hand-authored bundles must be enriched first so PIR filtering retains actors:
#   cd ../TRACE && uv run trace enrich-bundle --input <bundle.json> --output enriched.json && cd ../SAGE
uv run sage run-etl --input tests/fixtures/sample_bundle_mirrorface.json
uv run sage run-etl --input tests/fixtures/sample_bundle_inc.json

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
uv run sage visualize-combined --no-open   # combined view, suppress auto-open
uv run sage visualize-combined --limit 200 # cap rows per table
uv run sage visualize-graph --no-open      # attack graph only
uv run sage visualize-attack-flow --no-open # attack flow only
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

## Deleting data

There is no dedicated delete CLI.

**SQLite backend (default):** run DML directly against the database file
with the `sqlite3` shell — the table and column names are identical to
the Spanner DDL:

```sh
sqlite3 output/db/sage.db \
  "DELETE FROM ThreatActor WHERE stix_id = 'intrusion-set--xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx'"
```

For a full reset, delete the file (`rm output/db/sage.db`) — the schema
is recreated automatically on the next run. When `SAGE_STORAGE=gcs`,
edit a downloaded copy and re-upload it to the `db/sage.db` object, or
delete the object for a full reset.

**Spanner backend:** use `gcloud spanner databases execute-sql` with DML statements.

**Delete a specific node by STIX ID:**

```sh
# Delete a ThreatActor
gcloud spanner databases execute-sql ${SPANNER_DB} \
  --instance=${SPANNER_INSTANCE} --project=${GCP_PROJECT_ID} \
  --sql="DELETE FROM ThreatActor WHERE stix_id = 'intrusion-set--xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx'"

# Delete a TTP (also removes downstream FollowedBy edges referencing it)
gcloud spanner databases execute-sql ${SPANNER_DB} \
  --instance=${SPANNER_INSTANCE} --project=${GCP_PROJECT_ID} \
  --sql="DELETE FROM TTP WHERE stix_id = 'attack-pattern--xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx'"

# Delete an Asset loaded by mistake
gcloud spanner databases execute-sql ${SPANNER_DB} \
  --instance=${SPANNER_INSTANCE} --project=${GCP_PROJECT_ID} \
  --sql="DELETE FROM Asset WHERE id = 'asset-001-xxxxx-xxxx-xxxxxxxxxxxx'"
```

**Delete edges only (keep nodes):**

```sh
# Remove all Targets edges for a specific actor
gcloud spanner databases execute-sql ${SPANNER_DB} \
  --instance=${SPANNER_INSTANCE} --project=${GCP_PROJECT_ID} \
  --sql="DELETE FROM Targets WHERE src_actor_stix_id = 'intrusion-set--xxxx'"

# Remove FollowedBy edges from a specific source
gcloud spanner databases execute-sql ${SPANNER_DB} \
  --instance=${SPANNER_INSTANCE} --project=${GCP_PROJECT_ID} \
  --sql="DELETE FROM FollowedBy WHERE source = 'manual'"
```

**Full schema reset (wipe all data, keep schema):**

```sh
# Run DDL again — drops and recreates all tables
make init-schema
```

> **Note:** On the Spanner backend, DDL re-execution via `sage init-schema` drops all tables and recreates them empty. On SQLite the DDL is `CREATE TABLE IF NOT EXISTS` (no drop) — delete the database file instead for a clean slate. Use either only when a clean slate is needed.
