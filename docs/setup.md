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
| `CALDERA_URL` | No | — | MITRE Caldera server URL |
| `CALDERA_API_KEY` | No | — | Caldera REST API key |
| `SAGE_API_URL` | No | — | Base URL of the running Analysis API |
| `OTEL_SDK_DISABLED` | No | — | Set `true` to suppress Spanner client metrics export errors |

---

## Step 3 — Create GCP resources

```sh
export PROJECT_ID=your-project-id
export REGION=us-central1
export SPANNER_INSTANCE=sage-instance
export SPANNER_DB=sage-db
export GCS_BUCKET=sage-landing-${PROJECT_ID}

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

Edit `tests/fixtures/sample_assets.json` to reflect your actual asset inventory, then run:

```sh
uv run python cmd/load_assets.py

# To use a custom file:
uv run python cmd/load_assets.py --file path/to/assets.json
```

---

## Step 6 — Place PIR file

Generate a PIR JSON with [BEACON](https://github.com/sw33t-b1u/beacon) and place it at `PIR_FILE_PATH`:

```sh
cp /path/to/pir_output.json /path/to/config/pir.json
# or point PIR_FILE_PATH directly in .env
```

---

## Step 7 — Run ETL manually (first-time verification)

```sh
# No OpenCTI required — use a local STIX bundle
uv run python cmd/run_etl.py --manual-bundle tests/fixtures/sample_bundle_mirrorface.json

# Against live OpenCTI
make run-etl
```

---

## Step 8 — Deploy ETL worker to Cloud Run

```sh
export PROJECT_ID=your-project-id
export REGION=us-central1
export IMAGE=gcr.io/${PROJECT_ID}/sage-etl

# Build and push container image
gcloud builds submit --tag ${IMAGE} --project=${PROJECT_ID}

# Deploy
gcloud run deploy sage-etl \
  --image=${IMAGE} \
  --region=${REGION} \
  --no-allow-unauthenticated \
  --set-secrets="OPENCTI_TOKEN=opencti-token:latest,GCS_LANDING_BUCKET=sage-bucket:latest" \
  --set-env-vars="GCP_PROJECT_ID=${PROJECT_ID},SPANNER_INSTANCE_ID=sage-instance,SPANNER_DATABASE_ID=sage-db,PIR_FILE_PATH=/config/pir.json" \
  --project=${PROJECT_ID}
```

> **Secret Manager:** Store sensitive values with `gcloud secrets create opencti-token --data-file=- <<< "your-token"` and reference with `--set-secrets` instead of `--set-env-vars`.

> **Service account:** Create a dedicated service account and grant `roles/spanner.databaseUser`, `roles/storage.objectViewer`, and `roles/run.invoker` before deploying.

---

## Step 9 — Set up Cloud Scheduler (daily ETL)

```sh
export ETL_URL=$(gcloud run services describe sage-etl \
  --region=${REGION} --format='value(status.url)' --project=${PROJECT_ID})

gcloud services enable cloudscheduler.googleapis.com --project=${PROJECT_ID}

# Daily at 03:00 JST (18:00 UTC)
gcloud scheduler jobs create http sage-daily-etl \
  --location=${REGION} \
  --schedule="0 18 * * *" \
  --uri="${ETL_URL}" \
  --oidc-service-account-email="sage-etl@${PROJECT_ID}.iam.gserviceaccount.com" \
  --time-zone="UTC" \
  --project=${PROJECT_ID}
```

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
