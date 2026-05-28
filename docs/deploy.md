# SAGE — Deployment Guide

This guide assumes you have completed [setup.md](setup.md). Ensure `make check` passes before deploying.

---

## Step 8 — Deploy ETL worker to Cloud Run

```sh
# Load .env if not already sourced
source .env
export REGION=${REGION:-us-central1}

# Create Artifact Registry repository (first time only)
gcloud artifacts repositories create cloud-run \
  --repository-format=docker \
  --location=${REGION} \
  --project=${PROJECT_ID}

export IMAGE=${REGION}-docker.pkg.dev/${PROJECT_ID}/cloud-run/sage-etl

# Build and push container image
gcloud builds submit --tag ${IMAGE} --project=${PROJECT_ID}

# Deploy
gcloud run deploy sage-etl \
  --image=${IMAGE} \
  --region=${REGION} \
  --no-allow-unauthenticated \
  --set-secrets="OPENCTI_TOKEN=opencti-token:latest,GCS_BUCKET=sage-bucket:latest" \
  --set-env-vars="PROJECT_ID=${PROJECT_ID},SPANNER_INSTANCE=${SPANNER_INSTANCE},SPANNER_DB=${SPANNER_DB},PIR_FILE_PATH=/config/pir.json" \
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
