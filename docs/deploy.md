# SAGE — Deployment Guide

This guide assumes you have completed [setup.md](setup.md). Ensure `make check` passes before deploying.

---

## Step 8 — Deploy SAGE ETL to Cloud Run (Job)

Build the container image and deploy the SAGE ETL pipeline as a Cloud Run Job for batch execution.

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

# Build and push container image via Cloud Build
gcloud builds submit --tag ${IMAGE} --project=${PROJECT_ID}

# Create the Cloud Run Job
gcloud run jobs create sage-etl \
  --image=${IMAGE} \
  --region=${REGION} \
  --service-account="sage-etl@${PROJECT_ID}.iam.gserviceaccount.com" \
  --set-env-vars="PROJECT_ID=${PROJECT_ID},SPANNER_INSTANCE=${SPANNER_INSTANCE},SPANNER_DB=${SPANNER_DB},PIR_FILE_PATH=/config/pir.json,OPENCTI_URL=https://example.com,OPENCTI_TOKEN=skip" \
  --set-secrets="GCS_BUCKET=sage-bucket:latest" \
  --add-volume=name=pir,type=cloud-storage,bucket=${PIR_GCS_BUCKET} \
  --add-volume-mount=volume=pir,mount-path=/config \
  --project=${PROJECT_ID}
```

> **Secret Manager:** Store sensitive values with `gcloud secrets create sage-bucket --data-file=- <<< "your-bucket"` and reference with `--set-secrets` instead of `--set-env-vars`.

> **OpenCTI-skip deployments:** If you are not connecting to an OpenCTI instance, pass `OPENCTI_URL=https://example.com` and `OPENCTI_TOKEN=skip` as shown above. The ETL job will skip OpenCTI ingestion and proceed with STIX bundles from GCS.

> **PIR file supply:** The `pir.json` file is not bundled in the container image. Mount it at runtime via a GCS volume as shown above (`--add-volume` / `--add-volume-mount`). The file must exist at `gs://${PIR_GCS_BUCKET}/pir.json` before the job runs. Alternatively, store it in Secret Manager and mount as a volume secret.

> **Service account:** Create a dedicated service account and grant `roles/spanner.databaseUser`, `roles/storage.objectViewer`, and `roles/run.invoker` before deploying.
>
> ```sh
> gcloud iam service-accounts create sage-etl \
>   --display-name="SAGE ETL Job" \
>   --project=${PROJECT_ID}
>
> for ROLE in roles/spanner.databaseUser roles/storage.objectViewer roles/run.invoker; do
>   gcloud projects add-iam-policy-binding ${PROJECT_ID} \
>     --member="serviceAccount:sage-etl@${PROJECT_ID}.iam.gserviceaccount.com" \
>     --role="${ROLE}"
> done
> ```

---

## Step 9 — Set up Cloud Scheduler (daily ETL)

Trigger the SAGE ETL job automatically on a daily schedule.

```sh
gcloud services enable cloudscheduler.googleapis.com --project=${PROJECT_ID}

# Daily at 03:00 JST (18:00 UTC)
gcloud scheduler jobs create http sage-daily-etl \
  --location=${REGION} \
  --schedule="0 18 * * *" \
  --uri="https://${REGION}-run.googleapis.com/apis/run.googleapis.com/v1/namespaces/${PROJECT_ID}/jobs/sage-etl:run" \
  --message-body="{}" \
  --oauth-service-account-email="sage-etl@${PROJECT_ID}.iam.gserviceaccount.com" \
  --time-zone="UTC" \
  --project=${PROJECT_ID}
```

> **Manual trigger:** `gcloud run jobs execute sage-etl --region=${REGION} --project=${PROJECT_ID}`

---

## Step 10 — Deploy SAGE Analysis API to Cloud Run (Service)

Deploy the SAGE Analysis API as a long-running Cloud Run Service. This is the HTTP endpoint that BEACON queries via `SAGE_API_URL`.

The same container image used by the ETL Job is reused here; the ENTRYPOINT is overridden at deploy time to run `sage serve-api` instead of `sage run-etl`.

```sh
# Reuse the IMAGE variable from Step 8 (or re-export it)
export IMAGE=${REGION}-docker.pkg.dev/${PROJECT_ID}/cloud-run/sage-etl

gcloud run deploy sage-api \
  --image=${IMAGE} \
  --region=${REGION} \
  --no-allow-unauthenticated \
  --command='uv' \
  --args='run,sage,serve-api,--host,0.0.0.0,--port,8080' \
  --port=8080 \
  --service-account="sage-etl@${PROJECT_ID}.iam.gserviceaccount.com" \
  --set-env-vars="PROJECT_ID=${PROJECT_ID},SPANNER_INSTANCE=${SPANNER_INSTANCE},SPANNER_DB=${SPANNER_DB}" \
  --project=${PROJECT_ID}
```

> **IAP / Internal Load Balancer:** For BEACON-only access, place the Service behind an Internal Load Balancer or configure Identity-Aware Proxy (IAP) so the endpoint is not reachable from the public internet. `--no-allow-unauthenticated` is a minimum baseline; add IAP or VPC-SC for production deployments.

> **BEACON IAM:** BEACON's service account needs `roles/run.invoker` on the `sage-api` Service. This binding is added during the BEACON deployment phase:
> ```sh
> gcloud run services add-iam-policy-binding sage-api \
>   --region=${REGION} \
>   --member="serviceAccount:beacon-sa@${PROJECT_ID}.iam.gserviceaccount.com" \
>   --role="roles/run.invoker" \
>   --project=${PROJECT_ID}
> ```

> **Service URL:** After deploy, retrieve the URL for use in BEACON:
> ```sh
> gcloud run services describe sage-api \
>   --region=${REGION} \
>   --format='value(status.url)' \
>   --project=${PROJECT_ID}
> ```
> Set this value as `SAGE_API_URL` in BEACON's configuration.
