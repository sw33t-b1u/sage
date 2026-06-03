# SAGE — Cloud Run Deployment

Japanese translation: [`docs/deploy.ja.md`](deploy.ja.md)

Before deploying, complete [docs/setup.md](setup.md). Ensure `make check` passes before deploying.

---

## Day-0 Prerequisites

### Enable APIs

```sh
source .env
export REGION=${REGION:-us-central1}

gcloud services enable \
  run.googleapis.com \
  artifactregistry.googleapis.com \
  cloudbuild.googleapis.com \
  spanner.googleapis.com \
  cloudscheduler.googleapis.com \
  --project=${GCP_PROJECT_ID}
```

### Create Artifact Registry repository

```sh
gcloud artifacts repositories create cloud-run \
  --repository-format=docker \
  --location=${REGION} \
  --project=${GCP_PROJECT_ID}
```

### Create service account and grant IAM roles

Create the `sage-etl` service account and bind the required project-level roles before running any deploy commands that reference it.

```sh
gcloud iam service-accounts create sage-etl \
  --display-name="SAGE ETL Job" \
  --project=${GCP_PROJECT_ID}

for ROLE in roles/spanner.databaseUser roles/storage.objectViewer roles/run.invoker; do
  gcloud projects add-iam-policy-binding ${GCP_PROJECT_ID} \
    --member="serviceAccount:sage-etl@${GCP_PROJECT_ID}.iam.gserviceaccount.com" \
    --role="${ROLE}"
done

# Bucket-level binding for the TRACE output bucket (least-privilege
# alternative to a project-wide objectViewer):
gcloud storage buckets add-iam-policy-binding gs://${TRACE_STORAGE_BUCKET} \
  --member="serviceAccount:sage-etl@${GCP_PROJECT_ID}.iam.gserviceaccount.com" \
  --role="roles/storage.objectViewer"
```

### Create GCS buckets (if not already existing)

```sh
# ETL input bucket — TRACE writes STIX bundles here; SAGE reads from it
gcloud storage buckets create gs://${SAGE_ETL_INPUT_BUCKET} \
  --location=${REGION} \
  --project=${GCP_PROJECT_ID}

# Storage backend bucket (only when SAGE_STORAGE=gcs)
gcloud storage buckets create gs://${SAGE_STORAGE_BUCKET} \
  --location=${REGION} \
  --project=${GCP_PROJECT_ID}
```

---

## Day-1 Initial Deploy

### sage-etl (Cloud Run Job)

```sh
export IMAGE=${REGION}-docker.pkg.dev/${GCP_PROJECT_ID}/cloud-run/sage-etl

# Build and push container image via Cloud Build
gcloud builds submit --tag ${IMAGE} --project=${GCP_PROJECT_ID}

# Create the Cloud Run Job
gcloud run jobs create sage-etl \
  --image=${IMAGE} \
  --region=${REGION} \
  --service-account="sage-etl@${GCP_PROJECT_ID}.iam.gserviceaccount.com" \
  --set-env-vars="GCP_PROJECT_ID=${GCP_PROJECT_ID},SPANNER_INSTANCE=${SPANNER_INSTANCE},SPANNER_DB=${SPANNER_DB},PIR_FILE_PATH=/config/pir.json,OPENCTI_URL=https://example.com,OPENCTI_TOKEN=skip,SAGE_STORAGE=gcs,SAGE_ETL_INPUT_BUCKET=${SAGE_ETL_INPUT_BUCKET},SAGE_STORAGE_BUCKET=${SAGE_STORAGE_BUCKET},SAGE_STORAGE_PREFIX=trace/" \
  --add-volume=name=pir,type=cloud-storage,bucket=${PIR_GCS_BUCKET},mount-options="only-dir=pir" \
  --add-volume-mount=volume=pir,mount-path=/config \
  --project=${GCP_PROJECT_ID}
```

> **`SAGE_STORAGE=gcs` + `SAGE_ETL_INPUT_BUCKET` + `SAGE_STORAGE_PREFIX`:** required so
> `run-etl` reads STIX bundles produced by TRACE. Set `SAGE_ETL_INPUT_BUCKET` to the
> bucket where TRACE writes (typically `${TRACE_STORAGE_BUCKET}` per the TRACE
> deploy guide) and `SAGE_STORAGE_PREFIX` to TRACE's prefix (`trace/`). The ETL
> looks for objects under `${SAGE_STORAGE_PREFIX}/stix/`. Without these env vars
> the job falls back to OpenCTI mode and fails when `OPENCTI_TOKEN=skip`.

> **`mount-options="only-dir=pir"`:** the PIR bucket holds other artifacts
> (raw STIX landing, etc.); `only-dir=pir` exposes just the `pir/` subdir at
> `/config/`, so the file resolves to `/config/pir.json`. Omit the option if
> the bucket is dedicated to PIR.

> **OpenCTI-skip deployments:** If you are not connecting to an OpenCTI instance, pass `OPENCTI_URL=https://example.com` and `OPENCTI_TOKEN=skip` as shown above. The ETL job will skip OpenCTI ingestion and proceed with STIX bundles from GCS.

> **PIR file supply:** The `pir.json` file is not bundled in the container image. Mount it at runtime via a GCS volume as shown above (`--add-volume` / `--add-volume-mount`). With `only-dir=pir` the file must exist at `gs://${PIR_GCS_BUCKET}/pir/pir.json`; without that option it must be at `gs://${PIR_GCS_BUCKET}/pir.json`.

### (Optional) Cloud Scheduler for daily ETL trigger

```sh
# Daily at 03:00 JST (18:00 UTC)
gcloud scheduler jobs create http sage-daily-etl \
  --location=${REGION} \
  --schedule="0 18 * * *" \
  --uri="https://${REGION}-run.googleapis.com/apis/run.googleapis.com/v1/namespaces/${GCP_PROJECT_ID}/jobs/sage-etl:run" \
  --message-body="{}" \
  --oauth-service-account-email="sage-etl@${GCP_PROJECT_ID}.iam.gserviceaccount.com" \
  --time-zone="UTC" \
  --project=${GCP_PROJECT_ID}
```

> **Manual trigger:** `gcloud run jobs execute sage-etl --region=${REGION} --project=${GCP_PROJECT_ID}`

### sage-api (Cloud Run Service) — if Analysis API is needed

Deploy the SAGE Analysis API as a long-running Cloud Run Service. This is the HTTP endpoint that BEACON queries via `SAGE_API_URL`.

The same container image used by the ETL Job is reused here; the ENTRYPOINT is overridden at deploy time to run `sage serve-api` instead of `sage run-etl`.

```sh
# Reuse the IMAGE variable from above (or re-export it)
export IMAGE=${REGION}-docker.pkg.dev/${GCP_PROJECT_ID}/cloud-run/sage-etl

gcloud run deploy sage-api \
  --image=${IMAGE} \
  --region=${REGION} \
  --no-allow-unauthenticated \
  --command='uv' \
  --args='run,sage,serve-api,--host,0.0.0.0,--port,8080' \
  --port=8080 \
  --service-account="sage-etl@${GCP_PROJECT_ID}.iam.gserviceaccount.com" \
  --set-env-vars="GCP_PROJECT_ID=${GCP_PROJECT_ID},SPANNER_INSTANCE=${SPANNER_INSTANCE},SPANNER_DB=${SPANNER_DB}" \
  --project=${GCP_PROJECT_ID}
```

> **Service URL:** After deploy, retrieve the URL for use in BEACON:
> ```sh
> gcloud run services describe sage-api \
>   --region=${REGION} \
>   --format='value(status.url)' \
>   --project=${GCP_PROJECT_ID}
> ```
> Set this value as `SAGE_API_URL` in BEACON's configuration.

---

## Day-N Redeploy

### Code-only changes

Use this flow when only the container image changes (no env-var additions or removals).

```sh
export IMAGE=${REGION}-docker.pkg.dev/${GCP_PROJECT_ID}/cloud-run/sage-etl

# Rebuild and push the new image
gcloud builds submit --tag ${IMAGE} --project=${GCP_PROJECT_ID}

# Update the Cloud Run Job (sage-etl)
gcloud run jobs update sage-etl \
  --image=${IMAGE} \
  --region=${REGION} \
  --project=${GCP_PROJECT_ID}

# Update the Cloud Run Service (sage-api)
gcloud run services update sage-api \
  --image=${IMAGE} \
  --region=${REGION} \
  --project=${GCP_PROJECT_ID}
```

### Env-var changes on an existing revision

Use `--update-env-vars` and `--remove-env-vars` — **not** `--set-env-vars`, which replaces the entire env-var set and silently drops any key not re-listed.

```sh
# Add or update a single variable without touching others
gcloud run services update sage-api \
  --update-env-vars=NEW_VAR=value \
  --region=${REGION} \
  --project=${GCP_PROJECT_ID}

# Remove an old variable at the same time
gcloud run services update sage-api \
  --update-env-vars=NEW_VAR=value \
  --remove-env-vars=OLD_VAR \
  --region=${REGION} \
  --project=${GCP_PROJECT_ID}

# Same pattern for Cloud Run Jobs
gcloud run jobs update sage-etl \
  --update-env-vars=NEW_VAR=value \
  --remove-env-vars=OLD_VAR \
  --region=${REGION} \
  --project=${GCP_PROJECT_ID}
```

> **Verify:** `gcloud run services describe sage-api --region=${REGION} --format="value(spec.template.spec.containers[0].env[].name)" --project=${GCP_PROJECT_ID}`

---

## Access (Production = L2)

`--no-allow-unauthenticated` is already set during deploy. Grant `roles/run.invoker` to the identities that need access.

### Grant invoke permission

```sh
# Single user
gcloud run services add-iam-policy-binding sage-api \
  --region=${REGION} \
  --member="user:alice@example.com" \
  --role=roles/run.invoker \
  --project=${GCP_PROJECT_ID}

# Google Group (recommended for teams)
gcloud run services add-iam-policy-binding sage-api \
  --region=${REGION} \
  --member="group:sage-users@example.com" \
  --role=roles/run.invoker \
  --project=${GCP_PROJECT_ID}

# BEACON's service account (add during BEACON deployment)
gcloud run services add-iam-policy-binding sage-api \
  --region=${REGION} \
  --member="serviceAccount:beacon-sa@${GCP_PROJECT_ID}.iam.gserviceaccount.com" \
  --role=roles/run.invoker \
  --project=${GCP_PROJECT_ID}
```

### Verify via curl

```sh
URL=$(gcloud run services describe sage-api \
  --region=${REGION} \
  --format='value(status.url)' \
  --project=${GCP_PROJECT_ID})

# /openapi.json is served by FastAPI itself — no auth dependency, no Spanner
# access — so it confirms the service is up and the OIDC token is accepted.
# Business routes (/attack-paths etc.) need Spanner data; check those after sage-etl runs.
curl -sL -H "Authorization: Bearer $(gcloud auth print-identity-token)" \
  -w "\nHTTP=%{http_code}\n" \
  ${URL}/openapi.json | head -5
```

Expected: `HTTP=200` and JSON containing `"title":"SAGE Analysis API"`.

### Browser access

```sh
gcloud run services proxy sage-api --region=${REGION} --project=${GCP_PROJECT_ID}
# Open http://localhost:8080
```

---

## Out of scope

IAP / Internal Load Balancer / VPC Service Controls are not configured by this guide. For small Google Workspace user counts (a few users), the L2 IAM binding above is sufficient. If you need custom domain, browser access without gcloud, or context-aware access, see https://cloud.google.com/iap/docs.
