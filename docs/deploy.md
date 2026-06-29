# SAGE — Cloud Run Deployment

Japanese translation: [`docs/deploy.ja.md`](deploy.ja.md)

Before deploying, complete [docs/setup.md](setup.md). Ensure `make check` passes before deploying.

**Database backend (SAGE 4.0.0):** the default deployment runs on
**SQLite + GCS** — no Spanner instance is required. The flow is:

- **ETL job (`sage-etl`)**: downloads `db/sage.db` from the storage
  bucket on startup (creates a fresh one on first run), writes the graph,
  then uploads the file back. The ETL job is the **single writer**.
- **API service (`sage-api`)**: downloads `db/sage.db` on cold start and
  opens it **read-only**. It picks up new ETL output on the next cold
  start (scale-to-zero makes this the common case for a daily ETL).

Cloud Spanner remains available as an optional backend (`SAGE_DB=spanner`);
the Spanner-specific steps below are marked as such.

---

## Cross-repo deploy order

SAGE, BEACON, and TRACE form a cycle at deploy time: BEACON needs
`SAGE_API_URL` (the sage-api URL) and SAGE's ETL needs the validated
`pir.json` BEACON produces. Break the cycle in this order — unmet
dependencies are wired in afterward with `--update-env-vars`, so nothing
blocks on something that does not exist yet.

1. **SAGE — deploy `sage-api` first.** Create the GCS bucket (Day-0
   below) and deploy `sage-api` (Day-1 below). The API starts even with
   no database in the bucket — `/openapi.json` returns `HTTP=200` and
   confirms liveness. Note its URL.
2. **BEACON — deploy `beacon-web`.** Set `SAGE_API_URL` to the sage-api
   URL from step 1, and grant BEACON's service account
   (`beacon-sa@...`) `roles/run.invoker` on `sage-api` (see
   [Access](#access-production--l2)). See the
   [BEACON deploy guide](https://github.com/sw33t-b1u/beacon).
3. **BEACON — generate PIR / assets.** Produce `pir_output.json` and the
   asset artifacts from business context.
4. **TRACE — validate.** Pass the assets, PIR, and any STIX bundles
   through TRACE, the single validation gate for all SAGE inputs. See
   the [TRACE repo](https://github.com/sw33t-b1u/trace) for the commands
   (not duplicated here).
5. **SAGE — load and run ETL.** Place the validated `pir.json` and STIX
   bundles in GCS (`${PIR_GCS_BUCKET}` / `${TRACE_STORAGE_BUCKET}`), then
   run `sage-etl`. `sage-api` materializes the freshly published
   `db/sage.db` on its next cold start.

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
  cloudscheduler.googleapis.com \
  --project=${GCP_PROJECT_ID}

# Spanner backend only (SAGE_DB=spanner):
gcloud services enable spanner.googleapis.com --project=${GCP_PROJECT_ID}
```

> **Env vars come from `.env`.** `source .env` exports the variables
> used below, including `REGION`, `SAGE_STORAGE_BUCKET`,
> `${PIR_GCS_BUCKET}`, and `${TRACE_STORAGE_BUCKET}` (all defined in
> `.env.example`). The `gcloud` commands in Day-0 and Day-1 reference
> these directly and fail with an empty/unresolved argument if a
> variable is unset — confirm `echo ${PIR_GCS_BUCKET} ${TRACE_STORAGE_BUCKET}`
> prints non-empty values before deploying.

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

for ROLE in roles/storage.objectViewer roles/run.invoker; do
  gcloud projects add-iam-policy-binding ${GCP_PROJECT_ID} \
    --member="serviceAccount:sage-etl@${GCP_PROJECT_ID}.iam.gserviceaccount.com" \
    --role="${ROLE}"
done

# SQLite-on-GCS (default backend): the ETL job uploads db/sage.db back
# to the storage bucket after each run, so it needs write access there:
gcloud storage buckets add-iam-policy-binding gs://${SAGE_STORAGE_BUCKET} \
  --member="serviceAccount:sage-etl@${GCP_PROJECT_ID}.iam.gserviceaccount.com" \
  --role="roles/storage.objectAdmin"

# Bucket-level binding for the TRACE output bucket (least-privilege
# alternative to a project-wide objectViewer):
gcloud storage buckets add-iam-policy-binding gs://${TRACE_STORAGE_BUCKET} \
  --member="serviceAccount:sage-etl@${GCP_PROJECT_ID}.iam.gserviceaccount.com" \
  --role="roles/storage.objectViewer"

# Spanner backend only (SAGE_DB=spanner):
gcloud projects add-iam-policy-binding ${GCP_PROJECT_ID} \
  --member="serviceAccount:sage-etl@${GCP_PROJECT_ID}.iam.gserviceaccount.com" \
  --role="roles/spanner.databaseUser"
```

### Create GCS buckets (if not already existing)

```sh
# Storage backend bucket (SAGE_STORAGE=gcs — the default deployment).
# Holds the SQLite database (db/sage.db) and the STIX bundles SAGE reads.
# TRACE's output bucket is commonly reused here (see the sage-etl note below).
gcloud storage buckets create gs://${SAGE_STORAGE_BUCKET} \
  --location=${REGION} \
  --project=${GCP_PROJECT_ID}

# Spanner backend only (SAGE_DB=spanner): raw STIX landing bucket used by
# the OpenCTI ingestion mode
gcloud storage buckets create gs://${SAGE_ETL_INPUT_BUCKET} \
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
  --set-env-vars="PIR_FILE_PATH=/config/pir.json,OPENCTI_URL=https://example.com,OPENCTI_TOKEN=skip,SAGE_STORAGE=gcs,SAGE_STORAGE_BUCKET=${SAGE_STORAGE_BUCKET},SAGE_STORAGE_PREFIX=trace/" \
  --add-volume=name=pir,type=cloud-storage,bucket=${PIR_GCS_BUCKET},mount-options="only-dir=pir" \
  --add-volume-mount=volume=pir,mount-path=/config \
  --project=${GCP_PROJECT_ID}
```

> **`SAGE_STORAGE=gcs` + `SAGE_STORAGE_BUCKET` + `SAGE_STORAGE_PREFIX`:** required so
> `run-etl` reads STIX bundles produced by TRACE and syncs the database file.
> Set `SAGE_STORAGE_BUCKET` to the bucket where TRACE writes (typically
> `${TRACE_STORAGE_BUCKET}` per the TRACE deploy guide) and `SAGE_STORAGE_PREFIX`
> to TRACE's prefix (`trace/`). The ETL looks for bundles under
> `${SAGE_STORAGE_PREFIX}/stix/` and publishes the SQLite database to
> `${SAGE_STORAGE_PREFIX}/db/sage.db`. Without these env vars the job falls back
> to OpenCTI mode and fails when `OPENCTI_TOKEN=skip`.

> **Spanner backend variant (`SAGE_DB=spanner`):** add
> `SAGE_DB=spanner,GCP_PROJECT_ID=${GCP_PROJECT_ID},SPANNER_INSTANCE=${SPANNER_INSTANCE},SPANNER_DB=${SPANNER_DB},SAGE_ETL_INPUT_BUCKET=${SAGE_ETL_INPUT_BUCKET}`
> to `--set-env-vars`. These four GCP variables are required only on this backend.

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
  --set-env-vars="SAGE_STORAGE=gcs,SAGE_STORAGE_BUCKET=${SAGE_STORAGE_BUCKET},SAGE_STORAGE_PREFIX=trace/" \
  --project=${GCP_PROJECT_ID}
```

> **Same bucket/prefix as the ETL job:** the API downloads
> `${SAGE_STORAGE_PREFIX}/db/sage.db` on cold start and opens it read-only, so
> `SAGE_STORAGE_BUCKET` / `SAGE_STORAGE_PREFIX` must match the `sage-etl` values
> above. A database published by a later ETL run is picked up on the next cold
> start; with scale-to-zero and a daily ETL this happens naturally. To force it,
> deploy a new revision (e.g. `gcloud run services update sage-api ...`).

> **Spanner backend variant (`SAGE_DB=spanner`):** use
> `SAGE_DB=spanner,GCP_PROJECT_ID=${GCP_PROJECT_ID},SPANNER_INSTANCE=${SPANNER_INSTANCE},SPANNER_DB=${SPANNER_DB},SAGE_ETL_INPUT_BUCKET=${SAGE_ETL_INPUT_BUCKET}`
> in `--set-env-vars` instead.

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

# /openapi.json is served by FastAPI itself — no auth dependency, no database
# access — so it confirms the service is up and the OIDC token is accepted.
# Business routes (/attack-paths etc.) need graph data; check those after
# sage-etl has run and the API has materialized the published db on a cold start.
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

---

## CTI Platform unified deployment

For browser-complete operation, use the unified CTI Platform runbook in the
BEACON repository: `beacon/docs/deploy-cti-platform.md`. It keeps SAGE split into
`sage-api` (read-only Cloud Run service) and `sage-etl` (single-writer Cloud Run
Job), then wires `cti-console` to the `sage-api` URL and shared GCS storage.

Use this standalone SAGE deploy guide when you need a non-standard SAGE topology
(such as `SAGE_DB=spanner`) or custom IAM/networking.
