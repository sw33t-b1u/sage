# SAGE — Usage Guide

This guide describes the day-to-day workflow for CTI analysts and Blue Team members.

## Prerequisites

- `uv sync --extra dev` completed in the SAGE directory
- `.env` configured with production Spanner credentials
- `gcloud auth application-default login` completed on your local machine

---

## Daily workflow

### 1. ETL runs automatically (03:00 JST via Cloud Scheduler)

When `SLACK_WEBHOOK_URL` is configured, you receive a Slack notification containing:
- Count of new/updated threat actors, TTPs, and vulnerabilities ingested
- Top choke-point assets and their scores compared to the previous run

To trigger ETL manually:
```sh
# Against live OpenCTI
make run-etl

# With a local STIX bundle (no OpenCTI required)
uv run sage run-etl --input tests/fixtures/sample_bundle_mirrorface.json
```

---

### 2. Check choke points

Choke points are assets with the highest `choke_score = pir_adjusted_criticality × number_of_targeting_actors`. These are your highest-priority hardening targets.

```sh
# Print top 10 to terminal
uv run sage report-choke-points --top 10

# Save as Markdown
uv run sage report-choke-points --top 10 --output /tmp/choke_report.md

# Post as GitHub Enterprise Issue (requires GHE_TOKEN and GHE_REPO)
uv run sage report-choke-points --ghe
```

Example output:
```
# SAGE Choke Point Report — 2026-04-05

| Rank | Asset                  | choke_score | pir_adjusted_criticality | Targeting Actors  |
|------|------------------------|-------------|--------------------------|-------------------|
| 1    | Unified Auth Platform  | 42.0        | 10.0                     | APT10, Lazarus    |
| 2    | Messaging Platform     | 30.0        | 10.0                     | APT10             |
```

---

### 3. Find asset IDs and actor STIX IDs

**Asset IDs** are defined in your `assets.json` file (the `id` field of each asset entry).
After loading, you can also look them up from Spanner:

```sh
gcloud spanner databases execute-sql sage-db \
  --instance=sage-instance \
  --sql="SELECT id, name, criticality, pir_adjusted_criticality FROM Asset ORDER BY pir_adjusted_criticality DESC LIMIT 20"
```

**Actor STIX IDs** are assigned by OpenCTI or are embedded in STIX bundle files.
Look them up from Spanner after ETL:

```sh
gcloud spanner databases execute-sql sage-db \
  --instance=sage-instance \
  --sql="SELECT stix_id, name, tags FROM ThreatActor ORDER BY name LIMIT 50"
```

The choke point report also prints targeting actor names alongside each asset — use those names to find the corresponding STIX IDs from the query above.

### 4. Investigate a specific asset or actor

```sh
# Attack paths targeting a specific asset
uv run sage query-attack-paths --asset-id asset-xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx

# All TTPs used by a specific actor
uv run sage query-attack-paths --actor-id intrusion-set--xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx
```

---

### 5. Visualize the graph (on demand)

Generates an interactive HTML file and opens it in your browser. Nodes are color-coded by type, draggable, and zoomable. Runs locally against production Spanner.

```sh
# Combined view (attack graph + attack flow with FollowedBy weights)
uv run sage visualize-combined --output /tmp/sage_combined.html

# Filter to a specific actor
uv run sage visualize-combined --actor-id "intrusion-set--xxx"

# Attack graph only (all nodes, uniform edges)
uv run sage visualize-graph --output /tmp/sage_graph.html

# Attack flow only (TTP transitions with FollowedBy weights)
uv run sage visualize-attack-flow --output /tmp/attack_flow.html

# Suppress auto-open / limit rows per table
uv run sage visualize-combined --no-open --limit 200
```

> `make visualize` is a shortcut for local/emulator use. For production data, run the command directly as shown above.

---

### 6. Query via Analysis API (optional)

For integration with other tools or ad-hoc queries, start the API server locally pointing at production Spanner:

```sh
uv run sage serve-api --port 8080
```

Interactive API documentation (Swagger UI) is available at `http://localhost:8080/docs` once the server is running.

Available endpoints:

| Endpoint | Description |
|----------|-------------|
| `GET /choke-points?top_n=10` | Top N choke-point assets by score |
| `GET /asset-exposure` | All assets with targeting actor counts |
| `GET /attack-paths?asset_id=<id>` | Attack paths leading to an asset |
| `GET /actor-ttps?actor_id=<id>` | TTPs associated with a threat actor |
| `GET /actors?name=<query>&limit=20` | Threat actor name search (case-insensitive substring, min 2 chars) |
| `GET /similar-incidents?incident_id=<id>` | Incidents similar to a given one |

**Actor name search examples:**

```sh
# Find actors whose name contains "apt"
curl "http://localhost:8080/actors?name=apt"

# Find actors with "lazarus" in the name, top 5
curl "http://localhost:8080/actors?name=lazarus&limit=5"
```

Response format: `{"actors": [{stix_id, name, description, aliases, first_seen, last_seen, sophistication_level}, …], "count": N}`

**Loading artifacts via StorageBackend:**

When `SAGE_STORAGE_BASE_DIR` points to the shared `output/` directory (the default),
asset loading commands auto-detect files without `--input`:

```sh
# Auto-load from StorageBackend assets/ category
uv run sage load-assets
uv run sage load-identity-assets
uv run sage load-user-accounts

# ETL processes all STIX bundles from StorageBackend stix/ category
uv run sage run-etl
```

StorageBackend is configured via `SAGE_STORAGE` (`local` or `gcs`),
`SAGE_STORAGE_BASE_DIR` (default: `output`), `SAGE_GCS_BUCKET`, and `SAGE_GCS_PREFIX`.

---

## Quarterly PIR update workflow

Run this when organizational context changes (new projects, M&A, regulatory updates, new crown jewels):

```
1. Update input/<context>.md                  ← in BEACON repo (see docs/context_template.md)
2. uv run beacon pir-generate \               ← run in BEACON repo
     --context input/<context>.md \
     --output output/pir_output.json \
     --collection-plan output/collection_plan.md
3. cp output/pir_output.json /path/to/config/pir.json
4. make run-etl                               ← re-run ETL to apply new PIR weights
5. uv run sage report-choke-points            ← verify criticality changes
```

PIR generation (step 2) is handled by [BEACON](https://github.com/sw33t-b1u/beacon), not SAGE.
See [BEACON docs](https://github.com/sw33t-b1u/beacon) for usage details.

---

## IR response workflow

When an incident is detected or suspected:

```sh
# Create an IR incident template as a GHE Issue
uv run sage ir-template \
  --actor-id <stix-id> \
  --asset-id <asset-id>

# Sync actor TTPs to Caldera for red team simulation (requires CALDERA_URL)
uv run sage sync-caldera --actor-id <stix-id>
```

### Direct IR feedback registration (`sage incident-register`)

The `sage incident-register` CLI lets IR teams register an incident the same day it occurs (vs OpenCTI's 24h polling latency). Four modes:

```sh
# 1) Interactive — prompts for Diamond Model 4 quadrants.
uv run sage incident-register \
  --name "MIR-4242 mail relay compromise" \
  --occurred-at 2026-05-20T12:34:56Z \
  --severity high

# 2) Non-interactive flag mode (Diamond Model via --diamond key=value).
uv run sage incident-register \
  --name "MIR-4242" --occurred-at 2026-05-20T12:34:56Z --severity high \
  --diamond adversary=APT99 \
  --diamond capability="spear-phishing kit" \
  --diamond infrastructure="fastflux nodes" \
  --diamond victim="mail relay asset-001" \
  --no-interactive

# 3) MITRE Navigator layer import — TTP sequence from the Navigator UI.
uv run sage incident-register \
  --name "MIR-4242" --occurred-at 2026-05-20T12:34:56Z --severity high \
  --navigator-layer ./layer.json \
  --no-interactive

# 4) Air-gapped / token-less — bypass the API and write Spanner directly.
uv run sage incident-register \
  --from-file ./payload.json \
  --no-api --no-interactive
```

Defaults: `incident_stix_id` is auto-generated as
`incident--<uuid4>` (override with `--id`); the Bearer token reads
from `$SAGE_API_AUTH_TOKEN`; the API base URL reads from
`$SAGE_API_URL` (else `http://localhost:8000`).

---

## ETL Pipeline Operations

### Manual ETL run

```sh
# Against live OpenCTI
make run-etl

# With a local STIX bundle (no OpenCTI required)
uv run sage run-etl --input tests/fixtures/sample_bundle_mirrorface.json

# Process all STIX bundles from StorageBackend stix/ category
uv run sage run-etl
```

### Scheduled ETL (Cloud Scheduler)

ETL runs automatically at 03:00 JST (18:00 UTC) via Cloud Scheduler. The job is named `sage-daily-etl` and targets the `sage-etl` Cloud Run service.

To check scheduler status:

```sh
gcloud scheduler jobs describe sage-daily-etl --location=${REGION} --project=${PROJECT_ID}
```

To trigger the scheduled job immediately:

```sh
gcloud scheduler jobs run sage-daily-etl --location=${REGION} --project=${PROJECT_ID}
```

### ETL monitoring (Slack notifications)

When `SLACK_WEBHOOK_URL` is configured, each ETL run posts a Slack notification containing:

- Count of new/updated threat actors, TTPs, and vulnerabilities ingested
- Top choke-point assets and their scores compared to the previous run

Configure the webhook in `.env`:

```
SLACK_WEBHOOK_URL=https://hooks.slack.com/services/...
```

---

## Analysis API Health Check

Start the API server locally:

```sh
uv run sage serve-api --port 8080
```

Health and smoke checks:

```sh
curl http://localhost:8080/choke-points?top_n=5
curl http://localhost:8080/asset-exposure
curl http://localhost:8080/actors?name=apt&limit=5
```

Interactive API documentation (Swagger UI) is at `http://localhost:8080/docs`.

In production (Cloud Run, VPC-internal), the API requires a Bearer token:

```sh
curl -H "Authorization: Bearer ${SAGE_API_AUTH_TOKEN}" \
  https://<cloud-run-url>/choke-points?top_n=5
```

---

## Spanner Data Management

### Deleting nodes by STIX ID

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

### Deleting edges only (keep nodes)

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

### Full schema reset (wipe all data, keep schema)

```sh
# Drops and recreates all tables — use only when a clean slate is needed
make init-schema
```

---

## StorageBackend Management

SAGE uses the `StorageBackend` abstraction (Decision I-12). Configure via environment variables:

| Variable | Default | Purpose |
|----------|---------|---------|
| `SAGE_STORAGE` | `local` | Backend type: `local` or `gcs` |
| `SAGE_STORAGE_BASE_DIR` | `output` | Base directory for local storage (shared with TRACE/BEACON) |
| `SAGE_GCS_BUCKET` | (none) | GCS bucket name (required when `SAGE_STORAGE=gcs`) |
| `SAGE_GCS_PREFIX` | (none) | GCS object key prefix (optional) |

Auto-load commands (omit `--input` to pull from StorageBackend):

```sh
uv run sage load-assets
uv run sage load-identity-assets
uv run sage load-user-accounts
uv run sage run-etl          # processes all bundles in stix/ category
```

---

## Slack / GHE Notification Configuration

### Slack

Set `SLACK_WEBHOOK_URL` in `.env`. The ETL worker and choke-point reporter both use this webhook.

### GitHub Enterprise

Set `GHE_TOKEN`, `GHE_REPO` (format: `owner/repo`), and optionally `GHE_API_BASE` (defaults to `https://api.github.com`) for GHE self-hosted.

```sh
# Post choke-point report as a GHE Issue
uv run sage report-choke-points --ghe
```

---

## Troubleshooting

### ETL returns 0 new objects

- Verify OpenCTI connectivity: `curl ${OPENCTI_URL}/graphql -H "Authorization: Bearer ${OPENCTI_TOKEN}"`
- Check that STIX bundles exist in the StorageBackend `stix/` category.
- Inspect Spanner for existing data: `SELECT COUNT(*) FROM ThreatActor`

### `OTEL_SDK_DISABLED` metric export errors

Set `OTEL_SDK_DISABLED=true` in `.env` to suppress Spanner client OpenTelemetry metric export errors in environments without a metrics backend.

### Spanner `ALREADY_EXISTS` on schema init

The schema was previously initialized. Run `make init-schema` only when a clean slate is needed — it drops all tables.

### Analysis API returns 401

Ensure `SAGE_API_AUTH_TOKEN` is set and matches the token the API server was started with.

### StorageBackend path mismatch

When `SAGE_STORAGE=local`, SAGE, TRACE, and BEACON must all share the same `output/` base directory. Set `SAGE_STORAGE_BASE_DIR` (and the equivalent in TRACE/BEACON) to an absolute path to avoid working-directory-dependent mismatches.
