# SAGE — Analyst Usage Guide

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
uv run python cmd/run_etl.py --manual-bundle tests/fixtures/sample_bundle_mirrorface.json
```

---

### 2. Check choke points

Choke points are assets with the highest `choke_score = pir_adjusted_criticality × number_of_targeting_actors`. These are your highest-priority hardening targets.

```sh
# Print top 10 to terminal
uv run python cmd/report_choke_points.py --top 10

# Save as Markdown
uv run python cmd/report_choke_points.py --top 10 --output /tmp/choke_report.md

# Post as GitHub Enterprise Issue (requires GHE_TOKEN and GHE_REPO)
uv run python cmd/report_choke_points.py --ghe
```

Example output:
```
# SAGE Choke Point Report — 2026-04-05

| Rank | Asset                  | choke_score | pir_adjusted_criticality | Targeting Actors  |
|------|------------------------|-------------|--------------------------|-------------------|
| 1    | 統合認証基盤            | 42.0        | 10.0                     | APT10, Lazarus    |
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
uv run python cmd/query_attack_paths.py --asset-id asset-xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx

# All TTPs used by a specific actor
uv run python cmd/query_attack_paths.py --actor-id intrusion-set--xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx
```

---

### 5. Visualize the graph (on demand)

Generates an interactive HTML file and opens it in your browser. Nodes are color-coded by type, draggable, and zoomable. Runs locally against production Spanner.

```sh
# Combined view (attack graph + attack flow with FollowedBy weights)
uv run python cmd/visualize_combined.py --output /tmp/sage_combined.html

# Filter to a specific actor
uv run python cmd/visualize_combined.py --actor-id "intrusion-set--xxx"

# Attack graph only (all nodes, uniform edges)
uv run python cmd/visualize_graph.py --output /tmp/sage_graph.html

# Attack flow only (TTP transitions with FollowedBy weights)
uv run python cmd/visualize_attack_flow.py --output /tmp/attack_flow.html

# Suppress auto-open / limit rows per table
uv run python cmd/visualize_combined.py --no-open --limit 200
```

> `make visualize` is a shortcut for local/emulator use. For production data, run the command directly as shown above.

---

### 6. Query via Analysis API (optional)

For integration with other tools or ad-hoc queries, start the API server locally pointing at production Spanner:

```sh
uv run python cmd/analysis_api.py --port 8080
```

Interactive API documentation (Swagger UI) is available at `http://localhost:8080/docs` once the server is running.

Available endpoints:

| Endpoint | Description |
|----------|-------------|
| `GET /choke-points?top_n=10` | Top N choke-point assets by score |
| `GET /asset-exposure` | All assets with targeting actor counts |
| `GET /attack-paths?asset_id=<id>` | Attack paths leading to an asset |
| `GET /actor-ttps?actor_id=<id>` | TTPs associated with a threat actor |
| `GET /similar-incidents?incident_id=<id>` | Incidents similar to a given one |

---

## Quarterly PIR update workflow

Run this when organizational context changes (new projects, M&A, regulatory updates, new crown jewels):

```
1. Update input/<context>.md                  ← in BEACON repo (see docs/context_template.md)
2. uv run python cmd/generate_pir.py \        ← run in BEACON repo
     --context input/<context>.md \
     --output output/pir_output.json \
     --collection-plan output/collection_plan.md
3. cp output/pir_output.json /path/to/config/pir.json
4. make run-etl                               ← re-run ETL to apply new PIR weights
5. uv run python cmd/report_choke_points.py   ← verify criticality changes
```

PIR generation (step 2) is handled by [BEACON](https://github.com/sw33t-b1u/beacon), not SAGE.
See [BEACON docs](https://github.com/sw33t-b1u/beacon) for usage details.

---

## IR response workflow

When an incident is detected or suspected:

```sh
# Create an IR incident template as a GHE Issue
uv run python cmd/create_ir_template.py \
  --actor-id <stix-id> \
  --asset-id <asset-id>

# Sync actor TTPs to Caldera for red team simulation (requires CALDERA_URL)
uv run python cmd/sync_caldera.py --actor-id <stix-id>
```
