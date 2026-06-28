# SAGE API Stability Policy

**Status**: Draft for Initiative H — 1.0 Stabilization (sign-off pending).
Effective from SAGE 1.0.0.

**4.0.0 breaking-change record (2026-06-12)**: the default database
backend changed from Spanner to SQLite (`SAGE_DB` env var, default
`sqlite`; Spanner preserved as an optional backend via
`SAGE_DB=spanner`). `GCP_PROJECT_ID`, `SPANNER_INSTANCE`, `SPANNER_DB`,
and `SAGE_ETL_INPUT_BUCKET` are required only when `SAGE_DB=spanner`.
The REST API surface and the input file contracts (STIX bundle /
`assets.json` / PIR JSON) are unchanged. See CHANGELOG 4.0.0 for the
migration path back to Spanner.

This document enumerates SAGE's committed public surface and the
backward-compatibility (BC) guarantee that applies to it. Anything not
listed as **Committed** is **Evolving** and may change in any minor
release without warning.

---

## 1. Versioning policy (SemVer 2.0.0 strict)

SAGE follows [Semantic Versioning 2.0.0](https://semver.org/spec/v2.0.0.html)
strictly from 1.0.0 onwards.

- **Major** (`X.0.0`) — breaking changes to any Committed surface
  item listed in §3.
- **Minor** (`1.X.0`) — additive changes: new tables / columns / REST
  endpoints / CLI subcommands / env vars. Spanner DDL is additive
  only (column type widening like `STRING(64)` → `STRING(128)` is
  additive; narrowing or renaming is breaking).
- **Patch** (`1.0.X`) — bug fixes only, no surface change.

Deprecation path: announce in a `### Deprecated` CHANGELOG section with
the planned removal version, emit a runtime warning where applicable,
then remove in the next major. See BEACON `docs/api-stability.md` §1 for
the full policy text.

---

## 2. Quick reference

| Surface | Committed? | First version | Notes |
|---|---|---|---|
| REST API (12 endpoints) | ✓ | 1.0.0 | See §3.1 for endpoint list |
| Database backend selector (`SAGE_DB`) | ✓ | 4.0.0 | Values: `sqlite` (default) / `spanner` (optional, preserved) |
| Spanner Graph DDL (`schema/spanner_ddl.sql`) | ✓ | 1.0.0 | 36 tables; additive only (type widening OK; rename/drop = major); Spanner-backend-only since 4.0.0 |
| SQLite DDL (`schema/sqlite_ddl.sql`) | ✓ | 4.0.0 | Mirrors all 36 Spanner tables under the documented type mapping; same additive-only rule |
| `Incident.source` discriminator | ✓ | 1.0.0 | Values: `ir_feedback` (OpenCTI relay) / `direct_api` (POST /api/incidents) |
| Auth gate semantics (POST = 503 when `SAGE_API_AUTH_TOKEN` unset; GET = permissive) | ✓ | 1.0.0 | See §3.2 |
| `sage` CLI entry + subcommands (Phase 6 of H) | ✓ | 1.0.0 | Subcommand names + main flags frozen |
| Legacy `python -m cmd.<name>` | (removed) | n/a | Removed in 2.0.0; use `sage <subcommand>` |
| MITRE Navigator import format support (`sage incident-register --navigator-layer`) | ✓ | 1.0.0 | Reads MITRE Navigator JSON layer file |
| ETL contract (TRACE STIX bundle ingest) | ✓ | 1.0.0 | Conforms to STIX 2.1; `x_trace_*` properties stripped at landing |
| Env vars (§5) | ✓ | 1.0.0 | Name + meaning + default frozen |
| OpenCTI integration (legacy polling) | (deprecated for retention) | n/a | Continues to function in 1.x; planned removal in 2.0.0 (use direct API instead) |
| Internal Python modules (`src/sage/*` non-public symbols) | ✗ | n/a | Underscore-prefixed and undocumented helpers may change |
| Spanner migration script format | (operator-internal) | n/a | `src/sage/spanner/migrations/` mechanism kept stable but operator does not invoke directly |

---

## 3. Committed surface — detail

### 3.1 REST API endpoints

All 10 endpoints below are Committed. Each follows the auth gate
semantics in §3.2.

| Endpoint | Method | First | Purpose |
|---|---|---|---|
| `/actors` | GET | Initiative I | Actor search by name substring (`?name=` required, min 2 chars; `?limit=` optional) |
| `/indicators` | GET | 4.1.0 | Direct `IndicatesActor` Observables for selected actors (`?actor_id=` required, repeatable; `?limit=` optional) |
| `/export/stix` | GET | 4.1.0 | STIX 2.1 bundle subset of direct indicators (`?actor_id=` required, repeatable; `?download=` optional) |
| `/attack-paths` | GET | Initiative C | Multi-hop attack path search (actor → asset) |
| `/choke-points` | GET | Initiative C | Defense priority computation |
| `/actor-ttps` | GET | Initiative E + F-7 | Per-actor TTP list + `?since/until` filter |
| `/threat-summary` | GET | Initiative F-8 | Per-asset aggregated view (actors / paths / choke-points / vulnerabilities / incidents); `?limit=N` 1-100 (default 5); `Incident.occurred_at` only anchor |
| `/asset-exposure` | GET | Initiative F-7 | Per-asset exposure + `?since/until` filter |
| `/similar-incidents` | GET | (pre-existing) | Hybrid-score similar-incident search (`alpha × jaccard_ttp + (1-alpha) × transition_coverage`) |
| `/caldera/adversary` | POST | (pre-existing) | Generate + sync Caldera Adversary profile from actor TTPs |
| `/annotate` (`/api/annotate`) | POST | Initiative E + G Decision 10 retroactive | AnnotatesActor write — analyst annotation |
| `/incidents` (`/api/incidents`) | POST + GET | Initiative G Phase 1 + 2 | Direct IR intake (POST) + read endpoint (GET) |

**Committed**: route paths, request/response shapes (Pydantic
models in `src/sage/api/models.py`), query parameter names and
ranges, HTTP status codes.

**Evolving**: response field ordering, internal SQL query
implementation, log message formats.

### 3.2 Auth gate (per Decision 10 of Initiative G)

The `_verify_auth` dependency in `src/sage/api/auth.py` is centralised
and parametrised:

- **POST routes** (`POST /api/incidents`, `POST /api/annotate`,
  `POST /caldera/adversary`): `enforce_when_unset=True`. When
  `SAGE_API_AUTH_TOKEN` env is unset, POST returns **503** (write
  API foot-gun gate — explicit refusal beats silent permissiveness).
  When set, normal Bearer auth applies (401 missing, 403 wrong).
- **GET routes**: `enforce_when_unset=False`. Permissive when
  `SAGE_API_AUTH_TOKEN` is unset (backward-compat with current
  deployments). When set, normal Bearer auth applies.

**Committed**: the 503-on-unset behaviour for POST; the
permissive-on-unset behaviour for GET; the Bearer auth shape when
token is set (HTTP header `Authorization: Bearer <token>`, 401 on
missing, 403 on wrong).

### 3.3 Spanner Graph DDL (`schema/spanner_ddl.sql`)

36 tables total: **node tables** (ThreatActor, TTP, MalwareTool,
Vulnerability, Observable, Incident, Identity, SecurityControl,
Asset, UserAccount, PIR) and **edge tables** (Uses, UsesTool,
Exploits, FollowedBy, IncidentUsesTTP, MalwareUsesTTP, Targets,
TargetsAsset, AttributedToActor, AttributedToIdentity, IndicatesActor,
IndicatesTTP, ActorTargetsIdentity, ImpersonatesIdentity,
HasVulnerability, ConnectedTo, ProtectedBy, HasAccess, AccountOnAsset,
UserAccountBelongsTo, PirPrioritizesActor,
PirPrioritizesImpersonationTarget, PirPrioritizesTTP, PirWeightsAsset,
AnnotatesActor).

**Committed**: table presence, column names, column types, column
nullability, primary keys, default values.

**Additive (non-breaking)**:
- New tables.
- New columns on existing tables (with appropriate default for old
  rows).
- Widening a column type (`STRING(64)` → `STRING(128)`).
- New INDEX or GRAPH definition.

**Breaking (requires 2.0.0)**:
- Renaming a table or column.
- Dropping a table or column.
- Narrowing a column type.
- Changing a column from nullable to NOT NULL on an existing table
  with NULL data.
- Changing primary key composition.

The `src/sage/spanner/migrations/` directory stores forward-only
migration SQL files versioned per table change. Applying these
migration files is currently a manual operator step (executing the
SQL directly against Spanner); `sage init-schema` takes no
arguments and applies the base schema for the configured backend
(`schema/spanner_ddl.sql` when `SAGE_DB=spanner`,
`schema/sqlite_ddl.sql` otherwise).

Since 4.0.0 the same Committed surface (table presence, column names,
column nullability, primary keys, default values) applies to
`schema/sqlite_ddl.sql`, which mirrors all 36 tables under the
documented type mapping (`TIMESTAMP` → TEXT ISO 8601 UTC,
`ARRAY<STRING>` → TEXT JSON array, `INT64` → INTEGER, `FLOAT64` →
REAL, `STRING(n)` → TEXT). The additive / breaking rules above apply
to both DDL files.

### 3.4 `Incident.source` discriminator

Column type: `STRING(32) NOT NULL DEFAULT 'ir_feedback'`.

**Committed values**:
- `ir_feedback` — OpenCTI-relayed (existing behaviour, retained for
  legacy operators with OpenCTI deployments)
- `direct_api` — `POST /api/incidents` direct IR intake
  (Initiative G Phase 1)

Other values MAY appear in minors as new intake paths are added;
existing values cannot be removed without 2.0.0.

### 3.5 ETL contract (TRACE STIX bundle ingest + PIR file ingest)

SAGE ingests STIX 2.1 bundles produced by TRACE (or by other
operator-supplied tools) and the BEACON-emitted `pir_output.json`.

**Committed**:
- STIX 2.1 conformance (per OASIS spec).
- `x_trace_*` extension properties are stripped at landing-zone
  ingest (SAGE does not persist TRACE-internal markers).
- Mapping conventions: STIX `intrusion-set` → SAGE `ThreatActor`,
  `attack-pattern` → `TTP`, etc. (See `src/sage/stix/mapper.py`
  for the full mapping table.)
- **PIR file ingest format** (Initiative H Phase 3 strictness):
  `PIRFilter.from_file()` requires the wrapped envelope
  `{"schema_version": "1.0.0", "pirs": [...]}`. Bare-list /
  single-object PIR payloads are rejected with the migration
  message (same convention as TRACE 1.12.0).
- **`is_high_value_impersonation_target` flag**: BEACON-emitted
  identity_assets carry this boolean flag directly. SAGE 1.0.0
  removed the BEACON 0.12.x fallback (`HIGH_VALUE_IMPERSONATION_ROLES`
  15-entry role-tag frozenset). The flag-driven path is the only
  supported input.
- **`effective_priority` recompute API** signature: the
  `is_high_value_impersonation_target` flag is **positional** (no
  default) — callers must explicitly supply the flag value. Matches
  the flag-driven Initiative H Phase 3 contract.

**Evolving**: internal mapper helper functions, ETL worker
parallelism strategy.

### 3.6 `sage` CLI entry + subcommands (Phase 6 of H)

Initiative H Phase 6 introduces `sage` as a click `Group` entry
point. Operator-visible surface from 1.0.0:

| Subcommand | Replaces | Purpose |
|---|---|---|
| `sage init-schema` | `src/sage/cli/init_schema.py` | Apply the DDL for the configured backend (`SAGE_DB`) + create indexes |
| `sage load-assets` | `src/sage/cli/load_assets.py` | Load BEACON assets.json into the database |
| `sage load-identity-assets` | `src/sage/cli/load_identity_assets.py` | Load identity_assets.json |
| `sage load-user-accounts` | `src/sage/cli/load_user_accounts.py` | Load user_accounts.json |
| `sage incident-register` | `src/sage/cli/register_incident.py` | Interactive Diamond Model CLI (Initiative G Phase 3) |
| `sage actor-annotate` | `src/sage/cli/annotate_actor.py` | AnnotatesActor write CLI (Initiative E) |
| `sage query-attack-paths` | `src/sage/cli/query_attack_paths.py` | Attack path CLI query (offline) |
| `sage ir-template` | `src/sage/cli/create_ir_template.py` | Generate IR onboarding template |
| `sage serve-api` | `src/sage/cli/analysis_api.py` | Start REST API server |
| `sage run-etl` | `src/sage/cli/run_etl.py` | Run ETL pipeline (OpenCTI poll or `--input`) |
| `sage visualize-graph` | `src/sage/cli/visualize_graph.py` | Generate interactive HTML graph visualization |
| `sage report-choke-points` | `src/sage/cli/report_choke_points.py` | Generate a Markdown choke-point asset report (Blue Team) |
| `sage sync-caldera` | `src/sage/cli/sync_caldera.py` | Sync actor TTPs to a Caldera adversary profile |
| `sage visualize-attack-flow` | `src/sage/cli/visualize_attack_flow.py` | Generate a weighted Attack Flow HTML visualization |
| `sage visualize-combined` | `src/sage/cli/visualize_combined.py` | Generate a combined Attack Graph + Attack Flow HTML visualization |
| `sage setup-emulator` | `src/sage/cli/setup_emulator.py` | Create Spanner emulator instance and database (dev only) |

**Committed**: subcommand names + each subcommand's main flags
(e.g., `incident-register --id`, `--from-file`, `--navigator-layer`,
`--no-api`, `--token`, `--api-url`).

**Evolving**: optional flag defaults, help text, output formatting.

**Removed in 2.0.0**: `python -m cmd.<name>` invocation syntax. The
unified `sage` CLI is the only supported entry point from 2.0.0
onwards.

### 3.7 MITRE Navigator import (Initiative G Phase 3)

`sage incident-register --navigator-layer <layer.json>` accepts
MITRE ATT&CK Navigator layer JSON files. Per-technique
`techniqueID` is converted to STIX `attack-pattern--<uuid5>`
using `uuid.NAMESPACE_URL + MITRE URL`. Order in the layer file
preserved as `sequence_order` in `IncidentUsesTTP`.

**Committed**: Navigator layer file format support (top-level
`techniques: [{techniqueID, tactic, score, comment?}]`), UUID5
derivation namespace, sequence preservation.

### 3.8 Environment variables (Committed)

| Env | Default | Purpose |
|---|---|---|
| `SAGE_DB` | `sqlite` | Database backend selector: `sqlite` or `spanner` (4.0.0) |
| `GCP_PROJECT_ID` | (required when `SAGE_DB=spanner`) | GCP project ID |
| `SPANNER_INSTANCE` | (required when `SAGE_DB=spanner`) | Spanner instance ID |
| `SPANNER_DB` | (required when `SAGE_DB=spanner`) | Spanner database ID |
| `SAGE_ETL_INPUT_BUCKET` | (required when `SAGE_DB=spanner`) | GCS landing zone bucket |
| `OPENCTI_URL` | (required for legacy) | OpenCTI server URL (only required if using OpenCTI relay) |
| `OPENCTI_TOKEN` | (required for legacy) | OpenCTI API token |
| `PIR_FILE_PATH` | `/config/pir.json` | Path to BEACON-emitted pir_output.json |
| `TLP_MAX_LEVEL` | `amber` | TLP filter level for ETL ingest |
| `ACTIVITY_WINDOW_DAYS` | `90` | Shared with BEACON/TRACE. SAGE_ACTIVITY_WINDOW_DAYS falls back to this |
| `SAGE_ACTIVITY_WINDOW_DAYS` | (falls back to `ACTIVITY_WINDOW_DAYS`) | SAGE-specific window override |
| `SAGE_API_AUTH_TOKEN` | `""` | Bearer token for REST API. POST routes require this set; GET permissive when unset |
| `SLACK_WEBHOOK_URL` | `""` | Optional Slack notification webhook |

**Not committed** (deployment-internal): logging level, structlog
configuration env, GCP_CREDENTIALS_PATH (deployment-specific).

---

## 4. Evolving (NOT BC-protected)

- **Internal Python modules** under `src/sage/` not exported via
  the documented API surface.
- **Internal SQL queries** in `src/sage/spanner/query.py` — the
  endpoint-level contract is Committed but how SAGE produces those
  results is Evolving.
- **ETL worker parallelism / chunking strategy** —
  `src/sage/etl/worker.py` internals.
- **Prometheus metric names** beyond the documented
  `sage_incident_warnings_total` counter — may add new metrics in
  minors; existing names stay stable.
- **Migration script naming convention** in
  `src/sage/spanner/migrations/` — migration order + content is
  Committed (operators apply migration SQL manually against Spanner),
  but file naming is internal.
- **`/test/` routes** (none currently registered in prod app; if
  added, marked test-only).

---

## 5. Cross-repo dependencies

SAGE's Committed surface depends on:

- **BEACON `pir_output.json` schema** (BEACON 1.0.0+) for ETL
  PIR ingest (`PIR_FILE_PATH`).
- **TRACE STIX 2.1 bundle output** for actor / TTP / vulnerability
  / incident data.
- **OASIS STIX 2.1 specification** as the cross-repo data model
  bridge.
- **Google Cloud Spanner Graph (Preview/GA)** as the optional storage
  layer (`SAGE_DB=spanner`; SQLite from the Python standard library is
  the default backend since 4.0.0). Spanner Graph DDL syntax stability
  is upstream-controlled.

Full citation inventory: `../beacon/docs/citations.md`.

---

## 6. 2.0.0 trigger examples

Examples of changes that would force SAGE 2.0.0:

- Removing the `/attack-paths` endpoint or renaming its query params.
- Removing the `Incident.source = 'ir_feedback'` discriminator value
  (OpenCTI relay removal is the planned scenario).
- Renaming the `ThreatActor` table to `Actor`.
- Changing the auth gate semantics (e.g., making GET routes
  require auth by default when token unset).
- Removing `sage incident-register` subcommand or its `--no-api`
  flag.
- Removing `SAGE_API_AUTH_TOKEN` env var.
- Narrowing `Incident.kill_chain_phases` from `ARRAY<STRING(64)>`
  to `ARRAY<STRING(32)>`.

Adding new endpoints, new tables, new subcommands, new env vars,
new Incident.source values, new MITRE Navigator field support is
allowed in minor releases.

---

## 7. Maintenance

Update this document whenever a Committed surface item is introduced
or deprecated. See BEACON `docs/api-stability.md` §7 for the same
maintenance convention.

---

*Initiative H — 1.0 Stabilization. Effective from SAGE 1.0.0.*
