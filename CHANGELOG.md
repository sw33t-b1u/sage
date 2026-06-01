# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).


## [2.0.0] - 2026-06-01

### Breaking Changes
- **Removed deprecated `cmd/` directory and `python cmd/X.py` / `python -m cmd.X`
  invocation paths.** These were deprecated in 1.0.0 (Initiative H Phase 6) when
  the unified `sage <subcommand>` CLI was introduced. The 90-day backwards-
  compatibility window expired.

### Refactored
- Moved CLI implementations from top-level `cmd/` to `src/sage/cli/` as a proper
  Python package. `sage <subcommand>` API surface (16 commands) is unchanged.
- Rewrote `src/sage/cli/__init__.py` wrapper to use direct imports instead of
  `importlib.util.spec_from_file_location` dynamic loading.

### Internal
- Removed 13 vestigial `sys.path.insert(0, str(Path(__file__).parent.parent / "src"))`
  statements from moved CLI modules (no-op in installed package context).
- Cleaned up unused `import sys` and `from pathlib import Path` left after
  sys.path removal.
- Dockerfile no longer COPYs cmd/ (was dead code).
- Makefile ruff invocations no longer reference cmd/.


## [1.3.0] — 2026-05-28

### Added

- `sage report-choke-points` — unified CLI subcommand for choke-point
  reporting (wraps `cmd/report_choke_points.py`).
- `sage sync-caldera` — unified CLI subcommand for Caldera TTP sync
  (wraps `cmd/sync_caldera.py`).
- `sage visualize-attack-flow` — unified CLI subcommand for attack-flow
  HTML visualisation (wraps `cmd/visualize_attack_flow.py`).
- `sage visualize-combined` — unified CLI subcommand for combined
  (attack flow + attack graph) HTML visualisation (wraps
  `cmd/visualize_combined.py`).
- `sage setup-emulator` — unified CLI subcommand for Spanner emulator
  bootstrap (wraps `cmd/setup_emulator.py`).

### Removed

- Standalone `python -m cmd.<name>` / `python cmd/<name>.py` invocation
  syntax. All entry points are now exclusively reached via the `sage
  <subcommand>` unified CLI. Docs migrated accordingly.


## [1.2.0] — 2026-05-28

### Added

- `deterministic_vuln_stix_id(cve_id)` helper in `src/sage/stix/mapper.py`
  and the matching `_DETERMINISTIC_ID_NAMESPACE` constant (uuid5 namespace
  identical to TRACE 2.0.0's `_DETERMINISTIC_ID_NAMESPACE`).

### Changed

- `cmd/load_assets.py` (and the `sage load-assets` subcommand) now mints a
  deterministic-id stub `Vulnerability` node for org-provided CVEs that are
  absent from Spanner, instead of silently dropping the `HasVulnerability`
  edge. The stub uses `stix_id = vulnerability--uuid5(NS, cve_id)` where
  `NS = a1b2c3d4-e5f6-7890-abcd-ef1234567890`. Later CTI ETL of the same
  CVE enriches the same node via INSERT OR UPDATE (idempotent). Invalid CVE
  refs (non-CVE-YYYY-NNNNN format) are still skipped with a warning and no
  stub is created. Deterministic id matches TRACE 2.0.0's vulnerability
  uuid5(CVE) so the stub and the external CTI node collide correctly.


## [1.1.0] — 2026-05-25

**Initiative I — /actors endpoint + Storage Abstraction.** Paired
triple: BEACON 1.1.0 + SAGE 1.1.0 + TRACE 1.13.0.

### Added

- **`GET /actors?name=<query>`** — name-based actor search endpoint.
  Case-insensitive substring match, min 2 chars, returns
  `{"actors": [...], "count": N}` sorted by `last_seen` DESC.
- **StorageBackend abstraction layer** — `LocalStorage` and
  `GCSStorage` implementations (copied from BEACON per Decision I-12).
  Env vars: `SAGE_STORAGE`, `SAGE_STORAGE_BASE_DIR`,
  `SAGE_GCS_BUCKET`, `SAGE_GCS_PREFIX`.
- **Multi-bundle ETL** — `run_etl` processes all STIX bundles in the
  StorageBackend `stix/` category, not just a single file.
- `load_assets`, `load_identity_assets`, `load_user_accounts` fall
  back to StorageBackend when `--input` is not specified.

---

## [1.0.0] — 2026-05-24

**Initiative H — 1.0 Stabilization release.** SAGE 1.0.0 commits to
the public surface documented in `docs/api-stability.md` under a
90-day backward-compatibility guarantee. Paired triple: BEACON 1.0.0
+ TRACE 1.12.0 + SAGE 1.0.0.

### Committed surface

See `docs/api-stability.md` §3 for the authoritative inventory.
Summary:

- 9 REST endpoints: `GET /attack-paths`, `GET /choke-points`,
  `GET /actor-ttps`, `GET /threat-summary`, `GET /asset-exposure`,
  `GET /similar-incidents`, `POST /caldera/adversary`,
  `POST /annotate` (E + G Decision 10 retroactive),
  `POST /incidents` + `GET /incidents` (G Phase 1 + 2).
- Spanner Graph DDL (36 tables) — additive only; column type
  widening (e.g., `STRING(64)` → `STRING(128)`) OK; rename / drop /
  narrowing requires `2.0.0`.
- `Incident.source` discriminator values (`ir_feedback` /
  `direct_api`).
- Auth gate semantics: `POST` returns 503 when
  `SAGE_API_AUTH_TOKEN` unset (write-API foot-gun); `GET`
  permissive when unset.
- Unified `sage` console-script entry + 9 subcommands.
- MITRE Navigator import format support
  (`sage incident-register --navigator-layer`).
- ETL contract (TRACE STIX bundle ingest + BEACON `pir_output.json`
  wrapped-envelope ingest).
- Environment variables: `PROJECT_ID`, `SPANNER_INSTANCE`,
  `SPANNER_DB`, `GCS_BUCKET`, `OPENCTI_URL`, `OPENCTI_TOKEN`,
  `PIR_FILE_PATH`, `TLP_MAX_LEVEL`, `ACTIVITY_WINDOW_DAYS`,
  `SAGE_ACTIVITY_WINDOW_DAYS`, `SAGE_API_AUTH_TOKEN`,
  `SLACK_WEBHOOK_URL`.

### Migration guide (operator steps)

The Initiative H triple release is a coordinated cut. Apply in
order:

1. **BEACON 1.0.0**. Re-run `beacon pir-generate` so the emitted
   `pir_output.json` carries `schema_version: "1.0.0"`.
2. **TRACE 1.12.0**. Strict validator restricted to
   `schema_version: "1.0.0"`. Wrapped envelope required.
3. **SAGE 1.0.0** (this release). Deploy. `PIRFilter.from_file()`
   now requires the wrapped envelope (bare-list rejected with the
   migration message). The BEACON 0.12.x identity-asset fallback
   (`HIGH_VALUE_IMPERSONATION_ROLES` 15-entry frozenset) is removed
   — operators on BEACON ≤ 0.12.x must upgrade BEACON to 0.13.0+
   first so `is_high_value_impersonation_target` is emitted
   directly.

The `effective_priority` recompute API gains a positional
`is_high_value_impersonation_target` argument (no default). Callers
must supply the flag explicitly.

### Forward-looking note

SAGE 1.0.0 starts a **90-day backward-compatibility window** for
every item listed in `docs/api-stability.md` §3 (Committed surface).
Within that window:

- **Minor releases** (`1.X.0`) ship additive changes only — new
  tables, new columns, new endpoints, new CLI subcommands, new env
  vars, new `Incident.source` discriminator values, column type
  widening (`STRING(64)` → `STRING(128)` etc.).
- **Breaking changes** to any committed surface item require a new
  major release (`2.0.0`). Examples that would force SAGE 2.0.0:
  removing the `/attack-paths` endpoint, renaming the `ThreatActor`
  table, removing the `Incident.source = 'ir_feedback'`
  discriminator value (planned OpenCTI relay removal scenario),
  narrowing a column type, changing the auth gate semantics.
- **Deprecation path**: announce in 1.X.Y CHANGELOG + emit
  `DeprecationWarning` at runtime + remove in `2.0.0` after the
  90-day BC window and at least one further minor.

Items marked Evolving in `docs/api-stability.md` §4 (internal
SQL query implementation, ETL parallelism strategy, Prometheus
metric naming beyond documented counters, migration script file
naming) remain free to change in any minor.

### Removed (BREAKING) — Initiative H Phase 3

- **`HIGH_VALUE_IMPERSONATION_ROLES` 15-entry frozenset** in
  `src/sage/spanner/constants.py`. The flag-driven
  `is_high_value_impersonation_target` path (BEACON 0.13.0+) is the
  only supported input. Operators on BEACON ≤ 0.12.x must upgrade
  BEACON before SAGE 1.0.0 deployment.
- **BEACON 0.12.x compat branches in `src/sage/spanner/upsert.py`**.

### Changed (BREAKING) — Initiative H Phase 3

- **`PIRFilter.from_file()` requires the wrapped envelope**
  (`{"schema_version": "1.0.0", "pirs": [...]}`). Bare-list and
  single-object payloads are rejected with the migration message.
- **`effective_priority` recompute API**: the
  `is_high_value_impersonation_target` argument is positional (no
  default). Matches the flag-driven Phase 3 contract.

### Added — Initiative H Phase 6: unified `sage` CLI

- New `sage` console script (`sage.cli:cli`) exposes 9 verb-noun
  subcommands matching `docs/api-stability.md` §3.6: `init-schema`,
  `load-assets`, `load-identity-assets`, `load-user-accounts`,
  `incident-register`, `actor-annotate`, `query-attack-paths`,
  `ir-template`, `serve-api`. Each subcommand delegates to the
  existing `cmd/<name>.py` via `importlib.util.spec_from_file_location`
  (sidestepping the stdlib `cmd` module shadow).
- `cmd/<name>.py` modules gain a deprecation steer (module
  docstring + stderr warning at script invocation). Legacy
  invocation form remains supported through SAGE 1.x for backward
  compatibility; removal scheduled for SAGE 2.0.

## [0.13.0] — 2026-05-24

Initiative G (IR Feedback Ingestion + Diamond Model Support) release —
paired with BEACON 0.18.0 + TRACE 1.11.0.

### Added

- **`POST /api/incidents` direct IR intake endpoint** (Phase 1,
  `8a42e85`): operators (or `cmd/register_incident.py`, Phase 3) can
  register incidents without the OpenCTI relay's 24-hour polling
  latency. Required fields: `incident_stix_id`, `name`, `occurred_at`,
  `severity`. Optional: `kill_chain_phases[]`, `ttps[]` (with
  `sequence_order`), `diamond_model` (4-key dict per Caltagirone
  et al.), `iocs[]`, `description`. PUT-like full-replace upsert
  (`incident_stix_id` is PK). Response `warnings[]` includes
  `kcp_missing` / `sequence_order_null` codes; counters logged as
  `sage_incident_warnings_total{code}` (structlog fallback for the
  Prometheus counter the future metrics endpoint will adopt).
  `Incident.source` value `direct_api` discriminates from
  OpenCTI-relayed `ir_feedback` rows.
- **Centralised auth gate `src/sage/api/auth.py`** (Phase 1,
  `8a42e85`): `verify_auth(enforce_when_unset)` factory. POST routes
  use `enforce_when_unset=True` (returns **503** when
  `SAGE_API_AUTH_TOKEN` env is unset — write API foot-gun gate).
  GET routes remain permissive when unset (backward-compat). The
  Initiative E `POST /api/annotate` endpoint is retroactively
  upgraded to the same enforce-when-set policy per Decision 10.
- **`GET /api/incidents` read endpoint** (Phase 2, `cc664fc`): filter
  by `?since/?until/?actor_stix_id`, paginate via `?limit=N` (default
  50, range 1-100). Response is full incident shape: TTPs +
  `diamond_model` inline-expanded. Spanner strong-read consistency.
  Helper `_resolve_window` extracted to `src/sage/api/windows.py` so
  the read path can reuse F Phase 7's default-window logic without
  creating an import cycle through `app.py`.
- **`cmd/register_incident.py` Diamond Model CLI** (Phase 3,
  `8c8e9c8`): click-based helper for IR analysts. Modes:
  interactive (prompts 4 Diamond Model quadrants with hints drawn
  from Caltagirone et al.); `--from-file payload.json`;
  `--navigator-layer layer.json` (imports MITRE Navigator technique
  list, derives `kill_chain_phases` + `ttps` with `sequence_order`);
  `--no-api` (air-gapped — writes directly to Spanner). Reuses
  Phase 1's `IncidentRequest` Pydantic model. `--id` overrides
  auto-generated `incident--<uuid4>`. `--token` defaults to
  `$SAGE_API_AUTH_TOKEN`. Navigator technique IDs convert to STIX
  `attack-pattern--<uuid5>` (UUID5 from MITRE URL namespace —
  operators must use matching scheme on the Spanner load side; for
  Spanner-row-accurate joins use `--from-file` with explicit
  `ttp_stix_id` values).
- **`docs/ir-feedback-flow.md`** (Phase 8, `39e09a6`): authoritative
  cross-repo IR loop document. Includes mermaid sequenceDiagram,
  NIST SP 800-61r3 §2.1 verbatim quote (US gov public domain)
  anchoring the direct-API rationale, OpenCTI vs direct-API
  trade-off table, BEACON IR-boost methodology citation (MITRE
  Cyber Prep), TRACE IoC search workflow, auth-gate (Decision 10)
  semantics, and operator quick-start commands. BEACON and TRACE
  host relative symlinks pointing to this file.

### Fixed

- **`spanner/incidents._build_incident_row` kill_chain_phases
  serialisation** (`30576c4`): Phase 1 helper wrote `kill_chain_phases`
  as a JSON-string via `json.dumps([p.model_dump() for p in ...])`,
  but the Spanner DDL declares the column as `ARRAY<STRING(64)>`.
  Production writes would have failed with a type mismatch; mock-
  based tests did not surface the bug. Fix: persist as
  `list[str]` of `phase_name` (each truncated to 64 chars to match
  the DDL constraint), matching the existing OpenCTI relay mapper
  convention (`src/sage/stix/mapper.py:220`). Metadata
  (`kill_chain_name`, `x_ttp_stix_id`) is unaffected — flows to
  `IncidentUsesTTP` rows separately via `_build_iut_rows`.

### Changed

- **`/api/annotate` auth gate harmonisation** (Phase 1, `8a42e85`):
  Initiative E's "optional with warning" policy replaced by the same
  enforce-when-set / 503-when-unset gate that POST `/api/incidents`
  uses. Backward-compat for deployments that did not set the token:
  POST returns 503 (previously 200 with warning). Set
  `SAGE_API_AUTH_TOKEN` to restore writeability. GET routes
  unaffected.

## [0.12.0] — 2026-05-24

Initiative F (Temporal Window + Collection Plan + Summary API + RSS)
release — paired with BEACON 0.17.0 + TRACE 1.10.0.

### Added

- **`activity_window_days` config field** (Phase 7, `3a05d6b`,
  default 90): env hierarchy `SAGE_ACTIVITY_WINDOW_DAYS` →
  `ACTIVITY_WINDOW_DAYS` (BEACON-wide setting) → 90. Threaded into
  `Config.from_env`, `spanner/query.py`, `etl/worker.py`, and
  `cmd/run_etl.py`.
- **`?since` and `?until` query params on existing endpoints**
  (Phase 7, `3a05d6b`): `/actor-ttps` and `/asset-exposure` now
  accept time-range filtering via `?since=YYYY-MM-DD&until=YYYY-MM-DD`.
  Time anchors: `/actor-ttps` filters `Uses.last_observed`;
  `/asset-exposure` filters `Uses.last_observed`. Combined
  `Uses.last_observed ∪ Incident.occurred_at` view available via the
  new `/threat-summary` endpoint (Phase 8) which natively stitches
  both. Absent params → resolved via `_resolve_window`
  (until=today UTC, since=until − activity_window_days).
- **`/threat-summary?asset=X&since=...&until=...&limit=N` endpoint**
  (Phase 8, `6bc9b78`): single response stitching per asset:
  `prioritized_actors` (PirPrioritizesActor for PIRs valid in
  window via `PIR.valid_from ≤ since AND PIR.valid_until ≥ until`),
  `attack_paths`, `choke_points`, in-range `vulnerabilities`
  (`Vulnerability.published_date` in [since, until]), in-range
  `incidents` (`Incident.occurred_at` in [since, until] — **NOT**
  `resolved_at` per Q2=NO). `rationale_json` inline-expanded from
  Initiative D's persisted score breakdown. **Top-N default = 5
  per section** (aligned with BEACON Initiative E top-5
  prioritized_actors view); `?limit=N` 1-100 override (422 outside
  range). **Verbose-only response** (no compact mode in F).
  **Pagination = limit-only** (no offset/cursor in F). Auth: reuses
  existing `_verify_auth` Bearer.
- **`api/models.py`** (Phase 8, `6bc9b78`): `ThreatSummaryResponse`
  Pydantic model. `IncidentEntry` deliberately excludes
  `resolved_at` field — consumers cannot consult it (architectural
  enforcement of occurred_at-only anchor).
- **ETL FollowedBy weight recalculation reads `activity_window_days`
  from config** (Phase 7, `3a05d6b`): literal 90-day window removed
  from `etl/worker.py` and `stix/mapper.py`; operators can now
  modify the window through env without code changes.

### Changed

- **`/asset-exposure` time-anchor remains `Uses.last_observed`-only**
  (Phase 7 deviation): plan §2.6 noted a combined
  `Uses.last_observed ∪ Incident.occurred_at` view; in practice this
  naturally fits `/threat-summary` which stitches incident data
  explicitly. `/asset-exposure` response shape preserved for
  existing consumers; combined view available via
  `/threat-summary`.

## [0.11.0] — 2026-05-23

Initiative E (Actor Triage Phase 2) release — paired with BEACON 0.16.0 + TRACE 1.9.0.

### Added

- **AnnotatesActor write API — CLI** (Phase 5, e7973bf):
  `cmd/annotate_actor.py` writes analyst annotations to the
  `AnnotatesActor` Spanner table that was added schema-wise in 0.10.0.
  Four annotation types (controlled vocabulary):
    * `false-positive` — analyst rejects actor as relevant
    * `scope-exclusion` — actor relevant but out-of-scope for org
    * `analyst-note` — free-text comment, no scoring effect
    * `confidence-override` — analyst-provided Likelihood override
  Per-type Pydantic payload validation in `src/sage/models/annotation.py`
  enforces field constraints (e.g., `confidence-override.overridden_likelihood`
  must be in [0.0, 1.0]) BEFORE Spanner write.

- **AnnotatesActor write API — REST** (Phase 6, 2650d5a):
  `POST /api/annotate` on the existing FastAPI app
  (`src/sage/api/annotation.py`). Re-validates request payload against the
  per-type Pydantic model. Returns 200 on success, 422 on invalid payload,
  401/403 on auth failure. Router-level `Depends(_verify_auth)` mirrors
  existing endpoint auth pattern.

### Changed

- (none — schema unchanged from 0.10.2; this release adds write surface
  only, on top of the schema introduced in 0.10.0 and DDL-fixed in 0.10.2)

### Fixed

- (none — DDL fix for `AnnotatesActor.created_at` shipped in 0.10.2)

### Security

- (none — starlette pin shipped in 0.10.2)

### Infrastructure

- `.githooks/pre-commit` exports `UV_CACHE_DIR` to handle sandbox env
  (harmonized with BEACON Phase 7 fix; commit 1cb6bb8).

## [0.10.2] — 2026-05-23

Security + schema integrity patch release.

### Security

- Pin `starlette>=1.0.1` (top-level) to address `PYSEC-2026-161`. The
  vulnerability is transitive via `fastapi`. Detected during the
  `pip-audit` step of Initiative E Phase 5 review on 2026-05-23.
  Co-shipped with BEACON 0.15.2 (same CVE).
  TRACE is unaffected (no starlette/fastapi dependency).

### Fixed — AnnotatesActor.created_at allow_commit_timestamp option

- `schema/spanner_ddl.sql` and
  `src/sage/spanner/migrations/20260522_120000_actor_rationale.sql`:
  add `OPTIONS (allow_commit_timestamp=true)` to
  `AnnotatesActor.created_at`. The original 0.10.0 DDL omitted this
  option; any Spanner write of `spanner.COMMIT_TIMESTAMP` to that
  column (as introduced by the upcoming Initiative E Phase 5 write
  path) would have been rejected by the server. Discovered during
  Initiative E Phase 5 review; existing schema not yet deployed to
  production, so the migration file is amended in place rather than
  superseded with a new migration.

## [0.10.1] — 2026-05-22

Security patch release.

### Security

- Pin `idna>=3.15` to mitigate CVE-2026-45409 (GHSA-65pc-fj4g-8rjx). The previous
  transitive resolution to idna 3.11 was vulnerable to specially crafted inputs that
  could bypass the CVE-2024-3651 fix.
- Paired security release: BEACON 0.15.1 + TRACE 1.8.1 ship the same patch.

## [0.10.0] — 2026-05-22

### Added — Actor triage integration (BEACON 0.15.0 / TRACE 1.8.0 paired release)

Implements plan §7 Phase 6. BEACON 0.15.0 now emits `prioritized_actors[]` in
`pir_output.json`; SAGE 0.10.0 ingests and persists the scored actor list.

- **`PirPrioritizesActor` schema extension** (migration
  `src/sage/spanner/migrations/20260522_120000_actor_rationale.sql`):
  - `likelihood FLOAT64` — raw [0,1] actor triage score; NULL for legacy rows.
  - `rationale_json STRING(MAX)` — JSON-serialized full Rationale
    (`text`, `intent_factors`, `capability_factors`, `opportunity_factors`).
- **`AnnotatesActor` edge table** — new table for analyst annotations
  (operator write path; SAGE ETL provides read-side only in 0.10.0).
  Primary key: `(annotator_id, actor_stix_id, created_at)`.
- **`src/sage/pir/ingest.py`** — `ingest_prioritized_actors()` function:
  reads `prioritized_actors[]` from a BEACON PIR, builds `PirPrioritizesActor`
  rows with `likelihood` (raw float, no rescale) and `rationale_json`.
  Graceful fallback: missing sub-factors default to 0.0, missing rationale
  fields default to empty string/dict.
- **`src/sage/etl/worker.py`** — wired `ingest_prioritized_actors` into
  `process_bundle`; results reported as `stats["pir_actor_triage"]`.
- **`src/sage/spanner/upsert.py`** — `PirPrioritizesActor` column list updated;
  `AnnotatesActor` registered in `_TABLE_COLUMNS` for future write path.

### Changed

- `_TABLE_COLUMNS["PirPrioritizesActor"]` extended with `likelihood` and
  `rationale_json`. Legacy upserts that omit these keys write NULL (columns
  are NULLABLE; backward compat preserved).

## [Unreleased]

### Changed — RULES.md compliance pass

- `high-level-design.md` moved from the project root into `docs/` per
  Rule 27. The file remains gitignored per maintainer policy; the
  `.gitignore` entry is updated to the new path. `docs/structure.md`
  and `docs/structure.ja.md` updated to reflect the new location, and
  the in-code reference in `src/sage/pir/filter.py` is repointed.
- `.env.example` cleaned up: dropped the unused `REGION` placeholder
  (no code path reads it), documented `PORT` (Cloud Run /
  `cmd/analysis_api.py`) and `SPANNER_EMULATOR_HOST`
  (`cmd/setup_emulator.py`) so the template matches every env var the
  code actually reads (Rule 24).

## [0.9.0] — 2026-05-13

### Added — Initiative C Phase 2: Flag-First effective_priority + PirPrioritizesImpersonationTarget

Paired release with BEACON 0.13.0 and TRACE 1.6.0. Advances the
`effective_priority` formula from role-tag intersection–only (Phase 1) to a
**flag-first / role-fallback** design. Introduces the
`PirPrioritizesImpersonationTarget` cascade edge for impersonation-aware
PIR prioritization.

#### effective_priority formula migration (`src/sage/spanner/constants.py`)

`effective_priority(confidence, target_roles, is_high_value_impersonation_target=False)`:

- **flag=True** → multiplier = 1.5 unconditionally (BEACON 0.13.0+ explicit designation)
- **flag=False** → existing `HIGH_VALUE_IMPERSONATION_ROLES` 15-entry frozenset
  intersection (BEACON 0.12.x backward-compat fallback; frozenset **retained**)

Backward compat: old 2-argument callers receive `flag=False` by default — no
change in behavior for pre-Phase-2 data.

#### Identity schema extension (`schema/spanner_ddl.sql`)

Two columns appended to the `Identity` table:

```sql
ALTER TABLE Identity ADD COLUMN
  is_high_value_impersonation_target BOOL NOT NULL DEFAULT (FALSE);
ALTER TABLE Identity ADD COLUMN
  impersonation_risk_factors ARRAY<STRING(64)>;
```

`is_high_value_impersonation_target` defaults to FALSE, maintaining full
backward compatibility with BEACON 0.12.x `identity_assets.json` artifacts.
`impersonation_risk_factors` is nullable (NULL = BEACON 0.12.x legacy identity).

Migration SQL for production Spanner (run once per environment):
```sql
ALTER TABLE Identity ADD COLUMN
  is_high_value_impersonation_target BOOL NOT NULL DEFAULT (FALSE);
ALTER TABLE Identity ADD COLUMN
  impersonation_risk_factors ARRAY<STRING(64)>;
```

#### New cascade edge table: `PirPrioritizesImpersonationTarget`

```sql
CREATE TABLE PirPrioritizesImpersonationTarget (
  pir_id             STRING(64)  NOT NULL,
  identity_stix_id   STRING(128) NOT NULL,
  source_stix_id     STRING(128) NOT NULL,
  effective_priority INT64       NOT NULL,
  derived_at         TIMESTAMP   NOT NULL OPTIONS (allow_commit_timestamp=true),
) PRIMARY KEY (pir_id, identity_stix_id, source_stix_id);
```

ETL derivation: `ImpersonatesIdentity ⨝ Identity.is_high_value_impersonation_target=TRUE`
`⨝ PIR.threat_actor_tags` (actor tags ∩ PIR tags ≠ ∅). `effective_priority`
denormalized from the source `ImpersonatesIdentity` row.

#### Cascade changes

- **ETL worker** (`src/sage/etl/worker.py`): builds `identity_flag_map` from
  in-bundle identity rows; passes it to `map_relationship`; derives
  `PirPrioritizesImpersonationTarget` rows after `ImpersonatesIdentity` upsert.
- **`recompute_effective_priority_for_identity`** (`src/sage/spanner/upsert.py`):
  extended with `is_high_value_impersonation_target: bool = False`; existing
  call sites unchanged.
- **`load_identity_assets.py`**: parses new BEACON fields (default False/[]);
  calls recompute cascade and `derive_pir_prioritizes_impersonation_target_for_identity`
  after each Identity upsert.

#### Tests

17 new test cases (total 230, was 213):

- `TestEffectivePriorityRecompute`: 4 new flag-combination cases
  (flag-only, flag+role no double-boost, role-fallback, no-mult)
- `TestEffectivePriorityUnit`: 7 unit tests for the extended `effective_priority`
  function (including backward-compat and cap-at-100)
- `TestPirPrioritizesImpersonationTarget`: 6 tests covering row creation,
  flag=False no-op, tag-intersection miss, dedup idempotence, multi-PIR fan-out,
  and commit-timestamp sentinel

`tests/fixtures/initiative_c/spec_compliant_bundle.json`: `is_high_value_impersonation_target: true`
and `impersonation_risk_factors` added to the CFO identity (`identity--…000205`).
Existing roundtrip passes unchanged.

## [0.8.0] — 2026-05-12

### Added — Initiative C Phase 1: Attribution & Impersonation Edges

Paired release with TRACE 1.5.0. Materializes two STIX 2.1 §7.2 first-class
relationships (`attributed-to` / `impersonates`) in the Spanner Graph.
Introduces SAGE's first polymorphic edge table pattern with `source_type`
discriminator columns to accommodate Phase 2 expansion without schema migration.

See `/Users/test/Projects/claude_pj/docs/initiative_c_attributed_impersonates.md`
for full design rationale, STIX spec verification, and Phase 2 deferred scope.

#### New Spanner edge tables

**`AttributedToActor`** — campaign / intrusion-set → threat-actor / intrusion-set attribution
chain. Phase 1 emit-ready source types: `campaign | intrusion-set`. Target types:
`threat-actor | intrusion-set`. Precedence-aware upsert (`manual > beacon > trace`).

**`AttributedToIdentity`** — threat-actor → identity real-world provenance
("APT29 attributed to SVR-style identity"). Phase 1 source: threat-actor only.
`source_type` column retained for Phase 2 intrusion-set source activation.
Precedence-aware upsert (`manual > beacon > trace`).

**`ImpersonatesIdentity`** — threat-actor → identity deception relationship
("FIN7 impersonates DHL"). Phase 1 source: threat-actor only.
`effective_priority` column (ETL-computed, NOT a Spanner generated column —
Cloud Spanner generated columns cannot reference other tables or contain
subqueries; see HLD §6.6). Formula: `LEAST(100, confidence × role_boost)` where
`role_boost = 1.5` when the target Identity's `roles[]` intersects
`HIGH_VALUE_IMPERSONATION_ROLES` (15 entries; see
`src/sage/spanner/constants.py`). Precedence-aware upsert.

#### New source file: `src/sage/spanner/constants.py`

`HIGH_VALUE_IMPERSONATION_ROLES` (15-entry frozenset, pinned 2026-05-11):
`cfo / ceo / cto / coo / executive / it-admin / domain-admin / security-officer /
board / dpo / privacy-officer / auditor / legal-counsel / treasurer / procurement`.
`effective_priority()` and `roles_boost_multiplier()` helper functions.
`recompute_effective_priority_for_identity()` upsert helper for Identity
`roles` change cascade.

#### Out-of-spec combinations are drop-and-log (§3.1.1 pending list)

`incident → attributed-to → *`, `threat-actor → attributed-to → intrusion-set`,
`intrusion-set → attributed-to → identity`, `intrusion-set → impersonates → *`
are filtered at SAGE parser + mapper time with a `relationship_type_mismatch_dropped`
structured-log warning. Bundle processing continues uninterrupted.

#### parser / mapper / worker changes

- `campaign` and `x-identity-internal` added to `SUPPORTED_TYPES`
- `StixMapper.map_relationship` routes `attributed-to` / `impersonates` SROs
  to the three new tables; `identity_roles_map` parameter enables effective_priority
  computation at write time from in-bundle Identity objects
- ETL worker builds `identity_roles_map` from Identity rows before relationship
  processing; appends three new upsert calls after existing edge upserts

#### Tests

26 new test cases across `test_init_schema.py`, `test_parser.py`,
`test_mapper.py`, `test_upsert_initiative_c.py` (new), `test_worker.py`.

### Security

- `urllib3` bumped 2.6.3 → 2.7.0 to clear `CVE-2026-44431` and
  `CVE-2026-44432`. Transitive via `pycti` → `botocore`; no SAGE source
  code change required. `pip-audit` clean post-bump (Rule 21).

## [0.7.0] — 2026-05-10

### Added — Initiative B: User-Account SCO + edges

Final SAGE-side slice of the User-Account initiative (paired with
BEACON 0.12.0 and TRACE 1.3.0). Introduces three new graph tables
that drop one level deeper than Initiative A's Identity ↔ Asset
edge — to per-account granularity.

Backed by published frameworks (full citations in the local
Initiative B design doc): NIST SP 800-53 IA-2 / IA-4 / AC-2,
NIST SP 800-63B, ISO/IEC 27001:2022 A.5.16 / A.8.5, CIS Controls
v8 #5. Empirical reinforcement: Verizon DBIR 2025 (stolen
credentials = #1 initial-access at 22%), CrowdStrike GTR 2025
(valid-account abuse = #1 cloud vector at 35%), Mandiant M-Trends
2026 (privileged accounts in 60%+ of post-compromise lateral
movement).

#### `UserAccount` table

```sql
CREATE TABLE UserAccount (
  stix_id            STRING(128) NOT NULL,
  account_login      STRING(256) NOT NULL,
  display_name       STRING(256),
  account_type       STRING(64),                 -- STIX 2.1 §6.4 vocab
  is_privileged      BOOL NOT NULL DEFAULT (FALSE),
  is_service_account BOOL NOT NULL DEFAULT (FALSE),
  identity_stix_id   STRING(128),                -- optional FK to Identity
  source             STRING(32) NOT NULL,        -- beacon | trace | manual
  confidence         INT64,
  stix_modified      TIMESTAMP NOT NULL,
) PRIMARY KEY (stix_id);
```

#### `AccountOnAsset` table (UserAccount → Asset)

One edge per (account, host) pair. Same login on two hosts produces
two edges. Sources track which pipeline contributed.

```sql
CREATE TABLE AccountOnAsset (
  user_account_stix_id STRING(128) NOT NULL,
  asset_id             STRING(36)  NOT NULL,
  first_seen           TIMESTAMP,
  last_seen            TIMESTAMP,
  source               STRING(32) NOT NULL,
) PRIMARY KEY (user_account_stix_id, asset_id);
```

#### `UserAccountBelongsTo` table (Identity → UserAccount)

1:N: one Identity owns multiple accounts. Optional — many
UserAccounts (shared, service, unattributed) have no parent.

#### Precedence-aware upsert helpers

`spanner/upsert.py` factors out a `_precedence_upsert` helper used
by all four Initiative A/B tables:

- `upsert_has_access` (refactored to use the helper)
- `upsert_user_account` (PK: `stix_id`)
- `upsert_account_on_asset` (PK: `user_account_stix_id, asset_id`)
- `upsert_user_account_belongs_to` (PK: `identity_stix_id, user_account_stix_id`)

All four follow `manual > beacon > trace` precedence so analyst
overrides survive subsequent BEACON regeneration.

#### `cmd/load_user_accounts.py` — BEACON-source ingest

Reads BEACON's `user_accounts.json` and upserts UserAccount,
AccountOnAsset (`source=beacon`), and UserAccountBelongsTo (when
`identity_id` is set) rows. STIX ids are deterministic UUID5
hashes:

- Identity: shared namespace with `load_identity_assets.py` so the
  same `id-finance-team` produces the same Identity STIX id across
  both loaders.
- UserAccount: distinct namespace.

Asset id normalization: same `_normalize_asset_id` helper as
Initiative A.

#### `mapper.map_user_account` + relationship dispatch

- `map_user_account` — STIX 2.1 §6.4 user-account SCO → UserAccount
  row (source=trace, confidence=30 default). Uses `user_id` as the
  authoritative login field per STIX spec.
- `map_relationship` extends to:
  - `(user-account → x-asset-internal, x-trace-valids-on)` →
    `AccountOnAsset` row. Same x-asset-internal resolution path as
    HasAccess.
  - `(identity → user-account, related-to)` →
    `UserAccountBelongsTo` row.

#### `worker.process_bundle` dispatches the new tables

Three new dispatch branches (UserAccount upsert via
precedence-aware helper, plus AccountOnAsset and
UserAccountBelongsTo through their dedicated helpers). Stats keys
`user_accounts`, `account_on_asset`, `user_account_belongs_to`
exposed.

#### Parser

`SUPPORTED_TYPES` adds `user-account` and `observed-data`. The
`_parse_object` bypass (originally added for `x-asset-internal`)
now also covers `observed-data` SDOs because TRACE bundles include
the referenced user-account inline; the SDO itself contributes no
graph data.

#### Documentation

- `schema/spanner_ddl.sql` — three new tables added next to the
  Initiative A cluster.
- `docs/data-model.{md,ja.md}` — UserAccount node + AccountOnAsset
  + UserAccountBelongsTo edges added with citations.

### Tests

`test_worker.py::TestRelationshipDispatchCompleteness` invariant
guard updated to include `AccountOnAsset` and `UserAccountBelongsTo`
in the table → stats-key map. New mapper / load tests deferred to
the operational verification step (similar to Initiative A's
post-implementation validation pattern).

All 187 tests pass; 0 vulnerabilities.

### Migration notes

- BEACON 0.12.0 is required upstream — `user_accounts.json` is the
  authoritative input.
- TRACE 1.3.0 ships the schema + validator. TRACE 1.4.0 (deferred)
  will add L3-prompt-driven extraction and bundle assembler
  emission of `x-trace-valids-on`. SAGE 0.7.0 is forward-ready:
  trace-sourced bundles will dispatch correctly when 1.4.0 lands.
- No existing schema is modified; the three new tables are purely
  additive.

### Future scope (Phase 2 evaluation gate)

Same trigger pattern as Initiative A: ≥3 BEACON regen cycles + ≥1
TRACE-source UserAccount emission + ≥1 manual analyst override.
Candidate Phase 2 work: privileged-account PIR weighting, account
lifecycle automation, account-asset cardinality alerts (CIS #5.4),
query API endpoints (`/accounts-by-identity`,
`/assets-by-account`, `/privileged-accounts`).

---

## [0.6.2] — 2026-05-10

### Fixed — `x-trace-has-access` parser rejection (TRACE 1.2.1 paired)

E2E verification of the trace-source HasAccess path failed at the
SAGE parser: ``stix2`` library raised ``Invalid value for
Relationship 'target_ref': not a valid STIX identifier`` for every
``x-trace-has-access`` relationship targeting
``x-asset-internal--asset-CA-001``. STIX 2.1 §2.7 requires the
identifier suffix to be a UUIDv4 or UUIDv5; ``asset-CA-001`` was
neither.

TRACE 1.2.1 changed the synthesized id to
``x-asset-internal--<uuid5(NAMESPACE, asset_id)>`` and moved the
actual SAGE asset_id into a property on the object. SAGE 0.6.2 picks
up that property:

#### Parser

`SUPPORTED_TYPES` adds ``x-asset-internal``. The stix2 library
already accepts custom types via ``allow_custom=True``; the only
needed change here is to stop dropping the object as "unsupported"
during parse so the worker can read it.

#### Worker

`process_bundle` now pre-builds an
``x_asset_internal_map: dict[stix_id, asset_id]`` from
``by_type["x-asset-internal"]`` before the relationship loop. The
map is empty for non-TRACE bundles (OpenCTI, manual input) — those
flows are unaffected.

#### Mapper

`map_relationship` accepts an optional ``x_asset_internal_map``
keyword argument. The ``x-trace-has-access`` branch consults it to
resolve ``target_ref → asset_id``; if the map is absent (mapper-only
unit tests) it falls back to extracting the suffix from the
``target_ref`` string for backward compatibility with 0.6.0 fixtures.

The worker passes the map on every call, so production code uses
the property-based path; the fallback exists only for test
ergonomics and never executes in production.

#### Parser bypass for x-asset-internal

A second issue surfaced during the synthetic-bundle re-verification:
``stix2.parse(..., allow_custom=True)`` returns x-asset-internal as a
plain dict (no STIX class binding), and the subsequent
``parsed.serialize()`` call in `_parse_object` raises
``AttributeError: 'dict' object has no attribute 'serialize'`` —
caught by the `except Exception` so the parse failure is silently
logged and the object dropped. With the object missing, the worker's
`x_asset_internal_map` was empty, and the mapper fell back to
extracting the asset_id from the relationship's target_ref suffix
(producing the raw UUID5 string instead of `asset-CA-001`).

`_parse_object` now special-cases ``x-asset-internal`` and returns
the raw dict unchanged, bypassing the stix2 round-trip. Since this
is TRACE's own custom type with no validation requirements beyond
the format already enforced by the bundle assembler, the bypass is
safe.

### Tests

2 new cases in `tests/test_worker.py::TestXAssetInternalResolution`:

- end-to-end: identity + x-asset-internal + x-trace-has-access
  bundle resolves correctly and writes one HasAccess row
- target_ref pointing at an x-asset-internal id with no matching
  object falls back to suffix extraction (no crash)

3 new cases in `tests/test_parser.py::TestXAssetInternalPassthrough`:

- ``asset_id`` property survives parse (regression guard for the
  silent-drop bug)
- ``extension-definition`` continues to be silently skipped (not
  affected by the bypass)
- end-to-end ``x-trace-has-access`` relationship + x-asset-internal
  + identity bundle parses cleanly

Synthetic fixture `tests/fixtures/synthetic_trace_has_access_bundle.json`
updated to use the UUID5 form (asset-CA-001 →
``f6761eb5-ab89-5503-9f5f-ccfc7bf3ed22``).

All 187 tests pass; 0 vulnerabilities.

### Migration notes

- TRACE 1.2.1 is required upstream (1.2.0 emits the bug-format ids
  that SAGE rejects). Lockstep release.
- Existing BEACON-source HasAccess rows (0.6.0+) are unaffected —
  they go through `cmd/load_identity_assets.py`, not the bundle
  parser.

## [0.6.1] — 2026-05-10

### Fixed — `init_schema.py` semicolon-in-comment DDL splitter bug

`make init-schema` failed against the 0.6.0 schema with a
``Syntax error on line 9, column 55: Expecting ')' but found 'EOF'``.
Root cause: the DDL splitter only stripped full-line ``--`` comments,
leaving inline trailing comments intact. The HasAccess table's
``confidence INT64, -- 0-100; trace edges typically <50`` comment
contained a semicolon that the naive ``.split(";")`` treated as a
statement terminator, splitting the CREATE TABLE in half.

`split_ddl_statements` now strips everything after ``--`` on each
line (full-line and trailing inline alike) before splitting on
``;``. DDL files no longer need to avoid ``;`` inside comments.

### Tests

4 new cases in `tests/test_init_schema.py::TestSemicolonInComment`:

- inline comment with semicolon does not split the surrounding
  statement
- full-line comment continues to be stripped (regression guard)
- multiple statements split correctly when no comments interfere
- the specific HasAccess case (regression replay)

All 182 tests pass; 0 vulnerabilities.

## [0.6.0] — 2026-05-10

### Added — Initiative A: Identity-Asset HasAccess edge

Final SAGE-side slice of the 3-project Identity-Asset HasAccess
initiative (paired with BEACON 0.11.0 and TRACE 1.1.0). Materializes
the edge framework standards mandate (NIST SP 800-53 AC-2 / AC-3,
NIST SP 800-207, ISO/IEC 27001 A.5.16 / A.5.18, CIS Controls v8 #5 /
#6) — see local design doc for the full motivation.

#### `HasAccess` table

```sql
CREATE TABLE HasAccess (
  identity_stix_id STRING(128) NOT NULL,
  asset_id         STRING(36)  NOT NULL,
  access_level     STRING(32),                 -- read | write | admin | deny
  role             STRING(256),
  granted_at       TIMESTAMP,
  revoked_at       TIMESTAMP,                  -- soft-delete (NULL=active)
  source           STRING(32) NOT NULL,        -- beacon | trace | manual
  confidence       INT64,                      -- 0-100
  stix_modified    TIMESTAMP NOT NULL,
) PRIMARY KEY (identity_stix_id, asset_id);
```

The composite primary key (identity, asset) guarantees one
authoritative edge per pair. Multiple sources contribute through the
precedence-aware `upsert_has_access` (see below).

#### Precedence-aware upsert (`spanner/upsert.py::upsert_has_access`)

Decision 2026-05-10: **`manual > beacon > trace`**. Manual analyst
input has the highest authority — overrides everything, including
BEACON-supplied data, so analyst corrections survive subsequent
regeneration cycles.

Implementation reads the existing `(identity_stix_id, asset_id, source)`
keys before writing, compares precedence, and either accepts or skips
each row. Skipped rows log `has_access_upsert_skipped` with the
existing source for diagnostics; equal-rank writes overwrite (so
BEACON regen can update its own rows, e.g. for `revoked_at`).

#### `cmd/load_identity_assets.py` — BEACON-source ingest

Reads BEACON's `identity_assets.json` and upserts both `Identity`
nodes and `HasAccess` edges with `source = "beacon"`,
`confidence = 100`. Identity STIX ids are deterministic UUID v5
hashes of BEACON-supplied ids so re-loads idempotently update the
same rows.

```bash
# After validation passes:
uv run python cmd/load_identity_assets.py \
  --file ../BEACON/output/identity_assets.json
```

`asset_id` is normalized to match BEACON's `_normalize_asset_id`
convention (prefix `asset-` when missing).

#### `mapper.map_relationship` extends to `x-trace-has-access`

Custom relationship type emitted by TRACE 1.2.0+ from CTI report
extraction. Source must be `identity--*`, target must be
`x-asset-internal--<asset_id>` (TRACE's synthesized internal-asset
reference). Other source/target combinations return None and are
dropped at the worker. Trace-source rows default to `confidence=30`
(below the analyst-trust threshold) when the LLM doesn't supply one.

#### `worker.process_bundle` dispatches HasAccess

A new branch in the relationship dispatch table; rows are funneled
to `upsert_has_access` (precedence-aware) rather than `upsert_rows`
(unconditional). The dispatch-completeness invariant test in
`test_worker.py` was updated to include `HasAccess` so future
mapper additions can't slip through silently.

#### Documentation alignment

- `schema/spanner_ddl.sql` — `HasAccess` DDL block placed adjacent
  to `ActorTargetsIdentity` (Initiative A clusters identity-related
  edges).

### Tests

- `tests/test_upsert_has_access.py` (new, 8 cases) — precedence
  matrix (manual/beacon/trace combinations), new-row writes,
  empty-input no-op, mixed accepted/skipped batch.
- `tests/test_mapper.py::TestMapHasAccessRelationship` (4) — identity
  → x-asset-internal happy path, default confidence,
  non-identity-source drop, non-x-asset-internal-target drop.
- `tests/test_worker.py::TestRelationshipDispatchCompleteness` —
  invariant guard updated to include HasAccess.

All 178 tests pass; 0 vulnerabilities.

### Migration notes

- BEACON 0.11.0 is required upstream — `identity_assets.json` is the
  authoritative input.
- TRACE 1.1.0 ships the schema + validator. TRACE 1.2.0 (deferred)
  will add the L3-prompt-driven extraction and bundle assembler
  emission of `x-trace-has-access`. SAGE 0.6.0 is forward-ready:
  trace-sourced bundles will dispatch correctly when 1.2.0 lands.
- No existing schema is modified — `HasAccess` is purely additive,
  so 0.5.x ETL flows continue unaffected.

### Future scope (Phase 2 evaluation gate)

Phase 2 review triggers (per design doc): ≥3 BEACON regen cycles +
≥1 TRACE-sourced HasAccess emission + ≥1 manual analyst override.
Candidate work: PIR-weighted HasAccess propagation, automated
revocation lifecycle from HR feeds, privileged-identity flag,
periodic AccessReview events.

---

## [0.5.3] — 2026-05-10

### Fixed — Identity / ActorTargetsIdentity wiring missed in 0.5.0 (worker + upsert)

End-to-end verification (BEACON 0.10.2 → TRACE 1.0.3 → SAGE 0.5.2)
on the CISA AA22-108a Lazarus advisory revealed that the 0.5.0
release added the `Identity` table, `ActorTargetsIdentity` table,
mapper.map_identity, mapper.map_relationship targets dispatch, and
parser.SUPPORTED_TYPES += "identity" — but **never wired any of
this into etl/worker.py or spanner/upsert.py**. Two distinct gaps:

The bundle contained 22 identity SDOs and 26 `targets` relationships;
ETL silently dropped all of them because:

- `process_bundle` had no `by_type["identity"]` loop and never called
  `map_identity`.
- The relationship dispatch had no `elif table == "ActorTargetsIdentity":`
  branch — `map_relationship` returned the (table, row) tuple, the
  worker matched none of its branches, and the row was discarded.

The unit tests covered `map_identity` and `map_relationship` in
isolation, but no test exercised the worker's full dispatch table —
which is why the gap survived 0.5.0 release.

#### Wiring added — `etl/worker.py`

```python
# After Vulnerability upsert:
identity_rows = [
    r for obj in by_type["identity"] if (r := self._mapper.map_identity(obj))
]
stats["identities"] = upsert_rows(self._db, "Identity", identity_rows)

# In the relationship dispatch loop:
elif table == "ActorTargetsIdentity":
    actor_targets_identity_rows.append(row)

# After the relationship loop:
stats["actor_targets_identity"] = upsert_rows(
    self._db, "ActorTargetsIdentity", actor_targets_identity_rows
)
```

#### Column registration added — `spanner/upsert.py::_TABLE_COLUMNS`

The first re-run after the worker fix surfaced a second gap:
`upsert_rows("Identity", ...)` raised `KeyError: 'Identity'` because
the column-name list was never registered. Same root cause — schema
DDL added in 0.5.0 with no callsite update. Both `Identity` and
`ActorTargetsIdentity` entries added with column ordering aligned to
`schema/spanner_ddl.sql` (Spanner mutations are positional).

### Fixed — PIR-filtered actors no longer leave dangling FK edges

The second re-run with full Identity wiring revealed a structural
problem: PIR-filtered actors were dropped from the `ThreatActor`
table but their dependent edges (`Uses`, `UsesTool`,
`IndicatesActor`, `ActorTargetsIdentity`) were still written —
producing dangling foreign key references in the graph. The CISA
AA22-108a Lazarus advisory (financial-crime PIR mismatch) wrote
47 such dangling edges.

`worker.process_bundle` now computes
`kept_actor_ids = {r["stix_id"] for r in actor_rows}` after the
PIR filter and discards relationship rows whose `actor_stix_id`
falls outside that set. The drop is logged at INFO with
`edges_dropped_pir_filtered_actor` and a count.

Tables affected (filter applied):

- `Uses` — actor_stix_id is the source
- `UsesTool` — actor_stix_id is the source
- `IndicatesActor` — actor_stix_id is the target
- `ActorTargetsIdentity` — actor_stix_id is the source

Tables not affected (no actor reference):

- `MalwareUsesTTP`, `Exploits`, `IndicatesTTP`, `IncidentUsesTTP`
- `Targets`, `TargetsAsset` — already filtered at the
  PIR-tag-matching stage

Spanner does not enforce FK constraints on these tables (they share
no parent/child relationship), so the issue would have manifested
only as silent graph traversal dead-ends. Future
`MERGE` / `Spanner Graph` queries from Identity nodes would have
returned partial results.

`stats` now exposes two additional keys: `identities` and
`actor_targets_identity`. Existing dashboards / log consumers that
iterate `stats.items()` will see them automatically.

### Tests — `tests/test_worker.py` (new, 11 cases)

Filed in response to the 0.5.0 → 0.5.3 incident. The worker had no
dedicated test file; mapper-level unit tests covered isolated
methods but never the by_type loop or relationship dispatch. Three
test classes:

- `TestIdentityDispatch` (3) — single / multiple Identity objects
  upserted; non-identity objects don't pollute the Identity table.
- `TestActorTargetsIdentityDispatch` (2) — actor → identity edge
  reaches the table; non-identity targets dropped at mapper level
  before ever reaching dispatch.
- `TestPirFilterReferentialIntegrity` (5) — Lazarus + financial-
  crime PIR scenario reproducing the dangling-FK bug. Filtered
  actor's Uses / UsesTool / ActorTargetsIdentity edges drop;
  Identity nodes stay (not actor-dependent); kept actors keep
  their dependent edges.
- `TestRelationshipDispatchCompleteness` (1) — invariant guard:
  every mapper relationship table has a worker stats key. New
  mapper tables added without a worker branch will fail this test
  immediately, preventing a repeat of the 0.5.0 wiring miss.

Spanner is fully mocked via `_mock_db()` which records every
`batch.insert_or_update(...)` call so tests can assert on table
names and row counts without a live emulator.

All 165 tests pass; 0 vulnerabilities.

## [0.5.2] — 2026-05-10

### Fixed — Vulnerability ETL halted on non-CVE `name` (defensive guard)

End-to-end verification (BEACON 0.10.2 → TRACE 1.0.2 → SAGE 0.5.1)
on the CISA AA22-108a Lazarus advisory aborted ETL with
`Vulnerability.cve_id` exceeding the STRING(32) limit. The bundle
contained a vulnerability with
``name = "Common Vulnerabilities and Exposures (CVEs)"`` (43 chars)
that the L3 LLM had hallucinated from a generic prose mention.

TRACE 1.0.3 now drops these at the bundle assembly stage, but SAGE
must remain robust against other STIX sources (OpenCTI, Security
Hub, manual input) and against TRACE bundles that pre-date 1.0.3.

#### `_extract_cve_id` resolution order

`mapper.map_vulnerability` now resolves the CVE id via:

1. ``external_references[*]`` with ``source_name == "cve"``
   (case-insensitive). ``external_id`` is checked first; ``url`` is
   regex-scanned for a ``CVE-YYYY-NNNN`` token if needed.
2. Falls back to ``obj["name"]`` when it parses as a CVE id.

Vulnerabilities yielding no CVE id return ``None`` from
`map_vulnerability` and are dropped by the worker with a
`vulnerability_skipped_no_cve` structured-log warning. The Spanner
schema is unchanged; the column constraint now never reaches commit
on malformed data.

CVE format: ``^CVE-\d{4}-\d{4,}$`` (matches TRACE's regex). High-
volume years exceed 6 digits, so no upper bound on the trailing
block.

### Tests

5 new cases in `tests/test_mapper.py::TestMapVulnerability`:

- skips vulnerability without parseable CVE
- extracts CVE from `external_references[*].external_id`
- extracts CVE from `external_references[*].url` (NVD-style)
- skips when only unrelated external_references exist (e.g.
  ``mitre-attack`` source)
- canonical CVE id in `name` passes through unchanged

All 154 tests pass; 0 vulnerabilities.

## [0.5.1] — 2026-05-10

### Fixed — Documentation alignment with current schema

Several documents drifted from the implemented schema between
`0.4.x` and `0.5.0`. This release contains documentation-only fixes
(no code or schema changes).

#### CHANGELOG: `0.5.0` duplicate disambiguated

The CHANGELOG previously contained two `[0.5.0]` entries — one dated
`2026-04-15` (PIR-as-first-class-node + TargetsAsset) and one dated
`2026-05-09` (Identity SDO + ActorTargetsIdentity, the formally
tagged `v0.5.0` release). The 04-15 entry was renumbered to
`[0.4.1] - 2026-04-15` because that work was committed but never
tagged as a separate release; the formally tagged `v0.5.0` covers
the Identity SDO addition. SemVer caveat noted in the entry: new
tables would normally warrant a minor bump, but the patch number is
used here only because it is retroactive documentation of unreleased
internal changes.

#### `high-level-design.md` (local-only, gitignored): brought up to date

Added missing entries for tables that have shipped but were not
reflected in the design doc: `Identity`, `PIR`, `TargetsAsset`,
`ActorTargetsIdentity`, `PirPrioritizesActor`, `PirPrioritizesTTP`,
`PirWeightsAsset`. Updated the `CREATE PROPERTY GRAPH` block. Local
to maintainer; the doc is gitignored.

#### `README.md` / `README.ja.md`

- Architecture diagram now shows TRACE as a STIX bundle source and
  BEACON → TRACE → SAGE validation flow for `assets.json` /
  `pir_output.json`.
- Multi-source ingestion list adds TRACE.
- "PIR cascade will be materialized... see phase 2 roadmap" replaced
  with the actual `PIR` / `PirPrioritizes*` / `PirWeightsAsset` edge
  inventory (already shipped in `0.4.1`, generalized in `0.5.0`).
- New "Identity targeting" feature line covering `Identity` SDO and
  `ActorTargetsIdentity` (paired with TRACE 1.0.0+).

#### `docs/data-model.md` / `data-model.ja.md`

- Added `Identity` to the Nodes table with the `deleted_at` rationale.
- Added `TargetsAsset` (TTP → Asset) and `ActorTargetsIdentity`
  (ThreatActor → Identity) to the Edges table.

#### `docs/setup.md` / `setup.ja.md`

- Step 5 (load assets) now points at `TRACE/cmd/validate_assets.py`
  before `cmd/load_assets.py`.
- Step 6 (PIR file) calls out `TRACE/cmd/validate_pir.py --pir … --assets …`.
- Step 7 (ETL) explains TRACE-emitted bundle envelopes carry
  `x_trace_*` metadata which the SAGE parser ignores
  (forward-compatible).

### Tests

No code changes; existing test suite unchanged.

## [0.5.0] — 2026-05-09

### Added — Identity SDO support (paired with TRACE 1.0.0)

`identity` (STIX 2.1 §4.4) now produces a first-class graph node, and
the `targets` relationship from threat-actor / intrusion-set sources
now produces an `ActorTargetsIdentity` edge. This closes the
credential / org-targeting blind spot that Verizon DBIR 2025
(stolen-credentials = #1 initial-access vector at 22%) and CrowdStrike
GTR 2025 (valid-account abuse = #1 cloud vector at 35%) made
unavoidable.

#### `Identity` node

```sql
CREATE TABLE Identity (
  stix_id          STRING(128) NOT NULL,
  name             STRING(256) NOT NULL,
  identity_class   STRING(32),                  -- STIX identity-class-ov
  sectors          ARRAY<STRING(64)>,
  description      STRING(MAX),
  contact_information STRING(MAX),
  roles            ARRAY<STRING(64)>,
  deleted_at       TIMESTAMP,                   -- soft-delete (NULL = active)
  stix_modified    TIMESTAMP NOT NULL,
) PRIMARY KEY (stix_id);
```

`deleted_at` is a SAGE-internal soft-delete marker (NULL = active).
Distinct from STIX `revoked` because identities can leave an
organisation (HR action) without the upstream STIX object being
revoked. Set by SAGE-side workflows, not by parser.

#### `ActorTargetsIdentity` edge

```sql
CREATE TABLE ActorTargetsIdentity (
  actor_stix_id    STRING(128) NOT NULL,
  identity_stix_id STRING(128) NOT NULL,
  confidence       INT64,
  description      STRING(MAX),
  first_observed   TIMESTAMP,
  stix_id          STRING(128),
) PRIMARY KEY (actor_stix_id, identity_stix_id);
```

Restricted to `threat-actor` / `intrusion-set` source per STIX 2.1
§4.13's suggested subset. Other sources (`malware`, `tool`, etc.)
return `None` from `map_relationship` and are dropped with a
structured-log warning at the caller.

#### `parser.SUPPORTED_TYPES` += `identity`

Bundles emitted by TRACE 1.0.0 carry `identity` SDOs; the SAGE parser
now ingests them.

#### Property graph (commented Enterprise block)

`Identity` added to `NODE TABLES`; `ActorTargetsIdentity` added to
`EDGE TABLES` (source: `ThreatActor.stix_id`, destination:
`Identity.stix_id`).

### Tests

- 7 new cases in `tests/test_mapper.py`:
  - 3 in `TestMapIdentity` — minimal identity, full identity with all
    optional fields, non-identity type returning None.
  - 4 in `TestMapTargetsRelationship` — actor source → emit edge,
    intrusion-set source → also emit edge, malware source → drop,
    actor → vulnerability target (out-of-scope for 1.0.0) → drop.

### Future scope

- `HasAccess` edge (Identity → Asset) deferred to 0.6.0+ — requires
  BEACON-side identity-asset metadata which is not yet emitted.
- `user-account` SCO support (via observed-data SDO or indicator
  patterns) deferred to 0.6.0+ — covers credential-level granularity
  beyond the per-person Identity node.
- Other `targets` source types (attack-pattern → identity, malware
  → identity) deferred — empirical demand not yet confirmed.

### Security

- Pinned `pip>=26.1` in dev extras to address CVE-2026-6357 in the transitive
  `pip-api` → `pip` chain pulled by `pip-audit`. CVE-2026-3219 (also in `pip`)
  has no fix release as of this version; tracked upstream.

### Changed

**PIR tag vocabulary — follow-up for BEACON 0.8**
- `docs/data-model.md` — "Available threat_actor_tags" table rewritten to
  match BEACON's MITRE+MISP-derived vocabulary: nation-state as
  `apt-<country-slug>` (MISP `cfr-suspected-state-sponsor`), non-state
  motivation as `espionage` / `financial-crime` / `sabotage` / `subversion`
  (MISP `cfr-type-of-incident`), plus `cybercriminal`. Removed vocabulary
  listed for back-reference.
- `docs/data-model.md` / `docs/data-model.ja.md`, `high-level-design.md`,
  `schema/spanner_ddl.sql`, `src/sage/pir/filter.py` — example PIR tags
  and the ThreatActor.tags column comment updated from legacy values
  (`ransomware`, `financially-motivated`, `targets-japan`) to the new
  vocabulary.
- `src/sage/pir/filter.py` logic is unchanged: tag matching is pure set
  intersection, so existing PIRs in `input/pir_output.json` (legacy tags)
  continue to load and match against `ThreatActor.labels` as before.
  Fixtures and unit tests still exercise the legacy vocabulary to verify
  vocabulary-agnostic behavior.

### Added

**TTP → Asset derived edges (`TargetsAsset`)**
- `schema/spanner_ddl.sql` — New `TargetsAsset` edge table (ttp_stix_id,
  asset_id, match_reason).
- `src/sage/analysis/ttp_asset_matcher.py` — ATT&CK technique-ID prefix →
  asset-tag mapping. Replaces the earlier requirement that assets
  declare CVEs to link TTPs; now TTPs link to assets via stable tag
  signals (`identity`, `database`, `external-facing`, `ot`, etc.).
- `src/sage/etl/worker.py` — ETL emits TargetsAsset edges after
  loading TTP and Asset rows.
- `cmd/visualize_combined.py`, `cmd/visualize_graph.py` — Render
  TargetsAsset edges so TTP → Asset exposure is visible without a
  populated CVE inventory.
- `tests/test_ttp_asset_matcher.py` — Unit tests for the matcher.

### Fixed

- `src/sage/spanner/query.py` — `load_pir_edges()` now uses
  `multi_use=True` on the snapshot so its three SELECT queries share a
  single snapshot. Previously raised `Cannot re-use single-use snapshot`,
  causing visualizers to silently skip PIR node rendering.

## [0.4.1] - 2026-04-15

> **Note:** Originally drafted as a duplicate `0.5.0` entry. Renumbered
> to `0.4.1` because this work was committed but never tagged as a
> separate release; the formally tagged `v0.5.0` (2026-05-09) covers
> the Identity SDO addition. Per SemVer the new tables would warrant a
> minor bump; the patch number is used here only because it is
> retroactive documentation of unreleased internal changes between
> `v0.4.0` (2026-04-04) and `v0.5.0` (2026-05-09).

### Added

**PIR as first-class graph node**
- `schema/spanner_ddl.sql` — New tables: `PIR`, `PirPrioritizesActor` (TAP),
  `PirPrioritizesTTP` (PTTP, derived transitively via Uses), `PirWeightsAsset`
  (asset weight rule match)
- `src/sage/pir/filter.py` — Added `build_pir_nodes()`,
  `build_pir_actor_edges()`, `build_pir_ttp_edges()`,
  `build_pir_asset_edges()` row builders implementing the Strategic →
  Operational → Tactical cascade
- `src/sage/etl/worker.py` — Upserts PIR node + cascade edges after actor /
  TTP / asset loading; emits `pirs`, `pir_prioritizes_actor`,
  `pir_prioritizes_ttp`, `pir_weights_asset` counters
- `src/sage/spanner/query.py` — Added `load_pirs()` and `load_pir_edges()`
  helpers for visualizers and analysis tooling
- `tests/test_pir_filter.py` — 8 new tests covering the four row builders

PIR JSON consumers should now provide narrow, per-decision-point PIRs (≤5
per run) as produced by BEACON's clusterer; legacy single-PIR JSON still
loads unchanged.

---

## [0.4.0] - 2026-04-04

### Added

**Analysis API (FastAPI)**
- `src/sage/api/app.py` — FastAPI application serving all analysis endpoints on Cloud Run
- `cmd/analysis_api.py` — uvicorn entry point (`--host`, `--port`, `--reload`)
- Endpoints: `GET /attack-paths`, `GET /choke-points`, `GET /actor-ttps`, `GET /asset-exposure`, `GET /similar-incidents`, `POST /caldera/adversary`
- Validation via FastAPI `Query` parameters (range checks, required fields)

**IR Incident Similarity (P4-3a)**
- `src/sage/analysis/similarity.py` — Hybrid similarity engine
  - `jaccard_ttp`: TTP set Jaccard similarity
  - `transition_coverage`: BFS reachability on FollowedBy graph (max 2 hops) — handles missing intermediate TTPs
  - `hybrid_score = 0.5 × jaccard_ttp + 0.5 × transition_coverage` (α configurable)
  - `find_similar_incidents()`: loads FollowedBy graph into memory, ranks all candidate incidents
- `src/sage/spanner/query.py` — Added `find_incident_ttps()`, `find_followedby_edges()`, `find_all_incident_ttps()`

**Caldera Integration (P4-2)**
- `src/sage/caldera/client.py` — MITRE Caldera REST API client (`CALDERA_URL`, `CALDERA_API_KEY`)
  - `get_adversaries()`, `create_adversary()`, `update_adversary()`, `sync_actor_ttps()`
  - Upsert semantics: updates existing profile by name, creates new if absent
- `cmd/sync_caldera.py` — CLI to sync actor TTPs to Caldera adversary profiles (`--actor-id`, `--list-adversaries`)

**IR Template (P4-3b)**
- `cmd/create_ir_template.py` — Creates structured GHE Issue from IR incident metadata
  - `--dry-run` for local preview; fetches similar incidents from `SAGE_API_URL` when set
  - Template includes: summary table, timeline, affected assets, TTPs, similar incidents section

**Configuration**
- `src/sage/config.py` — Added `caldera_url`, `caldera_api_key` (env: `CALDERA_URL`, `CALDERA_API_KEY`)
- `pyproject.toml` — Added `fastapi>=0.115.0`, `uvicorn>=0.30.0`; dev: `httpx>=0.27.0`

**Tests**
- `tests/test_api.py` — 14 tests (TestClient for all endpoints, validation, error handling)
- `tests/test_similarity.py` — 25 tests (graph build, BFS, Jaccard, transition coverage, hybrid score, Spanner mock)
- `tests/test_caldera.py` — 10 tests (get/create/update/sync with mocked requests)

---

## [0.3.0] - 2026-04-03

### Added

**Attack Flow Visualization**
- `cmd/visualize_attack_flow.py` — Interactive HTML visualization of FollowedBy-weighted Attack Flow
  - Edge width and color gradient (red → yellow → green) encode `weight`
  - `source` field controls line style: `threat_intel` = solid, `ir_feedback`/`manual_analysis` = dashed
  - `--actor-id` filter, `--limit`, `--no-open`, `--output` options
  - Legend HTML injected into output file

**Slack Notifications**
- `src/sage/notify/slack.py` — ETL completion notifications via Slack Incoming Webhook
  - Detects ≥10% change in choke scores between runs
  - Block Kit message with stats and top choke point changes
- `cmd/run_etl.py` — Captures pre/post choke rows; calls `notify_etl_complete()` when `SLACK_WEBHOOK_URL` is set
- `src/sage/config.py` — Added `slack_webhook_url` (env: `SLACK_WEBHOOK_URL`)

**GitHub Enterprise Integration**
- `src/sage/notify/github.py` — GHE Issue creation/update via GitHub REST API
  - Finds existing open Issue by `sage-report` label within same ISO week; PATCHes if found, POSTs if not
  - `_ensure_label()` creates the `sage-report` label if absent
- `cmd/report_choke_points.py` — Added `--ghe` flag to post choke point report as GHE Issue

**Configuration**
- `src/sage/config.py` — Added `ghe_token`, `ghe_repo` (env: `GHE_TOKEN`, `GHE_REPO`)
- `pyproject.toml` — Added `requests>=2.32.0`

**Tests**
- `tests/test_notify.py` — 9 tests (Slack change detection, post logic; GHE create/update)

---

## [0.2.0] - 2026-04-02

### Added

**PIR-Adjusted Asset Criticality**
- `src/sage/pir/filter.py` — `update_asset_criticality()`: applies PIR tag matching and Targets-actor multiplier
  - `pir_adjusted_criticality = base × MAX(multiplier) × targets_multiplier` (1.5× if PIR actor targets the asset)
  - Capped at 10.0
- `src/sage/spanner/upsert.py` — `update_pir_criticality()`: partial `batch.update()` for `pir_adjusted_criticality`; `fetch_asset_rows()`: reads all Asset rows via `KeySet(all_=True)`
- `src/sage/etl/worker.py` — Calls `update_asset_criticality()` then `update_pir_criticality()` after Targets generation

**Spanner Query Module**
- `src/sage/spanner/query.py` — Analysis queries:
  - `find_attack_paths(asset_id, limit)`: SQL JOIN ThreatActor → Targets → Asset + Uses → TTP
  - `find_actor_ttps(actor_stix_id)`: SQL JOIN actor → Uses → TTP → FollowedBy → TTP
  - `find_choke_points(top_n)`: SQL ranking by `pir_adjusted_criticality × actor_count`
  - `find_asset_exposure()`: SQL for internet-exposed assets with reachable TTP count

**CLI Reports**
- `cmd/report_choke_points.py` — Markdown choke point report (`--top N`, `--output FILE`)
- `cmd/query_attack_paths.py` — Attack path query by `--asset-id` or `--actor-id`
- `cmd/load_assets.py` — Loads internal asset + Targets data into Spanner
- `cmd/visualize_graph.py` — Generates Attack Graph HTML using pyvis

**Schema Fix**
- `schema/spanner_ddl.sql` — `Targets.stix_id` → `Targets.source STRING(32)` (values: `pir_auto`, `manual`, `stix`)
- `schema/spanner_ddl.sql` — Moved `MalwareUsesTTP` from Attack Graph section to Attack Flow section

**Tests**
- `tests/test_pir_filter.py` — Added `TestUpdateAssetCriticality` (6 tests), `TestBuildTargets`
- `tests/test_spanner_query.py` — 10 tests (MagicMock for Spanner snapshot)
- `tests/test_mapper.py` — Added `TestMapIncidentTTPEdges` (5 tests); extended fixture `sample_bundle_inc.json`

---

## [0.1.0] - 2026-04-02

### Added

**ETL Pipeline**
- `etl/worker.py` — Cloud Run ETL worker: STIX object ingestion from GCS landing zone, PIR filtering, FollowedBy weight calculation, Spanner Graph upsert
- `stix/parser.py` — STIX 2.1 JSON parser supporting all node types (ThreatActor, TTP, Vulnerability, MalwareTool, Observable, Incident)
- `stix/mapper.py` — STIX object → Spanner Graph schema mapper (nodes and edges)
- `pir/filter.py` — PIR-based relevance filtering and `pir_adjusted_criticality` calculation for assets

**Spanner Graph**
- `spanner/client.py` — Google Cloud Spanner client with connection management
- `spanner/upsert.py` — Upsert logic for all node and edge tables
- `schema/` — DDL definitions for all Spanner tables and `ThreatIntelGraph` property graph

**OpenCTI Integration**
- `opencti/client.py` — OpenCTI REST API polling client (STIX 2.1 bundle export)

**Commands**
- `cmd/init_schema.py` — Initialize Spanner schema (DDL execution)
- `cmd/run_etl.py` — Manual ETL trigger

**Configuration**
- `config.py` — Environment-based configuration (GCP project, Spanner instance/database, GCS buckets, OpenCTI endpoint)
- `pyproject.toml` — Project metadata, dependencies, ruff and pytest configuration

**Infrastructure**
- `Dockerfile` — Cloud Run container image for ETL worker
- `Makefile` — `check` (vet → lint → test), `format`, `audit`, `init-schema`, `run-etl`

**Tests**
- `tests/test_mapper.py` — Unit tests for STIX → Spanner schema mapping
- `tests/test_pir_filter.py` — Unit tests for PIR filtering and asset criticality adjustment
- `tests/fixtures/` — Test fixture data (STIX bundles, PIR JSON)

[0.5.0]: https://github.com/your-org/sage/releases/tag/v0.5.0
[0.4.0]: https://github.com/your-org/sage/releases/tag/v0.4.0
[0.3.0]: https://github.com/your-org/sage/releases/tag/v0.3.0
[0.2.0]: https://github.com/your-org/sage/releases/tag/v0.2.0
[0.1.0]: https://github.com/your-org/sage/releases/tag/v0.1.0
