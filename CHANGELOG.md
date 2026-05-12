# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).


## [Unreleased]

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
