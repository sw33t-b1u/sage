-- =============================================================================
-- Threat Intelligence System — SQLite DDL
-- =============================================================================
-- This file is the SQLite-dialect mirror of schema/spanner_ddl.sql.
-- spanner_ddl.sql remains the SOURCE OF TRUTH for column semantics,
-- comments, and design rationale. Consult it for the "why" behind every
-- table and column; this file only restates the "what" in SQLite syntax.
--
-- Conversion rules (Decision D-3 of the SQLite-backend plan):
--   STRING(n) / STRING(MAX)        -> TEXT
--   INT64                          -> INTEGER
--   FLOAT64                        -> REAL
--   BOOL                           -> INTEGER (0 = FALSE, 1 = TRUE)
--   TIMESTAMP / DATE               -> TEXT (ISO 8601, UTC)
--   ARRAY<...>                     -> TEXT (JSON array; default '[]' where
--                                    the Spanner column was non-NULL)
--   JSON                           -> TEXT (raw JSON string)
--   composite PRIMARY KEY          -> preserved as table-level PRIMARY KEY
--   NOT NULL DEFAULT (expr)        -> preserved with SQLite literal syntax
--                                    (TRUE/FALSE -> 1/0)
--   OPTIONS (allow_commit_timestamp=true)
--                                  -> dropped; the upsert layer writes
--                                    datetime.now(UTC).isoformat() explicitly
--   CREATE PROPERTY GRAPH          -> not ported (unused by SAGE code)
--
-- All tables use CREATE TABLE IF NOT EXISTS so init_schema is idempotent.
-- =============================================================================

-- -----------------------------------------------------------------------------
-- NODE TABLES — external data (STIX-derived)
-- -----------------------------------------------------------------------------

CREATE TABLE IF NOT EXISTS ThreatActor (
  stix_id        TEXT NOT NULL,
  stix_type      TEXT NOT NULL,
  name           TEXT NOT NULL,
  aliases        TEXT,
  sophistication TEXT,
  motivation     TEXT,
  tags           TEXT,
  first_seen     TEXT,
  last_seen      TEXT,
  stix_modified  TEXT NOT NULL,
  PRIMARY KEY (stix_id)
);

CREATE TABLE IF NOT EXISTS TTP (
  stix_id              TEXT NOT NULL,
  attack_technique_id  TEXT,
  tactic               TEXT,
  name                 TEXT NOT NULL,
  description          TEXT,
  platforms            TEXT,
  detection_difficulty INTEGER,
  stix_modified        TEXT NOT NULL,
  PRIMARY KEY (stix_id)
);

CREATE TABLE IF NOT EXISTS Vulnerability (
  stix_id            TEXT NOT NULL,
  cve_id             TEXT,
  description        TEXT,
  cvss_score         REAL,
  epss_score         REAL,
  affected_platforms TEXT,
  published_date     TEXT,
  stix_modified      TEXT NOT NULL,
  PRIMARY KEY (stix_id)
);

CREATE TABLE IF NOT EXISTS MalwareTool (
  stix_id       TEXT NOT NULL,
  stix_type     TEXT NOT NULL,
  name          TEXT NOT NULL,
  description   TEXT,
  capabilities  TEXT,
  stix_modified TEXT NOT NULL,
  PRIMARY KEY (stix_id)
);

CREATE TABLE IF NOT EXISTS Observable (
  stix_id       TEXT NOT NULL,
  obs_type      TEXT NOT NULL,
  value         TEXT NOT NULL,
  confidence    INTEGER,
  tlp           TEXT,
  first_seen    TEXT,
  last_seen     TEXT,
  stix_modified TEXT NOT NULL,
  PRIMARY KEY (stix_id)
);

CREATE TABLE IF NOT EXISTS Incident (
  stix_id           TEXT NOT NULL,
  name              TEXT NOT NULL,
  description       TEXT,
  occurred_at       TEXT,
  resolved_at       TEXT,
  severity          TEXT,
  kill_chain_phases TEXT,
  diamond_model     TEXT,
  source            TEXT NOT NULL DEFAULT ('ir_feedback'),
  stix_modified     TEXT NOT NULL,
  PRIMARY KEY (stix_id)
);

CREATE TABLE IF NOT EXISTS Identity (
  stix_id          TEXT NOT NULL,
  name             TEXT NOT NULL,
  identity_class   TEXT,
  sectors          TEXT,
  description      TEXT,
  contact_information TEXT,
  roles            TEXT,
  deleted_at       TEXT,
  stix_modified    TEXT NOT NULL,
  is_high_value_impersonation_target INTEGER NOT NULL DEFAULT (0),
  impersonation_risk_factors TEXT,
  PRIMARY KEY (stix_id)
);

-- -----------------------------------------------------------------------------
-- NODE TABLES — internal data (UUID PK)
-- -----------------------------------------------------------------------------

CREATE TABLE IF NOT EXISTS SecurityControl (
  id           TEXT NOT NULL,
  name         TEXT NOT NULL,
  control_type TEXT,
  coverage     TEXT,
  PRIMARY KEY (id)
);

CREATE TABLE IF NOT EXISTS Asset (
  id                       TEXT NOT NULL,
  name                     TEXT NOT NULL,
  asset_type               TEXT,
  environment              TEXT,
  criticality              REAL NOT NULL DEFAULT (5.0),
  pir_adjusted_criticality REAL,
  owner                    TEXT,
  network_segment          TEXT,
  network_cidr             TEXT,
  network_zone             TEXT,
  exposed_to_internet      INTEGER NOT NULL DEFAULT (0),
  tags                     TEXT,
  last_updated             TEXT NOT NULL,
  PRIMARY KEY (id)
);

-- -----------------------------------------------------------------------------
-- EDGE TABLES — Attack Flow (TTP timeline)
-- -----------------------------------------------------------------------------

CREATE TABLE IF NOT EXISTS Uses (
  actor_stix_id  TEXT NOT NULL,
  ttp_stix_id    TEXT NOT NULL,
  confidence     INTEGER,
  first_observed TEXT,
  last_observed  TEXT,
  stix_id        TEXT,
  PRIMARY KEY (actor_stix_id, ttp_stix_id)
);

CREATE TABLE IF NOT EXISTS Exploits (
  ttp_stix_id  TEXT NOT NULL,
  vuln_stix_id TEXT NOT NULL,
  stix_id      TEXT,
  PRIMARY KEY (ttp_stix_id, vuln_stix_id)
);

CREATE TABLE IF NOT EXISTS FollowedBy (
  src_ttp_stix_id   TEXT NOT NULL,
  dst_ttp_stix_id   TEXT NOT NULL,
  source            TEXT NOT NULL,
  weight            REAL NOT NULL DEFAULT (0.0),
  actor_stix_id     TEXT,
  evidence_stix_ids TEXT,
  last_calculated   TEXT NOT NULL,
  PRIMARY KEY (src_ttp_stix_id, dst_ttp_stix_id, source)
);

CREATE TABLE IF NOT EXISTS IncidentUsesTTP (
  incident_stix_id TEXT NOT NULL,
  ttp_stix_id      TEXT NOT NULL,
  sequence_order   INTEGER,
  PRIMARY KEY (incident_stix_id, ttp_stix_id)
);

CREATE TABLE IF NOT EXISTS MalwareUsesTTP (
  malware_stix_id TEXT NOT NULL,
  ttp_stix_id     TEXT NOT NULL,
  confidence      INTEGER,
  first_observed  TEXT,
  last_observed   TEXT,
  stix_id         TEXT,
  PRIMARY KEY (malware_stix_id, ttp_stix_id)
);

-- -----------------------------------------------------------------------------
-- EDGE TABLES — Attack Graph (asset connectivity)
-- -----------------------------------------------------------------------------

CREATE TABLE IF NOT EXISTS UsesTool (
  actor_stix_id    TEXT NOT NULL,
  tool_stix_id     TEXT NOT NULL,
  confidence       INTEGER,
  first_observed   TEXT,
  last_observed    TEXT,
  stix_id          TEXT,
  PRIMARY KEY (actor_stix_id, tool_stix_id)
);

CREATE TABLE IF NOT EXISTS Targets (
  actor_stix_id TEXT NOT NULL,
  asset_id      TEXT NOT NULL,
  confidence    INTEGER,
  source        TEXT,
  PRIMARY KEY (actor_stix_id, asset_id)
);

CREATE TABLE IF NOT EXISTS TargetsAsset (
  ttp_stix_id  TEXT NOT NULL,
  asset_id     TEXT NOT NULL,
  match_reason TEXT,
  PRIMARY KEY (ttp_stix_id, asset_id)
);

CREATE TABLE IF NOT EXISTS HasVulnerability (
  asset_id           TEXT NOT NULL,
  vuln_stix_id       TEXT NOT NULL,
  remediation_status TEXT NOT NULL DEFAULT ('open'),
  detected_at        TEXT,
  PRIMARY KEY (asset_id, vuln_stix_id)
);

CREATE TABLE IF NOT EXISTS ConnectedTo (
  src_asset_id TEXT NOT NULL,
  dst_asset_id TEXT NOT NULL,
  protocol     TEXT,
  port         INTEGER,
  direction    TEXT NOT NULL DEFAULT ('bidirectional'),
  allowed      INTEGER NOT NULL DEFAULT (1),
  PRIMARY KEY (src_asset_id, dst_asset_id)
);

CREATE TABLE IF NOT EXISTS ProtectedBy (
  asset_id   TEXT NOT NULL,
  control_id TEXT NOT NULL,
  PRIMARY KEY (asset_id, control_id)
);

-- -----------------------------------------------------------------------------
-- EDGE TABLES — Observable (IoC)
-- -----------------------------------------------------------------------------

CREATE TABLE IF NOT EXISTS IndicatesTTP (
  observable_stix_id TEXT NOT NULL,
  ttp_stix_id        TEXT NOT NULL,
  confidence         INTEGER,
  stix_id            TEXT,
  PRIMARY KEY (observable_stix_id, ttp_stix_id)
);

CREATE TABLE IF NOT EXISTS IndicatesActor (
  observable_stix_id TEXT NOT NULL,
  actor_stix_id      TEXT NOT NULL,
  confidence         INTEGER,
  stix_id            TEXT,
  PRIMARY KEY (observable_stix_id, actor_stix_id)
);

CREATE TABLE IF NOT EXISTS HasAccess (
  identity_stix_id TEXT NOT NULL,
  asset_id         TEXT NOT NULL,
  access_level     TEXT,
  role             TEXT,
  granted_at       TEXT,
  revoked_at       TEXT,
  source           TEXT NOT NULL,
  confidence       INTEGER,
  stix_modified    TEXT NOT NULL,
  PRIMARY KEY (identity_stix_id, asset_id)
);

CREATE TABLE IF NOT EXISTS UserAccount (
  stix_id            TEXT NOT NULL,
  account_login      TEXT NOT NULL,
  display_name       TEXT,
  account_type       TEXT,
  is_privileged      INTEGER NOT NULL DEFAULT (0),
  is_service_account INTEGER NOT NULL DEFAULT (0),
  identity_stix_id   TEXT,
  source             TEXT NOT NULL,
  confidence         INTEGER,
  stix_modified      TEXT NOT NULL,
  PRIMARY KEY (stix_id)
);

CREATE TABLE IF NOT EXISTS AccountOnAsset (
  user_account_stix_id TEXT NOT NULL,
  asset_id             TEXT NOT NULL,
  first_seen           TEXT,
  last_seen            TEXT,
  source               TEXT NOT NULL,
  PRIMARY KEY (user_account_stix_id, asset_id)
);

CREATE TABLE IF NOT EXISTS UserAccountBelongsTo (
  identity_stix_id     TEXT NOT NULL,
  user_account_stix_id TEXT NOT NULL,
  source               TEXT NOT NULL,
  PRIMARY KEY (identity_stix_id, user_account_stix_id)
);

CREATE TABLE IF NOT EXISTS ActorTargetsIdentity (
  actor_stix_id    TEXT NOT NULL,
  identity_stix_id TEXT NOT NULL,
  confidence       INTEGER,
  description      TEXT,
  first_observed   TEXT,
  stix_id          TEXT,
  PRIMARY KEY (actor_stix_id, identity_stix_id)
);

-- Attribution & Impersonation edges
CREATE TABLE IF NOT EXISTS AttributedToActor (
  source_stix_id        TEXT NOT NULL,
  target_actor_stix_id  TEXT NOT NULL,
  source_type           TEXT NOT NULL,
  target_type           TEXT NOT NULL,
  confidence            INTEGER,
  description           TEXT,
  first_observed        TEXT,
  stix_id               TEXT,
  source                TEXT NOT NULL DEFAULT ('trace'),
  PRIMARY KEY (source_stix_id, target_actor_stix_id)
);

CREATE TABLE IF NOT EXISTS AttributedToIdentity (
  source_stix_id     TEXT NOT NULL,
  identity_stix_id   TEXT NOT NULL,
  source_type        TEXT NOT NULL,
  confidence         INTEGER,
  description        TEXT,
  first_observed     TEXT,
  stix_id            TEXT,
  source             TEXT NOT NULL DEFAULT ('trace'),
  PRIMARY KEY (source_stix_id, identity_stix_id)
);

CREATE TABLE IF NOT EXISTS ImpersonatesIdentity (
  source_stix_id     TEXT NOT NULL,
  identity_stix_id   TEXT NOT NULL,
  source_type        TEXT NOT NULL,
  confidence         INTEGER,
  description        TEXT,
  first_observed     TEXT,
  stix_id            TEXT,
  effective_priority INTEGER,
  source             TEXT NOT NULL DEFAULT ('trace'),
  PRIMARY KEY (source_stix_id, identity_stix_id)
);

-- -----------------------------------------------------------------------------
-- PIR (Priority Intelligence Requirement) — node + edges
-- -----------------------------------------------------------------------------

CREATE TABLE IF NOT EXISTS PIR (
  pir_id               TEXT NOT NULL,
  intelligence_level   TEXT NOT NULL,
  organizational_scope TEXT,
  decision_point       TEXT,
  description          TEXT NOT NULL,
  rationale            TEXT,
  recommended_action   TEXT,
  threat_actor_tags    TEXT,
  risk_composite       INTEGER,
  valid_from           TEXT,
  valid_until          TEXT,
  last_updated         TEXT NOT NULL,
  PRIMARY KEY (pir_id)
);

CREATE TABLE IF NOT EXISTS PirPrioritizesActor (
  pir_id        TEXT NOT NULL,
  actor_stix_id TEXT NOT NULL,
  overlap_ratio REAL,
  likelihood    REAL,
  rationale_json TEXT,
  PRIMARY KEY (pir_id, actor_stix_id)
);

CREATE TABLE IF NOT EXISTS AnnotatesActor (
  annotator_id    TEXT NOT NULL,
  actor_stix_id   TEXT NOT NULL,
  annotation_type TEXT,
  payload_json    TEXT,
  created_at      TEXT NOT NULL,
  evidence_url    TEXT,
  PRIMARY KEY (annotator_id, actor_stix_id, created_at)
);

CREATE TABLE IF NOT EXISTS PirPrioritizesTTP (
  pir_id      TEXT NOT NULL,
  ttp_stix_id TEXT NOT NULL,
  PRIMARY KEY (pir_id, ttp_stix_id)
);

CREATE TABLE IF NOT EXISTS PirWeightsAsset (
  pir_id                 TEXT NOT NULL,
  asset_id               TEXT NOT NULL,
  matched_tag            TEXT,
  criticality_multiplier REAL,
  PRIMARY KEY (pir_id, asset_id)
);

CREATE TABLE IF NOT EXISTS PirPrioritizesImpersonationTarget (
  pir_id             TEXT NOT NULL,
  identity_stix_id   TEXT NOT NULL,
  source_stix_id     TEXT NOT NULL,
  effective_priority INTEGER NOT NULL,
  derived_at         TEXT NOT NULL,
  PRIMARY KEY (pir_id, identity_stix_id, source_stix_id)
);
