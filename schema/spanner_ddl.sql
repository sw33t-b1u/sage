-- =============================================================================
-- Threat Intelligence System — Spanner Graph DDL
-- =============================================================================
-- 外部STIXエンティティ: stix_id を PRIMARY KEY として使用（upsert による冪等性）
-- 内部データ（Asset 等）: UUID を PRIMARY KEY として使用
-- =============================================================================

-- -----------------------------------------------------------------------------
-- NODE TABLES — 外部データ (STIX由来)
-- -----------------------------------------------------------------------------

CREATE TABLE ThreatActor (
  stix_id        STRING(128) NOT NULL,
  stix_type      STRING(32) NOT NULL,   -- "threat-actor" | "intrusion-set"
  name           STRING(256) NOT NULL,
  aliases        ARRAY<STRING(256)>,
  sophistication STRING(64),            -- minimal/intermediate/advanced/expert
  motivation     STRING(64),            -- financial/espionage/hacktivism 等
  tags           ARRAY<STRING(128)>,    -- STIX labels ("apt-china","espionage" 等、PIR 紐付け用)
  first_seen     TIMESTAMP,
  last_seen      TIMESTAMP,
  stix_modified  TIMESTAMP NOT NULL,
) PRIMARY KEY (stix_id);

CREATE TABLE TTP (
  stix_id              STRING(128) NOT NULL,
  attack_technique_id  STRING(16),      -- T1059.001 等
  tactic               STRING(64),      -- initial-access/execution/persistence 等
  name                 STRING(256) NOT NULL,
  description          STRING(MAX),
  platforms            ARRAY<STRING(64)>,  -- windows/linux/cloud 等
  detection_difficulty INT64,           -- Summiting the Pyramid レベル (1-5)
  stix_modified        TIMESTAMP NOT NULL,
) PRIMARY KEY (stix_id);

CREATE TABLE Vulnerability (
  stix_id            STRING(128) NOT NULL,
  cve_id             STRING(32),        -- CVE-2025-55182 等
  description        STRING(MAX),
  cvss_score         FLOAT64,
  epss_score         FLOAT64,           -- 悪用確率 (0.0-1.0)
  affected_platforms ARRAY<STRING(64)>,
  published_date     TIMESTAMP,
  stix_modified      TIMESTAMP NOT NULL,
) PRIMARY KEY (stix_id);

CREATE TABLE MalwareTool (
  stix_id       STRING(128) NOT NULL,
  stix_type     STRING(16) NOT NULL,    -- "malware" | "tool"
  name          STRING(256) NOT NULL,
  description   STRING(MAX),
  capabilities  ARRAY<STRING(128)>,
  stix_modified TIMESTAMP NOT NULL,
) PRIMARY KEY (stix_id);

CREATE TABLE Observable (
  stix_id       STRING(128) NOT NULL,
  obs_type      STRING(32) NOT NULL,    -- ip/domain/hash/email/url
  value         STRING(512) NOT NULL,
  confidence    INT64,                  -- 0-100
  tlp           STRING(16),            -- white/green/amber/red
  first_seen    TIMESTAMP,
  last_seen     TIMESTAMP,
  stix_modified TIMESTAMP NOT NULL,
) PRIMARY KEY (stix_id);

CREATE TABLE Incident (
  stix_id           STRING(128) NOT NULL,
  name              STRING(256) NOT NULL,
  description       STRING(MAX),
  occurred_at       TIMESTAMP,
  resolved_at       TIMESTAMP,
  severity          STRING(16),         -- low/medium/high/critical
  kill_chain_phases ARRAY<STRING(64)>,
  diamond_model     JSON,               -- adversary/capability/infrastructure/victim
  source            STRING(32) NOT NULL DEFAULT ('ir_feedback'),
  stix_modified     TIMESTAMP NOT NULL,
) PRIMARY KEY (stix_id);

-- Identity (SAGE 0.5.0) — STIX 2.1 §4.4 identity SDO. Represents
-- individuals / groups / systems / organizations targeted by threat
-- actors. Added in lockstep with TRACE 1.0.0, which emits identity
-- objects from CTI reports and `targets` relationships actor → identity.
--
-- `deleted_at` is a SAGE-internal soft-delete marker (NULL = active).
-- Distinct from STIX `revoked` because identities can leave an org
-- (HR action) without the STIX object being revoked at upstream.
CREATE TABLE Identity (
  stix_id          STRING(128) NOT NULL,
  name             STRING(256) NOT NULL,
  identity_class   STRING(32),                  -- individual | group | system | organization | class | unspecified
  sectors          ARRAY<STRING(64)>,           -- finance / healthcare / energy ...
  description      STRING(MAX),
  contact_information STRING(MAX),
  roles            ARRAY<STRING(64)>,
  deleted_at       TIMESTAMP,                   -- soft-delete (NULL = active)
  stix_modified    TIMESTAMP NOT NULL,
) PRIMARY KEY (stix_id);

-- -----------------------------------------------------------------------------
-- NODE TABLES — 内部データ (UUID PK)
-- =============================================================================
-- 設計基準: 以下の条件をいずれか満たす概念を Node とする
--   1. 複数エンティティから独立して参照される (例: SecurityControl は複数 Asset が共有)
--   2. グラフ上でパス探索の中継点になる (例: TTP → TTP の FollowedBy)
--   3. 独立したライフサイクルを持ち個別に管理・更新される
-- 上記に当てはまらない属性 (例: ネットワークセグメント情報) は Node にせず
-- 所属エンティティの Property として持つ。
-- =============================================================================

CREATE TABLE SecurityControl (
  id           STRING(36) NOT NULL,
  name         STRING(256) NOT NULL,
  control_type STRING(64),             -- edr/waf/siem/firewall/iam 等
  coverage     ARRAY<STRING(64)>,
) PRIMARY KEY (id);

-- ネットワークセグメント情報は Asset の property として保持する
-- (パス探索の中継点にならないため Node 化しない)
CREATE TABLE Asset (
  id                       STRING(36) NOT NULL,
  name                     STRING(256) NOT NULL,
  asset_type               STRING(64),            -- server/endpoint/saas/storage/network-device
  environment              STRING(32),            -- onprem/aws/gcp
  criticality              FLOAT64 NOT NULL DEFAULT (5.0),
  pir_adjusted_criticality FLOAT64,               -- PIR適用後重要度 (定期更新)
  owner                    STRING(256),
  network_segment          STRING(256),           -- セグメント名 (例: DMZ, Corporate LAN)
  network_cidr             STRING(64),            -- CIDR表記 (例: 10.0.1.0/24)
  network_zone             STRING(32),            -- dmz/internal/cloud-public/ot
  exposed_to_internet      BOOL NOT NULL DEFAULT (FALSE),
  tags                     ARRAY<STRING(128)>,    -- "external-facing","s3","backup" 等
  last_updated             TIMESTAMP NOT NULL OPTIONS (allow_commit_timestamp=true),
) PRIMARY KEY (id);

-- -----------------------------------------------------------------------------
-- EDGE TABLES — Attack Flow (TTP 時系列)
-- -----------------------------------------------------------------------------

-- ThreatActor/MalwareTool → TTP
CREATE TABLE Uses (
  actor_stix_id  STRING(128) NOT NULL,
  ttp_stix_id    STRING(128) NOT NULL,
  confidence     INT64,
  first_observed TIMESTAMP,
  last_observed  TIMESTAMP,
  stix_id        STRING(128),
) PRIMARY KEY (actor_stix_id, ttp_stix_id);

-- TTP → Vulnerability
CREATE TABLE Exploits (
  ttp_stix_id  STRING(128) NOT NULL,
  vuln_stix_id STRING(128) NOT NULL,
  stix_id      STRING(128),
) PRIMARY KEY (ttp_stix_id, vuln_stix_id);

-- TTP → TTP (Attack Flow 遷移・経路重み)
CREATE TABLE FollowedBy (
  src_ttp_stix_id   STRING(128) NOT NULL,
  dst_ttp_stix_id   STRING(128) NOT NULL,
  source            STRING(32) NOT NULL,   -- threat_intel | ir_feedback | manual_analysis
  weight            FLOAT64 NOT NULL DEFAULT (0.0),  -- 遷移確率 (0.0-1.0)
  actor_stix_id     STRING(128),           -- 特定アクターに限定する場合
  evidence_stix_ids ARRAY<STRING(128)>,    -- 根拠となるSTIX ID群
  last_calculated   TIMESTAMP NOT NULL OPTIONS (allow_commit_timestamp=true),
) PRIMARY KEY (src_ttp_stix_id, dst_ttp_stix_id, source);

-- Incident → TTP (IR Analysis → Attack Flow 還元)
CREATE TABLE IncidentUsesTTP (
  incident_stix_id STRING(128) NOT NULL,
  ttp_stix_id      STRING(128) NOT NULL,
  sequence_order   INT64,
) PRIMARY KEY (incident_stix_id, ttp_stix_id);

-- MalwareTool → TTP (STIX: malware/tool --[uses]--> attack-pattern)
CREATE TABLE MalwareUsesTTP (
  malware_stix_id STRING(128) NOT NULL,
  ttp_stix_id     STRING(128) NOT NULL,
  confidence      INT64,
  first_observed  TIMESTAMP,
  last_observed   TIMESTAMP,
  stix_id         STRING(128),
) PRIMARY KEY (malware_stix_id, ttp_stix_id);

-- -----------------------------------------------------------------------------
-- EDGE TABLES — Attack Graph (資産間接続性)
-- -----------------------------------------------------------------------------

-- ThreatActor → MalwareTool
CREATE TABLE UsesTool (
  actor_stix_id    STRING(128) NOT NULL,
  tool_stix_id     STRING(128) NOT NULL,
  confidence       INT64,
  first_observed   TIMESTAMP,
  last_observed    TIMESTAMP,
  stix_id          STRING(128),
) PRIMARY KEY (actor_stix_id, tool_stix_id);

-- ThreatActor → Asset (Attack Graph との結合点)
CREATE TABLE Targets (
  actor_stix_id STRING(128) NOT NULL,
  asset_id      STRING(36) NOT NULL,
  confidence    INT64,
  source        STRING(32),              -- pir_auto | manual | stix
) PRIMARY KEY (actor_stix_id, asset_id);

-- TTP → Asset (derived from ATT&CK technique-ID → asset-tag matching;
-- see src/sage/analysis/ttp_asset_matcher.py)
CREATE TABLE TargetsAsset (
  ttp_stix_id  STRING(128) NOT NULL,
  asset_id     STRING(36)  NOT NULL,
  match_reason STRING(64),              -- matched tag (e.g. "identity", "database")
) PRIMARY KEY (ttp_stix_id, asset_id);

-- Asset → Vulnerability
CREATE TABLE HasVulnerability (
  asset_id           STRING(36) NOT NULL,
  vuln_stix_id       STRING(128) NOT NULL,
  remediation_status STRING(32) NOT NULL DEFAULT ('open'),  -- open/mitigated/patched
  detected_at        TIMESTAMP,
) PRIMARY KEY (asset_id, vuln_stix_id);

-- Asset ↔ Asset (ネットワーク接続性)
CREATE TABLE ConnectedTo (
  src_asset_id STRING(36) NOT NULL,
  dst_asset_id STRING(36) NOT NULL,
  protocol     STRING(16),
  port         INT64,
  direction    STRING(16) NOT NULL DEFAULT ('bidirectional'),
  allowed      BOOL NOT NULL DEFAULT (TRUE),
) PRIMARY KEY (src_asset_id, dst_asset_id);

-- Asset → SecurityControl
CREATE TABLE ProtectedBy (
  asset_id   STRING(36) NOT NULL,
  control_id STRING(36) NOT NULL,
) PRIMARY KEY (asset_id, control_id);

-- -----------------------------------------------------------------------------
-- EDGE TABLES — Observable (IoC)
-- -----------------------------------------------------------------------------

-- Observable → TTP (IndicatesTTP/IndicatesActor を分割)
CREATE TABLE IndicatesTTP (
  observable_stix_id STRING(128) NOT NULL,
  ttp_stix_id        STRING(128) NOT NULL,
  confidence         INT64,
  stix_id            STRING(128),
) PRIMARY KEY (observable_stix_id, ttp_stix_id);

CREATE TABLE IndicatesActor (
  observable_stix_id STRING(128) NOT NULL,
  actor_stix_id      STRING(128) NOT NULL,
  confidence         INT64,
  stix_id            STRING(128),
) PRIMARY KEY (observable_stix_id, actor_stix_id);

-- ThreatActor / IntrusionSet → Identity (SAGE 0.5.0)
-- Source comes from STIX `targets` relationships emitted by TRACE 1.0.0+
-- when CTI reports describe attribution of attacks against specific
-- people / groups / systems / organizations.
--
-- Restricted to actor-source per STIX 2.1 §4.13 suggested subset
-- (other sources like attack-pattern→identity are dropped at mapping
-- time with a structured-log warning).
-- Identity → Asset (SAGE 0.6.0 / Initiative A)
-- Sources, in upsert precedence order:
--   manual  > beacon > trace
-- - beacon: BEACON's identity_assets.json via cmd/load_identity_assets.py
-- - trace : STIX `x-trace-has-access` from TRACE 1.2.0+ bundles
-- - manual: analyst direct upsert (highest authority)
-- Lower-precedence writes are skipped at upsert time with a structured
-- log entry; analyst overrides survive BEACON regeneration.
CREATE TABLE HasAccess (
  identity_stix_id STRING(128) NOT NULL,
  asset_id         STRING(36)  NOT NULL,
  access_level     STRING(32),                 -- read | write | admin | deny
  role             STRING(256),
  granted_at       TIMESTAMP,
  revoked_at       TIMESTAMP,                  -- soft-delete (NULL=active)
  source           STRING(32) NOT NULL,        -- beacon | trace | manual
  confidence       INT64,                      -- 0-100; trace edges typically <50
  stix_modified    TIMESTAMP NOT NULL,
) PRIMARY KEY (identity_stix_id, asset_id);

CREATE TABLE ActorTargetsIdentity (
  actor_stix_id    STRING(128) NOT NULL,
  identity_stix_id STRING(128) NOT NULL,
  confidence       INT64,
  description      STRING(MAX),
  first_observed   TIMESTAMP,
  stix_id          STRING(128),
) PRIMARY KEY (actor_stix_id, identity_stix_id);

-- -----------------------------------------------------------------------------
-- PIR (Priority Intelligence Requirement) — first-class graph node + edges
-- -----------------------------------------------------------------------------
-- A PIR is the Strategic layer of the intel cascade:
--   PIR → TAP (PirPrioritizesActor)  → PTTP (PirPrioritizesTTP)
-- Edges are derived at ETL time from PIR JSON + loaded actor/uses/asset rows.

CREATE TABLE PIR (
  pir_id               STRING(64) NOT NULL,
  intelligence_level   STRING(16) NOT NULL,         -- strategic | operational | tactical
  organizational_scope STRING(256),
  decision_point       STRING(256),
  description          STRING(MAX) NOT NULL,
  rationale            STRING(MAX),
  recommended_action   STRING(MAX),
  threat_actor_tags    ARRAY<STRING(128)>,
  risk_composite       INT64,
  valid_from           DATE,
  valid_until          DATE,
  last_updated         TIMESTAMP NOT NULL OPTIONS (allow_commit_timestamp=true),
) PRIMARY KEY (pir_id);

-- PIR → ThreatActor (TAP: Threat Actor Prioritization)
CREATE TABLE PirPrioritizesActor (
  pir_id        STRING(64) NOT NULL,
  actor_stix_id STRING(128) NOT NULL,
  overlap_ratio FLOAT64,                -- |PIR.tags ∩ actor.tags| / |PIR.tags|
) PRIMARY KEY (pir_id, actor_stix_id);

-- PIR → TTP (PTTP: Priority TTPs; derived transitively via Uses from prioritized actors)
CREATE TABLE PirPrioritizesTTP (
  pir_id      STRING(64) NOT NULL,
  ttp_stix_id STRING(128) NOT NULL,
) PRIMARY KEY (pir_id, ttp_stix_id);

-- PIR → Asset (weight rule match)
CREATE TABLE PirWeightsAsset (
  pir_id                 STRING(64) NOT NULL,
  asset_id               STRING(36) NOT NULL,
  matched_tag            STRING(128),
  criticality_multiplier FLOAT64,
) PRIMARY KEY (pir_id, asset_id);

-- =============================================================================
-- PROPERTY GRAPH (optional — requires Enterprise edition)
-- =============================================================================
-- The CREATE PROPERTY GRAPH statement below is commented out because it
-- requires Spanner Enterprise edition.  All SAGE queries use standard SQL
-- JOINs on the node/edge tables above, so the graph declaration is not
-- required for the system to function.
--
-- To enable GQL support on Enterprise, uncomment the block below and run
-- init_schema again (the existing tables will be skipped; only the graph
-- declaration will be applied).
--
-- CREATE PROPERTY GRAPH ThreatIntelGraph
--   NODE TABLES (
--     ThreatActor     KEY (stix_id)  LABEL ThreatActor     PROPERTIES ALL COLUMNS,
--     TTP             KEY (stix_id)  LABEL TTP             PROPERTIES ALL COLUMNS,
--     Vulnerability   KEY (stix_id)  LABEL Vulnerability   PROPERTIES ALL COLUMNS,
--     MalwareTool     KEY (stix_id)  LABEL MalwareTool     PROPERTIES ALL COLUMNS,
--     Observable      KEY (stix_id)  LABEL Observable      PROPERTIES ALL COLUMNS,
--     Incident        KEY (stix_id)  LABEL Incident        PROPERTIES ALL COLUMNS,
--     Identity        KEY (stix_id)  LABEL Identity        PROPERTIES ALL COLUMNS,
--     Asset           KEY (id)       LABEL Asset           PROPERTIES ALL COLUMNS,
--     SecurityControl KEY (id)       LABEL SecurityControl PROPERTIES ALL COLUMNS
--   )
--   EDGE TABLES (
--     Uses           SOURCE KEY (actor_stix_id)      REFERENCES ThreatActor (stix_id)
--                    DESTINATION KEY (ttp_stix_id)    REFERENCES TTP (stix_id)         LABEL USES PROPERTIES ALL COLUMNS,
--     MalwareUsesTTP SOURCE KEY (malware_stix_id)    REFERENCES MalwareTool (stix_id)
--                    DESTINATION KEY (ttp_stix_id)    REFERENCES TTP (stix_id)         LABEL MALWARE_USES_TTP PROPERTIES ALL COLUMNS,
--     UsesTool       SOURCE KEY (actor_stix_id)      REFERENCES ThreatActor (stix_id)
--                    DESTINATION KEY (tool_stix_id)   REFERENCES MalwareTool (stix_id) LABEL USES_TOOL PROPERTIES ALL COLUMNS,
--     Exploits       SOURCE KEY (ttp_stix_id)        REFERENCES TTP (stix_id)
--                    DESTINATION KEY (vuln_stix_id)   REFERENCES Vulnerability (stix_id) LABEL EXPLOITS PROPERTIES ALL COLUMNS,
--     FollowedBy     SOURCE KEY (src_ttp_stix_id)    REFERENCES TTP (stix_id)
--                    DESTINATION KEY (dst_ttp_stix_id) REFERENCES TTP (stix_id)        LABEL FOLLOWED_BY PROPERTIES ALL COLUMNS,
--     IncidentUsesTTP SOURCE KEY (incident_stix_id)  REFERENCES Incident (stix_id)
--                    DESTINATION KEY (ttp_stix_id)    REFERENCES TTP (stix_id)         LABEL INCIDENT_USES_TTP PROPERTIES ALL COLUMNS,
--     Targets        SOURCE KEY (actor_stix_id)      REFERENCES ThreatActor (stix_id)
--                    DESTINATION KEY (asset_id)       REFERENCES Asset (id)            LABEL TARGETS PROPERTIES ALL COLUMNS,
--     HasVulnerability SOURCE KEY (asset_id)          REFERENCES Asset (id)
--                    DESTINATION KEY (vuln_stix_id)   REFERENCES Vulnerability (stix_id) LABEL HAS_VULNERABILITY PROPERTIES ALL COLUMNS,
--     ConnectedTo    SOURCE KEY (src_asset_id)       REFERENCES Asset (id)
--                    DESTINATION KEY (dst_asset_id)   REFERENCES Asset (id)            LABEL CONNECTED_TO PROPERTIES ALL COLUMNS,
--     ProtectedBy    SOURCE KEY (asset_id)           REFERENCES Asset (id)
--                    DESTINATION KEY (control_id)     REFERENCES SecurityControl (id)  LABEL PROTECTED_BY PROPERTIES ALL COLUMNS,
--     IndicatesTTP   SOURCE KEY (observable_stix_id) REFERENCES Observable (stix_id)
--                    DESTINATION KEY (ttp_stix_id)    REFERENCES TTP (stix_id)         LABEL INDICATES_TTP PROPERTIES ALL COLUMNS,
--     IndicatesActor SOURCE KEY (observable_stix_id) REFERENCES Observable (stix_id)
--                    DESTINATION KEY (actor_stix_id)  REFERENCES ThreatActor (stix_id) LABEL INDICATES_ACTOR PROPERTIES ALL COLUMNS,
--     ActorTargetsIdentity SOURCE KEY (actor_stix_id) REFERENCES ThreatActor (stix_id)
--                    DESTINATION KEY (identity_stix_id) REFERENCES Identity (stix_id)  LABEL ACTOR_TARGETS_IDENTITY PROPERTIES ALL COLUMNS
--   );
