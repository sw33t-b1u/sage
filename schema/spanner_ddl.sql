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
  tags           ARRAY<STRING(128)>,    -- "ransomware","apt","targets-japan" 等 (PIR紐付け用)
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

-- =============================================================================
-- PROPERTY GRAPH 宣言
-- =============================================================================

CREATE PROPERTY GRAPH ThreatIntelGraph
  NODE TABLES (
    ThreatActor     KEY (stix_id)
      LABEL ThreatActor     PROPERTIES ALL COLUMNS,
    TTP             KEY (stix_id)
      LABEL TTP             PROPERTIES ALL COLUMNS,
    Vulnerability   KEY (stix_id)
      LABEL Vulnerability   PROPERTIES ALL COLUMNS,
    MalwareTool     KEY (stix_id)
      LABEL MalwareTool     PROPERTIES ALL COLUMNS,
    Observable      KEY (stix_id)
      LABEL Observable      PROPERTIES ALL COLUMNS,
    Incident        KEY (stix_id)
      LABEL Incident        PROPERTIES ALL COLUMNS,
    Asset           KEY (id)
      LABEL Asset           PROPERTIES ALL COLUMNS,
    SecurityControl KEY (id)
      LABEL SecurityControl PROPERTIES ALL COLUMNS
  )
  EDGE TABLES (
    Uses
      SOURCE KEY (actor_stix_id) REFERENCES ThreatActor (stix_id)
      DESTINATION KEY (ttp_stix_id) REFERENCES TTP (stix_id)
      LABEL USES PROPERTIES ALL COLUMNS,
    MalwareUsesTTP
      SOURCE KEY (malware_stix_id) REFERENCES MalwareTool (stix_id)
      DESTINATION KEY (ttp_stix_id) REFERENCES TTP (stix_id)
      LABEL MALWARE_USES_TTP PROPERTIES ALL COLUMNS,
    UsesTool
      SOURCE KEY (actor_stix_id) REFERENCES ThreatActor (stix_id)
      DESTINATION KEY (tool_stix_id) REFERENCES MalwareTool (stix_id)
      LABEL USES_TOOL PROPERTIES ALL COLUMNS,
    Exploits
      SOURCE KEY (ttp_stix_id) REFERENCES TTP (stix_id)
      DESTINATION KEY (vuln_stix_id) REFERENCES Vulnerability (stix_id)
      LABEL EXPLOITS PROPERTIES ALL COLUMNS,
    FollowedBy
      SOURCE KEY (src_ttp_stix_id) REFERENCES TTP (stix_id)
      DESTINATION KEY (dst_ttp_stix_id) REFERENCES TTP (stix_id)
      LABEL FOLLOWED_BY PROPERTIES ALL COLUMNS,
    IncidentUsesTTP
      SOURCE KEY (incident_stix_id) REFERENCES Incident (stix_id)
      DESTINATION KEY (ttp_stix_id) REFERENCES TTP (stix_id)
      LABEL INCIDENT_USES_TTP PROPERTIES ALL COLUMNS,
    Targets
      SOURCE KEY (actor_stix_id) REFERENCES ThreatActor (stix_id)
      DESTINATION KEY (asset_id) REFERENCES Asset (id)
      LABEL TARGETS PROPERTIES ALL COLUMNS,
    HasVulnerability
      SOURCE KEY (asset_id) REFERENCES Asset (id)
      DESTINATION KEY (vuln_stix_id) REFERENCES Vulnerability (stix_id)
      LABEL HAS_VULNERABILITY PROPERTIES ALL COLUMNS,
    ConnectedTo
      SOURCE KEY (src_asset_id) REFERENCES Asset (id)
      DESTINATION KEY (dst_asset_id) REFERENCES Asset (id)
      LABEL CONNECTED_TO PROPERTIES ALL COLUMNS,
    ProtectedBy
      SOURCE KEY (asset_id) REFERENCES Asset (id)
      DESTINATION KEY (control_id) REFERENCES SecurityControl (id)
      LABEL PROTECTED_BY PROPERTIES ALL COLUMNS,
    IndicatesTTP
      SOURCE KEY (observable_stix_id) REFERENCES Observable (stix_id)
      DESTINATION KEY (ttp_stix_id) REFERENCES TTP (stix_id)
      LABEL INDICATES_TTP PROPERTIES ALL COLUMNS,
    IndicatesActor
      SOURCE KEY (observable_stix_id) REFERENCES Observable (stix_id)
      DESTINATION KEY (actor_stix_id) REFERENCES ThreatActor (stix_id)
      LABEL INDICATES_ACTOR PROPERTIES ALL COLUMNS
  );
