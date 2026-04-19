# SAGE — Security Attack Graph Engine: High-Level Design

## 1. 目的とスコープ

脅威インテリジェンスサイクルを回す基盤システム。外部CTIデータ（STIX 2.1）と内部資産・組織情報を統合し、攻撃経路の可視化・重み付けを行い、Red/Blue/IRの各チームへ実用的なアウトプットを提供する。

**対象外:** リアルタイムSIEM検知、エンドポイント保護、脆弱性スキャン自動化（これらのデータを受け取る側）

---

## 2. システム全体構成

```
┌─────────────────────────────────────────────────────────────────┐
│                        INPUT SYSTEM                             │
│                                                                 │
│  [OpenCTI]──STIX 2.1──┐   [Analyst Input API]                  │
│  [Security Hub]────────┼──→ [GCS: Landing Zone]                 │
│  [Security Cmd Center]─┘        (raw STIX JSON)                 │
│                                                                 │
│  [IR Feedback]─STIX 2.1──────→ [GCS: Landing Zone]             │
│  (OpenCTIへ登録後、定期ポーリングで取り込み)                     │
│                                                                 │
│  [Asset/Network JSON]──────→ [Internal Data API]               │
│  [PIR JSON]────────────────→ [PIR Manager]                      │
└───────────────────────────────────┬─────────────────────────────┘
                                    │
                                    ▼
┌─────────────────────────────────────────────────────────────────┐
│                       ETL PIPELINE (Cloud Run)                  │
│                                                                 │
│   STIX 2.1 → Graph Schema 変換                                  │
│   PIR フィルタリング & 資産重み付け                               │
│   Targets エッジ生成（PIR タグマッチング）                       │
│   FOLLOWED_BY 重み計算（threat_intel + ir_feedback）             │
│   差分更新（手動トリガー時は影響ノードのみ再計算）                │
└───────────────────────────────────┬─────────────────────────────┘
                                    │
                                    ▼
┌─────────────────────────────────────────────────────────────────┐
│                    ANALYSIS SYSTEM (Spanner Graph)              │
│                                                                 │
│        ┌──────────────────┐       ┌─────────────────────┐       │
│        │  Attack Graph    │       │    Attack Flow      │       │
│        │  資産間接続性    │       │    TTP 時系列       │       │
│        │  到達可能経路    │       │    経路重み付け     │       │
│        └────────┬─────────┘       └──────────┬──────────┘       │
│                 └────────────────────────────┘                  │
│            Cross-domain edges (TARGETS, HAS_VULNERABILITY)      │
└───────────────────────────────────┬─────────────────────────────┘
                                    │
                                    ▼
┌─────────────────────────────────────────────────────────────────┐
│                       OUTPUT SYSTEM                             │
│                                                                 │
│  [Analysis API]──→ [GHE] Playbook Issue / Choke Point Report   │
│                 ──→ [Slack] 優先度別アラート通知                 │
│                 ──→ [Caldera] 攻撃シミュレーション Adversary     │
└─────────────────────────────────────────────────────────────────┘
```

---

## 3. Input System

### 3.1 外部データ取り込み

| ソース | 形式 | 取り込み方式 | 頻度 |
|--------|------|------------|------|
| OpenCTI | STIX 2.1 JSON | REST API Polling → GCS | 1日1回（Cloud Scheduler） |
| アナリスト手動入力 | STIX 2.1 JSON | Input API → GCS | 随時（1日4〜5回想定） |
| AWS Security Hub | ASFF → STIX変換 | EventBridge → Cloud Run → GCS | 随時（イベント駆動） |
| GCP Security Command Center | SCC Finding → STIX変換 | Pub/Sub → Cloud Run → GCS | 随時（イベント駆動） |
| IR Feedback | STIX 2.1 JSON (incident) | OpenCTI 登録後、OpenCTI Polling で GCS へ | 1日1回（Cloud Scheduler） |

**IR Feedback フロー:**
IR チームがインシデント対応完了後、OpenCTI へ `incident` オブジェクトを登録する（TTP sequence 付き）。
OpenCTI の通常ポーリングで GCS Landing Zone に取り込まれ、ETL により Incident ノード・IncidentUsesTTP エッジ・FollowedBy(ir_feedback) に変換される。

**GCS Landing Zone 構造:**
```
gs://threat-intel-landing/
  raw/stix/
    {date}/{source}/{uuid}.json   ← 生データ保持（監査用）
  processed/
    {date}/{uuid}.json            ← ETL処理済みSTIX
```

### 3.2 内部データ管理

手動更新（JSON）。更新時は Internal Data API 経由でSpanner Graphへ直接反映。

**PIR JSON スキーマ:**
```json
{
  "pir_id": "PIR-2025-001",
  "description": "ランサムウェアグループへの耐性強化",
  "threat_actor_tags": ["apt-china", "espionage"],
  "asset_weight_rules": [
    { "tag": "external-facing",  "criticality_multiplier": 2.0 },
    { "tag": "s3",               "criticality_multiplier": 1.8 },
    { "tag": "backup",           "criticality_multiplier": 1.5 },
    { "tag": "gcs",              "criticality_multiplier": 1.8 }
  ],
  "valid_from": "2025-01-01",
  "valid_until": "2025-12-31"
}
```

---

## 4. Analysis System — Spanner Graph スキーマ

### 4.0 Node / Property 判断基準

以下の条件をいずれか満たす概念を **Node（独立テーブル）** とする。満たさない場合は所属エンティティの **Property（カラム）** として持つ。

| 条件 | 例 |
|------|----|
| 複数エンティティから独立して参照される | `SecurityControl` は複数の `Asset` が共有 |
| グラフ上でパス探索の中継点になる | `TTP` は `FollowedBy` で TTP→TTP 遷移の中継点 |
| 独立したライフサイクルを持ち個別に管理・更新される | `Incident` は IR チームが随時登録 |

**変更履歴:**
- `NetworkSegment`: 当初 Node として設計したが、パス探索の中継点にならず Asset 以外から参照されないため Property 化。`Asset` に `network_segment`（名称）・`network_cidr`・`network_zone` カラムとして保持。

**現行 Node 一覧と根拠:**

| Node | 根拠 |
|------|------|
| ThreatActor | 独立ライフサイクル; Uses/Targets/IndicatesActor の起点 |
| TTP | FollowedBy で中継点; Uses/Exploits/IncidentUsesTTP で多方向参照 |
| Vulnerability | Asset と TTP の両方から独立参照 (HasVulnerability, Exploits) |
| MalwareTool | Actor・TTP から独立参照 (UsesTool, MalwareUsesTTP) |
| Observable | 独立ライフサイクル（IoC 管理）; IndicatesTTP/IndicatesActor の起点 |
| Incident | IR チームが独立管理; IncidentUsesTTP の起点 |
| Asset | ConnectedTo で中継点; HasVulnerability/ProtectedBy/Targets の終点 |
| SecurityControl | 複数 Asset から共有参照 (ProtectedBy) |

### 4.1 ノード定義

外部 STIX 由来のノードは `stix_id` を PRIMARY KEY とし upsert で冪等性を保つ。
内部データ（Asset, SecurityControl）は UUID を PRIMARY KEY として使用。

```sql
-- 脅威アクター (STIX: threat-actor, intrusion-set)
CREATE TABLE ThreatActor (
  stix_id        STRING(128) NOT NULL,
  stix_type      STRING(32) NOT NULL,   -- "threat-actor" | "intrusion-set"
  name           STRING(256) NOT NULL,
  aliases        ARRAY<STRING(256)>,
  sophistication STRING(64),            -- minimal/intermediate/advanced/expert
  motivation     STRING(64),            -- financial/espionage/hacktivism 等
  tags           ARRAY<STRING(128)>,    -- STIX labels（"apt-china","espionage" 等、PIR 紐付け用）
  first_seen     TIMESTAMP,
  last_seen      TIMESTAMP,
  stix_modified  TIMESTAMP NOT NULL,
) PRIMARY KEY (stix_id);

-- TTP (STIX: attack-pattern / ATT&CK技術)
CREATE TABLE TTP (
  stix_id              STRING(128) NOT NULL,
  attack_technique_id  STRING(16),      -- T1059.001 等
  tactic               STRING(64),      -- initial-access/execution/persistence 等
  name                 STRING(256) NOT NULL,
  description          STRING(MAX),
  platforms            ARRAY<STRING(64)>,
  detection_difficulty INT64,           -- Summiting the Pyramid レベル (1-5)
  stix_modified        TIMESTAMP NOT NULL,
) PRIMARY KEY (stix_id);

-- 脆弱性 (STIX: vulnerability)
CREATE TABLE Vulnerability (
  stix_id            STRING(128) NOT NULL,
  cve_id             STRING(32),
  description        STRING(MAX),
  cvss_score         FLOAT64,
  epss_score         FLOAT64,           -- 悪用確率 (0.0-1.0)
  affected_platforms ARRAY<STRING(64)>,
  published_date     TIMESTAMP,
  stix_modified      TIMESTAMP NOT NULL,
) PRIMARY KEY (stix_id);

-- マルウェア / ツール (STIX: malware, tool)
CREATE TABLE MalwareTool (
  stix_id       STRING(128) NOT NULL,
  stix_type     STRING(16) NOT NULL,    -- "malware" | "tool"
  name          STRING(256) NOT NULL,
  description   STRING(MAX),
  capabilities  ARRAY<STRING(128)>,
  stix_modified TIMESTAMP NOT NULL,
) PRIMARY KEY (stix_id);

-- Observable / IoC (STIX: indicator から抽出)
CREATE TABLE Observable (
  stix_id       STRING(128) NOT NULL,
  obs_type      STRING(32) NOT NULL,    -- ip/domain/hash/email/url
  value         STRING(512) NOT NULL,
  confidence    INT64,                  -- 0-100
  tlp           STRING(16),             -- white/green/amber/red
  first_seen    TIMESTAMP,
  last_seen     TIMESTAMP,
  stix_modified TIMESTAMP NOT NULL,
) PRIMARY KEY (stix_id);

-- インシデント (STIX: incident / IR Analysis)
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

-- 資産 (内部データ / UUID PK)
-- ネットワークセグメント情報はパス探索の中継点にならないため Property として保持
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

-- セキュリティ制御 (内部データ / UUID PK)
CREATE TABLE SecurityControl (
  id           STRING(36) NOT NULL,
  name         STRING(256) NOT NULL,
  control_type STRING(64),             -- edr/waf/siem/firewall/iam 等
  coverage     ARRAY<STRING(64)>,
) PRIMARY KEY (id);
```

### 4.2 エッジ定義

Spanner Graph の制約上、エッジテーブルは SOURCE/DESTINATION ノード型が1種類に限定される。
複数の送信元型を持つ関係（例: Observable → TTP または ThreatActor）は送信元ごとにテーブルを分割する。

```sql
-- ─── Attack Flow エッジ ──────────────────────────────────────────────────────

-- ThreatActor → TTP
CREATE TABLE Uses (
  actor_stix_id  STRING(128) NOT NULL,
  ttp_stix_id    STRING(128) NOT NULL,
  confidence     INT64,
  first_observed TIMESTAMP,
  last_observed  TIMESTAMP,
  stix_id        STRING(128),
) PRIMARY KEY (actor_stix_id, ttp_stix_id);

-- MalwareTool → TTP
-- (STIX: malware/tool --[uses]--> attack-pattern)
CREATE TABLE MalwareUsesTTP (
  malware_stix_id STRING(128) NOT NULL,
  ttp_stix_id     STRING(128) NOT NULL,
  confidence      INT64,
  first_observed  TIMESTAMP,
  last_observed   TIMESTAMP,
  stix_id         STRING(128),
) PRIMARY KEY (malware_stix_id, ttp_stix_id);

-- TTP → Vulnerability
CREATE TABLE Exploits (
  ttp_stix_id  STRING(128) NOT NULL,
  vuln_stix_id STRING(128) NOT NULL,
  stix_id      STRING(128),
) PRIMARY KEY (ttp_stix_id, vuln_stix_id);

-- TTP → TTP (Attack Flow 遷移・経路重み)
-- source ごとに独立レコードを保持し、クエリ時に合算またはフィルタ可能
CREATE TABLE FollowedBy (
  src_ttp_stix_id   STRING(128) NOT NULL,
  dst_ttp_stix_id   STRING(128) NOT NULL,
  source            STRING(32) NOT NULL,   -- threat_intel | ir_feedback | manual_analysis
  weight            FLOAT64 NOT NULL DEFAULT (0.0),
  actor_stix_id     STRING(128),           -- 特定アクターに限定する場合
  evidence_stix_ids ARRAY<STRING(128)>,
  last_calculated   TIMESTAMP NOT NULL OPTIONS (allow_commit_timestamp=true),
) PRIMARY KEY (src_ttp_stix_id, dst_ttp_stix_id, source);

-- Incident → TTP (IR Analysis → Attack Flow 還元)
CREATE TABLE IncidentUsesTTP (
  incident_stix_id STRING(128) NOT NULL,
  ttp_stix_id      STRING(128) NOT NULL,
  sequence_order   INT64,                  -- インシデント内でのTTP使用順序
) PRIMARY KEY (incident_stix_id, ttp_stix_id);

-- ─── Attack Graph エッジ ─────────────────────────────────────────────────────

-- ThreatActor → MalwareTool
CREATE TABLE UsesTool (
  actor_stix_id  STRING(128) NOT NULL,
  tool_stix_id   STRING(128) NOT NULL,
  confidence     INT64,
  first_observed TIMESTAMP,
  last_observed  TIMESTAMP,
  stix_id        STRING(128),
) PRIMARY KEY (actor_stix_id, tool_stix_id);

-- ThreatActor → Asset (Attack Flow と Attack Graph の結合点)
-- 自動生成: PIR タグマッチングによる（Section 5.3 参照）
CREATE TABLE Targets (
  actor_stix_id STRING(128) NOT NULL,
  asset_id      STRING(36) NOT NULL,
  confidence    INT64,
  source        STRING(32) NOT NULL DEFAULT ('pir_auto'),  -- pir_auto | manual | stix
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

-- ─── Observable (IoC) エッジ ─────────────────────────────────────────────────
-- Spanner Graph の制約でターゲット型ごとにテーブルを分割

-- Observable → TTP
CREATE TABLE IndicatesTTP (
  observable_stix_id STRING(128) NOT NULL,
  ttp_stix_id        STRING(128) NOT NULL,
  confidence         INT64,
  stix_id            STRING(128),
) PRIMARY KEY (observable_stix_id, ttp_stix_id);

-- Observable → ThreatActor
CREATE TABLE IndicatesActor (
  observable_stix_id STRING(128) NOT NULL,
  actor_stix_id      STRING(128) NOT NULL,
  confidence         INT64,
  stix_id            STRING(128),
) PRIMARY KEY (observable_stix_id, actor_stix_id);
```

### 4.3 Spanner Graph 宣言

```sql
CREATE PROPERTY GRAPH ThreatIntelGraph
  NODE TABLES (
    ThreatActor     KEY (stix_id)  LABEL ThreatActor     PROPERTIES ALL COLUMNS,
    TTP             KEY (stix_id)  LABEL TTP             PROPERTIES ALL COLUMNS,
    Vulnerability   KEY (stix_id)  LABEL Vulnerability   PROPERTIES ALL COLUMNS,
    MalwareTool     KEY (stix_id)  LABEL MalwareTool     PROPERTIES ALL COLUMNS,
    Observable      KEY (stix_id)  LABEL Observable      PROPERTIES ALL COLUMNS,
    Incident        KEY (stix_id)  LABEL Incident        PROPERTIES ALL COLUMNS,
    Asset           KEY (id)       LABEL Asset           PROPERTIES ALL COLUMNS,
    SecurityControl KEY (id)       LABEL SecurityControl PROPERTIES ALL COLUMNS
  )
  EDGE TABLES (
    Uses
      SOURCE KEY (actor_stix_id)   REFERENCES ThreatActor (stix_id)
      DESTINATION KEY (ttp_stix_id) REFERENCES TTP (stix_id)
      LABEL USES PROPERTIES ALL COLUMNS,
    MalwareUsesTTP
      SOURCE KEY (malware_stix_id) REFERENCES MalwareTool (stix_id)
      DESTINATION KEY (ttp_stix_id) REFERENCES TTP (stix_id)
      LABEL MALWARE_USES_TTP PROPERTIES ALL COLUMNS,
    UsesTool
      SOURCE KEY (actor_stix_id)   REFERENCES ThreatActor (stix_id)
      DESTINATION KEY (tool_stix_id) REFERENCES MalwareTool (stix_id)
      LABEL USES_TOOL PROPERTIES ALL COLUMNS,
    Exploits
      SOURCE KEY (ttp_stix_id)     REFERENCES TTP (stix_id)
      DESTINATION KEY (vuln_stix_id) REFERENCES Vulnerability (stix_id)
      LABEL EXPLOITS PROPERTIES ALL COLUMNS,
    FollowedBy
      SOURCE KEY (src_ttp_stix_id) REFERENCES TTP (stix_id)
      DESTINATION KEY (dst_ttp_stix_id) REFERENCES TTP (stix_id)
      LABEL FOLLOWED_BY PROPERTIES ALL COLUMNS,
    IncidentUsesTTP
      SOURCE KEY (incident_stix_id) REFERENCES Incident (stix_id)
      DESTINATION KEY (ttp_stix_id)  REFERENCES TTP (stix_id)
      LABEL INCIDENT_USES_TTP PROPERTIES ALL COLUMNS,
    Targets
      SOURCE KEY (actor_stix_id)   REFERENCES ThreatActor (stix_id)
      DESTINATION KEY (asset_id)   REFERENCES Asset (id)
      LABEL TARGETS PROPERTIES ALL COLUMNS,
    HasVulnerability
      SOURCE KEY (asset_id)        REFERENCES Asset (id)
      DESTINATION KEY (vuln_stix_id) REFERENCES Vulnerability (stix_id)
      LABEL HAS_VULNERABILITY PROPERTIES ALL COLUMNS,
    ConnectedTo
      SOURCE KEY (src_asset_id)    REFERENCES Asset (id)
      DESTINATION KEY (dst_asset_id) REFERENCES Asset (id)
      LABEL CONNECTED_TO PROPERTIES ALL COLUMNS,
    ProtectedBy
      SOURCE KEY (asset_id)        REFERENCES Asset (id)
      DESTINATION KEY (control_id) REFERENCES SecurityControl (id)
      LABEL PROTECTED_BY PROPERTIES ALL COLUMNS,
    IndicatesTTP
      SOURCE KEY (observable_stix_id) REFERENCES Observable (stix_id)
      DESTINATION KEY (ttp_stix_id)   REFERENCES TTP (stix_id)
      LABEL INDICATES_TTP PROPERTIES ALL COLUMNS,
    IndicatesActor
      SOURCE KEY (observable_stix_id) REFERENCES Observable (stix_id)
      DESTINATION KEY (actor_stix_id) REFERENCES ThreatActor (stix_id)
      LABEL INDICATES_ACTOR PROPERTIES ALL COLUMNS
  );
```

---

## 5. 経路重み計算アルゴリズム

### 5.1 FollowedBy.weight の算出（source="threat_intel"）

```
weight(src_ttp → dst_ttp) =
  base_prob           -- ATT&CK kill chain上の遷移頻度（STIX観測数から算出）
  × activity_score    -- 直近90日のOpenCTI観測頻度（0.0-2.0）
  × exploit_ease      -- CVSSv3 Exploitability + EPSS（該当する場合。なければ 1.0）
  × ir_multiplier     -- 自社IR実績で同一遷移が観測された場合に補正（後述）
```

各因子の算出方法:

| 因子 | 算出式 | 備考 |
|------|--------|------|
| `base_prob` | 当該遷移を行うアクター数 / 全アクター数（上限 1.0） | Kill Chain 順でソートした連続TTPペアを遷移候補とする |
| `activity_score` | min(直近90日の Uses 観測数 / 全観測数 × 2.0, 2.0) | OpenCTI の `last_observed` から算出 |
| `exploit_ease` | Exploits エッジあり: cvss_score/10 × 0.5 + epss_score × 0.5<br>Exploits エッジなし: **1.0（ニュートラル）** | CVEが存在しないTTP（ソーシャルエンジニアリング、フィッシング等）は技術的脆弱性の悪用がないため 1.0 とし、使用頻度の高さは base_prob・activity_score で表現する |
| `ir_multiplier` | ir_feedback source の FollowedBy が同一ペアに存在: 1.5 / なし: 1.0 | threat_intel weight 計算後に乗算 |

### 5.2 IR Feedback → FollowedBy 還元（source="ir_feedback"）

`IncidentUsesTTP` の `sequence_order` が付与されたレコードから FollowedBy エッジを導出する:

```
for each Incident:
  TTPリストを sequence_order 昇順でソート
  連続するTTPペア (src, dst) について:
    FollowedBy(src, dst, source="ir_feedback").weight =
      当該遷移を含むインシデント数 / 全インシデント数（上限 1.0）
```

sequence_order が未設定（NULL）の場合は FollowedBy 導出をスキップする。

### 5.3 Targets エッジ自動生成（PIR タグマッチング）

`Targets`（ThreatActor → Asset）は STIX に直接対応する関係がないため、PIR を仲介役としてETL 時に自動生成する:

```
for each active PIR:
  matched_actors = {actor | actor.tags ∩ PIR.threat_actor_tags ≠ ∅}
  matched_asset_tags = {rule.tag | rule in PIR.asset_weight_rules}
  matched_assets = {asset | asset.tags ∩ matched_asset_tags ≠ ∅}

  for each (actor, asset) in matched_actors × matched_assets:
    upsert Targets(actor.stix_id, asset.id,
                   source="pir_auto",
                   confidence=タグ重複率から算出)
```

PIR が更新された場合、`source="pir_auto"` の Targets エッジを再計算する。
`source="manual"` や `source="stix"` のエッジは保持する。

### 5.4 PIR による資産重み付け更新

```
Asset.pir_adjusted_criticality =
  Asset.criticality
  × MAX(matching PIR rules' criticality_multiplier)
  × (当該 Asset への Targets エッジが存在する ThreatActor のうち
     ThreatActor.tags ∩ PIR.threat_actor_tags ≠ ∅ なら 1.5、なければ 1.0)
```

---

## 6. ETL パイプライン

### 処理フロー

```
GCS Landing Zone
  └─→ Cloud Run Job (ETL Worker)
        ├─ STIX Object 種別判定
        ├─ 既存ノードとの重複排除（stix_id で upsert）
        ├─ TLP チェック（red は Spanner に格納せずアナリスト通知のみ）
        ├─ PIR フィルタリング（関連性スコアが閾値以下はスキップ）
        ├─ FollowedBy weight 再計算（影響ノードのみ差分計算）
        └─ Spanner Graph upsert
```

### 更新スケジュール

| トリガー | 処理範囲 | レイテンシ目標 |
|----------|----------|--------------|
| Cloud Scheduler（日次 03:00 JST） | 全ノード・エッジの重み再計算 | 完了まで2時間以内 |
| Input API（アナリスト手動） | 追加データのみ差分更新 | 5分以内に反映 |
| IR Feedback（OpenCTI Polling → GCS） | Incident + IncidentUsesTTP + FollowedBy(ir_feedback) | 日次バッチ内で処理 |

---

## 7. Output System

### 7.1 Analysis API

Spanner Graph クエリをラップする内部 REST API（FastAPI / Cloud Run）。

| エンドポイント | 用途 |
|---|---|
| `GET /attack-paths?asset_id=&limit=` | 指定資産への上位N経路（重み順） |
| `GET /choke-points?top_n=` | チョークポイント資産一覧 |
| `GET /actor-ttps?actor_id=` | アクターの攻撃フロー |
| `GET /asset-exposure` | 外部露出資産と到達可能TTP |
| `GET /similar-incidents?incident_id=` | 類似 Attack Flow インシデント検索 |
| `POST /caldera/adversary` | Attack FlowからCaldera Adversaryプロファイル生成 |

実装: `src/sage/api/app.py`（FastAPI）、`cmd/analysis_api.py`（uvicorn起動）

### 7.2 チーム別出力

**Red Team（Caldera連携）:**
- Analysis APIの`/actor-ttps`からTTP sequence取得
- Caldera REST APIでAdversaryプロファイル自動生成（`src/sage/caldera/client.py`）
- GHEにシミュレーション計画Issueを作成（`notify/github.py` 流用）

**Blue Team（GHE + Slack）:**
- チョークポイント資産レポートをGHE Issueとして定期生成（週次、`cmd/report_choke_points.py --ghe`）
- ETL完了後にチョークスコアの前回比変化（10%以上）をSlack通知（`notify/slack.py`）
- 推奨防御施策はSTIX CoA（Course of Action）オブジェクトをMarkdown変換

**IR Team（Slack + GHE）:**
- インシデント発生時、類似Attack FlowパターンをSlackへ通知（`GET /similar-incidents` → `notify/slack.py`）
- 対応完了後、IR記録をOpenCTIへ登録するためのGHE Issue template提供（`cmd/create_ir_template.py`）

### 7.3 IR 類似インシデント検索アルゴリズム

`GET /similar-incidents` は以下のハイブリッド類似度スコアで過去インシデントをランキングする。

```
hybrid_score = 0.5 × jaccard_ttp + 0.5 × transition_coverage
```

| コンポーネント | 算出式 | 特徴 |
|---|---|---|
| `jaccard_ttp` | `|incident_ttps ∩ reference_ttps| / |incident_ttps ∪ reference_ttps|` | 順序・欠損に強い。途中TTPが不明でも部分一致でスコアが出る |
| `transition_coverage` | インシデントの連続TTPペアが FollowedBy グラフ上で到達可能な割合 | 最大2ホップBFSで欠損TTPを許容（A→C は A→B→C で到達可能なら一致） |

**実装詳細（`src/sage/analysis/similarity.py`）:**
- FollowedBy エッジをメモリにキャッシュして有向グラフ（dict）として保持
- 各ペアに対して最大 2 ホップの BFS で到達可能性を判定
- `transition_coverage = matched_pairs / max(len(incident_pairs), 1)`

**欠損TTP許容の例:**

インシデント観測: `[A, C]`（B が不明）、参照事例: `A→B→C`
- `jaccard_ttp`: `{A,C} ∩ {A,B,C}` / `{A,B,C}` = 2/3
- `transition_coverage`: A→C を 2ホップ（A→B→C）で到達可能 → 1/1 = 1.0
- `hybrid_score` = 0.5 × 0.67 + 0.5 × 1.0 = **0.83**

---

## 8. GCP インフラ構成

```
┌── Spanner (us-central1)
│     └── ThreatIntelGraph (regional, 1000 PU)
│
├── Cloud Storage
│     ├── threat-intel-landing   （TTL: 生データ90日保持）
│     └── threat-intel-processed （TTL: 処理済み1年保持）
│
├── Cloud Run
│     ├── etl-worker             （バッチ・手動トリガー共用）
│     ├── analysis-api           （内部VPC内、IAP保護）
│     └── internal-data-api      （資産・PIR管理）
│
├── Cloud Scheduler
│     └── daily-etl-trigger      （03:00 JST → etl-worker）
│
├── Pub/Sub
│     └── scc-findings-topic     （Security Command Center → ETL）
│
├── Secret Manager
│     └── opencti-api-key, slack-token, ghe-token, caldera-token
│
└── Artifact Registry
      └── etl-worker イメージ, analysis-api イメージ
```

**ネットワーク:** analysis-api はパブリックIPなし、Cloud IAP + Internal Load Balancer経由でのみアクセス。

---

*未解決事項・実装フェーズは `TODO.md` を参照。*
