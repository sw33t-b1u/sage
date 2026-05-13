# SAGE — データモデル

英語版（正本）: [`docs/data-model.md`](data-model.md)

## グラフの概要

Spanner Graph（`ThreatIntelGraph`）には 2 つのサブグラフが共存する:

- **Attack Flow** — STIX 脅威インテリジェンスから導出された TTP 時系列遷移
- **Attack Graph** — 内部資産の接続性と脆弱性露出

クロスドメイン結合: `Targets` エッジが ThreatActor → Asset を接続する。

---

## ノード

| ノード | 説明 |
|--------|------|
| `ThreatActor` | 脅威アクターグループおよび個人（STIX アイデンティティ、PIR マッチング用タグ） |
| `TTP` | ATT&CK テクニック/サブテクニック（検出難易度レベル付き） |
| `Vulnerability` | CVSS スコア・EPSS スコア・影響プラットフォームを含む CVE |
| `MalwareTool` | マルウェアファミリーおよび攻撃者ツール |
| `Identity` | 標的となる人物・グループ・組織（STIX 2.1 §4.4 SDO）。TRACE 1.0.0+ が emit し、`ActorTargetsIdentity` で参照される。`deleted_at` は SAGE 内部 soft-delete マーカ（HR action 等で組織離脱した identity を、上流 STIX が revoked 化していなくても表現できる軸）。 |
| `UserAccount` | 個別ログインアカウント（STIX 2.1 §6.4 SCO）— `alice@corp`、`svc-jenkins`、ドメイン SID 等。Initiative B (SAGE 0.7.0)。`identity_stix_id` で Identity へ optional FK (1:N)。Initiative A の role-based access より 1 階深い粒度で credential theft の影響追跡を可能にする。 |
| `Asset` | 内部資産（サーバー・エンドポイント・SaaS・ストレージ・ネットワーク機器）。PIR 調整済みクリティカリティ付き。ネットワークセグメント情報（名前・CIDR・ゾーン）はプロパティとして保存。 |
| `SecurityControl` | 防御コントロール: EDR・WAF・SIEM・ファイアウォール・IAM |
| `Observable` | IoC — IP・ドメイン・ハッシュ・メール・URL（TLP・信頼度付き） |
| `Incident` | IR インシデント（ダイヤモンドモデル・キルチェインフェーズを含む） |
| `PIR` | Priority Intelligence Requirement — 1 ノード = 1 ディシジョンポイント（インテルカスケードの Strategic 層） |

## エッジ

| エッジ | 送信元 → 送信先 | 説明 |
|--------|----------------|------|
| `Uses` | ThreatActor → TTP | アクターがテクニックを使用 |
| `MalwareUsesTTP` | MalwareTool → TTP | マルウェア/ツールがテクニックを使用 |
| `UsesTool` | ThreatActor → MalwareTool | アクターがマルウェアまたはツールを使用 |
| `Exploits` | TTP → Vulnerability | テクニックが CVE を悪用 |
| `FollowedBy` | TTP → TTP | 確率的重みを持つ TTP 時系列遷移 |
| `IncidentUsesTTP` | Incident → TTP | IR インシデントで観測されたテクニック |
| `Targets` | ThreatActor → Asset | アクターが内部資産を標的（PIR タグマッチングで自動生成） |
| `TargetsAsset` | TTP → Asset | TTP の technique-id が資産タグにマッチ（例: `T1078` → `identity` タグの資産）。CVE 紐付けがない TTP の露出補完に使う。実装は `src/sage/analysis/ttp_asset_matcher.py`。 |
| `ActorTargetsIdentity` | ThreatActor → Identity | TRACE 1.0.0+ が emit する STIX `targets` 関係から派生。STIX 2.1 §4.13 suggested subset に従い、source は `threat-actor` / `intrusion-set` に限定。 |
| `HasAccess` | Identity → Asset | identity と内部 asset のアクセス関係 (Initiative A)。source: `beacon` (BEACON `identity_assets.json` 由来) / `trace` (TRACE 1.2.0+ `x-trace-has-access`) / `manual` (analyst 直接更新)。upsert 優先順位: `manual > beacon > trace`。NIST SP 800-53 AC-2/3、NIST SP 800-207、ISO/IEC 27001 A.5.16/18 を出典とする。 |
| `AccountOnAsset` | UserAccount → Asset | アカウントの host validity (Initiative B / SAGE 0.7.0)。 (account, host) ペアごとに 1 エッジ。同一 login が複数 host で有効なら複数エッジ。source / 優先順位は HasAccess と同じ。NIST SP 800-53 IA-2/IA-4/AC-2、CIS Controls v8 #5 を出典とする。 |
| `UserAccountBelongsTo` | Identity → UserAccount | アカウント所有権 (Initiative B)。1:N: 1 Identity が複数アカウントを所有。optional — 共有 / 不明アカウントは parent Identity を持たない。 |
| `HasVulnerability` | Asset → Vulnerability | 資産に未修正の CVE が存在 |
| `ConnectedTo` | Asset ↔ Asset | 資産間のネットワーク到達性 |
| `ProtectedBy` | Asset → SecurityControl | 資産が防御コントロールでカバーされている |
| `IndicatesTTP` | Observable → TTP | IoC が TTP に帰属 |
| `IndicatesActor` | Observable → ThreatActor | IoC が脅威アクターに帰属 |
| `PirPrioritizesActor` | PIR → ThreatActor | TAP — アクターが PIR の `threat_actor_tags` に一致（`overlap_ratio` 付き） |
| `PirPrioritizesTTP` | PIR → TTP | PTTP — 優先アクターの `Uses` から推移的に導出 |
| `PirWeightsAsset` | PIR → Asset | 資産が PIR の `asset_weight_rules` に一致（`matched_tag` と最大 `criticality_multiplier` 付き） |
| `AttributedToActor` | Campaign / IntrusionSet → ThreatActor / IntrusionSet | STIX 2.1 §7.2 `attributed-to` SRO (Initiative C Phase 1 / SAGE 0.8.0)。`source_type` / `target_type` discriminator 付きのポリモーフィックエッジ。Phase 1 で emit される組合せ: `campaign → {threat-actor, intrusion-set}`、`intrusion-set → threat-actor`。precedence-aware upsert (`manual > beacon > trace`)。 |
| `AttributedToIdentity` | ThreatActor → Identity | STIX 2.1 §7.2 `attributed-to` SRO で実世界 actor の帰属を表現 (Initiative C Phase 1 / SAGE 0.8.0)。Phase 1 source は `threat-actor` のみ。`source_type` は Phase 2 `intrusion-set` 起源活性化のため保持。precedence-aware upsert。 |
| `ImpersonatesIdentity` | ThreatActor → Identity | STIX 2.1 §7.2 `impersonates` SRO (Initiative C Phase 1 / SAGE 0.8.0)。ETL 計算の `effective_priority INT64` を持つ (HLD §6.6)。Phase 2 (SAGE 0.9.0) で `effective_priority` を **flag-first / role-fallback** に refactor: 対象 Identity の `is_high_value_impersonation_target=TRUE` (BEACON 0.13.0+) なら multiplier 1.5 を無条件適用、それ以外は `HIGH_VALUE_IMPERSONATION_ROLES` 15 entry frozenset との `roles[]` 交差で判定。precedence-aware upsert。 |
| `PirPrioritizesImpersonationTarget` | PIR → Identity | `ImpersonatesIdentity ⨝ Identity.is_high_value_impersonation_target=TRUE ⨝ PIR.threat_actor_tags ∩ ThreatActor.tags ≠ ∅` から導出される cascade エッジ (Initiative C Phase 2 / SAGE 0.9.0)。`effective_priority` は source の `ImpersonatesIdentity` から非正規化。impersonation を考慮した PIR 優先度をアナリストに surface する。 |

PIR カスケードエッジは ETL 時に PIR JSON とロード済みの actor / asset / `Uses`
行から構築されます。Strategic (PIR) → Operational (TAP) → Tactical (PTTP)
カスケードを実体化することで、アナリストが特定の PIR にスコープした
サブグラフを切り出せるようになります。

---

## PIR ベースの資産重み付け

Priority Intelligence Requirements（PIR）は ETL 時に動的な資産クリティカリティ調整を駆動する。

> **PIR の生成:** 組織のビジネスコンテキストから PIR JSON を自動生成するには [BEACON](https://github.com/sw33t-b1u/beacon) を使用する。BEACON は SAGE 互換の `pir_output.json` を `PIR_FILE_PATH` に配置できる形式で出力する。

### PIR JSON フォーマット

```json
{
  "pir_id": "PIR-2026-001",
  "description": "ベンダーシステム経由のサプライチェーン攻撃",
  "threat_actor_tags": ["apt-china", "espionage"],
  "asset_weight_rules": [
    { "tag": "authentication",    "criticality_multiplier": 3.0 },
    { "tag": "shared-infra",      "criticality_multiplier": 2.5 }
  ],
  "valid_from": "2026-01-01",
  "valid_until": "2026-12-31"
}
```

### クリティカリティ計算式

```
pir_adjusted_criticality =
  base_criticality
  × MAX(matching asset_weight_rules[].criticality_multiplier)
  × 1.5  (Targets エッジが存在する場合: actor.tags ∩ PIR.threat_actor_tags ≠ ∅)
  上限 10.0
```

---

## FollowedBy 重み計算

`FollowedBy.weight` は 2 つの TTP 間の遷移確率を表す:

```
weight(src_ttp → dst_ttp) =
  base_prob       ×   -- ATT&CK キルチェインにおける遷移頻度
  activity_score  ×   -- 直近 N 日間の OpenCTI 観測件数（0.0〜2.0）
  exploit_ease    ×   -- CVSSv3 Exploitability + EPSS（該当する場合）
  ir_multiplier       -- 内部 IR インシデントレコードからの補正
```

`ir_feedback` および `manual_analysis` ソースからの重みは個別レコードとして保存され、個別または集約してクエリできる。

---

## ETL スケジュール

| トリガー | スコープ | レイテンシ目標 |
|---------|---------|--------------|
| Cloud Scheduler（毎日 03:00 JST） | 全重み再計算 | 2 時間以内 |
| 手動（`run_etl.py`） | 追加データの増分更新 | 5 分以内 |
| IR フィードバック | Incident + IncidentUsesTTP + FollowedBy ir_feedback | 30 分以内 |
