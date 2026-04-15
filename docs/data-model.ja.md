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
| `HasVulnerability` | Asset → Vulnerability | 資産に未修正の CVE が存在 |
| `ConnectedTo` | Asset ↔ Asset | 資産間のネットワーク到達性 |
| `ProtectedBy` | Asset → SecurityControl | 資産が防御コントロールでカバーされている |
| `IndicatesTTP` | Observable → TTP | IoC が TTP に帰属 |
| `IndicatesActor` | Observable → ThreatActor | IoC が脅威アクターに帰属 |
| `PirPrioritizesActor` | PIR → ThreatActor | TAP — アクターが PIR の `threat_actor_tags` に一致（`overlap_ratio` 付き） |
| `PirPrioritizesTTP` | PIR → TTP | PTTP — 優先アクターの `Uses` から推移的に導出 |
| `PirWeightsAsset` | PIR → Asset | 資産が PIR の `asset_weight_rules` に一致（`matched_tag` と最大 `criticality_multiplier` 付き） |

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
  "threat_actor_tags": ["supply-chain", "apt-naver-linked"],
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
