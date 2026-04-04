# SAGE — Security Attack Graph Engine

脅威インテリジェンスサイクルを回す基盤システム。外部CTIデータ（STIX 2.1）と内部資産・組織情報を統合し、攻撃経路の可視化・重み付けを行い、Red/Blue/IRの各チームへ実用的なアウトプットを提供する。

[English README](README.md)

## 対象外

本システムはデータを受け取る側であり、以下を置き換えるものではありません：
リアルタイムSIEM検知、エンドポイント保護、脆弱性スキャン自動化。

## 主な機能

- **マルチソース取り込み** — OpenCTI（STIX 2.1）、AWS Security Hub（ASFF → STIX変換）、GCP Security Command Center（SCC Finding → STIX変換）、アナリスト手動入力API
- **アタックグラフ** — 資産間の接続性と到達可能な攻撃経路をモデル化。PIR（Priority Intelligence Requirements）に基づく資産重要度をクエリ時に動的調整
- **アタックフロー** — TTPの時系列遷移を重み付き `FollowedBy` エッジで追跡。重みはベース確率・直近の活動スコア（90日間）・Exploit容易性（CVSS+EPSS）・IRフィードバック補正を組み合わせて算出
- **Analysis API** — 攻撃経路・チョークポイント・アクターTTP・資産露出クエリを提供する内部REST API（Cloud Run、VPC内、IAP保護）
- **チーム別出力** — GitHub Enterpriseへのプレイブック・チョークポイントレポートIssue、Slackへの優先度別アラート、Calderaへのレッドチーム用Adversaryプロファイル生成
- **TLP制御** — TLP Redオブジェクトは Spanner に格納せずアナリスト通知のみ。`white`/`green`/`amber` のみ取り込む（設定変更可）
- **IRフィードバックループ** — インシデント記録を `FollowedBy` の重みに還元し、経路確率を継続的に精度向上

## システム構成

```
[OpenCTI]──STIX 2.1──┐
[Security Hub]────────┼──→ [GCS: Landing Zone（生STIXデータ）]
[SCC]─────────────────┘         gs://threat-intel-landing/raw/stix/{日付}/{ソース}/{uuid}.json
[アナリスト Input API]────────→  （手動、1日4〜5回想定）

                │
                ▼
        [ETLワーカー — Cloud Run]
          ├── STIXオブジェクト種別判定
          ├── stix_id による重複排除（upsert）
          ├── TLPチェック（red → アナリスト通知のみ、格納しない）
          ├── PIRフィルタリング（関連性スコアが閾値以下はスキップ）
          ├── FollowedBy重み再計算（影響ノードのみ差分計算）
          └── Spanner Graph upsert

                │
                ▼
        [Spanner Graph: ThreatIntelGraph]
          ノード: ThreatActor, TTP, Vulnerability, MalwareTool,
                  Asset, SecurityControl, Observable, Incident
          エッジ: Uses, MalwareUsesTTP, UsesTool, Exploits,
                  Targets, HasVulnerability, ConnectedTo, ProtectedBy,
                  FollowedBy, IncidentUsesTTP, IndicatesTTP, IndicatesActor

                │
                ▼
        [Analysis API — Cloud Run、VPC内]
          GET  /attack-paths?asset_id=&limit=
          GET  /choke-points?top_n=
          GET  /actor-ttps?actor_id=
          GET  /asset-exposure
          GET  /similar-incidents?incident_id=
          POST /caldera/adversary?actor_id=

                │
                ▼
[GHE Issues]  [Slack アラート]  [Caldera Adversary プロファイル]
```

## 必要環境

- Python 3.12+
- [uv](https://github.com/astral-sh/uv)
- Cloud Spanner・Cloud Storage が有効な GCP プロジェクト
- OpenCTI インスタンス（外部CTI取り込みに必要）

## セットアップ

### 1. クローンとインストール

```sh
git clone https://github.com/your-org/sage.git
cd sage
uv sync --extra dev
```

### 2. 環境変数の設定

| 変数名 | 必須 | デフォルト | 説明 |
|--------|------|-----------|------|
| `GCP_PROJECT_ID` | 必須 | — | GCPプロジェクトID |
| `SPANNER_INSTANCE_ID` | 必須 | — | SpannerインスタンスID |
| `SPANNER_DATABASE_ID` | 必須 | — | SpannerデータベースID |
| `GCS_LANDING_BUCKET` | 必須 | — | 生STIXデータ用GCSバケット名 |
| `OPENCTI_URL` | 必須 | — | OpenCTIのベースURL |
| `OPENCTI_TOKEN` | 必須 | — | OpenCTI APIトークン |
| `PIR_FILE_PATH` | 任意 | `/config/pir.json` | PIR JSONファイルのパス |
| `TLP_MAX_LEVEL` | 任意 | `amber` | 取り込む最大TLPレベル（`white`/`green`/`amber`） |
| `ACTIVITY_WINDOW_DAYS` | 任意 | `90` | FollowedBy活動スコアの参照期間（日） |
| `SLACK_WEBHOOK_URL` | 任意 | — | ETL完了アラート用 Slack Incoming Webhook URL |
| `GHE_TOKEN` | 任意 | — | GitHub Enterprise Personal Access Token |
| `GHE_REPO` | 任意 | — | GHEリポジトリ（`owner/repo` 形式） |
| `GHE_API_BASE` | 任意 | `https://api.github.com` | GHE APIベースURL（セルフホスト時に変更） |
| `CALDERA_URL` | 任意 | — | MITRE CalderaサーバーURL（例: `http://caldera.internal:8888`） |
| `CALDERA_API_KEY` | 任意 | — | Caldera REST APIキー |
| `SAGE_API_URL` | 任意 | — | Analysis APIのベースURL（`create_ir_template.py` が使用） |

### 3. Spannerスキーマの初期化

```sh
make init-schema
```

## ローカルテスト

### ユニットテスト（GCP不要）

```sh
make test
```

ユニットテストは `tests/fixtures/` のフィクスチャファイルを使用し、GCP認証もネットワーク接続も不要です。

### Spannerエミュレーターによるフルローカルテスト

Attack Flow（STIX脅威インテル）とAttack Graph（社内資産）の両方を含む完全なワークフローです。

```sh
# 1. エミュレーターを起動（Docker）
docker run -d --name spanner-emulator -p 9010:9010 -p 9020:9020 \
  gcr.io/cloud-spanner-emulator/emulator
export SPANNER_EMULATOR_HOST=localhost:9010

# 2. インスタンス・DB・スキーマを作成
uv run python cmd/setup_emulator.py
make init-schema

# 3. 脅威インテルを投入（Attack Flow）
uv run python cmd/run_etl.py --manual-bundle tests/fixtures/sample_bundle_mirrorface.json
uv run python cmd/run_etl.py --manual-bundle tests/fixtures/sample_bundle_inc.json

# 4. 社内資産データを投入（Attack Graph）
make load-assets

# 5. グラフを可視化 — tests/output/graph.html がブラウザで開く
make visualize

# 作業終了後にエミュレーターを停止・削除
docker stop spanner-emulator && docker rm spanner-emulator
```

### グラフ出力

`make visualize` は `tests/output/graph.html`（git管理外）を生成しブラウザで開きます。
ノードはドラッグ可能でズームにも対応しています。
`--no-open` でブラウザ自動オープンを抑制、`--limit N` でテーブルごとの取得行数を制限できます。

| ノード種別 | 色 | 接続先 |
|-----------|-----|--------|
| ThreatActor | 赤 | TTP (USES)、MalwareTool (USES_TOOL)、Asset (TARGETS) |
| TTP | オレンジ | Vulnerability (EXPLOITS)、TTP (FOLLOWED_BY) |
| Vulnerability | 黄 | — |
| MalwareTool | 紫 | TTP (MALWARE_USES_TTP) |
| Observable | ターコイズ | TTP (INDICATES_TTP)、ThreatActor (INDICATES_ACTOR) |
| Incident | ピンク | TTP (INCIDENT_USES_TTP) |
| Asset | 青 | Vulnerability (HAS_VULN)、Asset (CONNECTED_TO)、SecurityControl (PROTECTED_BY) |
| SecurityControl | グレー | — |

### サンプル fixture

| ファイル | 説明 |
|---------|------|
| `tests/fixtures/sample_bundle_mirrorface.json` | MirrorFace / Earth Kasha APT（日本標的、2024〜2025年）。TTP: T1190, T1566.001, T1574.002, T1071.001, T1083, T1041。CVE-2023-28461・CVE-2024-21412。LODEINFOバックドア + C2 IoC。 |
| `tests/fixtures/sample_bundle_inc.json` | INC ランサムウェア（2023年〜、医療・製造業標的）。TTP: T1190, T1078, T1003.001, T1021.002, T1048.002, T1486。CVE-2023-3519・CVE-2023-4966（Citrix）。ツール: Cobalt Strike, AnyDesk, MegaSync。Trend Micro レポートの IoC 収録。 |
| `tests/fixtures/sample_assets.json` | 日本の製造業を想定した社内資産。Citrix NetScaler ADC（DMZ・インターネット公開）、AD、ファイルサーバ、バックアップサーバ、ERP（SAP）、工場PLC、ワークステーション。ネットワークトポロジとセキュリティコントロール割当含む。 |

## 開発

```sh
# 全品質チェック: vet → lint → test
make check

# 個別ターゲット
make vet       # ruff check（リント）
make lint      # ruff format --check（フォーマットチェック）
make format    # ruff format + ruff check --fix（自動修正）
make test      # pytest
make audit     # pip-audit（依存パッケージの脆弱性スキャン）

# ETLを手動実行
make run-etl
```

## ディレクトリ構成

```
sage/
├── src/sage/
│   ├── config.py              # 環境変数ベースの設定
│   ├── etl/
│   │   └── worker.py          # ETLパイプラインワーカー（GCS → Spanner）
│   ├── stix/
│   │   ├── parser.py          # STIX 2.1 JSONパーサー
│   │   └── mapper.py          # STIXオブジェクト → Spannerスキーママッパー
│   ├── pir/
│   │   └── filter.py          # PIRフィルタリング & pir_adjusted_criticality算出
│   ├── spanner/
│   │   ├── client.py          # Spannerクライアント
│   │   ├── upsert.py          # グラフノード/エッジのupsertロジック
│   │   └── query.py           # 分析クエリ（GQL + SQL）
│   ├── notify/
│   │   ├── slack.py           # Slack Incoming Webhook通知
│   │   └── github.py          # GitHub Enterprise Issue作成
│   ├── api/
│   │   └── app.py             # FastAPI Analysis API（Cloud Runエントリポイント）
│   ├── caldera/
│   │   └── client.py          # MITRE Caldera REST APIクライアント
│   ├── analysis/
│   │   └── similarity.py      # ハイブリッドIRインシデント類似度（Jaccard + BFS）
│   └── opencti/
│       └── client.py          # OpenCTI REST APIポーリングクライアント
├── cmd/
│   ├── init_schema.py         # Spannerスキーマ初期化（DDL実行）
│   ├── run_etl.py             # ETL手動トリガー（+ Slack通知）
│   ├── load_assets.py         # 社内資産データをSpannerに投入
│   ├── report_choke_points.py # チョークポイントレポート出力（--gheでGHE Issue投稿）
│   ├── query_attack_paths.py  # 資産またはアクター別の攻撃経路クエリ
│   ├── visualize_graph.py     # Attack Graph HTML生成（pyvis）
│   ├── visualize_attack_flow.py  # FollowedBy重み付きAttack Flow HTML生成
│   ├── analysis_api.py        # uvicornでAnalysis APIを起動
│   ├── sync_caldera.py        # アクターTTPをCaldera Adversaryプロファイルに同期
│   └── create_ir_template.py  # IRインシデントGHE IssueテンプレートをGHEに投稿
├── schema/                    # Spanner DDL定義
├── tests/
│   ├── fixtures/              # テスト用STIXバンドル・PIR JSON
│   ├── test_mapper.py
│   ├── test_pir_filter.py
│   ├── test_spanner_query.py
│   ├── test_notify.py
│   ├── test_api.py
│   ├── test_similarity.py
│   └── test_caldera.py
├── Dockerfile                 # Cloud Runコンテナイメージ
├── Makefile
└── pyproject.toml
```

## データモデル

Spanner Graph（`ThreatIntelGraph`）のノードとエッジ定義。

### ノード

| ノード | 説明 |
|--------|------|
| `ThreatActor` | 脅威アクターグループ・個人（STIX identity、PIRマッチング用タグ） |
| `TTP` | ATT&CKテクニック・サブテクニック（検知難度レベル付き） |
| `Vulnerability` | CVE（CVSSスコア・EPSSスコア・影響プラットフォーム） |
| `MalwareTool` | マルウェアファミリー・攻撃ツール |
| `Asset` | 内部資産（サーバー、エンドポイント、SaaS、ストレージ、ネットワーク機器）。PIR調整済み重要度を保持。ネットワークセグメント情報（名称・CIDR・ゾーン）はこのノードのプロパティとして保持する。 |
| `SecurityControl` | 防御制御：EDR、WAF、SIEM、ファイアウォール、IAM |
| `Observable` | IoC — IP、ドメイン、ハッシュ、メール、URL（TLPと信頼度付き） |
| `Incident` | IRインシデント（ダイヤモンドモデル・キルチェーンフェーズ含む） |

### エッジ

| エッジ | 接続方向 | 説明 |
|--------|---------|------|
| `Uses` | ThreatActor → TTP | アクターがテクニックを使用 |
| `MalwareUsesTTP` | MalwareTool → TTP | マルウェア・ツールがテクニックを使用 |
| `UsesTool` | ThreatActor → MalwareTool | アクターがマルウェア・ツールを使用 |
| `Exploits` | TTP → Vulnerability | テクニックがCVEを悪用 |
| `FollowedBy` | TTP → TTP | TTP間の時系列遷移（確率重み付き） |
| `IncidentUsesTTP` | Incident → TTP | IRインシデントで観測されたテクニック |
| `Targets` | ThreatActor → Asset | アクターが内部資産を標的に（PIRタグマッチングで自動生成） |
| `HasVulnerability` | Asset → Vulnerability | 資産が未修正のCVEを保有 |
| `ConnectedTo` | Asset ↔ Asset | 資産間のネットワーク到達可能性 |
| `ProtectedBy` | Asset → SecurityControl | 資産が防御制御でカバーされている |
| `IndicatesTTP` | Observable → TTP | IoCがTTPに帰属 |
| `IndicatesActor` | Observable → ThreatActor | IoCがアクターに帰属 |

## PIRによる資産重み付け

PIR（Priority Intelligence Requirements）により、資産の重要度をクエリ時に動的調整します。

```json
{
  "pir_id": "PIR-2025-001",
  "description": "ランサムウェアグループへの耐性強化",
  "threat_actor_tags": ["ransomware", "financially-motivated"],
  "asset_weight_rules": [
    { "tag": "external-facing", "criticality_multiplier": 2.0 },
    { "tag": "s3",              "criticality_multiplier": 1.8 },
    { "tag": "backup",          "criticality_multiplier": 1.5 }
  ],
  "valid_from": "2025-01-01",
  "valid_until": "2025-12-31"
}
```

```
pir_adjusted_criticality =
  criticality
  × MAX(マッチしたPIRルールの criticality_multiplier)
  × 1.5  （ThreatActorがこの資産をTargetsかつ actor.tags ∩ PIR.threat_actor_tags ≠ ∅ の場合）
```

## FollowedBy 重み計算

`FollowedBy.weight` は2つのTTP間の遷移確率を表します。

```
weight(src_ttp → dst_ttp) =
  base_prob        ×   -- ATT&CKキルチェーン上の遷移頻度（STIX観測数から算出）
  activity_score   ×   -- OpenCTIでの直近90日の観測頻度（0.0〜2.0）
  exploit_ease     ×   -- CVSSv3 Exploitability + EPSS（該当する場合）
  ir_multiplier        -- 自社IRで観測された遷移への補正値
```

`ir_feedback` と `manual_analysis` ソースの重みは独立したレコードとして保持。クエリ時にソース別参照・合算が可能です。

## ETL更新スケジュール

| トリガー | 処理範囲 | レイテンシ目標 |
|----------|----------|--------------|
| Cloud Scheduler（日次 03:00 JST） | 全ノード・エッジの重み再計算 | 2時間以内 |
| アナリスト Input API（手動） | 追加データのみ差分更新 | 5分以内 |
| IRフィードバック（OpenCTI → GCS） | Incident + IncidentUsesTTP + FollowedBy ir_feedback | 30分以内 |

## GCPインフラ構成

```
Spanner（us-central1）
  └── ThreatIntelGraph（リージョナル、1000 PU）

Cloud Storage
  ├── threat-intel-landing    （TTL: 生データ90日保持）
  └── threat-intel-processed  （TTL: 処理済み1年保持）

Cloud Run
  ├── etl-worker              （バッチ・手動トリガー共用）
  ├── analysis-api            （VPC内部、IAP保護、パブリックIPなし）
  └── internal-data-api       （資産・PIR管理）

Cloud Scheduler
  └── daily-etl-trigger       （03:00 JST → etl-worker）

Pub/Sub
  └── scc-findings-topic      （Security Command Center → ETL）

Secret Manager
  └── opencti-api-key, slack-token, ghe-token, caldera-token
```

> **注意:** `analysis-api` はパブリックIPを持ちません。Cloud IAP + Internal Load Balancer 経由でのみアクセス可能です。

## 実装フェーズ

| フェーズ | 内容 | 成果物 | 状態 |
|--------|------|--------|------|
| Phase 1 | Spanner Graphスキーマ構築 + OpenCTI → STIX取り込みETL | 動くグラフDB | 完了 |
| Phase 2 | 内部資産データ登録 + PIR適用 + 攻撃経路クエリ | チョークポイント可視化 | 完了 |
| Phase 3 | FollowedBy重み計算 + 攻撃フロー可視化 + Slack/GHE通知 | Blue Team利用可能 | 完了 |
| Phase 4 | Caldera連携 + IRフィードバックループ + Analysis API | Red/IR Team利用可能 | 完了 |

## ライセンス

Apache-2.0 — [LICENSE](LICENSE) を参照
