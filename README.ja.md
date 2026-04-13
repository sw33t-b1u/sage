# SAGE — Security Attack Graph Engine

脅威インテリジェンスサイクルを回す基盤システム。外部 CTI データ（STIX 2.1）と内部資産・組織情報を統合し、攻撃経路の可視化・重み付けを行い、Red/Blue/IR の各チームへ実用的なアウトプットを提供する。

[English README](README.md)

## 対象外

本システムはデータを受け取る側であり、以下を置き換えるものではない:
リアルタイム SIEM 検知、エンドポイント保護、脆弱性スキャン自動化。

## 主な機能

- **マルチソース取り込み** — OpenCTI（STIX 2.1）、AWS Security Hub、GCP Security Command Center、アナリスト手動入力 API
- **アタックグラフ** — 資産間の接続性と到達可能な攻撃経路をモデル化。PIR に基づく資産重要度を ETL 時に動的調整
- **アタックフロー** — TTP の時系列遷移を重み付き `FollowedBy` エッジで追跡
- **Analysis API** — 攻撃経路・チョークポイント・アクター TTP・資産露出クエリを提供する内部 REST API（Cloud Run、VPC 内、IAP 保護）
- **チーム別出力** — GitHub Enterprise プレイブック Issue、Slack 優先度別アラート、Caldera レッドチーム用 Adversary プロファイル生成
- **TLP 制御** — TLP Red オブジェクトはストレージ除外。`white`/`green`/`amber` のみ取り込む
- **IR フィードバックループ** — インシデント記録を `FollowedBy` 重みに還元し、経路確率を継続的に精度向上

## システム構成

```
[OpenCTI]──STIX 2.1──┐
[Security Hub]────────┼──→ [GCS: Landing Zone]
[SCC]─────────────────┘
[アナリスト Input API]──→ （手動）

        │
        ▼
[ETL ワーカー — Cloud Run]
  ├── STIX パース + 重複排除
  ├── TLP 制御
  ├── PIR 関連性フィルタリング
  ├── FollowedBy 重み再計算
  └── Spanner Graph upsert

        │
        ▼
[Spanner Graph: ThreatIntelGraph]

        │
        ▼
[Analysis API — Cloud Run、VPC 内]
  GET /attack-paths  GET /choke-points
  GET /actor-ttps    GET /asset-exposure

        │
        ▼
[GHE Issues]  [Slack アラート]  [Caldera Adversary プロファイル]
```

## ドキュメント

| ドキュメント | 内容 |
|-------------|------|
| [docs/ja/setup.md](docs/ja/setup.md) | GCP リソース作成、スキーマ初期化、Cloud Run・Scheduler デプロイ |
| [docs/ja/analyst-guide.md](docs/ja/analyst-guide.md) | 日常利用: ETL・チョークポイント・グラフ可視化・PIR 更新・IR ワークフロー |
| [docs/ja/data-model.md](docs/ja/data-model.md) | ノード/エッジ定義、PIR 重み付け計算式、FollowedBy 重み計算 |
| [docs/ja/local-testing.md](docs/ja/local-testing.md) | Spanner エミュレーター、ユニットテスト、サンプルフィクスチャ |
| [docs/ja/dependencies.md](docs/ja/dependencies.md) | 依存パッケージの選定理由とライセンス情報 |

## クイックスタート

```sh
git clone https://github.com/sw33t-b1u/sage.git
cd sage
uv sync --extra dev
cp .env.example .env   # GCP_PROJECT_ID, SPANNER_*, GCS_*, OPENCTI_* を入力
make setup             # Git フックをインストール
```

詳細なセットアップ手順は [docs/ja/setup.md](docs/ja/setup.md) を参照。

## ディレクトリ構成

詳細なディレクトリレイアウトと設計方針は [docs/ja/structure.md](docs/ja/structure.md) を参照。

## 開発

```sh
make check     # lint + test + audit（フル品質ゲート）
make vet       # ruff check
make lint      # ruff format --check
make format    # ruff format + fix
make test      # pytest
make audit     # pip-audit
make setup     # Git フックをインストール（pre-commit: vet lint、pre-push: check）
```

## GCP インフラ構成

```
Spanner (us-central1)       — ThreatIntelGraph
Cloud Storage               — STIX ランディングゾーン（90 日 TTL）
Cloud Run                   — ETL ワーカー + Analysis API
Cloud Scheduler             — 日次 ETL トリガー（03:00 JST）
Secret Manager              — API トークンと認証情報
```

## ライセンス

Apache-2.0 — [LICENSE](LICENSE) を参照
