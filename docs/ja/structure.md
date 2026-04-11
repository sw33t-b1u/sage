# SAGE — プロジェクトディレクトリ構成

英語版（正本）: [`docs/structure.md`](../structure.md)

このドキュメントは SAGE リポジトリのトップレベルレイアウトを説明します。

```
SAGE/
├── src/sage/                   # コア Python パッケージ
│   ├── config.py               # 環境変数ベース設定（Config dataclass）
│   ├── etl/
│   │   └── worker.py           # ETL パイプラインオーケストレーター
│   ├── stix/
│   │   ├── parser.py           # STIX 2.1 バンドルの解析とバリデーション
│   │   └── mapper.py           # STIX オブジェクト → Spanner ノード/エッジ行
│   ├── pir/
│   │   └── filter.py           # PIR 関連度フィルタリングと資産クリティカリティ重み付け
│   ├── spanner/
│   │   ├── client.py           # Spanner Database クライアントのセットアップ
│   │   ├── upsert.py           # 一括 upsert ヘルパー（INSERT OR UPDATE）
│   │   └── query.py            # 分析クエリ関数（GQL + SQL）
│   ├── notify/
│   │   ├── slack.py            # Slack Webhook 通知
│   │   └── github.py           # GitHub / GHE Issue の作成・更新
│   ├── api/
│   │   └── app.py              # FastAPI Analysis API（内部 REST エンドポイント）
│   ├── caldera/
│   │   └── client.py           # MITRE Caldera REST API クライアント
│   ├── analysis/
│   │   └── similarity.py       # ハイブリッドインシデント類似度スコアリング
│   └── opencti/
│       └── client.py           # OpenCTI STIX 2.1 エクスポートクライアント
│
├── cmd/                        # CLI エントリポイント（コマンドごとに1スクリプト）
│   ├── init_schema.py          # Spanner Graph DDL の初期化
│   ├── run_etl.py              # ETL パイプラインの実行
│   ├── load_assets.py          # 内部資産データを Spanner にロード
│   ├── report_choke_points.py  # チョークポイントレポートの出力/エクスポート/投稿
│   ├── query_attack_paths.py   # 攻撃経路または脅威アクター TTP のクエリ
│   ├── visualize_graph.py      # インタラクティブな攻撃グラフ HTML を生成
│   ├── visualize_attack_flow.py# インタラクティブな攻撃フロー HTML を生成
│   ├── analysis_api.py         # Analysis API サーバーの起動
│   ├── sync_caldera.py         # 脅威アクター TTP を Caldera アドバーサリプロファイルに同期
│   ├── create_ir_template.py   # IR インシデントテンプレートを GHE Issue として作成
│   └── setup_emulator.py       # ローカルテスト用 Spanner エミュレーターの設定
│
├── schema/
│   └── spanner_ddl.sql         # Spanner Graph DDL（ノード・エッジ・プロパティグラフ）
│
├── tests/
│   ├── fixtures/               # サンプル STIX バンドル・資産 JSON・PIR JSON
│   └── test_*.py               # pytest テストファイル
│
├── docs/                       # 英語ドキュメント（正本）
│   ├── setup.md                # GCP リソース作成・デプロイ・スケジューラ設定
│   ├── analyst-guide.md        # CTI アナリスト向け日常利用ガイド
│   ├── data-model.md           # ノード/エッジ定義・PIR 計算式・FollowedBy 重み
│   ├── local-testing.md        # Spanner エミュレーターのセットアップとユニットテスト手順
│   ├── dependencies.md         # サードパーティ依存の選定理由とライセンス
│   ├── structure.md            # ディレクトリレイアウトリファレンス（英語正本）
│   └── ja/                     # 日本語翻訳（英語版と同期して維持）
│
├── .githooks/                  # Git フック（make setup でインストール）
│   ├── pre-commit              # コミット前に make vet lint を実行
│   └── pre-push                # プッシュ前に make check を実行
│
├── high-level-design.md        # システム設計ドキュメント（正本）
├── CHANGELOG.md                # バージョン履歴
├── Dockerfile                  # Cloud Run デプロイ用コンテナイメージ
├── Makefile                    # 品質ゲートターゲット（check, vet, lint, test, audit, setup）
├── pyproject.toml              # Python プロジェクト設定（uv + ruff）
├── uv.lock                     # 依存バージョンのロックファイル
└── .env.example                # 環境変数設定テンプレート
```

## 設計方針

- **`src/sage/`** はすべての再利用可能なライブラリコードを含みます。各サブパッケージは単一の責務を持ちます。
- **`cmd/`** には引数解析と `src/sage/` モジュールへの委譲のみを行う薄い CLI スクリプトを置きます。ビジネスロジックはここに書きません。
- **`schema/`** は Spanner Graph DDL の唯一の情報源です。
- **`docs/`** は英語の利用者向けドキュメントを保持します。`docs/ja/` は日本語翻訳で、英語版と同期して維持します。
- **`high-level-design.md`** はアーキテクチャ変更を実装する前に更新しなければなりません（Rule 27）。
