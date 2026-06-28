# SAGE — 使用ガイド

英語版（正本）: [`docs/usage.md`](usage.md)

CTI アナリストおよびブルーチームメンバー向けの日常ワークフローを説明する。

## 前提条件

- `uv sync --extra dev` が SAGE ディレクトリで完了していること
- `.env` が設定されていること。既定バックエンドは SQLite（`SAGE_DB=sqlite`）で
  GCP の値は不要。任意の Spanner バックエンドを使う場合は `SAGE_DB=spanner` と
  Spanner 認証情報を設定する
- ローカルマシンで `gcloud auth application-default login` が完了していること
  （GCS ストレージまたは Spanner バックエンドを使う場合のみ）

---

## 日常ワークフロー

### 1. ETL の自動実行（JST 03:00、Cloud Scheduler）

`SLACK_WEBHOOK_URL` が設定されている場合、以下の内容を含む Slack 通知が届く:
- 新規/更新された脅威アクター・TTP・脆弱性の取り込み件数
- 上位チョークポイント資産とそのスコア（前回実行との比較）

ETL を手動で実行するには:

```sh
# ライブの OpenCTI に対して実行
make run-etl

# ローカルの STIX バンドルを使用（OpenCTI 不要）
uv run sage run-etl --input tests/fixtures/sample_bundle_mirrorface.json
```

---

### 2. チョークポイントの確認

チョークポイントは `choke_score = pir_adjusted_criticality × targeting_actor_count` が最も高い資産。最優先の強化対象となる。

```sh
# 上位 10 件をターミナルに表示
uv run sage report-choke-points --top 10

# Markdown として保存
uv run sage report-choke-points --top 10 --output /tmp/choke_report.md

# GitHub Enterprise Issue として投稿（GHE_TOKEN と GHE_REPO が必要）
uv run sage report-choke-points --ghe
```

出力例:

```
# SAGE Choke Point Report — 2026-04-05

| Rank | Asset                  | choke_score | pir_adjusted_criticality | Targeting Actors  |
|------|------------------------|-------------|--------------------------|-------------------|
| 1    | 統合認証基盤            | 42.0        | 10.0                     | APT10, Lazarus    |
| 2    | メッセージング基盤      | 30.0        | 10.0                     | APT10             |
```

---

### 3. 資産 ID・アクター STIX ID の確認

**資産 ID** は `assets.json` ファイルの `id` フィールドで定義される。
投入後はデータベースから検索することもできる:

```sh
# SQLite バックエンド（既定）
sqlite3 output/db/sage.db \
  "SELECT id, name, criticality, pir_adjusted_criticality FROM Asset ORDER BY pir_adjusted_criticality DESC LIMIT 20"

# Spanner バックエンド（SAGE_DB=spanner）
gcloud spanner databases execute-sql sage-db \
  --instance=sage-instance \
  --sql="SELECT id, name, criticality, pir_adjusted_criticality FROM Asset ORDER BY pir_adjusted_criticality DESC LIMIT 20"
```

**アクター STIX ID** は OpenCTI によって割り当てられるか、STIX バンドルファイルに含まれている。
ETL 後に検索できる:

```sh
# SQLite バックエンド（既定）
sqlite3 output/db/sage.db \
  "SELECT stix_id, name, tags FROM ThreatActor ORDER BY name LIMIT 50"

# Spanner バックエンド（SAGE_DB=spanner）
gcloud spanner databases execute-sql sage-db \
  --instance=sage-instance \
  --sql="SELECT stix_id, name, tags FROM ThreatActor ORDER BY name LIMIT 50"
```

チョークポイントレポートには各資産のターゲティングアクター名も表示される。それを使って上記クエリで STIX ID を取得する。

### 4. 特定の資産・アクターの調査

```sh
# 特定の資産を狙う攻撃経路
uv run sage query-attack-paths --asset-id asset-xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx

# 特定のアクターが使用する全 TTP
uv run sage query-attack-paths --actor-id intrusion-set--xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx
```

---

### 5. グラフの可視化（オンデマンド）

インタラクティブな HTML ファイルを生成してブラウザで開く。ノードはタイプ別に色分けされ、ドラッグ・ズームが可能。設定されたデータベースバックエンド（`SAGE_DB`）に対してローカルで動作する。

```sh
# 統合ビュー（攻撃グラフ + FollowedBy 重み付き攻撃フロー）
uv run sage visualize-combined --output /tmp/sage_combined.html

# 特定アクターに絞る
uv run sage visualize-combined --actor-id "intrusion-set--xxx"

# 攻撃グラフのみ（全ノード、均一エッジ）
uv run sage visualize-graph --output /tmp/sage_graph.html

# 攻撃フローのみ（FollowedBy 重み付き TTP 遷移）
uv run sage visualize-attack-flow --output /tmp/attack_flow.html

# ブラウザ自動起動を抑制 / テーブルごとの行数を制限
uv run sage visualize-combined --no-open --limit 200
```

> `make visualize` はローカル/エミュレーター用のショートカット。本番データに対しては上記コマンドを直接実行する。

---

### 6. Analysis API を使ったクエリ（オプション）

他のツールとの統合やアドホッククエリのために、API サーバーをローカルで起動する（起動時に設定されたデータベースを materialize し read-only で開く）:

```sh
uv run sage serve-api --port 8080
```

起動後は `http://localhost:8080/docs` でインタラクティブな API ドキュメント（Swagger UI）を参照できる。

利用可能なエンドポイント:

| エンドポイント | 説明 |
|--------------|------|
| `GET /choke-points?top_n=10` | スコア上位 N 件のチョークポイント資産 |
| `GET /asset-exposure` | ターゲティングアクター数を含む全資産一覧 |
| `GET /attack-paths?asset_id=<id>` | 指定資産への攻撃経路 |
| `GET /actor-ttps?actor_id=<id>` | 脅威アクターに関連する TTP |
| `GET /actors?name=<query>&limit=20` | 脅威アクター名の部分一致検索（大小文字不問、最小 2 文字） |
| `GET /indicators?actor_id=<id>` | 選択アクターに直接紐づく Observable（`actor_id` を繰り返して複数選択） |
| `GET /export/stix?actor_id=<id>&download=true` | 直接紐づく indicator の STIX 2.1 bundle サブセット（ファイルダウンロード） |
| `GET /similar-incidents?incident_id=<id>` | 指定インシデントに類似した過去インシデント |

**アクター名検索の例:**

```sh
# "apt" を含むアクターを検索
curl "http://localhost:8080/actors?name=apt"

# "lazarus" を含むアクターを上位 5 件取得
curl "http://localhost:8080/actors?name=lazarus&limit=5"
```

レスポンス形式: `{"actors": [{stix_id, name, description, aliases, first_seen, last_seen, sophistication_level}, …], "count": N}`

**手動ハンティング向け STIX 抽出:**

```sh
# 選択した1つ以上のアクターに直接紐づく indicator（複数選択は actor_id を繰り返す）
curl "http://localhost:8080/indicators?actor_id=intrusion-set--<a>&actor_id=intrusion-set--<b>"

# STIX 2.1 bundle サブセット（indicator + actor + indicates + TLP marking）をダウンロード
curl -OJ "http://localhost:8080/export/stix?actor_id=intrusion-set--<a>&download=true"
```

`/indicators` と `/export/stix` は、選択アクターに `IndicatesActor` エッジで
**直接**紐づく Observable のみを返す（TTP/malware 経由の多段は対象外）。TLP Red は除外。
出力 bundle は人手レビューと手動 SIEM 取り込み用で、SAGE は SIEM へ送信しない。

**StorageBackend 経由でのアーティファクトロード:**

`SAGE_STORAGE_BASE_DIR` が共有の `output/` ディレクトリを指している場合（デフォルト）、
`--input` を省略するとアセットロードコマンドが自動検出する:

```sh
# StorageBackend の assets/ カテゴリから自動取得
uv run sage load-assets
uv run sage load-identity-assets
uv run sage load-user-accounts

# StorageBackend の stix/ カテゴリから全 STIX バンドルを ETL 処理
uv run sage run-etl
```

StorageBackend は `SAGE_STORAGE`（`local` または `gcs`）、`SAGE_STORAGE_BASE_DIR`（デフォルト: `output`）、`SAGE_STORAGE_BUCKET`、`SAGE_STORAGE_PREFIX` で設定する。

---

## 四半期 PIR 更新ワークフロー

組織の状況変化（新プロジェクト、M&A、規制改定、新たな重要資産）が生じた際に実行する:

```
1. business_context.json（または .md）を更新  ← BEACON リポジトリで実施
2. uv run beacon pir-generate ...               ← BEACON リポジトリで実行（BEACON ドキュメント参照）
3. cp pir_output.json /path/to/config/pir.json
4. make run-etl                                  ← 新しい PIR 重みを適用するために ETL を再実行
5. uv run sage report-choke-points               ← クリティカリティの変化を確認
```

PIR の生成（Step 2）は SAGE ではなく [BEACON](https://github.com/sw33t-b1u/beacon) で行う。
詳細は BEACON ドキュメントを参照。

---

## IR 対応ワークフロー

インシデントが検知または疑われる場合:

```sh
# IR インシデントテンプレートを GHE Issue として作成
uv run sage ir-template \
  --actor-id <stix-id> \
  --asset-id <asset-id>

# レッドチームシミュレーション用にアクターの TTP を Caldera に同期（CALDERA_URL が必要）
uv run sage sync-caldera --actor-id <stix-id>
```

### 直接 IR フィードバック登録（`sage incident-register`）

`sage incident-register` CLI を使うと、IR チームはインシデント発生当日に登録できる（OpenCTI の 24 時間ポーリング遅延との対比）。4 つのモード:

```sh
# 1) インタラクティブ — Diamond Model 4 象限をプロンプトで入力。
uv run sage incident-register \
  --name "MIR-4242 mail relay compromise" \
  --occurred-at 2026-05-20T12:34:56Z \
  --severity high

# 2) 非インタラクティブフラグモード（--diamond key=value で Diamond Model を指定）。
uv run sage incident-register \
  --name "MIR-4242" --occurred-at 2026-05-20T12:34:56Z --severity high \
  --diamond adversary=APT99 \
  --diamond capability="spear-phishing kit" \
  --diamond infrastructure="fastflux nodes" \
  --diamond victim="mail relay asset-001" \
  --no-interactive

# 3) MITRE Navigator レイヤーインポート — Navigator UI からの TTP シーケンス。
uv run sage incident-register \
  --name "MIR-4242" --occurred-at 2026-05-20T12:34:56Z --severity high \
  --navigator-layer ./layer.json \
  --no-interactive

# 4) エアギャップ / トークンレス — API をバイパスしてデータベースに直接書き込む。
uv run sage incident-register \
  --from-file ./payload.json \
  --no-api --no-interactive
```

デフォルト: `incident_stix_id` は `incident--<uuid4>` として自動生成（`--id` で上書き可）。Bearer トークンは `$SAGE_API_AUTH_TOKEN` から読み込み、API ベース URL は `$SAGE_API_URL`（未設定時は `http://localhost:8000`）から読み込む。

---

## ETL パイプライン操作

### ETL の手動実行

```sh
# ライブの OpenCTI に対して実行
make run-etl

# ローカルの STIX バンドルを使用（OpenCTI 不要）
uv run sage run-etl --input tests/fixtures/sample_bundle_mirrorface.json

# StorageBackend の stix/ カテゴリから全バンドルを処理
uv run sage run-etl
```

### スケジュール実行（Cloud Scheduler）

ETL は Cloud Scheduler によって毎日 JST 03:00（UTC 18:00）に自動実行される。ジョブ名は `sage-daily-etl` で、`sage-etl` Cloud Run サービスをターゲットとする。

スケジューラの状態確認:

```sh
gcloud scheduler jobs describe sage-daily-etl --location=${REGION} --project=${GCP_PROJECT_ID}
```

スケジュールジョブを即時トリガー:

```sh
gcloud scheduler jobs run sage-daily-etl --location=${REGION} --project=${GCP_PROJECT_ID}
```

### ETL モニタリング（Slack 通知）

`SLACK_WEBHOOK_URL` が設定されている場合、各 ETL 実行完了時に以下を含む Slack 通知が届く:

- 新規/更新された脅威アクター・TTP・脆弱性の取り込み件数
- 上位チョークポイント資産とそのスコア（前回実行との比較）

`.env` で Webhook を設定する:

```
SLACK_WEBHOOK_URL=https://hooks.slack.com/services/...
```

---

## Analysis API ヘルスチェック

API サーバーをローカルで起動:

```sh
uv run sage serve-api --port 8080
```

ヘルス・スモークチェック:

```sh
curl http://localhost:8080/choke-points?top_n=5
curl http://localhost:8080/asset-exposure
curl http://localhost:8080/actors?name=apt&limit=5
```

インタラクティブな API ドキュメント（Swagger UI）は `http://localhost:8080/docs` で参照できる。

本番環境（Cloud Run、VPC 内）では Bearer トークンが必要:

```sh
curl -H "Authorization: Bearer ${SAGE_API_AUTH_TOKEN}" \
  https://<cloud-run-url>/choke-points?top_n=5
```

---

## データベースのデータ管理

**SQLite バックエンド（既定）:** 同じ DML をデータベースファイルに対して直接実行する
— テーブル名・カラム名は Spanner DDL と同一:

```sh
sqlite3 output/db/sage.db \
  "DELETE FROM ThreatActor WHERE stix_id = 'intrusion-set--xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx'"
```

完全リセットはファイルを削除する（`rm output/db/sage.db`）— スキーマは次回実行時に
自動的に再作成される。`SAGE_STORAGE=gcs` の場合は、ダウンロードしたコピーを編集して
`db/sage.db` オブジェクトに再アップロードするか、完全リセットならオブジェクトを削除する。

**Spanner バックエンド（`SAGE_DB=spanner`）:** 以下の各セクションでは
`gcloud spanner databases execute-sql` を使用する。

### STIX ID によるノード削除

```sh
# ThreatActor を削除
gcloud spanner databases execute-sql ${SPANNER_DB} \
  --instance=${SPANNER_INSTANCE} --project=${GCP_PROJECT_ID} \
  --sql="DELETE FROM ThreatActor WHERE stix_id = 'intrusion-set--xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx'"

# TTP を削除（参照する FollowedBy エッジも削除される）
gcloud spanner databases execute-sql ${SPANNER_DB} \
  --instance=${SPANNER_INSTANCE} --project=${GCP_PROJECT_ID} \
  --sql="DELETE FROM TTP WHERE stix_id = 'attack-pattern--xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx'"

# 誤ってロードした Asset を削除
gcloud spanner databases execute-sql ${SPANNER_DB} \
  --instance=${SPANNER_INSTANCE} --project=${GCP_PROJECT_ID} \
  --sql="DELETE FROM Asset WHERE id = 'asset-001-xxxxx-xxxx-xxxxxxxxxxxx'"
```

### エッジのみ削除（ノードは保持）

```sh
# 特定アクターの全 Targets エッジを削除
gcloud spanner databases execute-sql ${SPANNER_DB} \
  --instance=${SPANNER_INSTANCE} --project=${GCP_PROJECT_ID} \
  --sql="DELETE FROM Targets WHERE src_actor_stix_id = 'intrusion-set--xxxx'"

# 特定ソースからの FollowedBy エッジを削除
gcloud spanner databases execute-sql ${SPANNER_DB} \
  --instance=${SPANNER_INSTANCE} --project=${GCP_PROJECT_ID} \
  --sql="DELETE FROM FollowedBy WHERE source = 'manual'"
```

### 全データリセット（スキーマ保持）

```sh
# Spanner バックエンド: 全テーブルを DROP して再作成 — クリーンな状態が必要な
# 場合のみ使用。SQLite では DDL が CREATE TABLE IF NOT EXISTS（DROP なし）の
# ため、代わりにデータベースファイルを削除する。
make init-schema
```

---

## StorageBackend 管理

SAGE は `StorageBackend` 抽象化（Decision I-12）を採用する。環境変数で設定:

| 変数 | デフォルト | 用途 |
|------|-----------|------|
| `SAGE_STORAGE` | `local` | バックエンド種別: `local` または `gcs` |
| `SAGE_STORAGE_BASE_DIR` | `output` | ローカルストレージのベースディレクトリ（TRACE/BEACON と共有） |
| `SAGE_STORAGE_BUCKET` | (なし) | GCS バケット名（`SAGE_STORAGE=gcs` 時に必須） |
| `SAGE_STORAGE_PREFIX` | (なし) | GCS オブジェクトキーのプレフィックス（任意） |

`--input` を省略すると StorageBackend から自動取得:

```sh
uv run sage load-assets
uv run sage load-identity-assets
uv run sage load-user-accounts
uv run sage run-etl          # stix/ カテゴリの全バンドルを処理
```

---

## Slack / GHE 通知設定

### Slack

`.env` に `SLACK_WEBHOOK_URL` を設定する。ETL ワーカーとチョークポイントレポーターの両方がこの Webhook を使用する。

### GitHub Enterprise

`GHE_TOKEN`、`GHE_REPO`（形式: `owner/repo`）、および任意で `GHE_API_BASE`（デフォルト: `https://api.github.com`、セルフホスト GHE 時は上書き）を設定する。

```sh
# チョークポイントレポートを GHE Issue として投稿
uv run sage report-choke-points --ghe
```

---

## トラブルシューティング

### ETL で新規オブジェクトが 0 件

- OpenCTI の接続確認: `curl ${OPENCTI_URL}/graphql -H "Authorization: Bearer ${OPENCTI_TOKEN}"`
- StorageBackend の `stix/` カテゴリに STIX バンドルが存在するか確認。
- データベースの既存データを確認: `sqlite3 output/db/sage.db "SELECT COUNT(*) FROM ThreatActor"`（Spanner バックエンドでは `gcloud spanner databases execute-sql` の同等コマンド）

### `OTEL_SDK_DISABLED` メトリクスエクスポートエラー（Spanner バックエンドのみ）

メトリクスバックエンドのない環境での Spanner クライアント OpenTelemetry エクスポートエラーを抑制するには、`.env` に `OTEL_SDK_DISABLED=true` を設定する。

### スキーマ初期化時の Spanner `ALREADY_EXISTS` エラー（`SAGE_DB=spanner`）

スキーマが既に初期化されている。`make init-schema` はクリーンな状態が必要な場合のみ実行する — Spanner バックエンドでは全テーブルが DROP される。

### Analysis API が 401 を返す

`SAGE_API_AUTH_TOKEN` が設定されており、API サーバーの起動時に使用したトークンと一致しているか確認する。

### StorageBackend のパスミスマッチ

`SAGE_STORAGE=local` の場合、SAGE・TRACE・BEACON はすべて同じ `output/` ベースディレクトリを共有する必要がある。作業ディレクトリに依存しないよう `SAGE_STORAGE_BASE_DIR`（および TRACE/BEACON の同等の変数）に絶対パスを設定する。
