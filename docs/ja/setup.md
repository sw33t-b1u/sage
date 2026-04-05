# SAGE — セットアップガイド

英語版（正本）: [`docs/setup.md`](../setup.md)

## 前提条件

- Python 3.12+
- [uv](https://github.com/astral-sh/uv)
- 課金が有効な Google Cloud プロジェクト
- OpenCTI インスタンス（ライブ CTI 取り込み用。手動 STIX バンドルモードでは不要）

---

## Step 1 — クローンとインストール

```sh
git clone https://github.com/sw33t-b1u/sage.git
cd sage
uv sync --extra dev
```

Git フックをインストールする（pre-commit: `vet lint`、pre-push: `make check`）:

```sh
make setup
```

---

## Step 2 — 環境変数の設定

`.env.example` を `.env` にコピーして値を入力する。

| 変数 | 必須 | デフォルト | 説明 |
|------|------|-----------|------|
| `GCP_PROJECT_ID` | Yes | — | GCP プロジェクト ID |
| `SPANNER_INSTANCE_ID` | Yes | — | Spanner インスタンス ID |
| `SPANNER_DATABASE_ID` | Yes | — | Spanner データベース ID |
| `GCS_LANDING_BUCKET` | Yes | — | 生 STIX を受け取る GCS バケット |
| `OPENCTI_URL` | Yes | — | OpenCTI ベース URL |
| `OPENCTI_TOKEN` | Yes | — | OpenCTI API トークン |
| `PIR_FILE_PATH` | No | `/config/pir.json` | PIR JSON ファイルのパス |
| `TLP_MAX_LEVEL` | No | `amber` | 取り込む最大 TLP レベル（`white`/`green`/`amber`） |
| `ACTIVITY_WINDOW_DAYS` | No | `90` | FollowedBy アクティビティスコアの振り返り期間（日） |
| `SLACK_WEBHOOK_URL` | No | — | ETL 完了通知用 Slack Incoming Webhook URL |
| `GHE_TOKEN` | No | — | GitHub Enterprise Personal Access Token |
| `GHE_REPO` | No | — | GHE リポジトリ（`owner/repo` 形式） |
| `GHE_API_BASE` | No | `https://api.github.com` | GHE API ベース URL（セルフホスト時に上書き） |
| `CALDERA_URL` | No | — | MITRE Caldera サーバー URL |
| `CALDERA_API_KEY` | No | — | Caldera REST API キー |
| `SAGE_API_URL` | No | — | 稼働中の Analysis API のベース URL |
| `OTEL_SDK_DISABLED` | No | — | `true` に設定すると Spanner クライアントのメトリクスエクスポートエラーを抑制 |

---

## Step 3 — GCP リソースの作成

```sh
export PROJECT_ID=your-project-id
export REGION=us-central1
export SPANNER_INSTANCE=sage-instance
export SPANNER_DB=sage-db
export GCS_BUCKET=sage-landing-${PROJECT_ID}

# 必要な API を有効化
gcloud services enable spanner.googleapis.com storage.googleapis.com \
  --project=${PROJECT_ID}

# Spanner インスタンスを作成
gcloud spanner instances create ${SPANNER_INSTANCE} \
  --config=regional-${REGION} \
  --description="SAGE Threat Intelligence" \
  --nodes=1 \
  --project=${PROJECT_ID}

# Spanner データベースを作成
gcloud spanner databases create ${SPANNER_DB} \
  --instance=${SPANNER_INSTANCE} \
  --project=${PROJECT_ID}

# GCS ランディングバケットを作成
gcloud storage buckets create gs://${GCS_BUCKET} \
  --location=${REGION} \
  --project=${PROJECT_ID}
```

> **コスト注記:** 1 ノード Spanner インスタンスは約 $0.90/時間。評価時のコスト最小化には `--nodes=1` の代わりに `--processing-units=100` を使用。

---

## Step 4 — Spanner スキーマの初期化

```sh
make init-schema
```

---

## Step 5 — 初期資産データの投入

`tests/fixtures/sample_assets.json` を実際の資産インベントリに合わせて編集し、実行する:

```sh
uv run python cmd/load_assets.py

# カスタムファイルを使用する場合:
uv run python cmd/load_assets.py --file path/to/assets.json
```

---

## Step 6 — PIR ファイルの配置

[BEACON](https://github.com/sw33t-b1u/beacon) で PIR JSON を生成し、`PIR_FILE_PATH` に配置する:

```sh
cp /path/to/pir_output.json /path/to/config/pir.json
# または .env で PIR_FILE_PATH を直接指定
```

---

## Step 7 — ETL の手動実行（初回確認）

```sh
# OpenCTI 不要 — ローカルの STIX バンドルを使用
uv run python cmd/run_etl.py --manual-bundle tests/fixtures/sample_bundle_mirrorface.json

# ライブの OpenCTI に対して実行
make run-etl
```

---

## Step 8 — ETL ワーカーを Cloud Run にデプロイ

```sh
export PROJECT_ID=your-project-id
export REGION=us-central1
export IMAGE=gcr.io/${PROJECT_ID}/sage-etl

# コンテナイメージをビルドしてプッシュ
gcloud builds submit --tag ${IMAGE} --project=${PROJECT_ID}

# デプロイ
gcloud run deploy sage-etl \
  --image=${IMAGE} \
  --region=${REGION} \
  --no-allow-unauthenticated \
  --set-secrets="OPENCTI_TOKEN=opencti-token:latest,GCS_LANDING_BUCKET=sage-bucket:latest" \
  --set-env-vars="GCP_PROJECT_ID=${PROJECT_ID},SPANNER_INSTANCE_ID=sage-instance,SPANNER_DATABASE_ID=sage-db,PIR_FILE_PATH=/config/pir.json" \
  --project=${PROJECT_ID}
```

> **Secret Manager:** `gcloud secrets create opencti-token --data-file=- <<< "your-token"` で機密値を登録し、`--set-env-vars` の代わりに `--set-secrets` で参照する。

> **サービスアカウント:** デプロイ前に専用のサービスアカウントを作成し、`roles/spanner.databaseUser`、`roles/storage.objectViewer`、`roles/run.invoker` を付与する。

---

## Step 9 — Cloud Scheduler の設定（日次 ETL）

```sh
export ETL_URL=$(gcloud run services describe sage-etl \
  --region=${REGION} --format='value(status.url)' --project=${PROJECT_ID})

gcloud services enable cloudscheduler.googleapis.com --project=${PROJECT_ID}

# 毎日 03:00 JST（18:00 UTC）
gcloud scheduler jobs create http sage-daily-etl \
  --location=${REGION} \
  --schedule="0 18 * * *" \
  --uri="${ETL_URL}" \
  --oidc-service-account-email="sage-etl@${PROJECT_ID}.iam.gserviceaccount.com" \
  --time-zone="UTC" \
  --project=${PROJECT_ID}
```
