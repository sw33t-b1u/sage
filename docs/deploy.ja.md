# SAGE — デプロイガイド

英語版（正本）: [`docs/deploy.md`](deploy.md)

このガイドは [setup.ja.md](setup.ja.md) の手順が完了していることを前提とする。デプロイ前に `make check` がパスすることを確認すること。

---

## Step 8 — ETL ワーカーを Cloud Run にデプロイ

```sh
# .env を未読み込みの場合は読み込む
source .env
export REGION=${REGION:-us-central1}

# Artifact Registry リポジトリを作成（初回のみ）
gcloud artifacts repositories create cloud-run \
  --repository-format=docker \
  --location=${REGION} \
  --project=${PROJECT_ID}

export IMAGE=${REGION}-docker.pkg.dev/${PROJECT_ID}/cloud-run/sage-etl

# コンテナイメージをビルドしてプッシュ
gcloud builds submit --tag ${IMAGE} --project=${PROJECT_ID}

# デプロイ
gcloud run deploy sage-etl \
  --image=${IMAGE} \
  --region=${REGION} \
  --no-allow-unauthenticated \
  --set-secrets="OPENCTI_TOKEN=opencti-token:latest,GCS_BUCKET=sage-bucket:latest" \
  --set-env-vars="PROJECT_ID=${PROJECT_ID},SPANNER_INSTANCE=${SPANNER_INSTANCE},SPANNER_DB=${SPANNER_DB},PIR_FILE_PATH=/config/pir.json" \
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
