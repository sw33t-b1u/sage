# SAGE — Cloud Run デプロイガイド

英語版（正本）: [`docs/deploy.md`](deploy.md)

デプロイ前に [docs/setup.ja.md](setup.ja.md) の手順を完了すること。デプロイ前に `make check` がパスすることを確認すること。

---

## Day-0 前提条件

### API の有効化

```sh
source .env
export REGION=${REGION:-us-central1}

gcloud services enable \
  run.googleapis.com \
  artifactregistry.googleapis.com \
  cloudbuild.googleapis.com \
  spanner.googleapis.com \
  cloudscheduler.googleapis.com \
  --project=${GCP_PROJECT_ID}
```

### Artifact Registry リポジトリの作成

```sh
gcloud artifacts repositories create cloud-run \
  --repository-format=docker \
  --location=${REGION} \
  --project=${GCP_PROJECT_ID}
```

### サービスアカウントの作成と IAM ロールの付与

デプロイコマンドでサービスアカウントを参照する前に、`sage-etl` サービスアカウントを作成して必要なロールを付与しておく。

```sh
gcloud iam service-accounts create sage-etl \
  --display-name="SAGE ETL Job" \
  --project=${GCP_PROJECT_ID}

for ROLE in roles/spanner.databaseUser roles/storage.objectViewer roles/run.invoker; do
  gcloud projects add-iam-policy-binding ${GCP_PROJECT_ID} \
    --member="serviceAccount:sage-etl@${GCP_PROJECT_ID}.iam.gserviceaccount.com" \
    --role="${ROLE}"
done

# TRACE 出力 bucket に対する bucket-level binding
# （project-wide な objectViewer を避ける least-privilege 代替）:
gcloud storage buckets add-iam-policy-binding gs://${TRACE_STORAGE_BUCKET} \
  --member="serviceAccount:sage-etl@${GCP_PROJECT_ID}.iam.gserviceaccount.com" \
  --role="roles/storage.objectViewer"
```

### GCS バケットの作成（未作成の場合）

```sh
# ETL 入力バケット — TRACE が STIX バンドルを書き込み、SAGE がここから読み込む
gcloud storage buckets create gs://${SAGE_ETL_INPUT_BUCKET} \
  --location=${REGION} \
  --project=${GCP_PROJECT_ID}

# ストレージバックエンドバケット（SAGE_STORAGE=gcs の場合のみ）
gcloud storage buckets create gs://${SAGE_STORAGE_BUCKET} \
  --location=${REGION} \
  --project=${GCP_PROJECT_ID}
```

---

## Day-1 初回デプロイ

### sage-etl（Cloud Run Job）

```sh
export IMAGE=${REGION}-docker.pkg.dev/${GCP_PROJECT_ID}/cloud-run/sage-etl

# Cloud Build でコンテナイメージをビルドしてプッシュ
gcloud builds submit --tag ${IMAGE} --project=${GCP_PROJECT_ID}

# Cloud Run Job を作成
gcloud run jobs create sage-etl \
  --image=${IMAGE} \
  --region=${REGION} \
  --service-account="sage-etl@${GCP_PROJECT_ID}.iam.gserviceaccount.com" \
  --set-env-vars="GCP_PROJECT_ID=${GCP_PROJECT_ID},SPANNER_INSTANCE=${SPANNER_INSTANCE},SPANNER_DB=${SPANNER_DB},PIR_FILE_PATH=/config/pir.json,OPENCTI_URL=https://example.com,OPENCTI_TOKEN=skip,SAGE_STORAGE=gcs,SAGE_ETL_INPUT_BUCKET=${SAGE_ETL_INPUT_BUCKET},SAGE_STORAGE_BUCKET=${SAGE_STORAGE_BUCKET},SAGE_STORAGE_PREFIX=trace/" \
  --add-volume=name=pir,type=cloud-storage,bucket=${PIR_GCS_BUCKET},mount-options="only-dir=pir" \
  --add-volume-mount=volume=pir,mount-path=/config \
  --project=${GCP_PROJECT_ID}
```

> **`SAGE_STORAGE=gcs` + `SAGE_ETL_INPUT_BUCKET` + `SAGE_STORAGE_PREFIX`:** TRACE が生成
> した STIX バンドルを `run-etl` が読み込むために必須。`SAGE_ETL_INPUT_BUCKET` は
> TRACE が書き込むバケット（典型的には `${TRACE_STORAGE_BUCKET}`、TRACE デプロイ
> ガイド参照）、`SAGE_STORAGE_PREFIX` は TRACE のプレフィックス（`trace/`）を指定する。
> ETL は `${SAGE_STORAGE_PREFIX}/stix/` 配下を探す。設定しないと OpenCTI モードに
> フォールバックし、`OPENCTI_TOKEN=skip` の構成では失敗する。

> **`mount-options="only-dir=pir"`:** PIR バケットは他の成果物（raw STIX
> landing 等）も保持しうるため、`only-dir=pir` で `pir/` サブディレクトリのみ
> を `/config/` に露出させ、ファイルが `/config/pir.json` として解決されるようにする。バケットが PIR 専用なら省略可。

> **OpenCTI なし構成:** OpenCTI インスタンスに接続しない場合は、上記のように `OPENCTI_URL=https://example.com` と `OPENCTI_TOKEN=skip` を渡す。ETL ジョブは OpenCTI 取り込みをスキップし、GCS 上の STIX バンドルを処理する。

> **PIR ファイルの供給:** `pir.json` はコンテナイメージに含まれない。上記の GCS ボリュームマウント（`--add-volume` / `--add-volume-mount`）を使ってランタイムに供給する。`only-dir=pir` を指定する構成ではジョブ実行前に `gs://${PIR_GCS_BUCKET}/pir/pir.json` が必要。`only-dir` を省略した場合は `gs://${PIR_GCS_BUCKET}/pir.json` に置く。

### （オプション）日次 ETL トリガー用 Cloud Scheduler

```sh
# 毎日 03:00 JST（18:00 UTC）
gcloud scheduler jobs create http sage-daily-etl \
  --location=${REGION} \
  --schedule="0 18 * * *" \
  --uri="https://${REGION}-run.googleapis.com/apis/run.googleapis.com/v1/namespaces/${GCP_PROJECT_ID}/jobs/sage-etl:run" \
  --message-body="{}" \
  --oauth-service-account-email="sage-etl@${GCP_PROJECT_ID}.iam.gserviceaccount.com" \
  --time-zone="UTC" \
  --project=${GCP_PROJECT_ID}
```

> **手動実行:** `gcloud run jobs execute sage-etl --region=${REGION} --project=${GCP_PROJECT_ID}`

### sage-api（Cloud Run Service）— Analysis API が必要な場合

SAGE Analysis API を常駐の Cloud Run Service としてデプロイする。これは BEACON が `SAGE_API_URL` で参照する HTTP エンドポイントである。

ETL Job と同じコンテナイメージを再利用する。デプロイ時に `--command/--args` で ENTRYPOINT を上書きし、`sage run-etl` の代わりに `sage serve-api` を起動する。

```sh
# 上記の IMAGE 変数を再利用（または再エクスポート）
export IMAGE=${REGION}-docker.pkg.dev/${GCP_PROJECT_ID}/cloud-run/sage-etl

gcloud run deploy sage-api \
  --image=${IMAGE} \
  --region=${REGION} \
  --no-allow-unauthenticated \
  --command='uv' \
  --args='run,sage,serve-api,--host,0.0.0.0,--port,8080' \
  --port=8080 \
  --service-account="sage-etl@${GCP_PROJECT_ID}.iam.gserviceaccount.com" \
  --set-env-vars="GCP_PROJECT_ID=${GCP_PROJECT_ID},SPANNER_INSTANCE=${SPANNER_INSTANCE},SPANNER_DB=${SPANNER_DB}" \
  --project=${GCP_PROJECT_ID}
```

> **Service URL の取得:** デプロイ後、BEACON 設定に使用する URL を確認する:
> ```sh
> gcloud run services describe sage-api \
>   --region=${REGION} \
>   --format='value(status.url)' \
>   --project=${GCP_PROJECT_ID}
> ```
> この値を BEACON の `SAGE_API_URL` として設定する。

---

## Day-N 再デプロイ

### コード変更のみの場合

env-var の追加・削除がなく、コンテナイメージのみ変更する場合はこのフローを使う。

```sh
export IMAGE=${REGION}-docker.pkg.dev/${GCP_PROJECT_ID}/cloud-run/sage-etl

# 新しいイメージをビルドしてプッシュ
gcloud builds submit --tag ${IMAGE} --project=${GCP_PROJECT_ID}

# Cloud Run Job（sage-etl）を更新
gcloud run jobs update sage-etl \
  --image=${IMAGE} \
  --region=${REGION} \
  --project=${GCP_PROJECT_ID}

# Cloud Run Service（sage-api）を更新
gcloud run services update sage-api \
  --image=${IMAGE} \
  --region=${REGION} \
  --project=${GCP_PROJECT_ID}
```

### 既存リビジョンの env-var 変更

`--update-env-vars` と `--remove-env-vars` を使うこと — **`--set-env-vars` は使わない**。`--set-env-vars` は env-var セット全体を置き換えるため、再指定しなかったキーが無音で削除される。

```sh
# 他の変数に影響せず 1 つの変数を追加・更新する
gcloud run services update sage-api \
  --update-env-vars=NEW_VAR=value \
  --region=${REGION} \
  --project=${GCP_PROJECT_ID}

# 古い変数を削除しながら新しい変数を追加する
gcloud run services update sage-api \
  --update-env-vars=NEW_VAR=value \
  --remove-env-vars=OLD_VAR \
  --region=${REGION} \
  --project=${GCP_PROJECT_ID}

# Cloud Run Job でも同じパターン
gcloud run jobs update sage-etl \
  --update-env-vars=NEW_VAR=value \
  --remove-env-vars=OLD_VAR \
  --region=${REGION} \
  --project=${GCP_PROJECT_ID}
```

> **確認:** `gcloud run services describe sage-api --region=${REGION} --format="value(spec.template.spec.containers[0].env[].name)" --project=${GCP_PROJECT_ID}`

---

## アクセス（本番推奨 = L2）

デプロイ時に `--no-allow-unauthenticated` が既に設定されている。アクセスが必要なアイデンティティに `roles/run.invoker` を付与する。

### 呼び出し権限の付与

```sh
# 個人ユーザー
gcloud run services add-iam-policy-binding sage-api \
  --region=${REGION} \
  --member="user:alice@example.com" \
  --role=roles/run.invoker \
  --project=${GCP_PROJECT_ID}

# Google グループ（チーム利用に推奨）
gcloud run services add-iam-policy-binding sage-api \
  --region=${REGION} \
  --member="group:sage-users@example.com" \
  --role=roles/run.invoker \
  --project=${GCP_PROJECT_ID}

# BEACON のサービスアカウント（BEACON デプロイ時に追加する）
gcloud run services add-iam-policy-binding sage-api \
  --region=${REGION} \
  --member="serviceAccount:beacon-sa@${GCP_PROJECT_ID}.iam.gserviceaccount.com" \
  --role=roles/run.invoker \
  --project=${GCP_PROJECT_ID}
```

### curl による動作確認

```sh
URL=$(gcloud run services describe sage-api \
  --region=${REGION} \
  --format='value(status.url)' \
  --project=${GCP_PROJECT_ID})

curl -H "Authorization: Bearer $(gcloud auth print-identity-token)" ${URL}/health
```

### ブラウザアクセス

```sh
gcloud run services proxy sage-api --region=${REGION} --project=${GCP_PROJECT_ID}
# http://localhost:8080 を開く
```

---

## 対象外

IAP / 内部ロードバランサ / VPC Service Controls はこのガイドでは設定しない。少数の Google Workspace ユーザー運用（数名程度）では、上記の L2 IAM バインディングで十分である。カスタムドメイン、gcloud を使わないブラウザアクセス、コンテキストアウェアアクセスが必要な場合は https://cloud.google.com/iap/docs を参照すること。
