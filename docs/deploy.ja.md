# SAGE — デプロイガイド

英語版（正本）: [`docs/deploy.md`](deploy.md)

このガイドは [setup.ja.md](setup.ja.md) の手順が完了していることを前提とする。デプロイ前に `make check` がパスすることを確認すること。

---

## Step 8 — SAGE ETL を Cloud Run Job としてデプロイ

コンテナイメージをビルドし、SAGE ETL パイプラインをバッチ実行用の Cloud Run Job としてデプロイする。

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

# Cloud Build でコンテナイメージをビルドしてプッシュ
gcloud builds submit --tag ${IMAGE} --project=${PROJECT_ID}

# Cloud Run Job を作成
gcloud run jobs create sage-etl \
  --image=${IMAGE} \
  --region=${REGION} \
  --service-account="sage-etl@${PROJECT_ID}.iam.gserviceaccount.com" \
  --set-env-vars="PROJECT_ID=${PROJECT_ID},SPANNER_INSTANCE=${SPANNER_INSTANCE},SPANNER_DB=${SPANNER_DB},PIR_FILE_PATH=/config/pir.json,OPENCTI_URL=https://example.com,OPENCTI_TOKEN=skip,SAGE_STORAGE=gcs,SAGE_GCS_BUCKET=${TRACE_GCS_BUCKET},SAGE_GCS_PREFIX=trace/" \
  --set-secrets="GCS_BUCKET=sage-bucket:latest" \
  --add-volume=name=pir,type=cloud-storage,bucket=${PIR_GCS_BUCKET},mount-options="only-dir=pir" \
  --add-volume-mount=volume=pir,mount-path=/config \
  --project=${PROJECT_ID}
```

> **`SAGE_STORAGE=gcs` + `SAGE_GCS_BUCKET` + `SAGE_GCS_PREFIX`:** TRACE が生成
> した STIX バンドルを `run-etl` が読み込むために必須。`SAGE_GCS_BUCKET` は
> TRACE が書き込む bucket（典型的には `${TRACE_GCS_BUCKET}`、TRACE デプロイ
> ガイド参照）、`SAGE_GCS_PREFIX` は TRACE の prefix（`trace/`）を指定する。
> ETL は `${SAGE_GCS_PREFIX}/stix/` 配下を探す。設定しないと OpenCTI モードに
> fallback し、`OPENCTI_TOKEN=skip` の構成では失敗する。

> **`mount-options="only-dir=pir"`:** PIR bucket は他の artifact（raw STIX
> landing 等）も保持しうるため、`only-dir=pir` で `pir/` サブディレクトリのみ
> を `/config/` に露出させ、ファイルが `/config/pir.json` として解決されるよう
> にする。bucket が PIR 専用なら省略可。

> **`--set-env-vars` vs `--update-env-vars`:** `gcloud run jobs update --set-env-vars=...` を後から実行すると、env-var セット全体が**置き換え**られ、再指定しなかったキーは無音で削除される。マージするには `--update-env-vars=KEY=VAL` を使うこと。毎回の更新後に
> `gcloud run jobs describe sage-etl --format="value(spec.template.spec.containers[0].env[].name)"`
> で確認すること。

> **Secret Manager:** `gcloud secrets create sage-bucket --data-file=- <<< "your-bucket"` で機密値を登録し、`--set-env-vars` の代わりに `--set-secrets` で参照する。

> **OpenCTI なし構成:** OpenCTI インスタンスに接続しない場合は、上記のように `OPENCTI_URL=https://example.com` と `OPENCTI_TOKEN=skip` を渡す。ETL ジョブは OpenCTI 取り込みをスキップし、GCS 上の STIX バンドルを処理する。

> **PIR ファイルの供給:** `pir.json` はコンテナイメージに含まれない。上記の GCS ボリュームマウント（`--add-volume` / `--add-volume-mount`）を使ってランタイムに供給する。`only-dir=pir` を指定する構成ではジョブ実行前に `gs://${PIR_GCS_BUCKET}/pir/pir.json` が必要。`only-dir` を省略した場合は `gs://${PIR_GCS_BUCKET}/pir.json` に置く。Secret Manager にボリュームシークレットとして格納することも可能。

> **サービスアカウント:** デプロイ前に専用のサービスアカウントを作成し、`roles/spanner.databaseUser`、`roles/storage.objectViewer`、`roles/run.invoker` を付与する。**さらに TRACE 出力 bucket (`gs://${TRACE_GCS_BUCKET}`) に対して `roles/storage.objectViewer` を bind** し、ETL が TRACE 生成 STIX バンドルを list/read できるようにする。
>
> ```sh
> gcloud iam service-accounts create sage-etl \
>   --display-name="SAGE ETL Job" \
>   --project=${PROJECT_ID}
>
> for ROLE in roles/spanner.databaseUser roles/storage.objectViewer roles/run.invoker; do
>   gcloud projects add-iam-policy-binding ${PROJECT_ID} \
>     --member="serviceAccount:sage-etl@${PROJECT_ID}.iam.gserviceaccount.com" \
>     --role="${ROLE}"
> done
>
> # TRACE 出力 bucket に対する bucket-level binding（project-wide な
> # objectViewer を避ける least-privilege 代替）:
> gcloud storage buckets add-iam-policy-binding gs://${TRACE_GCS_BUCKET} \
>   --member="serviceAccount:sage-etl@${PROJECT_ID}.iam.gserviceaccount.com" \
>   --role="roles/storage.objectViewer"
> ```

---

## Step 9 — Cloud Scheduler の設定（日次 ETL）

SAGE ETL ジョブを日次スケジュールで自動実行する。

```sh
gcloud services enable cloudscheduler.googleapis.com --project=${PROJECT_ID}

# 毎日 03:00 JST（18:00 UTC）
gcloud scheduler jobs create http sage-daily-etl \
  --location=${REGION} \
  --schedule="0 18 * * *" \
  --uri="https://${REGION}-run.googleapis.com/apis/run.googleapis.com/v1/namespaces/${PROJECT_ID}/jobs/sage-etl:run" \
  --message-body="{}" \
  --oauth-service-account-email="sage-etl@${PROJECT_ID}.iam.gserviceaccount.com" \
  --time-zone="UTC" \
  --project=${PROJECT_ID}
```

> **手動実行:** `gcloud run jobs execute sage-etl --region=${REGION} --project=${PROJECT_ID}`

---

## Step 10 — SAGE Analysis API を Cloud Run Service としてデプロイ

SAGE Analysis API を常駐の Cloud Run Service としてデプロイする。これは BEACON が `SAGE_API_URL` で参照する HTTP エンドポイントである。

ETL Job と同じコンテナイメージを再利用する。デプロイ時に `--command/--args` で ENTRYPOINT を上書きし、`sage run-etl` の代わりに `sage serve-api` を起動する。

```sh
# Step 8 の IMAGE 変数を再利用（または再エクスポート）
export IMAGE=${REGION}-docker.pkg.dev/${PROJECT_ID}/cloud-run/sage-etl

gcloud run deploy sage-api \
  --image=${IMAGE} \
  --region=${REGION} \
  --no-allow-unauthenticated \
  --command='uv' \
  --args='run,sage,serve-api,--host,0.0.0.0,--port,8080' \
  --port=8080 \
  --service-account="sage-etl@${PROJECT_ID}.iam.gserviceaccount.com" \
  --set-env-vars="PROJECT_ID=${PROJECT_ID},SPANNER_INSTANCE=${SPANNER_INSTANCE},SPANNER_DB=${SPANNER_DB}" \
  --project=${PROJECT_ID}
```

> **`--set-env-vars` vs `--update-env-vars`:** `gcloud run services update --set-env-vars=...` を後から実行すると、env-var セット全体が**置き換え**られ、再指定しなかったキーは無音で削除される。マージするには `--update-env-vars=KEY=VAL` を使うこと。毎回の更新後に
> `gcloud run services describe sage-api --format="value(spec.template.spec.containers[0].env[].name)"`
> で確認すること。

> **IAP / 内部ロードバランサ:** BEACON 専用アクセスにする場合は、Service を内部ロードバランサの背後に配置するか Identity-Aware Proxy (IAP) を設定し、エンドポイントが公開インターネットから到達できない状態にする。`--no-allow-unauthenticated` は最低限の設定であり、本番環境では IAP または VPC-SC を追加すること。

> **BEACON の IAM 設定:** BEACON のサービスアカウントには `sage-api` Service に対して `roles/run.invoker` が必要である。このバインディングは BEACON デプロイ時に追加する:
> ```sh
> gcloud run services add-iam-policy-binding sage-api \
>   --region=${REGION} \
>   --member="serviceAccount:beacon-sa@${PROJECT_ID}.iam.gserviceaccount.com" \
>   --role="roles/run.invoker" \
>   --project=${PROJECT_ID}
> ```

> **Service URL の取得:** デプロイ後、BEACON 設定に使用する URL を確認する:
> ```sh
> gcloud run services describe sage-api \
>   --region=${REGION} \
>   --format='value(status.url)' \
>   --project=${PROJECT_ID}
> ```
> この値を BEACON の `SAGE_API_URL` として設定する。
