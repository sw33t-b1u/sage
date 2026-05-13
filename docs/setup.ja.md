# SAGE — セットアップガイド

英語版（正本）: [`docs/setup.md`](setup.md)

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
| `PROJECT_ID` | Yes | — | GCP プロジェクト ID |
| `REGION` | Yes | `us-central1` | Spanner・Cloud Run・Scheduler のリージョン |
| `SPANNER_INSTANCE` | Yes | — | Spanner インスタンス ID |
| `SPANNER_DB` | Yes | — | Spanner データベース ID |
| `GCS_BUCKET` | Yes | — | 生 STIX を受け取る GCS バケット |
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
# .env を読み込む（Step 2 で設定済み）— REGION を含むすべての変数が使用可能になる
source .env

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

`input/` ディレクトリを作成し（gitignore 対象 — 機微情報を含む場合あり）、資産ファイルを配置する:

```sh
mkdir input

# BEACON で assets.json を生成するか、サンプルフィクスチャから開始:
cp tests/fixtures/sample_assets.json input/assets.json
# input/assets.json を実際の資産インベントリに合わせて編集
```

> **load_assets 前に TRACE で検証する。** SAGE は schema / 意味論違反の
> ある artifact を取り込むべきでない。`assets.json` / `pir_output.json` /
> STIX bundle の検証ゲートは [TRACE](https://github.com/sw33t-b1u/trace)
> に集約されている:
>
> ```sh
> cd ../TRACE && uv run python cmd/validate_assets.py --assets ../SAGE/input/assets.json
> ```

```sh
uv run python cmd/load_assets.py                              # デフォルト: input/assets.json
uv run python cmd/load_assets.py --file path/to/assets.json  # カスタムパス
```

---

## Step 5.1 — identity assets のロード (Initiative A / Initiative C Phase 2)

BEACON は `identity_assets.json` (内部資産へのアクセス権を持つ
person / role / group) も emit する。`input/` に配置し、TRACE で検証
してからロード — TRACE 1.6.0+ は各 `has_access[].asset_id` を `assets.json`
とクロス参照し、Initiative C Phase 2 のフラグ
`is_high_value_impersonation_target` + `impersonation_risk_factors`
も検証する:

```sh
cp /path/to/identity_assets.json input/identity_assets.json

cd ../TRACE && uv run python cmd/validate_identity_assets.py \
  --identity-assets ../SAGE/input/identity_assets.json \
  --assets          ../SAGE/input/assets.json

cd ../SAGE && uv run python cmd/load_identity_assets.py \
  --file input/identity_assets.json
```

SAGE は `Identity` 行 + `HasAccess` エッジを upsert し、フラグが立っている
場合は `PirPrioritizesImpersonationTarget` カスケードエッジを導出して
`ImpersonatesIdentity` の `effective_priority` を multiplier=1.5 に切替える。

---

## Step 5.2 — user accounts のロード (Initiative B)

BEACON `user_accounts.json` は identity 層より細かい account レベルの
粒度 (個別ログイン識別子、例: `alice@corp`, `svc-jenkins`) を持つ。
TRACE で検証してロード:

```sh
cp /path/to/user_accounts.json input/user_accounts.json

cd ../TRACE && uv run python cmd/validate_user_accounts.py \
  --user-accounts ../SAGE/input/user_accounts.json \
  --assets        ../SAGE/input/assets.json

cd ../SAGE && uv run python cmd/load_user_accounts.py \
  --file input/user_accounts.json
```

`UserAccount` 行は任意 FK `identity_id` で `Identity` にリンクし、
`AccountOnAsset` エッジ (複合キー `(user_account_id, asset_id)`) で
ホスト `Asset` 行に紐付く。

---

## Step 6 — PIR ファイルの配置

[BEACON](https://github.com/sw33t-b1u/beacon)（`cmd/generate_pir.py`）で PIR JSON を生成し、`input/` に配置する:

```sh
cp /path/to/pir_output_<timestamp>.json input/pir.json
# PIR_FILE_PATH=input/pir.json は .env.example に既定値として記載済み
```

> **ETL 前に TRACE で検証する。** Pydantic スキーマ、`threat_actor_tags[*]`
> の脅威タクソノミー存在確認、`asset_weight_rules[*].tag` が assets の
> いずれかのタグにマッチするかを TRACE 側でチェックする:
>
> ```sh
> cd ../TRACE && uv run python cmd/validate_pir.py \
>   --pir ../SAGE/input/pir.json --assets ../SAGE/input/assets.json
> ```

---

## Step 7 — ETL の手動実行（初回確認）

> **STIX バンドルのソース。** SAGE は OpenCTI / Security Hub / SCC /
> [TRACE](https://github.com/sw33t-b1u/trace) からの STIX bundle を受理
> する。TRACE 由来 bundle の場合は事前に `validate_stix.py` を通すこと
> （SAGE は dangling reference を sliently skip するが、TRACE は upfront
> で捕捉する）。TRACE 由来 bundle は envelope に `x_trace_*` メタデータ
> を持つが、SAGE parser は未知 `x_*` を無視する forward-compatible 設計。

```sh
# OpenCTI 不要 — ローカルの STIX バンドルを使用
uv run python cmd/run_etl.py --manual-bundle tests/fixtures/sample_bundle_mirrorface.json

# ライブの OpenCTI に対して実行
make run-etl
```

---

## Step 8 — ETL ワーカーを Cloud Run にデプロイ

```sh
# .env を未読み込みの場合は読み込む
source .env
export IMAGE=gcr.io/${PROJECT_ID}/sage-etl

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
