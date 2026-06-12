# SAGE — セットアップガイド

英語版（正本）: [`docs/setup.md`](setup.md)

## 前提条件

- Python 3.12+
- [uv](https://github.com/astral-sh/uv)
- 課金が有効な Google Cloud プロジェクト — 任意の Spanner バックエンド
  （`SAGE_DB=spanner`）または GCS ストレージ（`SAGE_STORAGE=gcs`）を使う場合
  **のみ**必要。既定構成（SQLite + ローカルストレージ）に GCP アカウントは不要
- OpenCTI インスタンス（ライブ CTI 取り込み用。手動 STIX バンドルモードでは不要）

SAGE 4.0.0 は既定で **SQLite データベースファイル**にグラフを格納する
（`SAGE_DB=sqlite`）。ファイルは StorageBackend の `db/` カテゴリに置かれる
（ローカルでは `<base_dir>/db/sage.db`、GCS では同期）。Cloud Spanner は
`SAGE_DB=spanner` で選択できる任意バックエンドとして利用可能。

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
| `SAGE_DB` | No | `sqlite` | データベースバックエンド: `sqlite`（既定）または `spanner` |
| `GCP_PROJECT_ID` | Spanner のみ | — | GCP プロジェクト ID（`SAGE_DB=spanner` 時に必須） |
| `REGION` | シェルのみ | `us-central1` | `gcloud` コマンド用リージョン（Python コードでは未使用） |
| `SPANNER_INSTANCE` | Spanner のみ | — | Spanner インスタンス ID（`SAGE_DB=spanner` 時に必須） |
| `SPANNER_DB` | Spanner のみ | — | Spanner データベース ID（`SAGE_DB=spanner` 時に必須） |
| `SAGE_ETL_INPUT_BUCKET` | Spanner のみ | — | 生 STIX を受け取る GCS バケット（`SAGE_DB=spanner` 時に必須） |
| `OPENCTI_URL` | Yes | — | OpenCTI ベース URL |
| `OPENCTI_TOKEN` | Yes | — | OpenCTI API トークン |
| `PIR_FILE_PATH` | No | `/config/pir.json` | PIR JSON ファイルのパス |
| `TLP_MAX_LEVEL` | No | `amber` | 取り込む最大 TLP レベル（`white`/`green`/`amber`） |
| `ACTIVITY_WINDOW_DAYS` | No | `90` | FollowedBy アクティビティスコアの振り返り期間（日）（`SAGE_ACTIVITY_WINDOW_DAYS` で上書き可） |
| `SAGE_ACTIVITY_WINDOW_DAYS` | No | — | `ACTIVITY_WINDOW_DAYS` の SAGE 固有オーバーライド |
| `SLACK_WEBHOOK_URL` | No | — | ETL 完了通知用 Slack Incoming Webhook URL |
| `GHE_TOKEN` | No | — | GitHub Enterprise Personal Access Token |
| `GHE_REPO` | No | — | GHE リポジトリ（`owner/repo` 形式） |
| `GHE_API_BASE` | No | `https://api.github.com` | GHE API ベース URL（セルフホスト時に上書き） |
| `CALDERA_URL` | No | — | MITRE Caldera サーバー URL |
| `CALDERA_API_KEY` | No | — | Caldera REST API キー |
| `SAGE_API_URL` | No | — | 稼働中の Analysis API のベース URL |
| `SAGE_API_AUTH_TOKEN` | API 利用時 | — | Analysis API の Bearer 認証トークン |
| `SAGE_STORAGE` | No | `local` | ストレージバックエンド: `local` または `gcs` |
| `SAGE_STORAGE_BASE_DIR` | No | `output` | `local` バックエンドのベースディレクトリ |
| `SAGE_STORAGE_BUCKET` | GCS 利用時 | — | GCS バケット名（`SAGE_STORAGE=gcs` 時必須） |
| `SAGE_STORAGE_PREFIX` | No | (空文字) | GCS バケット内のキープレフィックス |
| `OTEL_SDK_DISABLED` | No | — | `true` に設定すると Spanner クライアントのメトリクスエクスポートエラーを抑制（Spanner バックエンドのみ） |

既定バックエンド（`SAGE_DB=sqlite`）+ 既定ストレージ（`SAGE_STORAGE=local`）
では GCP の変数は一切不要 — データベースファイルは初回実行時に
`output/db/sage.db` に作成される。GCS 経由でデータベースを同期する場合は
`SAGE_STORAGE=gcs` + `SAGE_STORAGE_BUCKET` を設定する。

---

## Step 3 —（任意）Spanner バックエンド — GCP リソースの作成

**既定の SQLite バックエンドではこの Step をスキップする。**
`SAGE_DB=spanner` を設定する場合のみ実施する。

```sh
# .env を読み込む（Step 2 で設定済み）— REGION を含むすべての変数が使用可能になる
source .env

# 必要な API を有効化
gcloud services enable spanner.googleapis.com storage.googleapis.com \
  --project=${GCP_PROJECT_ID}

# Spanner インスタンスを作成
gcloud spanner instances create ${SPANNER_INSTANCE} \
  --config=regional-${REGION} \
  --description="SAGE Threat Intelligence" \
  --nodes=1 \
  --project=${GCP_PROJECT_ID}

# Spanner データベースを作成
gcloud spanner databases create ${SPANNER_DB} \
  --instance=${SPANNER_INSTANCE} \
  --project=${GCP_PROJECT_ID}

# GCS ランディングバケットを作成
gcloud storage buckets create gs://${SAGE_ETL_INPUT_BUCKET} \
  --location=${REGION} \
  --project=${GCP_PROJECT_ID}
```

> **コスト注記:** 1 ノード Spanner インスタンスは約 $0.90/時間で、停止はできない。評価時のコスト最小化には `--nodes=1` の代わりに `--processing-units=100` を使用。既定の SQLite バックエンドはまさにこの常時稼働コストを避けるためのもの — Spanner はデータ量や同時実行性が必要になった場合にのみ選択する。

---

## Step 4 — データベーススキーマの初期化

```sh
make init-schema
```

既定の SQLite バックエンドでは `schema/sqlite_ddl.sql` を、`SAGE_DB=spanner`
では `schema/spanner_ddl.sql` を適用する。SQLite ではこの Step は省略可能 —
データベースファイルが未作成の場合、各 CLI エントリポイントがスキーマを
自動適用する。

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
> cd ../TRACE && uv run trace validate-assets --assets ../SAGE/input/assets.json
> ```

```sh
uv run sage load-assets                               # デフォルト: input/assets.json
uv run sage load-assets --input path/to/assets.json  # カスタムパス
```

---

## Step 5.1 — identity assets のロード

BEACON は `identity_assets.json` (内部資産へのアクセス権を持つ
person / role / group) も emit する。`input/` に配置し、TRACE で検証
してからロード — TRACE は各 `has_access[].asset_id` を `assets.json`
とクロス参照し、フラグ
`is_high_value_impersonation_target` + `impersonation_risk_factors`
も検証する:

```sh
cp /path/to/identity_assets.json input/identity_assets.json

cd ../TRACE && uv run trace validate-identity \
  --identity-assets ../SAGE/input/identity_assets.json \
  --assets          ../SAGE/input/assets.json

cd ../SAGE && uv run sage load-identity-assets \
  --input input/identity_assets.json
```

SAGE は `Identity` 行 + `HasAccess` エッジを upsert し、フラグが立っている
場合は `PirPrioritizesImpersonationTarget` カスケードエッジを導出して
`ImpersonatesIdentity` の `effective_priority` を multiplier=1.5 に切替える。

---

## Step 5.2 — user accounts のロード

BEACON `user_accounts.json` は identity 層より細かい account レベルの
粒度 (個別ログイン識別子、例: `alice@corp`, `svc-jenkins`) を持つ。
TRACE で検証してロード:

```sh
cp /path/to/user_accounts.json input/user_accounts.json

cd ../TRACE && uv run trace validate-accounts \
  --user-accounts ../SAGE/input/user_accounts.json \
  --assets        ../SAGE/input/assets.json

cd ../SAGE && uv run sage load-user-accounts \
  --input input/user_accounts.json
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
> cd ../TRACE && uv run trace validate-pir \
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
uv run sage run-etl --input tests/fixtures/sample_bundle_mirrorface.json

# ライブの OpenCTI に対して実行
make run-etl
```

---

---

## テスト

### ユニットテスト（GCP 不要）

```sh
make test
```

`tests/fixtures/` 配下のフィクスチャファイルを使用する。GCP の認証情報やネットワークアクセスは不要。

カバレッジレポートを出力する場合:

```sh
uv run pytest --cov=src/sage --cov-report=term-missing
```

---

### フルローカルテスト（SQLite 既定）

既定バックエンドでは、Attack Flow（STIX 脅威インテリジェンス）+
Attack Graph（内部資産）の完全なワークフローがエミュレーターも Docker も
GCP 認証情報も無しで動作する:

```sh
# データベースファイルは output/db/sage.db に自動作成される
uv run sage run-etl --input tests/fixtures/sample_bundle_mirrorface.json
uv run sage run-etl --input tests/fixtures/sample_bundle_inc.json
make load-assets
make visualize
```

---

### Spanner エミュレーターを使ったフルローカルテスト（`SAGE_DB=spanner`）

同じワークフローを任意の Spanner バックエンドに対して検証する。

**Docker または Podman が必要。**

```sh
# 0. このシェルで Spanner バックエンドを選択
export SAGE_DB=spanner

# 1. Spanner エミュレーターを起動
docker run -d --name spanner-emulator -p 9010:9010 -p 9020:9020 \
  gcr.io/cloud-spanner-emulator/emulator
export SPANNER_EMULATOR_HOST=localhost:9010

# 2. インスタンス・データベース・スキーマを作成
uv run sage setup-emulator
make init-schema

# 3. 脅威インテリジェンスを投入（Attack Flow）
# 注意: 外部バンドルや手動作成バンドルは PIR フィルタがアクターを保持できるよう事前にエンリッチが必要:
#   cd ../TRACE && uv run trace enrich-bundle --input <bundle.json> --output enriched.json && cd ../SAGE
uv run sage run-etl --input tests/fixtures/sample_bundle_mirrorface.json
uv run sage run-etl --input tests/fixtures/sample_bundle_inc.json

# 4. 内部資産を投入（Attack Graph）
make load-assets

# 5. 可視化 — tests/output/graph.html を生成してブラウザで開く
make visualize

# 6. 完了後にエミュレーターを停止・削除
docker stop spanner-emulator && docker rm spanner-emulator
```

#### Docker の代わりに Podman を使う

Podman は Docker のドロップイン代替であり、上記の `docker` サブコマンドはすべて `podman` でそのまま動作する。フラグやイメージ名の変更は不要。

macOS では Podman は VM を必要とする（初回のみ）:

```sh
podman machine init
podman machine start
```

その後、ステップ 1 と 6 で `docker` を `podman` に置き換える:

```sh
# ステップ 1
podman run -d --name spanner-emulator -p 9010:9010 -p 9020:9020 \
  gcr.io/cloud-spanner-emulator/emulator
export SPANNER_EMULATOR_HOST=localhost:9010

# ステップ 6
podman stop spanner-emulator && podman rm spanner-emulator
```

ステップ 2〜5（uv と `make` コマンド）は変更不要。

---

### グラフ可視化

`make visualize` は `tests/output/graph.html`（git 管理外）を生成してブラウザで開く。ノードはタイプ別に色分けされ、ドラッグ・ズームが可能。

| ノードタイプ | 色 | 接続先 |
|------------|-----|--------|
| ThreatActor | 赤 | TTP (USES)、MalwareTool (USES_TOOL)、Asset (TARGETS) |
| TTP | オレンジ | Vulnerability (EXPLOITS)、TTP (FOLLOWED_BY) |
| Vulnerability | 黄 | — |
| MalwareTool | 紫 | TTP (MALWARE_USES_TTP) |
| Observable | ティール | TTP (INDICATES_TTP)、ThreatActor (INDICATES_ACTOR) |
| Incident | ピンク | TTP (INCIDENT_USES_TTP) |
| Asset | 青 | Vulnerability (HAS_VULN)、Asset (CONNECTED_TO)、SecurityControl (PROTECTED_BY) |
| SecurityControl | グレー | — |

オプション:

```sh
uv run sage visualize-combined --no-open   # 統合ビュー、ブラウザ自動起動を抑制
uv run sage visualize-combined --limit 200 # テーブルごとの行数を制限
uv run sage visualize-graph --no-open      # 攻撃グラフのみ
uv run sage visualize-attack-flow --no-open # 攻撃フローのみ
```

---

### サンプルフィクスチャ

| ファイル | 説明 |
|---------|------|
| `sample_bundle_mirrorface.json` | MirrorFace / Earth Kasha APT（日本標的、2024〜2025）。TTP: T1190, T1566.001, T1574.002, T1071.001, T1083, T1041。CVE-2023-28461, CVE-2024-21412。LODEINFO バックドア + C2 IoC。 |
| `sample_bundle_inc.json` | INC ランサムウェア（2023年〜、医療/製造業標的）。TTP: T1190, T1078, T1003.001, T1021.002, T1048.002, T1486。CVE-2023-3519, CVE-2023-4966 (Citrix)。ツール: Cobalt Strike, AnyDesk, MegaSync。 |
| `sample_assets.json` | 日本の製造業企業: Citrix NetScaler ADC, Active Directory, ファイルサーバー, バックアップサーバー, ERP (SAP), 工場 PLC, ワークステーション。 |
| `sample_pir.json` | ユニットテスト用の最小 PIR。 |

---

## データの削除

専用の削除 CLI はない。

**SQLite バックエンド（既定）:** `sqlite3` シェルでデータベースファイルに
直接 DML を実行する — テーブル名・カラム名は Spanner DDL と同一:

```sh
sqlite3 output/db/sage.db \
  "DELETE FROM ThreatActor WHERE stix_id = 'intrusion-set--xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx'"
```

完全リセットはファイル削除（`rm output/db/sage.db`）で行う — スキーマは
次回実行時に自動で再作成される。`SAGE_STORAGE=gcs` の場合は、ダウンロード
したコピーを編集して `db/sage.db` オブジェクトに再アップロードするか、
完全リセットならオブジェクトを削除する。

**Spanner バックエンド:** `gcloud spanner databases execute-sql` で DML を実行する。

**特定ノードを STIX ID で削除する:**

```sh
# ThreatActor を削除
gcloud spanner databases execute-sql ${SPANNER_DB} \
  --instance=${SPANNER_INSTANCE} --project=${GCP_PROJECT_ID} \
  --sql="DELETE FROM ThreatActor WHERE stix_id = 'intrusion-set--xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx'"

# TTP を削除（参照する下流 FollowedBy エッジも削除される）
gcloud spanner databases execute-sql ${SPANNER_DB} \
  --instance=${SPANNER_INSTANCE} --project=${GCP_PROJECT_ID} \
  --sql="DELETE FROM TTP WHERE stix_id = 'attack-pattern--xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx'"

# 誤って投入した Asset を削除
gcloud spanner databases execute-sql ${SPANNER_DB} \
  --instance=${SPANNER_INSTANCE} --project=${GCP_PROJECT_ID} \
  --sql="DELETE FROM Asset WHERE id = 'asset-001-xxxxx-xxxx-xxxxxxxxxxxx'"
```

**エッジのみ削除する（ノードは残す）:**

```sh
# 特定アクターの Targets エッジを全削除
gcloud spanner databases execute-sql ${SPANNER_DB} \
  --instance=${SPANNER_INSTANCE} --project=${GCP_PROJECT_ID} \
  --sql="DELETE FROM Targets WHERE src_actor_stix_id = 'intrusion-set--xxxx'"

# 特定ソースの FollowedBy エッジを削除
gcloud spanner databases execute-sql ${SPANNER_DB} \
  --instance=${SPANNER_INSTANCE} --project=${GCP_PROJECT_ID} \
  --sql="DELETE FROM FollowedBy WHERE source = 'manual'"
```

**スキーマの完全リセット（全データ削除、スキーマは維持）:**

```sh
# DDL を再実行 — 全テーブルを drop して再作成する
make init-schema
```

> **Note:** Spanner バックエンドでは `sage init-schema` による DDL 再実行は全テーブルを drop して空で再作成する。SQLite の DDL は `CREATE TABLE IF NOT EXISTS`（drop なし）のため、クリーンスレートが必要な場合はデータベースファイルを削除する。いずれもクリーンスレートが必要な場合のみ使うこと。
