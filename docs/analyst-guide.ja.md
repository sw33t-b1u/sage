# SAGE — アナリスト利用ガイド

英語版（正本）: [`docs/analyst-guide.md`](analyst-guide.md)

CTI アナリストおよびブルーチームメンバー向けの日常ワークフローを説明する。

## 前提条件

- `uv sync --extra dev` が SAGE ディレクトリで完了していること
- 本番 Spanner の認証情報で `.env` が設定されていること
- ローカルマシンで `gcloud auth application-default login` が完了していること

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
uv run python cmd/run_etl.py --manual-bundle tests/fixtures/sample_bundle_mirrorface.json
```

---

### 2. チョークポイントの確認

チョークポイントは `choke_score = pir_adjusted_criticality × targeting_actor_count` が最も高い資産。最優先の強化対象となる。

```sh
# 上位 10 件をターミナルに表示
uv run python cmd/report_choke_points.py --top 10

# Markdown として保存
uv run python cmd/report_choke_points.py --top 10 --output /tmp/choke_report.md

# GitHub Enterprise Issue として投稿（GHE_TOKEN と GHE_REPO が必要）
uv run python cmd/report_choke_points.py --ghe
```

出力例:

```
# SAGE Choke Point Report — 2026-04-05

| Rank | Asset                  | choke_score | pir_adjusted_criticality | Targeting Actors  |
|------|------------------------|-------------|--------------------------|-------------------|
| 1    | 統合認証基盤            | 42.0        | 10.0                     | APT10, Lazarus    |
```

---

### 3. 資産 ID・アクター STIX ID の確認

**資産 ID** は `assets.json` ファイルの `id` フィールドで定義される。
投入後は Spanner から検索することもできる:

```sh
gcloud spanner databases execute-sql sage-db \
  --instance=sage-instance \
  --sql="SELECT id, name, criticality, pir_adjusted_criticality FROM Asset ORDER BY pir_adjusted_criticality DESC LIMIT 20"
```

**アクター STIX ID** は OpenCTI によって割り当てられるか、STIX バンドルファイルに含まれている。
ETL 後に Spanner から検索できる:

```sh
gcloud spanner databases execute-sql sage-db \
  --instance=sage-instance \
  --sql="SELECT stix_id, name, tags FROM ThreatActor ORDER BY name LIMIT 50"
```

チョークポイントレポートには各資産のターゲティングアクター名も表示される。それを使って上記クエリで STIX ID を取得する。

### 4. 特定の資産・アクターの調査

```sh
# 特定の資産を狙う攻撃経路
uv run python cmd/query_attack_paths.py --asset-id asset-xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx

# 特定のアクターが使用する全 TTP
uv run python cmd/query_attack_paths.py --actor-id intrusion-set--xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx
```

---

### 5. グラフの可視化（オンデマンド）

インタラクティブな HTML ファイルを生成してブラウザで開く。ノードはタイプ別に色分けされ、ドラッグ・ズームが可能。本番 Spanner に対してローカルで動作する。

```sh
# 統合ビュー（攻撃グラフ + FollowedBy 重み付き攻撃フロー）
uv run python cmd/visualize_combined.py --output /tmp/sage_combined.html

# 特定アクターに絞る
uv run python cmd/visualize_combined.py --actor-id "intrusion-set--xxx"

# 攻撃グラフのみ（全ノード、均一エッジ）
uv run python cmd/visualize_graph.py --output /tmp/sage_graph.html

# 攻撃フローのみ（FollowedBy 重み付き TTP 遷移）
uv run python cmd/visualize_attack_flow.py --output /tmp/attack_flow.html

# ブラウザ自動起���を抑制 / テーブルごとの行数を制限
uv run python cmd/visualize_combined.py --no-open --limit 200
```

> `make visualize` はローカル/エミュレーター用のショートカット。本番データに対しては上記コマンドを直接実行する。

---

### 6. Analysis API を使ったクエリ（オプション）

他のツールとの統合やアドホッククエリのために、本番 Spanner を参照して API サーバーをローカルで起動する:

```sh
uv run python cmd/analysis_api.py --port 8080
```

起動後は `http://localhost:8080/docs` でインタラクティブな API ドキュメント（Swagger UI）を参照できる。

利用可能なエンドポイント:

| エンドポイント | 説明 |
|--------------|------|
| `GET /choke-points?top_n=10` | スコア上位 N 件のチョークポイント資産 |
| `GET /asset-exposure` | ターゲティングアクター数を含む全資産一覧 |
| `GET /attack-paths?asset_id=<id>` | 指定資産への攻撃経路 |
| `GET /actor-ttps?actor_id=<id>` | 脅威アクターに関連する TTP |
| `GET /similar-incidents?incident_id=<id>` | 指定インシデントに類似した過去インシデント |

---

## 四半期 PIR 更新ワークフロー

組織の状況変化（新プロジェクト、M&A、規制改定、新たな重要資産）が生じた際に実行する:

```
1. business_context.json（または .md）を更新  ← BEACON リポジトリで実施
2. uv run python cmd/generate_pir.py ...        ← BEACON リポジトリで実行（BEACON ドキュメント参照）
3. cp pir_output.json /path/to/config/pir.json
4. make run-etl                                  ← 新しい PIR 重みを適用するために ETL を再実行
5. uv run python cmd/report_choke_points.py      ← クリティカリティの変化を確認
```

PIR の生成（Step 2）は SAGE ではなく [BEACON](https://github.com/sw33t-b1u/beacon) で行う。
詳細は BEACON ドキュメントを参照。

---

## IR 対応ワークフロー

インシデントが検知または疑われる場合:

```sh
# IR インシデントテンプレートを GHE Issue として作成
uv run python cmd/create_ir_template.py \
  --actor-id <stix-id> \
  --asset-id <asset-id>

# レッドチームシミュレーション用にアクターの TTP を Caldera に同期（CALDERA_URL が必要）
uv run python cmd/sync_caldera.py --actor-id <stix-id>
```
