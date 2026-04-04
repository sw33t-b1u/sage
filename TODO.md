# SAGE — TODO / 未解決事項

## コード修正（HLD との乖離）— 完了済み ✅

| # | ファイル | 内容 | 状態 |
|---|----------|------|------|
| 1 | `src/sage/stix/mapper.py` `build_followed_by_weights()` | 4因子計算（base_prob × activity_score × exploit_ease × ir_multiplier）に修正 | ✅ 完了 |
| 2 | `src/sage/etl/worker.py` | IncidentUsesTTP から FollowedBy(ir_feedback) 導出を追加 | ✅ 完了 |
| 3 | `src/sage/etl/worker.py` | PIR タグマッチングによる Targets 自動生成を追加 | ✅ 完了 |
| 4 | `schema/spanner_ddl.sql` + `mapper.py` | MalwareUsesTTP テーブル追加・PROPERTY GRAPH 更新・mapper 対応 | ✅ 完了 |

---

## 次にやること

### 優先度: High

- [x] **lint / 静的解析を通す** ✅
  - `timedelta` を `mapper.py` 先頭インポートに移動
  - 未使用変数 `cutoff` を削除（`cutoff_dt` のみ残す）
  - テストの行長違反（E501）を修正

- [x] **テストフィクスチャの拡充** ✅
  - `sample_bundle.json` に `malware--emotet` オブジェクトと `malware--[uses]-->attack-pattern--t1059` 関係を追加
  - `sample_bundle_inc.json` に `incident--inc-2026-001`（5フェーズ、x_ttp_stix_id 付き）を追加
  - `TestMapIncidentTTPEdges` 統合テストを5件追加（計46テスト全通過）

- [x] **`upsert.py` / DDL のカラム整合性確認** ✅
  - `IncidentUsesTTP`：commit_timestamp カラムなし → `upsert_rows()` で問題なし
  - `Targets` DDL の旧 `stix_id` カラムを `source STRING(32)` に修正
  - `MalwareUsesTTP` を Attack Graph 節から Attack Flow 節へ移動（DDL 整理）

### 優先度: Medium

- [x] **`process_bundle()` への asset_rows 渡し方の設計** ✅
  - `fetch_asset_rows(database)` を `sage/spanner/upsert.py` に追加
  - ETL 実行前に Spanner から全資産データを取得して `process_bundle()` に渡す設計を実装

- [x] **`cmd/run_etl.py` の更新** ✅
  - `fetch_asset_rows()` を呼び出して `asset_rows` を取得
  - `worker.process_bundle(objects, asset_rows=asset_rows)` で Targets エッジ生成フローを完成

- [x] **`load_assets.py` の Targets `stix_id` → `source` 修正** ✅
  - 旧 `stix_id: uuid4()` を `source: "manual"` に修正（DDL の `source` カラムと一致）
  - 不要になった `import uuid` を削除

### 優先度: Low（将来検討）

| 項目 | 内容 |
|------|------|
| Spanner Graph クエリ性能 | 資産数百・TTP千オーダーでの経路探索レイテンシ検証。問題があれば Neo4j on GCP へ移行を検討 |
| TLP Red の扱い | 現状 Spanner 格納除外。アナリスト向け別経路が必要か検討 |
| Security Hub → STIX変換仕様 | ASFF-to-STIX 変換の詳細マッピング未定義 |
| 重みパラメータのチューニング | activity_score 等の係数は実運用データで調整 |
| マルチテナント対応 | 現状シングル組織想定。将来的に MSSP 用途があれば再設計要 |

---

## 実装フェーズ

| フェーズ | 内容 | 成果物 | 状態 |
|--------|------|--------|------|
| Phase 1 | Spanner Graph スキーマ構築 + OpenCTI→STIX 取り込み ETL | 動くグラフDB | ✅ 完了 |
| Phase 2 | pir_adjusted_criticality更新 + Spannerクエリ + CLIレポート | チョークポイント可視化 | ✅ 完了 |
| Phase 3 | FollowedBy 重み可視化 + Slack/GHE 通知 | Blue Team 利用可能 | ✅ 完了 |
| Phase 4 | Caldera 連携 + IR Feedback ループ | Red/IR Team 利用可能 | ✅ 完了 |

---

## Phase 2 タスク

### P2-1: `pir_adjusted_criticality` 更新処理 ✅
- [x] `PIRFilter.update_asset_criticality()` を追加（Targets エッジ × PIRマッチアクターで 1.5 倍補正）
- [x] `upsert.py` に `update_pir_criticality()` を追加（`batch.update()` で部分更新）
- [x] `etl/worker.py` に統合（Targets 生成後に自動呼び出し）
- [x] テスト6件追加（計62テスト全通過）

### P2-2: Spanner クエリモジュール ✅
- [x] `src/sage/spanner/query.py` を新規作成
- [x] `find_attack_paths(asset_id, limit)` — GQL（ThreatActor→Targets→Asset, Uses→TTP）
- [x] `find_choke_points(top_n)` — SQL（pir_adjusted_criticality × actor数でスコア）
- [x] `find_actor_ttps(actor_stix_id)` — GQL（actor→Uses→TTP→FollowedBy→TTP）
- [x] `find_asset_exposure()` — SQL（exposed_to_internet=TRUE + Targets + Uses集計）
- [x] テスト10件追加（MagicMockでSpannerスナップショットをモック）

### P2-3: CLI レポートスクリプト ✅
- [x] `cmd/report_choke_points.py` — チョークポイント上位N資産をMarkdown出力（`--top`, `--output`）
- [x] `cmd/query_attack_paths.py` — `--asset-id` / `--actor-id` 切り替え型攻撃経路クエリ

### P2-4: Slack通知（Phase 3 へ繰り越し） → Phase 3 で実装

---

## Phase 3 タスク

### P3-1: FollowedBy 重み付き Attack Flow 可視化 ✅
- [x] `cmd/visualize_attack_flow.py` を新規作成
  - FollowedBy の `weight` をエッジ幅・色グラデーション（赤→黄→緑）で表現
  - `--actor-id` フィルタで特定アクターの攻撃フローのみ表示
  - `source`（threat_intel / ir_feedback）で実線 vs 破線を区別
  - TTP / ThreatActor / MalwareTool ノードと凡例 HTML を表示

### P3-2: Slack webhook 通知 ✅
- [x] `src/sage/notify/slack.py` を新規作成（Webhook URL は環境変数 `SLACK_WEBHOOK_URL`）
- [x] `cmd/run_etl.py` に統合：ETL 前後でチョークスコアを比較し 10% 以上の変化があれば通知
- [x] `Config` に `slack_webhook_url` / `ghe_token` / `ghe_repo` を追加
- [x] テスト追加（5件）

### P3-3: GHE Issue 生成（GitHub REST API） ✅
- [x] `src/sage/notify/github.py` を新規作成（`GHE_TOKEN`, `GHE_REPO` 環境変数）
- [x] `cmd/report_choke_points.py` に `--ghe` フラグを追加
- [x] 同週の既存 Issue があれば更新、なければ新規作成（週番号タイトルで重複排除）
- [x] テスト追加（4件）　計74テスト全通過

### P3-4: FastAPI Analysis API → Phase 4 へ繰り越し

---

## Phase 4 タスク

### P4-1: FastAPI Analysis API ✅
- [x] `pyproject.toml` に `fastapi`, `uvicorn`, `httpx`（dev）を追加
- [x] `src/sage/api/app.py` を新規作成（Cloud Run エントリポイント）
- [x] エンドポイント実装（`query.py` をラップ）:
  - `GET /attack-paths?asset_id=&limit=`
  - `GET /choke-points?top_n=`
  - `GET /actor-ttps?actor_id=`
  - `GET /asset-exposure`
  - `GET /similar-incidents?incident_id=&top_k=&alpha=&max_hops=`
  - `POST /caldera/adversary?actor_id=`
- [x] `cmd/analysis_api.py`（uvicorn 起動エントリポイント）
- [x] テスト14件追加（TestClient でエンドポイントを検証）

### P4-2: Caldera 連携 ✅
- [x] `src/sage/caldera/client.py` を新規作成（`CALDERA_URL`, `CALDERA_API_KEY` 環境変数）
- [x] `cmd/sync_caldera.py` — actor-ttps → Caldera Adversary プロファイル生成 CLI
- [x] `POST /caldera/adversary` を P4-1 API に統合済み
- [x] `Config` に `caldera_url`, `caldera_api_key` を追加
- [x] テスト10件追加（Caldera API をモック）

### P4-3: IR Feedback 支援 ✅

#### (a) 類似 Attack Flow 検索
- [x] `src/sage/analysis/similarity.py` を新規作成
- [x] ハイブリッド類似度スコア実装:
  ```
  hybrid_score = 0.5 × jaccard_ttp + 0.5 × transition_coverage
  ```
  - `jaccard_ttp`: インシデントと過去事例の TTP 集合 Jaccard 類似度
  - `transition_coverage`: FollowedBy グラフ上の到達可能性（最大 2 ホップ BFS）
    - 途中 TTP が欠損していても 2 ホップで到達可能なら一致とみなす
  - `build_followedby_graph()` / `bfs_reachable()` でメモリ上のグラフ走査
- [x] `GET /similar-incidents` エンドポイントを P4-1 API に追加
- [x] Spanner に `find_incident_ttps()`, `find_followedby_edges()`, `find_all_incident_ttps()` を追加
- [x] テスト25件追加（BFS・Jaccard・ハイブリッドスコア・Spanner モック）

#### (b) IR 記録 GHE Issue テンプレート
- [x] `cmd/create_ir_template.py` — インシデント情報から Markdown テンプレートを GHE Issue として投稿
- [x] `--dry-run` でローカル出力確認、`SAGE_API_URL` 設定時は類似インシデント取得して本文に添付
