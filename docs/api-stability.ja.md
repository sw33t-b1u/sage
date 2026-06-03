# SAGE API 安定性ポリシー

**ステータス**: Initiative H — 1.0 安定化のドラフト（サインオフ保留中）。
SAGE 1.0.0 から有効。

本ドキュメントは SAGE のコミット済み公開サーフェスと、それに適用される
後方互換性（BC）保証を列挙する。**Committed（コミット済み）** として列挙されていないものは
**Evolving（発展中）** であり、事前通知なしに任意のマイナーリリースで変更される可能性がある。

---

## 1. バージョニングポリシー（SemVer 2.0.0 厳格準拠）

SAGE は 1.0.0 以降、[Semantic Versioning 2.0.0](https://semver.org/spec/v2.0.0.html)
を厳格に遵守する。

- **メジャー** (`X.0.0`) — §3 に列挙された Committed サーフェス項目に対する破壊的変更。
- **マイナー** (`1.X.0`) — 追加的変更: 新規テーブル / カラム / REST エンドポイント / CLI サブコマンド / 環境変数。Spanner DDL は追加のみ（`STRING(64)` → `STRING(128)` のようなカラム型の拡張は追加的; 縮小または改名は破壊的）。
- **パッチ** (`1.0.X`) — バグ修正のみ。サーフェス変更なし。

廃止パス: `### Deprecated` CHANGELOG セクションで削除予定バージョンを告知し、該当する場合はランタイム警告を出し、次のメジャーで削除する。完全なポリシー文は BEACON `docs/api-stability.md` §1 を参照。

---

## 2. クイックリファレンス

| サーフェス | Committed? | 初版 | 備考 |
|---|---|---|---|
| REST API（10 エンドポイント）| ✓ | 1.0.0 | エンドポイント一覧は §3.1 参照 |
| Spanner Graph DDL（`schema/spanner_ddl.sql`）| ✓ | 1.0.0 | 36 テーブル; 追加のみ（型拡張は可; 改名/削除 = 2.0.0）|
| `Incident.source` 識別子 | ✓ | 1.0.0 | 値: `ir_feedback`（OpenCTI リレー）/ `direct_api`（POST /api/incidents）|
| 認証ゲートのセマンティクス（POST = `SAGE_API_AUTH_TOKEN` 未設定時 503; GET = 許可）| ✓ | 1.0.0 | §3.2 参照 |
| `sage` CLI エントリ + サブコマンド（H フェーズ 6）| ✓ | 1.0.0 | サブコマンド名 + 主要フラグは固定 |
| レガシー `python -m cmd.<name>` | （削除済み）| n/a | 2.0.0 で削除; `sage <subcommand>` を使用 |
| MITRE Navigator インポート形式のサポート（`sage incident-register --navigator-layer`）| ✓ | 1.0.0 | MITRE Navigator JSON レイヤーファイルを読み込む |
| ETL コントラクト（TRACE STIX バンドル取り込み）| ✓ | 1.0.0 | STIX 2.1 準拠; `x_trace_*` プロパティはランディング時に除去 |
| 環境変数（§5）| ✓ | 1.0.0 | 名前 + 意味 + デフォルト値を固定 |
| OpenCTI 統合（レガシーポーリング）| （保持目的で非推奨）| n/a | 1.x では継続動作; 2.0.0 での削除を予定（代わりに直接 API を使用）|
| 内部 Python モジュール（`src/sage/*` 非公開シンボル）| ✗ | n/a | アンダースコア付きおよびドキュメント未記載のヘルパーは変更される可能性あり |
| Spanner マイグレーションスクリプト形式 | （オペレーター内部）| n/a | `src/sage/spanner/migrations/` の仕組みは安定を保つが、オペレーターは直接呼び出さない |

---

## 3. Committed サーフェス — 詳細

### 3.1 REST API エンドポイント

以下の 10 エンドポイントはすべて Committed。各エンドポイントは §3.2 の認証ゲートのセマンティクスに従う。

| エンドポイント | メソッド | 初版 | 目的 |
|---|---|---|---|
| `/actors` | GET | Initiative I | アクター名サブストリング検索（`?name=` 必須、最低 2 文字; `?limit=` 任意）|
| `/attack-paths` | GET | Initiative C | マルチホップ攻撃パス検索（actor → asset）|
| `/choke-points` | GET | Initiative C | 防御優先度の計算 |
| `/actor-ttps` | GET | Initiative E + F-7 | アクターごとの TTP リスト + `?since/until` フィルタ |
| `/threat-summary` | GET | Initiative F-8 | アセットごとの集約ビュー（アクター / パス / チョークポイント / 脆弱性 / インシデント）; `?limit=N` 1-100（デフォルト 5）; `Incident.occurred_at` のみアンカー |
| `/asset-exposure` | GET | Initiative F-7 | アセットごとのエクスポージャー + `?since/until` フィルタ |
| `/similar-incidents` | GET | （既存）| ハイブリッドスコアによる類似インシデント検索（`alpha × jaccard_ttp + (1-alpha) × transition_coverage`）|
| `/caldera/adversary` | POST | （既存）| アクター TTP から Caldera Adversary プロファイルを生成・同期 |
| `/annotate`（`/api/annotate`）| POST | Initiative E + G 決定 10 遡及適用 | AnnotatesActor 書き込み — アナリストアノテーション |
| `/incidents`（`/api/incidents`）| POST + GET | Initiative G フェーズ 1 + 2 | 直接 IR インテーク（POST）+ 読み取りエンドポイント（GET）|

**Committed**: ルートパス、リクエスト/レスポンスのシェイプ（`src/sage/api/models.py` の Pydantic モデル）、クエリパラメーター名と範囲、HTTP ステータスコード。

**Evolving**: レスポンスフィールドの順序、内部 SQL クエリの実装、ログメッセージのフォーマット。

### 3.2 認証ゲート（Initiative G 決定 10 による）

`src/sage/api/auth.py` の `_verify_auth` 依存関係は集中管理され、パラメーター化されている:

- **POST ルート**（`POST /api/incidents`、`POST /api/annotate`、`POST /caldera/adversary`）: `enforce_when_unset=True`。`SAGE_API_AUTH_TOKEN` 環境変数が未設定の場合、POST は **503** を返す（書き込み API フットガンゲート — 明示的な拒否は暗黙の許可に勝る）。設定済みの場合、通常の Bearer 認証が適用される（401 = 欠落、403 = 誤り）。
- **GET ルート**: `enforce_when_unset=False`。`SAGE_API_AUTH_TOKEN` が未設定の場合、許可（現行デプロイメントとの後方互換）。設定済みの場合、通常の Bearer 認証が適用される。

**Committed**: POST に対する未設定時 503 の動作; GET に対する未設定時許可の動作; トークン設定済み時の Bearer 認証の形式（HTTP ヘッダー `Authorization: Bearer <token>`、401 = 欠落、403 = 誤り）。

### 3.3 Spanner Graph DDL（`schema/spanner_ddl.sql`）

合計 36 テーブル: **ノードテーブル**（ThreatActor、TTP、MalwareTool、Vulnerability、Observable、Incident、Identity、SecurityControl、Asset、UserAccount、PIR）と **エッジテーブル**（Uses、UsesTool、Exploits、FollowedBy、IncidentUsesTTP、MalwareUsesTTP、Targets、TargetsAsset、AttributedToActor、AttributedToIdentity、IndicatesActor、IndicatesTTP、ActorTargetsIdentity、ImpersonatesIdentity、HasVulnerability、ConnectedTo、ProtectedBy、HasAccess、AccountOnAsset、UserAccountBelongsTo、PirPrioritizesActor、PirPrioritizesImpersonationTarget、PirPrioritizesTTP、PirWeightsAsset、AnnotatesActor）。

**Committed**: テーブルの存在、カラム名、カラム型、カラムの NULL 可否、主キー、デフォルト値。

**追加的（非破壊的）**:
- 新規テーブルの追加。
- 既存テーブルへの新規カラムの追加（古い行に適切なデフォルト値を設定）。
- カラム型の拡張（`STRING(64)` → `STRING(128)`）。
- 新規 INDEX または GRAPH 定義の追加。

**破壊的（2.0.0 が必要）**:
- テーブルまたはカラムの改名。
- テーブルまたはカラムの削除。
- カラム型の縮小。
- NULL データが存在する既存テーブルのカラムを nullable から NOT NULL に変更。
- 主キー構成の変更。

`src/sage/spanner/migrations/` ディレクトリにはテーブル変更ごとにバージョン管理された前進のみのマイグレーションが格納される。オペレーターは `sage init-schema --apply-migrations` を通じてマイグレーションを適用する。

### 3.4 `Incident.source` 識別子

カラム型: `STRING(32) NOT NULL DEFAULT 'ir_feedback'`。

**Committed 値**:
- `ir_feedback` — OpenCTI リレー経由（既存の動作; OpenCTI デプロイメントを持つレガシーオペレーター向けに保持）
- `direct_api` — `POST /api/incidents` による直接 IR インテーク（Initiative G フェーズ 1）

新しいインテークパスが追加されるにつれてマイナーリリースで他の値が追加される可能性がある; 既存の値は 2.0.0 なしに削除できない。

### 3.5 ETL コントラクト（TRACE STIX バンドル取り込み + PIR ファイル取り込み）

SAGE は TRACE（または他のオペレーター提供ツール）が生成した STIX 2.1 バンドルと、BEACON が出力した `pir_output.json` を取り込む。

**Committed**:
- STIX 2.1 準拠（OASIS 仕様に従う）。
- `x_trace_*` 拡張プロパティはランディングゾーン取り込み時に除去される（SAGE は TRACE 内部マーカーを永続化しない）。
- マッピング規約: STIX `intrusion-set` → SAGE `ThreatActor`、`attack-pattern` → `TTP` など（完全なマッピングテーブルは `src/sage/stix/mapper.py` を参照）。
- **PIR ファイル取り込み形式**（Initiative H フェーズ 3 厳格化）: `PIRFilter.from_file()` はラップされたエンベロープ `{"schema_version": "1.0.0", "pirs": [...]}` を必要とする。ベアリスト / 単一オブジェクトの PIR ペイロードはマイグレーションメッセージとともに拒否される（TRACE 1.12.0 と同じ規約）。
- **`is_high_value_impersonation_target` フラグ**: BEACON が出力した identity_assets はこのブール値フラグを直接搬送する。SAGE 1.0.0 では BEACON 0.12.x のフォールバック（`HIGH_VALUE_IMPERSONATION_ROLES` 15 エントリのロールタグ frozenset）は削除された。フラグ駆動パスのみがサポートされる入力となる。
- **`effective_priority` 再計算 API** シグネチャ: `is_high_value_impersonation_target` フラグは **位置引数**（デフォルトなし）— 呼び出し元はフラグ値を明示的に指定する必要がある。Initiative H フェーズ 3 コントラクトのフラグ駆動パスに対応。

**Evolving**: 内部マッパーのヘルパー関数、ETL ワーカーの並列化戦略。

### 3.6 `sage` CLI エントリ + サブコマンド（H フェーズ 6）

Initiative H フェーズ 6 は `sage` を click `Group` エントリポイントとして導入する。1.0.0 からのオペレーター向け公開サーフェス:

| サブコマンド | 置き換え対象 | 目的 |
|---|---|---|
| `sage init-schema` | `src/sage/cli/init_schema.py` | Spanner Graph DDL を適用 + インデックスを作成 |
| `sage load-assets` | `src/sage/cli/load_assets.py` | BEACON assets.json を Spanner にロード |
| `sage load-identity-assets` | `src/sage/cli/load_identity_assets.py` | identity_assets.json をロード |
| `sage load-user-accounts` | `src/sage/cli/load_user_accounts.py` | user_accounts.json をロード |
| `sage incident-register` | `src/sage/cli/register_incident.py` | インタラクティブな Diamond Model CLI（Initiative G フェーズ 3）|
| `sage actor-annotate` | `src/sage/cli/annotate_actor.py` | AnnotatesActor 書き込み CLI（Initiative E）|
| `sage query-attack-paths` | `src/sage/cli/query_attack_paths.py` | 攻撃パス CLI クエリ（オフライン）|
| `sage ir-template` | `src/sage/cli/create_ir_template.py` | IR オンボーディングテンプレートを生成 |
| `sage serve-api` | `src/sage/cli/analysis_api.py` | REST API サーバーを起動 |
| `sage run-etl` | `src/sage/cli/run_etl.py` | ETL パイプラインを実行（OpenCTI ポーリングまたは `--input`）|
| `sage visualize-graph` | `src/sage/cli/visualize_graph.py` | インタラクティブな HTML グラフ可視化を生成 |
| `sage report-choke-points` | `src/sage/cli/report_choke_points.py` | Markdown 形式のチョークポイント資産レポートを生成（Blue Team 向け）|
| `sage sync-caldera` | `src/sage/cli/sync_caldera.py` | アクターの TTP を Caldera Adversary プロファイルに同期 |
| `sage visualize-attack-flow` | `src/sage/cli/visualize_attack_flow.py` | 重み付き Attack Flow HTML 可視化を生成 |
| `sage visualize-combined` | `src/sage/cli/visualize_combined.py` | Attack Graph + Attack Flow の統合 HTML 可視化を生成 |
| `sage setup-emulator` | `src/sage/cli/setup_emulator.py` | Spanner エミュレーターのインスタンスとデータベースを作成（開発用）|

**Committed**: サブコマンド名 + 各サブコマンドの主要フラグ（例: `incident-register --id`、`--from-file`、`--navigator-layer`、`--no-api`、`--token`、`--api-url`）。

**Evolving**: オプションフラグのデフォルト値、ヘルプテキスト、出力フォーマット。

**2.0.0 で削除**: `python -m cmd.<name>` の呼び出し構文。2.0.0 以降、統一された `sage` CLI が唯一サポートされるエントリポイントとなる。

### 3.7 MITRE Navigator インポート（Initiative G フェーズ 3）

`sage incident-register --navigator-layer <layer.json>` は MITRE ATT&CK Navigator のレイヤー JSON ファイルを受け付ける。テクニックごとの `techniqueID` は `uuid.NAMESPACE_URL + MITRE URL` を使用して STIX `attack-pattern--<uuid5>` に変換される。レイヤーファイル内の順序は `IncidentUsesTTP` の `sequence_order` として保持される。

**Committed**: Navigator レイヤーファイル形式のサポート（トップレベル `techniques: [{techniqueID, tactic, score, comment?}]`）、UUID5 導出ネームスペース、シーケンスの保持。

### 3.8 環境変数（Committed）

| 環境変数 | デフォルト | 目的 |
|---|---|---|
| `GCP_PROJECT_ID` | （必須）| GCP プロジェクト ID |
| `SPANNER_INSTANCE` | （必須）| Spanner インスタンス ID |
| `SPANNER_DB` | （必須）| Spanner データベース ID |
| `SAGE_ETL_INPUT_BUCKET` | （必須）| GCS ランディングゾーンバケット |
| `OPENCTI_URL` | （レガシー時必須）| OpenCTI サーバー URL（OpenCTI リレーを使用する場合のみ必須）|
| `OPENCTI_TOKEN` | （レガシー時必須）| OpenCTI API トークン |
| `PIR_FILE_PATH` | `/config/pir.json` | BEACON が出力した pir_output.json へのパス |
| `TLP_MAX_LEVEL` | `amber` | ETL 取り込みの TLP フィルタレベル |
| `ACTIVITY_WINDOW_DAYS` | `90` | BEACON/TRACE と共有。SAGE_ACTIVITY_WINDOW_DAYS はこの値にフォールバック |
| `SAGE_ACTIVITY_WINDOW_DAYS` | （`ACTIVITY_WINDOW_DAYS` にフォールバック）| SAGE 固有のウィンドウオーバーライド |
| `SAGE_API_AUTH_TOKEN` | `""` | REST API 用 Bearer トークン。POST ルートは設定必須; GET は未設定時許可 |
| `SLACK_WEBHOOK_URL` | `""` | オプションの Slack 通知 Webhook |

**Committed 対象外**（デプロイメント内部）: ログレベル、structlog 設定環境変数、GCP_CREDENTIALS_PATH（デプロイメント固有）。

---

## 4. Evolving（BC 保護対象外）

- **内部 Python モジュール** — `src/sage/` 配下の、文書化された API サーフェス経由で公開されていないもの。
- **内部 SQL クエリ** — `src/sage/spanner/query.py` 内のもの。エンドポイントレベルのコントラクトは Committed だが、SAGE がその結果を生成する方法は Evolving。
- **ETL ワーカーの並列化 / チャンク戦略** — `src/sage/etl/worker.py` の内部実装。
- **Prometheus メトリクス名** — 文書化された `sage_incident_warnings_total` カウンター以外は、マイナーリリースで新規メトリクスが追加される可能性がある; 既存名は安定を保つ。
- **マイグレーションスクリプトの命名規則** — `src/sage/spanner/migrations/` 内のもの。マイグレーションの順序と内容は Committed（オペレーターは `sage init-schema` 経由で適用する）だが、ファイル命名は内部的。
- **`/test/` ルート**（現在本番アプリには登録されていない; 追加する場合はテスト専用としてマーク）。

---

## 5. クロスリポジトリ依存関係

SAGE の Committed サーフェスは以下に依存する:

- **BEACON `pir_output.json` スキーマ**（BEACON 1.0.0+）: ETL PIR 取り込み（`PIR_FILE_PATH`）に使用。
- **TRACE STIX 2.1 バンドル出力**: アクター / TTP / 脆弱性 / インシデントデータ。
- **OASIS STIX 2.1 仕様**: クロスリポジトリのデータモデルブリッジとして。
- **Google Cloud Spanner Graph（Preview/GA）**: ストレージレイヤーとして。Spanner Graph DDL 構文の安定性はアップストリームが制御する。

完全な引用インベントリ: `../beacon/docs/citations.md`。

---

## 6. 2.0.0 トリガー例

SAGE 2.0.0 を強制する変更の例:

- `/attack-paths` エンドポイントの削除またはクエリパラメーターの改名。
- `Incident.source = 'ir_feedback'` 識別子値の削除（OpenCTI リレー削除が想定シナリオ）。
- `ThreatActor` テーブルを `Actor` に改名。
- 認証ゲートのセマンティクスの変更（例: トークン未設定時に GET ルートにデフォルトで認証を要求）。
- `sage incident-register` サブコマンドまたはその `--no-api` フラグの削除。
- `SAGE_API_AUTH_TOKEN` 環境変数の削除。
- `Incident.kill_chain_phases` を `ARRAY<STRING(64)>` から `ARRAY<STRING(32)>` に縮小。

新規エンドポイント、新規テーブル、新規サブコマンド、新規環境変数、新規 Incident.source 値、新規 MITRE Navigator フィールドサポートの追加はマイナーリリースで許可される。

---

## 7. メンテナンス

Committed サーフェス項目が導入または非推奨化されるたびに本ドキュメントを更新すること。同様のメンテナンス規約については BEACON `docs/api-stability.md` §7 を参照。

---

*Initiative H — 1.0 安定化。SAGE 1.0.0 から有効。*
