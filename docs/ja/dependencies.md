# SAGE — 依存パッケージ一覧

このドキュメントは [プロジェクトルール 18](../../../docs/RULES.md) に従い、
すべてのサードパーティ依存パッケージの目的・選定理由・ライセンスを記録します。

英語版（正本）: [`docs/dependencies.md`](../dependencies.md)

---

## ランタイム依存

| パッケージ | バージョン制約 | ライセンス | 目的 | 内製しない理由 |
|-----------|-------------|---------|------|------------|
| `stix2` | `>=3.0.1` | BSD-3-Clause | STIX 2.1 オブジェクト（ThreatActor、TTP、Incident 等）の解析・シリアライズ | STIX 2.1 は多数のオブジェクト型と関係スキーマを持つ複雑な標準規格。内製パーサーは OASIS 仕様全体の再実装に等しい。|
| `pycti` | `>=6.3.0` | Apache-2.0 | OpenCTI REST API クライアント — STIX バンドルのポーリング・ページネーション・認証 | OpenCTI の API はリリースごとに変化する。公式 SDK がその変更を追跡し、型付きヘルパーを提供している。|
| `google-cloud-spanner` | `>=3.49.0` | Apache-2.0 | Cloud Spanner クライアント — ノード・エッジの upsert、GQL・SQL クエリ、スナップショット読み取り | Google 公式クライアントが gRPC 接続プール・リトライロジック・Spanner 固有の型マッピングを担っており、内製は現実的でない。|
| `google-cloud-storage` | `>=2.18.0` | Apache-2.0 | GCS ランディングゾーンからの生 STIX バンドル読み取り | Google 公式クライアントがリジューム可能アップロード・リトライポリシー・IAM 認証を処理する。|
| `structlog` | `>=24.4.0` | MIT | 構造化ログ出力（Cloud Run は JSON、ターミナルは色付きテキスト） | stdlib の `logging` には構造化コンテキストバインディングがない。`structlog` は Cloud Logging 互換 JSON 出力を最小オーバーヘッドで実現する。|
| `requests` | `>=2.32.0` | Apache-2.0 | Slack Incoming Webhook・GitHub REST API・MITRE Caldera REST API への HTTP クライアント | これら 3 つの外部 API はすべて平易な HTTPS/JSON を使用。ETL 層に非同期の複雑さを持ち込まないため `requests`（同期）を採用。|
| `fastapi` | `>=0.115.0` | MIT | Analysis API の Web フレームワーク — 宣言的ルーティング・OpenAPI 自動生成・Pydantic バリデーション | Flask は OpenAPI 生成と型ベースバリデーションを標準では持たない。FastAPI の `Query` ディスクリプターで範囲チェックや必須パラメーターを最小ボイラープレートで記述できる。|
| `uvicorn` | `>=0.30.0` | BSD-3-Clause | Cloud Run 上で FastAPI を動かす ASGI サーバー | FastAPI は ASGI サーバーが必要。uvicorn は FastAPI と同じ Encode チームが開発しており、事実上の標準ペアリング。|

---

## 開発専用依存

| パッケージ | バージョン制約 | ライセンス | 目的 |
|-----------|-------------|---------|------|
| `ruff` | `>=0.6.0` | MIT | リンター・フォーマッター（flake8 + isort + black を 1 バイナリに統合）|
| `pytest` | `>=8.3.0` | MIT | テストランナー |
| `pytest-cov` | `>=5.0.0` | MIT | `make test` 用カバレッジレポート |
| `pip-audit` | `>=2.7.0` | Apache-2.0 | 依存パッケージの既知脆弱性スキャン（ルール 21）。`make audit` / `make check` で実行。|
| `pyvis` | `>=0.3.2` | BSD-3-Clause | インタラクティブグラフの HTML 生成（`visualize_combined.py`、`visualize_graph.py`、`visualize_attack_flow.py`）|
| `httpx` | `>=0.27.0` | BSD-3-Clause | FastAPI `TestClient` に必要（Starlette の依存）。`tests/test_api.py` でのみ使用。|

---

## 不採用 / 検討済み

| パッケージ | 不採用理由 |
|-----------|---------|
| `neo4j` | Spanner Graph（GQL）が既存 GCP スタック内でグラフ探索要件を満たす。Neo4j 導入はインフラ複雑度とコストを増加させる。Spanner GQL のパフォーマンスが大規模で不十分と判明した場合は再検討（`TODO.md` 参照）。|
| `httpx`（ランタイム）| ETL・通知層は同期処理であり、非同期の複雑さは不要。`httpx` はテスト用の開発依存としてのみ含む。|
| `pydantic`（単独）| FastAPI が Pydantic v2 を内包しているため、追加インストール不要。|
