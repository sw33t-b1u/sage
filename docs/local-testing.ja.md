# SAGE — ローカルテスト

英語版（正本）: [`docs/local-testing.md`](local-testing.md)

## ユニットテスト（GCP 不要）

```sh
make test
```

`tests/fixtures/` 配下のフィクスチャファイルを使用する。GCP の認証情報やネットワークアクセスは不要。

カバレッジレポートを出力する場合:

```sh
uv run pytest --cov=src/sage --cov-report=term-missing
```

---

## Spanner エミュレーターを使ったフルローカルテスト

Attack Flow（STIX 脅威インテリジェンス）と Attack Graph（内部資産）の完全なワークフローを検証する。

**Docker または Podman が必要。**

```sh
# 1. Spanner エミュレーターを起動
docker run -d --name spanner-emulator -p 9010:9010 -p 9020:9020 \
  gcr.io/cloud-spanner-emulator/emulator
export SPANNER_EMULATOR_HOST=localhost:9010

# 2. インスタンス・データベース・スキーマを作成
uv run python cmd/setup_emulator.py
make init-schema

# 3. 脅威インテリジェンスを投入（Attack Flow）
uv run python cmd/run_etl.py --manual-bundle tests/fixtures/sample_bundle_mirrorface.json
uv run python cmd/run_etl.py --manual-bundle tests/fixtures/sample_bundle_inc.json

# 4. 内部資産を投入（Attack Graph）
make load-assets

# 5. 可視化 — tests/output/graph.html を生成してブラウザで開く
make visualize

# 6. 完了後にエミュレーターを停止・削除
docker stop spanner-emulator && docker rm spanner-emulator
```

### Docker の代わりに Podman を使う

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

## グラフ可視化

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
uv run python cmd/visualize_combined.py --no-open   # 統合ビュー、ブラウザ自動起動を抑制
uv run python cmd/visualize_combined.py --limit 200 # テーブルごとの行数を制限
uv run python cmd/visualize_graph.py --no-open      # 攻撃グラフのみ
uv run python cmd/visualize_attack_flow.py --no-open # 攻撃フローのみ
```

---

## サンプルフィクスチャ

| ファイル | 説明 |
|---------|------|
| `sample_bundle_mirrorface.json` | MirrorFace / Earth Kasha APT（日本標的、2024〜2025）。TTP: T1190, T1566.001, T1574.002, T1071.001, T1083, T1041。CVE-2023-28461, CVE-2024-21412。LODEINFO バックドア + C2 IoC。 |
| `sample_bundle_inc.json` | INC ランサムウェア（2023年〜、医療/製造業標的）。TTP: T1190, T1078, T1003.001, T1021.002, T1048.002, T1486。CVE-2023-3519, CVE-2023-4966 (Citrix)。ツール: Cobalt Strike, AnyDesk, MegaSync。 |
| `sample_assets.json` | 日本の製造業企業: Citrix NetScaler ADC, Active Directory, ファイルサーバー, バックアップサーバー, ERP (SAP), 工場 PLC, ワークステーション。 |
| `sample_pir.json` | ユニットテスト用の最小 PIR。 |
