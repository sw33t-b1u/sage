# SAGE ドキュメント

## オペレーター向け（デプロイ・運用）

| ドキュメント | 説明 |
|-------------|------|
| [setup.md](setup.md) | GCP リソース作成、Spanner セットアップ、Cloud Run デプロイ |
| [local-testing.md](local-testing.md) | ローカル開発向け Spanner エミュレーターのセットアップ |

## アナリスト向け（日常利用）

| ドキュメント | 説明 |
|-------------|------|
| [analyst-guide.md](analyst-guide.md) | CLI 使用方法、攻撃パスクエリ、可視化 |

## 開発者向け（コード貢献）

| ドキュメント | 説明 |
|-------------|------|
| [structure.md](structure.md) | プロジェクトのディレクトリ構成 |
| [data-model.md](data-model.md) | Spanner Graph スキーマ、ノード/エッジ定義 |
| [dependencies.md](dependencies.md) | サードパーティ依存関係の採用理由 |

## アーキテクト向け（設計上の判断）

| ドキュメント | 説明 |
|-------------|------|
| [api-stability.md](api-stability.md) | API 安定性ポリシーおよび後方互換性の保証 |
| [high-level-design.md](high-level-design.md) | システム設計（ローカルのみ、gitignored） |

## クロスプロジェクト（シンボリックリンク経由で共有）

| ドキュメント | 正規リポジトリ | 説明 |
|-------------|--------------|------|
| [pipeline-guide.md](pipeline-guide.md) | BEACON | エンドツーエンド CTI パイプライン操作 |
| [ir-feedback-flow.md](ir-feedback-flow.md) | SAGE | IR フィードバックループとスコアリング計算式 |
| [citations.md](citations.md) | BEACON | 外部引用とライセンス一覧 |

日本語版は各ファイルの `.ja.md` サフィックスで同ディレクトリに配置。
