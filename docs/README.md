# SAGE Documentation

## For Operators (deploy & run)

| Document | Description |
|----------|-------------|
| [setup.md](setup.md) | GCP resource creation, Spanner setup, Cloud Run deployment |
| [local-testing.md](local-testing.md) | Spanner emulator setup for local development |

## For Analysts (daily use)

| Document | Description |
|----------|-------------|
| [analyst-guide.md](analyst-guide.md) | CLI usage, attack-path queries, visualization |

## For Developers (contribute code)

| Document | Description |
|----------|-------------|
| [structure.md](structure.md) | Project directory layout |
| [data-model.md](data-model.md) | Spanner Graph schema, node/edge definitions |
| [dependencies.md](dependencies.md) | Third-party dependency rationale |

## For Architects (design decisions)

| Document | Description |
|----------|-------------|
| [api-stability.md](api-stability.md) | API stability policy and BC guarantees |
| [high-level-design.md](high-level-design.md) | System design (local-only, gitignored) |

## Cross-project (shared via symlink)

| Document | Canonical repo | Description |
|----------|---------------|-------------|
| [pipeline-guide.md](pipeline-guide.md) | BEACON | End-to-end CTI pipeline operations |
| [ir-feedback-flow.md](ir-feedback-flow.md) | SAGE | IR feedback loop and scoring formulas |
| [citations.md](citations.md) | BEACON | External citations and license inventory |

日本語版は各ファイルの `.ja.md` サフィックスで同ディレクトリに配置。
