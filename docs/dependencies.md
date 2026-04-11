# SAGE — Dependency Rationale

This document records the purpose, justification, and license for every third-party dependency,
per [project Rule 18](../../docs/RULES.md).

---

## Runtime Dependencies

| Package | Version constraint | License | Purpose | Why not in-house? |
|---------|-------------------|---------|---------|-------------------|
| `stix2` | `>=3.0.1` | BSD-3-Clause | Parse and serialize STIX 2.1 objects (ThreatActor, TTP, Incident, etc.) | STIX 2.1 is a complex, versioned standard with many object types and relationship semantics. Implementing a compliant parser in-house would replicate the entire OASIS specification. |
| `pycti` | `>=6.3.0` | Apache-2.0 | OpenCTI REST API client — polls STIX bundle exports, handles pagination and authentication. | OpenCTI's API surface changes with each release. The official SDK tracks these changes and provides typed helpers. |
| `google-cloud-spanner` | `>=3.49.0` | Apache-2.0 | Cloud Spanner client — node/edge upsert, GQL and SQL queries, snapshot reads. | Google's official client handles gRPC connection pooling, retry logic, and Spanner-specific type mappings that are non-trivial to replicate. |
| `google-cloud-storage` | `>=2.18.0` | Apache-2.0 | Read raw STIX bundles from GCS Landing Zone. | Google's official client handles resumable uploads, retry policies, and IAM-based auth. |
| `structlog` | `>=24.4.0` | MIT | Structured logging with consistent key-value output (JSON in Cloud Run, colored in terminal). | `logging` stdlib lacks structured context binding. `structlog` adds processors, bound loggers, and Cloud Logging-compatible JSON output with minimal overhead. |
| `requests` | `>=2.32.0` | Apache-2.0 | HTTP client for Slack Incoming Webhook, GitHub REST API, and MITRE Caldera REST API. | All three external APIs use plain HTTPS/JSON. `httpx` was not chosen to avoid an async dependency at the ETL layer; `requests` is synchronous and simpler. |
| `fastapi` | `>=0.115.0` | MIT | Analysis API web framework — declarative routing, automatic OpenAPI docs, Pydantic validation. | Flask lacks built-in OpenAPI generation and type-based validation. FastAPI's `Query` descriptor handles range checks and required parameters with minimal boilerplate. |
| `uvicorn` | `>=0.30.0` | BSD-3-Clause | ASGI server for FastAPI on Cloud Run. | FastAPI requires an ASGI server; uvicorn is the de facto standard pairing and is maintained by the same Encode team. |
| `cryptography` | `>=46.0.7` | Apache-2.0 / BSD | Transitive dependency of `google-cloud-spanner`. Pinned to `>=46.0.7` to resolve CVE-2026-39892 in 46.0.6. No direct usage in SAGE code. |

---

## Development-only Dependencies

| Package | Version constraint | License | Purpose |
|---------|-------------------|---------|---------|
| `ruff` | `>=0.6.0` | MIT | Linter and formatter (replaces flake8 + isort + black in a single binary). |
| `pytest` | `>=8.3.0` | MIT | Test runner. |
| `pytest-cov` | `>=5.0.0` | MIT | Coverage reporting for `make test`. |
| `pip-audit` | `>=2.7.0` | Apache-2.0 | Dependency vulnerability scanning (Rule 21). |
| `pyvis` | `>=0.3.2` | BSD-3-Clause | Interactive graph HTML generation (`visualize_graph.py`, `visualize_attack_flow.py`). |
| `httpx` | `>=0.27.0` | BSD-3-Clause | Required by FastAPI `TestClient` (Starlette dependency). Used only in `tests/test_api.py`. |

---

## Removed / Not Adopted

| Package | Reason not adopted |
|---------|-------------------|
| `neo4j` | Spanner Graph (GQL) covers traversal needs within the existing GCP stack. Switching to Neo4j would add infrastructure complexity and cost. Revisit if Spanner GQL performance proves insufficient at scale (see `TODO.md`). |
| `httpx` (runtime) | ETL and notify layers are synchronous; adding async complexity is unwarranted. `httpx` is included only as a dev dependency for testing. |
| `pydantic` (standalone) | FastAPI bundles Pydantic v2 internally. No additional install needed. |
