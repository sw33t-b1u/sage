FROM python:3.12-slim

WORKDIR /app

# uv をインストール
COPY --from=ghcr.io/astral-sh/uv:latest /uv /usr/local/bin/uv

# 依存関係をインストール（キャッシュ最適化）
COPY pyproject.toml uv.lock* ./
RUN uv sync --no-dev --frozen

# ソースをコピー
COPY src/ ./src/
COPY cmd/ ./cmd/
COPY schema/ ./schema/

ENV PYTHONPATH=/app/src

ENTRYPOINT ["uv", "run", "python", "cmd/run_etl.py"]
