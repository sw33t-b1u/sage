FROM python:3.12-slim

WORKDIR /app

# pycti (OpenCTI client) → python-magic → libmagic. Slim image lacks it.
RUN apt-get update && apt-get install -y --no-install-recommends libmagic1 \
    && rm -rf /var/lib/apt/lists/*

# Install uv
COPY --from=ghcr.io/astral-sh/uv:latest /uv /usr/local/bin/uv

# Install dependencies (cache-optimized)
COPY pyproject.toml uv.lock* ./
RUN uv sync --no-install-project --no-dev --frozen

# Copy source code
COPY src/ ./src/
COPY schema/ ./schema/
RUN uv sync --no-dev --frozen

ENV PYTHONPATH=/app/src

ENTRYPOINT ["uv", "run", "sage", "run-etl"]
