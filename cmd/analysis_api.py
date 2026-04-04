"""SAGE Analysis API — uvicorn 起動エントリポイント。

Usage:
  uv run python -m cmd.analysis_api [--host HOST] [--port PORT] [--reload]

Cloud Run では PORT 環境変数を自動で参照する。
"""

from __future__ import annotations

import argparse
import os


def main() -> None:
    parser = argparse.ArgumentParser(description="Start SAGE Analysis API")
    parser.add_argument("--host", default="0.0.0.0", help="Bind host (default: 0.0.0.0)")
    parser.add_argument(
        "--port",
        type=int,
        default=int(os.environ.get("PORT", "8080")),
        help="Bind port (default: $PORT or 8080)",
    )
    parser.add_argument(
        "--reload",
        action="store_true",
        help="Enable auto-reload (development only)",
    )
    args = parser.parse_args()

    try:
        import uvicorn
    except ImportError:
        raise SystemExit("uvicorn is not installed. Run: uv sync")

    uvicorn.run(
        "sage.api.app:app",
        host=args.host,
        port=args.port,
        reload=args.reload,
        log_level="info",
    )


if __name__ == "__main__":
    main()
