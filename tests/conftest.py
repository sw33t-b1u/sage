"""Shared test configuration — hermetic environment.

Two leak vectors make unguarded tests environment-dependent:

1. Ambient shell/.env values (GCP_PROJECT_ID, SPANNER_*, SAGE_STORAGE=gcs,
   OPENCTI/GHE/SLACK/CALDERA credentials, *_PROXY): an unmocked code path
   could build a real Spanner/GCS/OpenCTI client and hang on network.
2. ``sage.config._load_dotenv`` loads the repo-root ``.env`` (CWD-relative)
   on every ``Config.from_env()`` call, re-injecting the developer's values
   even after an env scrub.

The autouse fixture below closes both: it deletes the ambient keys for every
test and makes ``_load_dotenv`` a no-op for the repo-root ``.env`` only —
explicit ``dotenv_path=...`` arguments (used by test_config.py with tmp
paths) keep working. Tests that need any of these values must set env
explicitly via monkeypatch and mock the network layer.
"""

from __future__ import annotations

import os
from pathlib import Path

import pytest

_REPO_ROOT = Path(__file__).resolve().parent.parent
_REPO_DOTENV = _REPO_ROOT / ".env"

_AMBIENT_ENV_KEYS_TO_SCRUB = (
    "GCP_PROJECT_ID",
    "REGION",
    "PIR_FILE_PATH",
    "TLP_MAX_LEVEL",
    "ACTIVITY_WINDOW_DAYS",
    "ALL_PROXY",
    "HTTP_PROXY",
    "HTTPS_PROXY",
    "all_proxy",
    "http_proxy",
    "https_proxy",
)
_AMBIENT_ENV_PREFIXES_TO_SCRUB = (
    "SAGE_",
    "SPANNER_",
    "OPENCTI_",
    "GHE_",
    "CALDERA_",
    "SLACK_",
)


@pytest.fixture(autouse=True)
def _hermetic_env(monkeypatch):
    """Scrub ambient product/proxy env and block repo-root .env re-injection."""
    for _key in _AMBIENT_ENV_KEYS_TO_SCRUB:
        monkeypatch.delenv(_key, raising=False)
    for _key in list(os.environ):
        if _key.startswith(_AMBIENT_ENV_PREFIXES_TO_SCRUB):
            monkeypatch.delenv(_key, raising=False)

    import sage.config as _config_module  # noqa: PLC0415

    _original_load_dotenv = _config_module._load_dotenv

    def _guarded_load_dotenv(path: str = ".env") -> None:
        try:
            resolved = Path(path).resolve()
        except OSError:  # pragma: no cover - defensive
            resolved = None
        if resolved == _REPO_DOTENV:
            return  # never re-inject the developer's repo-root .env in tests
        _original_load_dotenv(path)

    monkeypatch.setattr(_config_module, "_load_dotenv", _guarded_load_dotenv)
