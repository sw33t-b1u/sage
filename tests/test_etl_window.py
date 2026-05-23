"""Tests for Initiative F Phase 7 env-driven activity window.

Covers:

- ``Config.from_env`` env hierarchy
  (``SAGE_ACTIVITY_WINDOW_DAYS`` > ``ACTIVITY_WINDOW_DAYS`` > 90).
- ``ETLWorker`` propagates the window into
  ``build_followed_by_weights``.
- ``build_followed_by_weights(activity_window_days=…)`` changes the
  per-TTP activity_score cutoff and therefore the resulting weight.
"""

from __future__ import annotations

from datetime import UTC, datetime, timedelta
from unittest.mock import MagicMock

import pytest

from sage.config import Config
from sage.etl.worker import ETLWorker
from sage.stix import mapper as mapper_mod
from sage.stix.mapper import build_followed_by_weights


@pytest.fixture
def env_required(monkeypatch):
    """Populate the env vars Config.from_env() validates as mandatory."""
    monkeypatch.setenv("PROJECT_ID", "test-project")
    monkeypatch.setenv("SPANNER_INSTANCE", "test-instance")
    monkeypatch.setenv("SPANNER_DB", "test-db")
    monkeypatch.setenv("GCS_BUCKET", "test-bucket")
    monkeypatch.setenv("OPENCTI_URL", "https://opencti.example/graphql")
    monkeypatch.setenv("OPENCTI_TOKEN", "x")


class TestConfigEnvHierarchy:
    def test_default_window_when_no_env(self, env_required, monkeypatch):
        monkeypatch.delenv("SAGE_ACTIVITY_WINDOW_DAYS", raising=False)
        monkeypatch.delenv("ACTIVITY_WINDOW_DAYS", raising=False)
        cfg = Config.from_env(dotenv_path="/nonexistent/.env")
        assert cfg.activity_window_days == 90

    def test_activity_window_days_env_used_when_sage_var_absent(self, env_required, monkeypatch):
        monkeypatch.delenv("SAGE_ACTIVITY_WINDOW_DAYS", raising=False)
        monkeypatch.setenv("ACTIVITY_WINDOW_DAYS", "180")
        cfg = Config.from_env(dotenv_path="/nonexistent/.env")
        assert cfg.activity_window_days == 180

    def test_sage_var_takes_precedence(self, env_required, monkeypatch):
        monkeypatch.setenv("ACTIVITY_WINDOW_DAYS", "180")
        monkeypatch.setenv("SAGE_ACTIVITY_WINDOW_DAYS", "365")
        cfg = Config.from_env(dotenv_path="/nonexistent/.env")
        assert cfg.activity_window_days == 365


class TestEtlWorkerWiresWindow:
    def test_worker_passes_window_into_followed_by(self, monkeypatch):
        captured: dict = {}

        def fake_build(uses_rows, ttp_phases, **kwargs):
            captured.update(kwargs)
            return []

        # Stub out everything the worker writes so we can run process_bundle
        # without a real Spanner backend; only the call into
        # build_followed_by_weights matters here.
        monkeypatch.setattr("sage.etl.worker.build_followed_by_weights", fake_build)
        monkeypatch.setattr("sage.etl.worker.upsert_rows", lambda *a, **kw: 0)
        monkeypatch.setattr("sage.etl.worker.upsert_followed_by", lambda *a, **kw: 0)
        monkeypatch.setattr("sage.etl.worker.upsert_has_access", lambda *a, **kw: 0)
        monkeypatch.setattr("sage.etl.worker.upsert_account_on_asset", lambda *a, **kw: 0)
        monkeypatch.setattr("sage.etl.worker.upsert_user_account_belongs_to", lambda *a, **kw: 0)
        monkeypatch.setattr("sage.etl.worker.upsert_attributed_to_actor", lambda *a, **kw: 0)
        monkeypatch.setattr("sage.etl.worker.upsert_attributed_to_identity", lambda *a, **kw: 0)
        monkeypatch.setattr("sage.etl.worker.upsert_impersonates_identity", lambda *a, **kw: 0)
        monkeypatch.setattr("sage.etl.worker.upsert_user_account", lambda *a, **kw: 0)
        monkeypatch.setattr(
            "sage.etl.worker.upsert_pir_prioritizes_impersonation_target",
            lambda *a, **kw: 0,
        )
        monkeypatch.setattr("sage.etl.worker.update_pir_criticality", lambda *a, **kw: 0)
        monkeypatch.setattr(
            "sage.etl.worker.build_ir_feedback_followed_by", lambda *a, **kw: ([], set())
        )
        monkeypatch.setattr("sage.etl.worker.ingest_prioritized_actors", lambda *a, **kw: 0)

        pir = MagicMock()
        pir.is_relevant_actor.return_value = True
        pir.build_pir_nodes.return_value = []
        pir.build_pir_actor_edges.return_value = []
        pir.build_pir_ttp_edges.return_value = []
        pir.build_pir_asset_edges.return_value = []
        pir._pirs = []
        pir.build_targets.return_value = []
        pir.update_asset_criticality.return_value = []

        db = MagicMock()
        worker = ETLWorker(db, pir, activity_window_days=180)
        worker.process_bundle(objects=[], asset_rows=None)
        assert captured.get("activity_window_days") == 180


class TestBuildFollowedByWindow:
    def _uses(self, last_observed):
        # actor with two TTPs phased Reconnaissance → Initial Access so
        # there is one transition; activity_score depends on
        # last_observed timestamps and the window.
        return [
            {
                "actor_stix_id": "intrusion-set--apt99",
                "ttp_stix_id": "attack-pattern--t1595",
                "last_observed": last_observed,
            },
            {
                "actor_stix_id": "intrusion-set--apt99",
                "ttp_stix_id": "attack-pattern--t1190",
                "last_observed": last_observed,
            },
        ]

    def _phases(self) -> dict[str, str]:
        return {
            "attack-pattern--t1595": "reconnaissance",
            "attack-pattern--t1190": "initial-access",
        }

    def test_observation_120d_ago_excluded_when_window_90d(self, monkeypatch):
        fixed_now = datetime(2026, 5, 23, tzinfo=UTC)
        monkeypatch.setattr(mapper_mod, "_now", lambda: fixed_now)
        old = fixed_now - timedelta(days=120)
        rows = build_followed_by_weights(self._uses(old), self._phases(), activity_window_days=90)
        assert len(rows) == 1
        # 120d > 90d window → activity_score = 0.0 → weight = 0.
        assert rows[0]["weight"] == 0.0

    def test_observation_120d_ago_included_when_window_180d(self, monkeypatch):
        fixed_now = datetime(2026, 5, 23, tzinfo=UTC)
        monkeypatch.setattr(mapper_mod, "_now", lambda: fixed_now)
        old = fixed_now - timedelta(days=120)
        rows = build_followed_by_weights(self._uses(old), self._phases(), activity_window_days=180)
        assert len(rows) == 1
        # 120d <= 180d window → activity_score = 1.0 → weight > 0.
        assert rows[0]["weight"] > 0.0

    def test_default_window_remains_90d_for_legacy_callers(self, monkeypatch):
        fixed_now = datetime(2026, 5, 23, tzinfo=UTC)
        monkeypatch.setattr(mapper_mod, "_now", lambda: fixed_now)
        # Caller omits activity_window_days → the historic 90-day default
        # applies, so observations older than 90 days are excluded.
        old = fixed_now - timedelta(days=120)
        rows = build_followed_by_weights(self._uses(old), self._phases())
        assert rows[0]["weight"] == 0.0
