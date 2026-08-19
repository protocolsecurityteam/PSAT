"""Regression tests for DB engine pool sizing in ``db/models.py``.

The pool was previously left at SQLAlchemy defaults (5+10). At 10 worker
processes per VM that caps out at 150 connections per VM under load,
which can blow past Neon's pool ceiling and surface as
``OperationalError: too many connections`` from random workers.

Pool size is now env-tunable via ``PSAT_DB_POOL_SIZE`` /
``PSAT_DB_MAX_OVERFLOW`` / ``PSAT_DB_POOL_RECYCLE``. ``deploy/start_workers.sh``
ships tight defaults (2+3) for workers; api/scripts keep 5+10 by default.

These tests pin the defaults *and* verify env overrides take effect, so a
silent revert (e.g. someone refactors the engine block and drops the
kwargs) gets caught at unit-test time rather than as a Fly incident.
"""

from __future__ import annotations

import importlib
import sys
from pathlib import Path

import pytest


@pytest.fixture(autouse=True)
def _pristine_db_models():
    """Restore the ORIGINAL db.models after every test here.

    A reloaded db.models left in sys.modules poisons the rest of a serial
    suite run: modules that bound classes at import time keep the old
    declarative registry while any deferred `from db.models import ...`
    resolves to the new one — two mappers over the same table in one
    session, and stale identity-map reads for whoever mixes them.
    """
    original = sys.modules.get("db.models")
    yield
    for mod in _RELOADED:
        if mod is not original:
            mod.engine.dispose()
    _RELOADED.clear()
    if original is not None:
        sys.modules["db.models"] = original


_RELOADED: list = []


def _reload_models():
    """Re-import db.models so module-level engine picks up current env."""
    if "db.models" in sys.modules:
        del sys.modules["db.models"]
    mod = importlib.import_module("db.models")
    _RELOADED.append(mod)
    return mod


def test_default_pool_size_matches_sqlalchemy_baseline(monkeypatch):
    """Without env overrides we must match the historical 5+10 to avoid
    a surprise behavior change for api/scripts that import the engine."""
    monkeypatch.delenv("PSAT_DB_POOL_SIZE", raising=False)
    monkeypatch.delenv("PSAT_DB_MAX_OVERFLOW", raising=False)
    monkeypatch.delenv("PSAT_DB_POOL_RECYCLE", raising=False)
    models = _reload_models()
    pool = models.engine.pool
    assert pool.size() == 5
    assert pool._max_overflow == 10


def test_pool_size_env_override_honored(monkeypatch):
    """deploy/start_workers.sh sets PSAT_DB_POOL_SIZE=2 PSAT_DB_MAX_OVERFLOW=3.
    A regression here would silently re-balloon worker DB connections."""
    monkeypatch.setenv("PSAT_DB_POOL_SIZE", "2")
    monkeypatch.setenv("PSAT_DB_MAX_OVERFLOW", "3")
    models = _reload_models()
    pool = models.engine.pool
    assert pool.size() == 2
    assert pool._max_overflow == 3


def test_pool_recycle_env_override_honored(monkeypatch):
    """Neon idle-disconnects at ~5 min; recycle must be tunable so we can
    drop below that ceiling on noisy networks."""
    monkeypatch.setenv("PSAT_DB_POOL_RECYCLE", "120")
    models = _reload_models()
    assert models.engine.pool._recycle == 120


def test_pool_pre_ping_still_enabled(monkeypatch):
    """pool_pre_ping is what catches Neon-killed connections before
    SQLAlchemy hands one out — must survive any future engine refactor."""
    monkeypatch.delenv("PSAT_DB_POOL_SIZE", raising=False)
    models = _reload_models()
    assert models.engine.pool._pre_ping is True


def test_connect_timeout_still_set():
    """psycopg2 defaults connect_timeout to infinity. A Neon cold-start
    must not block a worker forever — keep the 10s ceiling. Source-level
    check (the kwarg is consumed by psycopg2 at connect time and not
    introspectable via the engine API once the engine is built)."""
    src = (Path(__file__).resolve().parents[2] / "db" / "models.py").read_text()
    assert 'connect_args={"connect_timeout": 10}' in src
