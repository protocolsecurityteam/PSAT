"""SQLAlchemy's default 5+10 pool at 10 workers per VM is 150 connections, past Neon's ceiling.

Workers ship 2+3 via ``deploy/start_workers.sh``.
"""

from __future__ import annotations

import importlib
import sys

import pytest


@pytest.fixture(autouse=True)
def _pristine_db_models():
    """A reloaded db.models left in sys.modules gives two mappers over the same table in one session for any module
    that bound classes at import time.
    """
    original = sys.modules.get("db.models")
    original_session = sys.modules.get("db.models.session")
    yield
    for mod in _RELOADED:
        if mod is not original:
            mod.engine.dispose()
    _RELOADED.clear()
    if original is not None:
        sys.modules["db.models"] = original
    if original_session is not None:
        sys.modules["db.models.session"] = original_session


_RELOADED: list = []


def _reload_models():
    """Only ``session`` is evicted so the mapper submodules never re-register."""
    for name in ("db.models", "db.models.session"):
        if name in sys.modules:
            del sys.modules[name]
    mod = importlib.import_module("db.models")
    _RELOADED.append(mod)
    return mod


def test_default_pool_size_matches_sqlalchemy_baseline(monkeypatch):
    monkeypatch.delenv("PSAT_DB_POOL_SIZE", raising=False)
    monkeypatch.delenv("PSAT_DB_MAX_OVERFLOW", raising=False)
    monkeypatch.delenv("PSAT_DB_POOL_RECYCLE", raising=False)
    models = _reload_models()
    pool = models.engine.pool
    assert pool.size() == 5
    assert pool._max_overflow == 10


def test_pool_size_env_override_honored(monkeypatch):
    monkeypatch.setenv("PSAT_DB_POOL_SIZE", "2")
    monkeypatch.setenv("PSAT_DB_MAX_OVERFLOW", "3")
    models = _reload_models()
    pool = models.engine.pool
    assert pool.size() == 2
    assert pool._max_overflow == 3
