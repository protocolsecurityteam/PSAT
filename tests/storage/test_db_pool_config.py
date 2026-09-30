"""Regression tests for DB engine pool sizing in ``db/models/session.py``.

The pool was left at SQLAlchemy defaults (5+10); at 10 worker processes per VM that is 150
connections, which can blow past Neon's ceiling (``too many connections``). It is now env-tunable
via ``PSAT_DB_POOL_SIZE`` / ``PSAT_DB_MAX_OVERFLOW`` / ``PSAT_DB_POOL_RECYCLE`` (workers ship 2+3 in
``deploy/start_workers.sh``). These tests pin defaults and overrides so a silent revert is caught
at unit-test time rather than as a Fly incident.
"""

from __future__ import annotations

import importlib
import sys

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
    """Re-import db.models so module-level engine picks up current env.

    Only ``db.models.session`` is evicted alongside the package: the engine
    lives there, and leaving the mapper submodules cached means the reload
    never re-registers mappers (no duplicate-mapper poisoning).
    """
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
    """deploy/start_workers.sh sets POOL_SIZE=2 MAX_OVERFLOW=3; a regression would re-balloon worker connections."""
    monkeypatch.setenv("PSAT_DB_POOL_SIZE", "2")
    monkeypatch.setenv("PSAT_DB_MAX_OVERFLOW", "3")
    models = _reload_models()
    pool = models.engine.pool
    assert pool.size() == 2
    assert pool._max_overflow == 3


def test_pool_recycle_env_override_honored(monkeypatch):
    """Neon idle-disconnects at ~5 min; recycle must be tunable below that."""
    monkeypatch.setenv("PSAT_DB_POOL_RECYCLE", "120")
    models = _reload_models()
    assert models.engine.pool._recycle == 120


def test_pool_pre_ping_still_enabled(monkeypatch):
    """pool_pre_ping is what catches Neon-killed connections before
    SQLAlchemy hands one out — must survive any future engine refactor."""
    monkeypatch.delenv("PSAT_DB_POOL_SIZE", raising=False)
    models = _reload_models()
    assert models.engine.pool._pre_ping is True
