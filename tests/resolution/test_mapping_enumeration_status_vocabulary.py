"""A new status outgrew the column, the upsert swallowed the error, and a stale ``complete`` kept being served.

The vocabulary is scraped from the producer so a forgotten member is caught.
"""

from __future__ import annotations

import ast
from pathlib import Path

import pytest

from db import mapping_enumeration_cache as db_cache
from db.models import MappingEnumerationCache
from tests.conftest import requires_postgres

_PRODUCER = Path(__file__).resolve().parents[2] / "services" / "resolution" / "mapping_enumerator.py"

# A floor against a broken scraper passing vacuously.
_SCRAPER_SANITY_FLOOR = {"complete", "error", "incomplete_timeout", "incomplete_max_pages"}


def _string_constants(node: ast.AST) -> set[str]:
    return {n.value for n in ast.walk(node) if isinstance(n, ast.Constant) and isinstance(n.value, str)}


def _scrape_status_vocabulary() -> set[str]:
    """Walking the bound expression picks up conditional or tuple forms."""
    tree = ast.parse(_PRODUCER.read_text(encoding="utf-8"))
    found: set[str] = set()
    for node in ast.walk(tree):
        if isinstance(node, ast.Call):
            for kw in node.keywords:
                if kw.arg == "status":
                    found |= _string_constants(kw.value)
        elif isinstance(node, ast.AnnAssign):
            if isinstance(node.target, ast.Name) and node.target.id == "status" and node.value is not None:
                found |= _string_constants(node.value)
        elif isinstance(node, ast.Assign):
            if any(isinstance(t, ast.Name) and t.id == "status" for t in node.targets):
                found |= _string_constants(node.value)
    return found


ADDR = "0x" + "ab" * 20
SPECS_HASH = "c" * 64


@pytest.fixture()
def _l2(monkeypatch, db_session):
    import os

    from sqlalchemy import create_engine
    from sqlalchemy.orm import Session, sessionmaker

    test_url = os.environ["TEST_DATABASE_URL"]
    engine = create_engine(test_url)
    monkeypatch.setattr("db.mapping_enumeration_cache.SessionLocal", sessionmaker(bind=engine, class_=Session))

    def _clear() -> None:
        db_session.query(MappingEnumerationCache).filter(MappingEnumerationCache.address == ADDR.lower()).delete()
        db_session.commit()

    _clear()
    try:
        yield
    finally:
        _clear()
        engine.dispose()


def _result(status: str, *, last_block: int = 1) -> dict:
    return {
        "principals": [],
        "status": status,
        "pages_fetched": 0,
        "last_block_scanned": last_block,
        "error": None,
    }


def test_scraper_finds_the_known_statuses():
    vocabulary = _scrape_status_vocabulary()
    missing = _SCRAPER_SANITY_FLOOR - vocabulary
    assert not missing, f"status scraper lost known members {sorted(missing)} — it no longer reads the producer"
    # Moving one emission behind a helper could drop it while the floor still passes.
    import re

    module_source = _PRODUCER.read_text()
    literal_members = set(re.findall(r'"(incomplete_[a-z_]+)"', module_source))
    escaped = literal_members - vocabulary
    assert not escaped, f"incomplete_* literals outside the scraper's reach: {sorted(escaped)}"


@requires_postgres
def test_every_producible_status_round_trips_through_the_cache(_l2):
    """The column width is what's under test."""
    failures: list[str] = []
    for status in sorted(_scrape_status_vocabulary()):
        try:
            db_cache.upsert(chain="1", address=ADDR, specs_hash=SPECS_HASH, result=_result(status))
        except Exception as exc:
            failures.append(f"{status!r} (len {len(status)}) could not be written: {type(exc).__name__}: {exc}")
            continue
        served = db_cache.find_fresh(chain="1", address=ADDR, specs_hash=SPECS_HASH, ttl_s=9999)
        assert served is not None, f"{status!r} vanished from the cache after a successful upsert"
        if served["status"] != status:
            failures.append(f"{status!r} (len {len(status)}) was written but the cache serves {served['status']!r}")
    assert not failures, "mapping_enumeration_cache.status cannot hold the producer's vocabulary:\n" + "\n".join(
        failures
    )


@requires_postgres
def test_truncated_status_displaces_a_prior_complete_row(_l2):
    """A truncated verdict must be able to overwrite a fresh ``complete``."""
    db_cache.upsert(chain="1", address=ADDR, specs_hash=SPECS_HASH, result=_result("complete", last_block=100))
    prior = db_cache.find_fresh(chain="1", address=ADDR, specs_hash=SPECS_HASH, ttl_s=9999)
    assert prior is not None and prior["status"] == "complete"

    longest = max(_scrape_status_vocabulary(), key=len)
    db_cache.upsert(chain="1", address=ADDR, specs_hash=SPECS_HASH, result=_result(longest, last_block=999))

    served = db_cache.find_fresh(chain="1", address=ADDR, specs_hash=SPECS_HASH, ttl_s=9999)
    assert served is not None
    assert served["status"] == longest, f"{longest!r} failed to displace the stale 'complete' row"
    assert served["last_block_scanned"] == 999


@requires_postgres
def test_oversized_status_raises_instead_of_silently_leaving_the_stale_row(_l2):
    """The swallow is for transient DB trouble; a value that doesn't fit is a programming error."""
    from sqlalchemy.exc import DataError

    db_cache.upsert(chain="1", address=ADDR, specs_hash=SPECS_HASH, result=_result("complete", last_block=100))
    with pytest.raises(DataError):
        db_cache.upsert(chain="1", address=ADDR, specs_hash=SPECS_HASH, result=_result("x" * 65, last_block=999))
