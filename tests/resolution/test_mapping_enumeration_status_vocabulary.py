"""Every enumeration status the producer can emit must survive the L2 cache.

``mapping_enumerator`` owns the ``status`` vocabulary; ``db.mapping_enumeration_cache``
persists it into a fixed-width column. When a new member outgrew the column the write
raised ``StringDataRightTruncation``, the upsert swallowed it, and the *previous* row
survived, so an in-TTL ``complete`` kept being served for an address whose re-scan had come
back truncated (its partial set republished as authoritative).

The vocabulary is scraped from the producer module, not hand-copied: a copied list only pins
members someone remembered, and this file exists to catch a member nobody thought about.
Offline (PostgreSQL via requires_postgres).
"""

from __future__ import annotations

import ast
from pathlib import Path

import pytest

from db import mapping_enumeration_cache as db_cache
from db.models import MappingEnumerationCache
from tests.conftest import requires_postgres

_PRODUCER = Path(__file__).resolve().parents[2] / "services" / "resolution" / "mapping_enumerator.py"

# A floor, not the vocabulary: if the scraper breaks (say emissions move into a helper) it
# would return an empty set and pass vacuously. These are the oldest, least-renamed members.
_SCRAPER_SANITY_FLOOR = {"complete", "error", "incomplete_timeout", "incomplete_max_pages"}


def _string_constants(node: ast.AST) -> set[str]:
    return {n.value for n in ast.walk(node) if isinstance(n, ast.Constant) and isinstance(n.value, str)}


def _scrape_status_vocabulary() -> set[str]:
    """Collect every string literal the producer can bind to ``status``: a ``status=...``
    keyword on an ``EnumerationResult`` / ``EnumerationValueResult`` construction, or an
    assignment to a local named ``status`` (including conditional forms). Walking the bound
    expression for string constants picks up future ``"a" if p else "b"`` or tuple forms.
    """
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
    """Point the cache module's SessionLocal at the test database and clear this module's
    key before and after."""
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
    """Guards the guard: a scraper that stops finding emissions would make every
    round-trip vacuous."""
    vocabulary = _scrape_status_vocabulary()
    missing = _SCRAPER_SANITY_FLOOR - vocabulary
    assert not missing, f"status scraper lost known members {sorted(missing)} — it no longer reads the producer"
    # Constant-indirection guard: moving ONE emission behind a helper or constant could drop
    # just that member while the floor above still passes, so every incomplete_* literal in
    # the producer module must be in the scraped set.
    import re

    module_source = _PRODUCER.read_text()
    literal_members = set(re.findall(r'"(incomplete_[a-z_]+)"', module_source))
    escaped = literal_members - vocabulary
    assert not escaped, f"incomplete_* literals outside the scraper's reach: {sorted(escaped)}"


@requires_postgres
def test_every_producible_status_round_trips_through_the_cache(_l2):
    """The whole vocabulary through the real column, one member at a time. The column width
    is the thing under test, so Postgres must actually accept and return the value.
    """
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
    """The property the width bug broke: a rejected upsert leaves the previous row standing,
    so the honest truncated verdict must be able to overwrite a fresh ``complete`` (whose
    member set would otherwise keep being republished).
    """
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
    """A status the column cannot hold must be loud. The WARN-swallow in ``upsert`` is for
    transient DB trouble (one re-scan); a value that doesn't fit the schema is a programming
    error, so it raises. Pins that the swallow was narrowed, not just moved.
    """
    from sqlalchemy.exc import DataError

    db_cache.upsert(chain="1", address=ADDR, specs_hash=SPECS_HASH, result=_result("complete", last_block=100))
    with pytest.raises(DataError):
        db_cache.upsert(chain="1", address=ADDR, specs_hash=SPECS_HASH, result=_result("x" * 65, last_block=999))
