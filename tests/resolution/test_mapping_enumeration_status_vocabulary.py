"""Every enumeration status the producer can emit must survive the L2 cache.

``services.resolution.mapping_enumerator`` owns the ``status`` vocabulary of
``EnumerationResult``; ``db.mapping_enumeration_cache`` persists it into a
fixed-width column. When a new member outgrew that column the write raised
``StringDataRightTruncation``, the upsert swallowed it as a warning, and the
*previous* row survived — so an in-TTL ``complete`` kept being served for an
address whose re-scan had honestly come back truncated, republishing that
scan's partial member set as authoritative for the rest of the TTL.

The vocabulary is scraped out of the producer module rather than hand-copied
here: a copied list only ever pins the members someone remembered to add to
it, and the failure mode this file exists to catch is precisely a member
nobody thought about. Adding a status to the enumerator therefore extends
this test automatically.

Marker: offline (PostgreSQL via requires_postgres). No live hypersync.
"""

from __future__ import annotations

import ast
from pathlib import Path

import pytest

from db import mapping_enumeration_cache as db_cache  # noqa: E402
from db.models import MappingEnumerationCache  # noqa: E402
from tests.conftest import requires_postgres  # noqa: E402

_PRODUCER = Path(__file__).resolve().parents[2] / "services" / "resolution" / "mapping_enumerator.py"

# A floor, not the vocabulary. If the scraper below breaks (a refactor moves
# the emissions into a helper, say) it would otherwise return an empty set and
# pass vacuously. These four are the oldest members and the least likely to be
# renamed; the scraper must find at least them.
_SCRAPER_SANITY_FLOOR = {"complete", "error", "incomplete_timeout", "incomplete_max_pages"}


def _string_constants(node: ast.AST) -> set[str]:
    return {n.value for n in ast.walk(node) if isinstance(n, ast.Constant) and isinstance(n.value, str)}


def _scrape_status_vocabulary() -> set[str]:
    """Collect every string literal the producer can bind to ``status``.

    Two emission shapes exist: a ``status=...`` keyword on an
    ``EnumerationResult`` / ``EnumerationValueResult`` construction, and a
    plain or annotated assignment to a local named ``status`` (including the
    conditional form, whose branches are both reachable). Both are collected
    by walking the bound expression for string constants, so a future
    ``"a" if p else "b"`` or tuple form is picked up without changing this.
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
    """Point the cache module's own SessionLocal at the test database and
    clear the key this module writes to, both before and after."""
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
    """Guards the guard: a scraper that silently stops finding emissions
    would make every round-trip below vacuous."""
    vocabulary = _scrape_status_vocabulary()
    missing = _SCRAPER_SANITY_FLOOR - vocabulary
    assert not missing, f"status scraper lost known members {sorted(missing)} — it no longer reads the producer"
    # Constant-indirection blindness guard: the scraper only sees literals in
    # the covered assignment shapes, so a refactor that moves ONE emission
    # behind a helper or module constant could drop just that member while
    # the floor above still passes. Every incomplete_* string literal in the
    # producer module must therefore be in the scraped set.
    import re

    module_source = _PRODUCER.read_text()
    literal_members = set(re.findall(r'"(incomplete_[a-z_]+)"', module_source))
    escaped = literal_members - vocabulary
    assert not escaped, f"incomplete_* literals outside the scraper's reach: {sorted(escaped)}"


@requires_postgres
def test_every_producible_status_round_trips_through_the_cache(_l2):
    """The whole vocabulary, through the real column, one member at a time.

    Not a length assertion against a constant — the column width is the
    thing under test, so the test has to actually make Postgres accept the
    value and hand it back.
    """
    failures: list[str] = []
    for status in sorted(_scrape_status_vocabulary()):
        try:
            db_cache.upsert(chain="1", address=ADDR, specs_hash=SPECS_HASH, result=_result(status))
        except Exception as exc:  # noqa: BLE001 — collect all, report together
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
    """The property the width bug actually broke.

    A rejected upsert is not a lost optimization — it leaves the previous
    row standing. So the specific damage is directional: the honest
    truncated verdict must be able to overwrite a fresh ``complete``,
    because the member set that produced that ``complete`` is exactly what
    would otherwise keep being republished.
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
    """A status the column genuinely cannot hold must be loud.

    The WARN-swallow in ``upsert`` is for transient DB trouble, where
    dropping a cache write costs one re-scan. A value that does not fit the
    declared schema is a programming error whose silent form is the bug
    above, so it raises — this pins that the swallow was narrowed and not
    just moved.
    """
    from sqlalchemy.exc import DataError

    db_cache.upsert(chain="1", address=ADDR, specs_hash=SPECS_HASH, result=_result("complete", last_block=100))
    with pytest.raises(DataError):
        db_cache.upsert(chain="1", address=ADDR, specs_hash=SPECS_HASH, result=_result("x" * 65, last_block=999))
