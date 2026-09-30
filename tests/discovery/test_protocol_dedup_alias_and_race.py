
from __future__ import annotations

import os
import threading

import pytest
from sqlalchemy import create_engine, select
from sqlalchemy.orm import Session

from db.models import Protocol
from db.queue import get_or_create_protocol
from services.discovery.protocol_resolver import _match_protocol
from tests.conftest import requires_postgres

pytestmark = [requires_postgres]


def test_orphan_duplicates_merge_via_aliases(db_session):
    """``aliases`` merges NULL-slug family rows onto the adopted row."""
    from db.models import AuditReport

    row_a = Protocol(name="ether fi", canonical_slug=None)
    row_b = Protocol(name="etherfi", canonical_slug=None)
    db_session.add_all([row_a, row_b])
    db_session.flush()

    # The CASCADE FK row must follow the survivor.
    orphan_audit = AuditReport(
        protocol_id=row_a.id,
        url="https://example.com/audit",
        auditor="TestAuditor",
        title="Test Audit",
    )
    db_session.add(orphan_audit)
    db_session.commit()

    adopted = get_or_create_protocol(
        db_session,
        "etherfi",
        canonical_slug="ether.fi-cash",
        aliases=["ether fi", "Ether.fi", "etherfi"],
    )
    db_session.commit()

    rows = db_session.execute(select(Protocol)).scalars().all()
    assert len(rows) == 1, f"expected merge to one row, got {[(r.name, r.canonical_slug) for r in rows]}"
    assert rows[0].id == adopted.id
    assert adopted.canonical_slug == "ether.fi-cash"

    db_session.refresh(orphan_audit)
    assert orphan_audit.protocol_id == adopted.id


def test_concurrent_slug_insert_serializes():
    """Separate engines give separate connections; the barrier makes both SELECT before either flushes."""
    db_url = os.environ.get("TEST_DATABASE_URL")
    if not db_url:
        pytest.skip("TEST_DATABASE_URL not set")

    cleanup_engine = create_engine(db_url)
    with Session(cleanup_engine, expire_on_commit=False) as s:
        s.query(Protocol).filter(Protocol.canonical_slug == "race-test-slug").delete()
        s.query(Protocol).filter(Protocol.name.in_(["race-A", "race-B"])).delete()
        s.commit()

    barrier = threading.Barrier(2)
    results: dict[str, dict] = {"a": {}, "b": {}}

    def worker(label: str, name: str) -> None:
        engine = create_engine(db_url)
        try:
            with Session(engine, expire_on_commit=False) as s:
                s.execute(select(Protocol).where(Protocol.canonical_slug == "race-test-slug")).scalar_one_or_none()
                barrier.wait(timeout=10)
                try:
                    row = get_or_create_protocol(s, name=name, canonical_slug="race-test-slug")
                    s.commit()
                    results[label] = {"id": row.id, "exc": None}
                except BaseException as exc:
                    s.rollback()
                    results[label] = {"id": None, "exc": exc}
        finally:
            engine.dispose()

    t1 = threading.Thread(target=worker, args=("a", "race-A"))
    t2 = threading.Thread(target=worker, args=("b", "race-B"))
    t1.start()
    t2.start()
    t1.join(timeout=15)
    t2.join(timeout=15)

    with Session(cleanup_engine, expire_on_commit=False) as s:
        s.query(Protocol).filter(Protocol.canonical_slug == "race-test-slug").delete()
        s.query(Protocol).filter(Protocol.name.in_(["race-A", "race-B"])).delete()
        s.commit()
    cleanup_engine.dispose()

    assert results["a"]["exc"] is None, f"thread A raised: {results['a']['exc']!r}"
    assert results["b"]["exc"] is None, f"thread B raised: {results['b']['exc']!r}"
    assert results["a"]["id"] == results["b"]["id"], f"expected both threads to see the same row, got {results!r}"


def test_resolver_matches_bare_hostname():
    """The reverse substring direction (with the same 50% length gate) lets "etherfi.org" match the "etherfi" slug."""
    protocols = [
        {
            "slug": "etherfi",
            "name": "Ether.fi",
            "url": "https://ether.fi",
            "chains": ["Ethereum"],
            "tvl": 1_000_000_000,
        },
        {"slug": "aave-v3", "name": "Aave V3", "url": "https://aave.com", "chains": ["Ethereum"], "tvl": 1},
        {"slug": "uniswap-v3", "name": "Uniswap V3", "url": "https://uniswap.org", "chains": ["Ethereum"], "tvl": 1},
    ]

    assert _match_protocol("etherfi", protocols) is not None
    assert _match_protocol("Ether.fi", protocols) is not None
    assert _match_protocol("ether fi", protocols) is not None

    matched = _match_protocol("etherfi.org", protocols)
    assert matched is not None and matched["slug"] == "etherfi"

    assert _match_protocol("zzz", protocols) is None
