"""Protocol dedup regression guards: alias-driven merge, slug race, hostname match.

Originally POC reproductions of three concrete issues raised in code review.
After the fixes landed they were inverted into regression guards:

(1) ``test_orphan_duplicates_merge_via_aliases`` — passing ``aliases`` to
    ``get_or_create_protocol`` pulls every NULL-slug row sharing the family
    onto the slug-keyed row and reassigns FK children before deleting the
    orphans. Without aliases, the legacy single-row adoption still works.

(2) ``test_concurrent_slug_insert_serializes`` — concurrent workers racing
    to create a row for the same canonical slug now serialize cleanly: one
    INSERTs, the other catches the ``uq_protocol_canonical_slug``
    IntegrityError inside a savepoint and re-fetches the winner.

(3) ``test_resolver_matches_bare_hostname`` — ``_match_protocol`` now does
    a bidirectional substring check, so ``"etherfi.org"`` matches the
    ``"etherfi"`` slug. Hostname-only dapp-crawl jobs dedupe correctly with
    discovery's row.
"""

from __future__ import annotations

import os
import threading

import pytest
from sqlalchemy import create_engine, select
from sqlalchemy.orm import Session

from db.models import Protocol  # noqa: E402
from db.queue import get_or_create_protocol  # noqa: E402
from services.discovery.protocol_resolver import _match_protocol  # noqa: E402
from tests.conftest import requires_postgres  # noqa: E402

pytestmark = [requires_postgres]


# ---------------------------------------------------------------------------
# (1) Pre-existing duplicates merge via the aliases parameter.
# ---------------------------------------------------------------------------


def test_orphan_duplicates_merge_via_aliases(db_session):
    """Simulate post-migration prod state — two NULL-slug rows for the
    same family — and verify that the first worker call collapses them.

    The fix: ``get_or_create_protocol`` accepts an ``aliases`` list (the
    family's display-name spellings, e.g. from ``resolved["all_names"]``).
    On a slug-keyed miss it gathers every NULL-slug row whose name matches
    the requested name OR an alias, adopts the first, and merges the rest
    into it (FK children reassigned, orphan deleted).
    """
    from db.models import AuditReport

    row_a = Protocol(name="ether fi", canonical_slug=None)
    row_b = Protocol(name="etherfi", canonical_slug=None)
    db_session.add_all([row_a, row_b])
    db_session.flush()

    # Attach an audit report to the row that's about to be merged-from
    # (CASCADE FK). After merge it must point at the surviving row, not
    # be deleted alongside the orphan.
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

    # Exactly one row remains, with the slug stamped.
    rows = db_session.execute(select(Protocol)).scalars().all()
    assert len(rows) == 1, f"expected merge to one row, got {[(r.name, r.canonical_slug) for r in rows]}"
    assert rows[0].id == adopted.id
    assert adopted.canonical_slug == "ether.fi-cash"

    # The audit report's FK was reassigned, not cascade-deleted.
    db_session.refresh(orphan_audit)
    assert orphan_audit.protocol_id == adopted.id


def test_no_aliases_keeps_legacy_single_row_adoption(db_session):
    """When ``aliases`` is omitted, the function must still adopt the one
    row that matches by exact name. Guards the no-regression path for
    callers that don't yet pass aliases.
    """
    row = Protocol(name="solo-protocol", canonical_slug=None)
    db_session.add(row)
    db_session.commit()

    adopted = get_or_create_protocol(
        db_session,
        "solo-protocol",
        canonical_slug="solo-slug",
    )
    db_session.commit()

    assert adopted.id == row.id
    assert adopted.canonical_slug == "solo-slug"
    assert len(db_session.execute(select(Protocol)).scalars().all()) == 1


# ---------------------------------------------------------------------------
# (2) Concurrent slug-keyed inserts serialize cleanly via savepoint retry.
# ---------------------------------------------------------------------------


def test_concurrent_slug_insert_serializes():
    """Two threads, two sessions, same canonical_slug. Both miss the lookup
    and call INSERT. The fix wraps the INSERT in a savepoint and catches
    ``IntegrityError`` on ``uq_protocol_canonical_slug``, re-fetching the
    winner. Both threads should see the same final row id.

    Two engines (one per thread) so the connections are genuinely separate.
    A barrier ensures both transactions issue their SELECT before either
    flushes — that's the window the savepoint retry has to handle.
    """
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
                except BaseException as exc:  # noqa: BLE001
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

    # Neither thread should have raised — the savepoint catches the loser's
    # IntegrityError and re-fetches the winner.
    assert results["a"]["exc"] is None, f"thread A raised: {results['a']['exc']!r}"
    assert results["b"]["exc"] is None, f"thread B raised: {results['b']['exc']!r}"
    # Both should converge on the same row id.
    assert results["a"]["id"] == results["b"]["id"], f"expected both threads to see the same row, got {results!r}"


# ---------------------------------------------------------------------------
# (3) Resolver matches bare hostnames via bidirectional substring.
# ---------------------------------------------------------------------------


def test_resolver_matches_bare_hostname():
    """``_match_protocol`` now does a bidirectional substring check:
    ``slug_norm in name_norm`` was missing, so ``"etherfiorg"`` (the
    normalized form of the hostname ``"etherfi.org"``) failed to match
    the ``"etherfi"`` slug. Adding the reverse direction with the same
    ≥50% length gate fixes the dapp_crawl fall-through.
    """
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

    # Existing match paths still work.
    assert _match_protocol("etherfi", protocols) is not None
    assert _match_protocol("Ether.fi", protocols) is not None
    assert _match_protocol("ether fi", protocols) is not None

    # Bare-hostname inputs from dapp_crawl_worker now resolve.
    matched = _match_protocol("etherfi.org", protocols)
    assert matched is not None and matched["slug"] == "etherfi"

    # And we should not pick up an unrelated short-input false positive:
    # an input with no real overlap should still miss.
    assert _match_protocol("zzz", protocols) is None
