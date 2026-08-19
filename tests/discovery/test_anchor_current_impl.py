"""Regression tests for the current-impl anchor bug (1B).

The upgrade-history backfill used to stamp ``upgrade_history`` on *every* impl in
a proxy's ``Upgraded`` events — including the proxy's CURRENT live impl (it
appears in the last event). The anchor predicate then excluded that live impl
(where the proxy's real functions + principals live) from analysis, requeue, and
coverage metrics.

Pins:
  * ``is_superseded_impl`` / ``not_superseded_impl_clause`` treat a row tagged
    ``current_implementation`` as live, not a superseded anchor;
  * ``backfill_historical_impl_contracts`` tags the *current* impl
    ``current_implementation`` (not ``upgrade_history``) on both the create and
    adopt paths, while genuinely-superseded impls stay anchored.
"""

from __future__ import annotations

import uuid

from services.discovery.ranking import is_superseded_impl
from tests.conftest import requires_postgres


def _addr() -> str:
    return "0x" + uuid.uuid4().hex[:40]


def test_is_superseded_impl_predicate():
    # Superseded-only anchor → excluded.
    assert is_superseded_impl(["upgrade_history"]) is True
    # Current live impl (also seen in upgrade events) → kept.
    assert is_superseded_impl(["upgrade_history", "current_implementation"]) is False
    assert is_superseded_impl(["current_implementation"]) is False
    # Ordinary discovered contract → kept.
    assert is_superseded_impl(["deployer_expansion"]) is False
    # Legacy NULL sources → kept.
    assert is_superseded_impl(None) is False
    assert is_superseded_impl([]) is False


@requires_postgres
def test_not_superseded_impl_clause_filters(db_session):
    from sqlalchemy import select

    from db.models import Contract, Protocol
    from services.discovery.ranking import not_superseded_impl_clause

    p = Protocol(name=f"anchor-{uuid.uuid4().hex[:8]}")
    db_session.add(p)
    db_session.commit()

    superseded = Contract(address=_addr(), chain="ethereum", protocol_id=p.id, discovery_sources=["upgrade_history"])
    current = Contract(
        address=_addr(),
        chain="ethereum",
        protocol_id=p.id,
        discovery_sources=["upgrade_history", "current_implementation"],
    )
    normal = Contract(address=_addr(), chain="ethereum", protocol_id=p.id, discovery_sources=["deployer_expansion"])
    legacy = Contract(address=_addr(), chain="ethereum", protocol_id=p.id, discovery_sources=None)
    db_session.add_all([superseded, current, normal, legacy])
    db_session.commit()

    kept = {
        a.lower()
        for a in db_session.execute(
            select(Contract.address).where(
                Contract.protocol_id == p.id,
                not_superseded_impl_clause(Contract.discovery_sources),
            )
        ).scalars()
    }
    assert superseded.address.lower() not in kept, "superseded-only anchor must be excluded"
    assert current.address.lower() in kept, "current live impl must be kept"
    assert normal.address.lower() in kept
    assert legacy.address.lower() in kept


def _stub_backfill_io(monkeypatch):
    """Backfill resolves impl names via Etherscan and refreshes audit coverage.
    Stub both so the test stays offline + hermetic."""
    monkeypatch.setattr("utils.etherscan.parallel_get", lambda calls: {k: fn() for k, fn in calls.items()})
    monkeypatch.setattr("utils.etherscan.get_contract_info", lambda addr, **_kw: (f"Impl_{addr[-4:]}", True))
    monkeypatch.setattr("services.audits.coverage.upsert_coverage_for_contract", lambda *a, **k: 0)


@requires_postgres
def test_backfill_tags_current_impl_live_create(db_session, monkeypatch):
    """Create path: the current impl is created tagged ``current_implementation``
    (not the superseded anchor), while other impls are anchored."""
    from db.models import Contract, Protocol
    from services.discovery.upgrade_history import backfill_historical_impl_contracts

    _stub_backfill_io(monkeypatch)
    p = Protocol(name=f"uh-create-{uuid.uuid4().hex[:8]}")
    db_session.add(p)
    db_session.commit()

    current = _addr().lower()
    superseded = _addr().lower()
    backfill_historical_impl_contracts(
        db_session,
        protocol_id=p.id,
        chain="ethereum",
        impl_addrs={current, superseded},
        parent_proxy_sources=["dapp_crawl"],  # low-confidence → no ownership/coverage churn
        parent_proxy_current_impl_address=current,
    )
    db_session.commit()

    rows = {
        c.address.lower(): set(c.discovery_sources or [])
        for c in db_session.query(Contract).filter(Contract.address.in_([current, superseded])).all()
    }
    assert "current_implementation" in rows[current]
    assert "upgrade_history" not in rows[current]
    assert is_superseded_impl(rows[current]) is False  # stays analyzable

    assert "upgrade_history" in rows[superseded]
    assert "current_implementation" not in rows[superseded]
    assert is_superseded_impl(rows[superseded]) is True


@requires_postgres
def test_backfill_tags_current_impl_live_adopt(db_session, monkeypatch):
    """Adopt path: a pre-existing live impl row (as analysis writes it) gets the
    ``current_implementation`` marker appended — NOT ``upgrade_history`` — so it
    stops being hidden from anchor-excluding metrics/requeue."""
    from db.models import Contract, Protocol
    from services.discovery.upgrade_history import backfill_historical_impl_contracts

    _stub_backfill_io(monkeypatch)
    p = Protocol(name=f"uh-adopt-{uuid.uuid4().hex[:8]}")
    db_session.add(p)
    db_session.commit()

    current = _addr().lower()
    # Pre-existing row as the analysis pipeline would have written it (low-source
    # so the ownership gate doesn't fire coverage work).
    db_session.add(
        Contract(
            address=current,
            chain="ethereum",
            protocol_id=p.id,
            contract_name="LRTSquaredCore",
            discovery_sources=["dapp_crawl"],
        )
    )
    db_session.commit()

    backfill_historical_impl_contracts(
        db_session,
        protocol_id=p.id,
        chain="ethereum",
        impl_addrs={current},
        parent_proxy_sources=["dapp_crawl"],
        parent_proxy_current_impl_address=current,
    )
    db_session.commit()

    row = db_session.query(Contract).filter(Contract.address == current).one()
    sources = set(row.discovery_sources or [])
    assert "current_implementation" in sources
    assert "upgrade_history" not in sources
    assert is_superseded_impl(sources) is False
