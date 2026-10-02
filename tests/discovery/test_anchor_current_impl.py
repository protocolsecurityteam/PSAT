"""The backfill used to tag the current live impl ``upgrade_history`` too, hiding it from analysis, requeue and
coverage.
"""

from __future__ import annotations

import uuid

from services.discovery.ranking import is_superseded_impl
from tests.conftest import requires_postgres


def _addr() -> str:
    return "0x" + uuid.uuid4().hex[:40]


def _stub_backfill_io(monkeypatch):
    """Stub Etherscan name lookup, the near-line probe and audit-coverage refresh to stay offline + hermetic."""
    monkeypatch.setattr("services.clients.etherscan.parallel_get", lambda calls: {k: fn() for k, fn in calls.items()})
    monkeypatch.setattr("services.clients.etherscan.get_contract_info", lambda addr, **_kw: (f"Impl_{addr[-4:]}", True))
    monkeypatch.setattr("services.discovery.membership_gate.probe", lambda session, contract: None)
    monkeypatch.setattr("services.audits.coverage.upsert_coverage_for_contract", lambda *a, **k: 0)


@requires_postgres
def test_backfill_tags_current_impl_live_create(db_session, monkeypatch):
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
        current_impl_address=current,
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
    from db.models import Contract, Protocol
    from services.discovery.upgrade_history import backfill_historical_impl_contracts

    _stub_backfill_io(monkeypatch)
    p = Protocol(name=f"uh-adopt-{uuid.uuid4().hex[:8]}")
    db_session.add(p)
    db_session.commit()

    current = _addr().lower()
    # Low-source so the ownership gate doesn't fire coverage work.
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
        current_impl_address=current,
    )
    db_session.commit()

    row = db_session.query(Contract).filter(Contract.address == current).one()
    sources = set(row.discovery_sources or [])
    assert "current_implementation" in sources
    assert "upgrade_history" not in sources
    assert is_superseded_impl(sources) is False
