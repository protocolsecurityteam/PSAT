"""Shared by ``test_audit_coverage.py`` and ``test_audit_coverage_integration.py``.

``seed_protocol`` is a fixture, so importing it registers it.
"""

from __future__ import annotations

import uuid
from datetime import datetime, timezone

import pytest


@pytest.fixture()
def seed_protocol(db_session):
    from db.models import AuditContractCoverage, AuditReport, Contract, Protocol, UpgradeEvent

    name = f"cov-test-{uuid.uuid4().hex[:12]}"
    p = Protocol(name=name)
    db_session.add(p)
    db_session.commit()
    protocol_id = p.id
    try:
        yield protocol_id, name
    finally:
        db_session.query(AuditContractCoverage).filter_by(protocol_id=protocol_id).delete()
        contract_ids = [c.id for c in db_session.query(Contract).filter_by(protocol_id=protocol_id).all()]
        if contract_ids:
            db_session.query(UpgradeEvent).filter(UpgradeEvent.contract_id.in_(contract_ids)).delete(
                synchronize_session=False
            )
        db_session.query(Contract).filter_by(protocol_id=protocol_id).delete()
        db_session.query(AuditReport).filter_by(protocol_id=protocol_id).delete()
        db_session.query(Protocol).filter_by(id=protocol_id).delete()
        db_session.commit()


def _add_contract(
    session,
    protocol_id: int,
    *,
    address: str,
    name: str,
    is_proxy: bool = False,
    implementation: str | None = None,
    chain: str = "ethereum",
):
    from db.models import Contract

    c = Contract(
        protocol_id=protocol_id,
        address=address.lower(),
        contract_name=name,
        is_proxy=is_proxy,
        implementation=implementation.lower() if implementation else None,
        chain=chain,
    )
    session.add(c)
    session.commit()
    return c


def _add_audit(
    session,
    protocol_id: int,
    *,
    auditor: str = "TestFirm",
    title: str = "Audit",
    date: str | None = None,
    scope: list[str] | None = None,
    status: str | None = "success",
):
    from db.models import AuditReport

    ar = AuditReport(
        protocol_id=protocol_id,
        url=f"https://example.com/{uuid.uuid4().hex}.pdf",
        auditor=auditor,
        title=title,
        date=date,
        confidence=0.9,
        scope_extraction_status=status,
        scope_contracts=scope or [],
    )
    session.add(ar)
    session.commit()
    return ar


def _add_upgrade_event(
    session,
    *,
    contract_id: int,
    proxy_address: str,
    new_impl: str,
    old_impl: str | None = None,
    block_number: int,
    timestamp: datetime | None = None,
    tx_hash: str | None = None,
):
    from db.models import UpgradeEvent

    ev = UpgradeEvent(
        contract_id=contract_id,
        proxy_address=proxy_address.lower(),
        old_impl=old_impl.lower() if old_impl else None,
        new_impl=new_impl.lower(),
        block_number=block_number,
        timestamp=timestamp,
        tx_hash=tx_hash or f"0x{uuid.uuid4().hex[:64]}",
    )
    session.add(ev)
    session.commit()
    return ev


def _ts(year: int, month: int = 1, day: int = 1) -> datetime:
    return datetime(year, month, day, tzinfo=timezone.utc)


def _stub_get_code(code_map: dict[str, str]):
    """Keys are lowercased addresses; values include ``'0x'`` for EOAs."""

    def fake_get_code(rpc_url, addr):
        return code_map.get((addr or "").lower(), "0x")

    return fake_get_code
