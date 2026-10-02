"""DB-layer triggers, checks and indexes, so raw SQL can't corrupt data and a hot-path index can't quietly vanish."""

from __future__ import annotations

import uuid

import pytest
from sqlalchemy import text
from sqlalchemy.exc import InternalError, ProgrammingError

from tests.conftest import requires_postgres

pytestmark = [requires_postgres]


def _fresh_protocol_contract_audit(db_session, *, is_proxy: bool):
    from db.models import AuditReport, Contract, Protocol

    suffix = uuid.uuid4().hex[:12]
    p = Protocol(name=f"trig-test-{suffix}")
    db_session.add(p)
    db_session.commit()

    c = Contract(
        protocol_id=p.id,
        address=f"0x{suffix.rjust(40, '0')}"[-42:],
        contract_name="TestContract",
        is_proxy=is_proxy,
        chain="ethereum",
    )
    db_session.add(c)
    db_session.commit()

    ar = AuditReport(
        protocol_id=p.id,
        url=f"https://example.com/{suffix}.pdf",
        auditor="TestFirm",
        title="Test Audit",
        confidence=0.9,
        scope_extraction_status="success",
        scope_contracts=["TestContract"],
    )
    db_session.add(ar)
    db_session.commit()
    return p.id, c.id, ar.id


def _cleanup(db_session, protocol_id):
    from db.models import AuditContractCoverage, AuditReport, Contract, Protocol

    db_session.rollback()
    db_session.query(AuditContractCoverage).filter_by(protocol_id=protocol_id).delete()
    db_session.query(Contract).filter_by(protocol_id=protocol_id).delete()
    db_session.query(AuditReport).filter_by(protocol_id=protocol_id).delete()
    db_session.query(Protocol).filter_by(id=protocol_id).delete()
    db_session.commit()


@requires_postgres
def test_coverage_trigger_rejects_proxy_contract_insert(db_session):
    """Even a raw insert can't produce a false-positive proxy coverage row."""
    protocol_id, contract_id, audit_id = _fresh_protocol_contract_audit(db_session, is_proxy=True)
    try:
        with pytest.raises((InternalError, ProgrammingError)) as exc_info:
            db_session.execute(
                text(
                    "INSERT INTO audit_contract_coverage "
                    "(contract_id, audit_report_id, protocol_id, matched_name, "
                    "match_type, match_confidence) VALUES "
                    "(:cid, :aid, :pid, 'UUPSProxy', 'direct', 'high')"
                ),
                {"cid": contract_id, "aid": audit_id, "pid": protocol_id},
            )
            db_session.commit()
        # Ops can diagnose without reading the trigger source.
        assert "proxy" in str(exc_info.value).lower()
    finally:
        _cleanup(db_session, protocol_id)


@requires_postgres
def test_coverage_trigger_allows_non_proxy_insert(db_session):
    from db.models import AuditContractCoverage

    protocol_id, contract_id, audit_id = _fresh_protocol_contract_audit(db_session, is_proxy=False)
    try:
        db_session.execute(
            text(
                "INSERT INTO audit_contract_coverage "
                "(contract_id, audit_report_id, protocol_id, matched_name, "
                "match_type, match_confidence) VALUES "
                "(:cid, :aid, :pid, 'TestContract', 'direct', 'high')"
            ),
            {"cid": contract_id, "aid": audit_id, "pid": protocol_id},
        )
        db_session.commit()
        rows = db_session.query(AuditContractCoverage).filter_by(contract_id=contract_id).all()
        assert len(rows) == 1
    finally:
        _cleanup(db_session, protocol_id)


# Postgres doesn't auto-index foreign-key columns.
