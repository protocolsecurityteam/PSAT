"""Schema-level invariants enforced at the DB layer: triggers, checks, indexes.

These exist so that even a direct SQL INSERT (bypassing the Python
matcher) cannot corrupt the dataset, and so that an index a hot path
depends on cannot quietly disappear. If someone drops a trigger, relaxes
a check or drops an index, the corresponding assertion here fires and the
build breaks — a much louder failure than a silent data drift.
"""

from __future__ import annotations

import uuid

import pytest
from sqlalchemy import text
from sqlalchemy.exc import InternalError, ProgrammingError

from tests.conftest import requires_postgres  # noqa: E402

pytestmark = [requires_postgres]


def _fresh_protocol_contract_audit(db_session, *, is_proxy: bool):
    """Seed one Protocol + Contract + AuditReport row and return their ids."""
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
    """Attempting to insert an ``audit_contract_coverage`` row whose
    ``contract_id`` references an is_proxy=True Contract must raise at
    the DB layer, not silently succeed. This is the belt-and-suspenders
    for the app-level candidate filter: even a raw SQL insert can't
    produce a false-positive proxy coverage row.
    """
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
        # The exception message must name the trigger reason so ops can
        # diagnose without reading the trigger source.
        assert "proxy" in str(exc_info.value).lower()
    finally:
        _cleanup(db_session, protocol_id)


@requires_postgres
def test_coverage_trigger_allows_non_proxy_insert(db_session):
    """The trigger must not block legitimate inserts — is_proxy=False
    Contract rows are the normal coverage target."""
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


# ---------------------------------------------------------------------------
# Required indexes (merged from tests/test_schema_indexes.py)
#
# Postgres does NOT auto-create an index on a foreign-key column, and several
# hot paths scan those columns.
# ---------------------------------------------------------------------------


def test_upgrade_events_contract_id_index_exists(db_session):
    """``upgrade_events.contract_id`` must have an index.

    Hit by services.audits.coverage._compute_impl_windows* and by
    api.contract_audit_timeline on every request. The FK constraint alone
    does not create one; we rely on ``ix_upgrade_events_contract_id``.
    """
    row = db_session.execute(
        text(
            "SELECT indexname FROM pg_indexes "
            "WHERE tablename = 'upgrade_events' "
            "AND indexname = 'ix_upgrade_events_contract_id'"
        )
    ).scalar_one_or_none()
    assert row == "ix_upgrade_events_contract_id", (
        "Missing index ix_upgrade_events_contract_id on upgrade_events(contract_id) — "
        "this index is required by the coverage matcher and audit_timeline API; "
        "re-add it via an Alembic revision."
    )
