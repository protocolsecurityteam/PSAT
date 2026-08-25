"""Promotion-triggered selection enqueue (DISCOVERY_MEMBERSHIP_GATE_SPEC.md
§3.4): a protocol that just gained members needs a selection pass, and needs
exactly one — the enqueue fires only on net-new promotions, dedupes against a
queued/processing pass, and never fires from the non-worker ``evaluate`` entry
the reconcile/re-earn CLIs use.

Fixtures are the anchor-chain shapes, which are what makes a candidate promote
on stored facts alone.
"""

from __future__ import annotations

from db.models import Job, JobStage, JobStatus
from services.discovery import membership_gate as gate
from tests.conftest import ADDR, requires_postgres
from tests.discovery.test_membership_anchor_chain import (
    PROPOSER_ROLE,
    _anchored_holder,
    _anchored_member,
    _caller_gate,
    _contract,
    _d2_member,
    _role_plane,
    protocol,
)

pytestmark = [requires_postgres]

__all__ = ["protocol"]


def _selection_jobs(db_session, protocol):
    return db_session.query(Job).filter(Job.stage == JobStage.selection, Job.protocol_id == protocol.id).all()


def test_promotion_enqueues_exactly_one_selection_pass(db_session, protocol):
    anchor = _anchored_member(db_session, protocol, ADDR(0x5001))
    timelock = _d2_member(db_session, protocol, ADDR(0x5002), controls=anchor)
    safe = _anchored_holder(db_session, protocol, ADDR(0x5003))
    _role_plane(db_session, timelock.address, PROPOSER_ROLE, [safe])
    ward_a = _contract(db_session, ADDR(0x5005), nominated=protocol.id)
    ward_b = _contract(db_session, ADDR(0x5006), nominated=protocol.id)
    _caller_gate(db_session, ward_a, timelock.address)
    _caller_gate(db_session, ward_b, timelock.address)
    db_session.commit()

    result = gate.evaluate_committed(
        db_session, gate.FactsDelta(recheck_contract_ids=(ward_a.id, ward_b.id)), context="test"
    )
    assert result is not None and len(result.promoted_contract_ids) == 2
    assert len(_selection_jobs(db_session, protocol)) == 1, "two promotions in one protocol are one pass"


def test_no_promotion_enqueues_nothing(db_session, protocol):
    anchor = _anchored_member(db_session, protocol, ADDR(0x5101))
    stranger = _contract(db_session, ADDR(0x5102), nominated=protocol.id)
    db_session.commit()
    result = gate.evaluate_committed(db_session, gate.FactsDelta(recheck_contract_ids=(stranger.id,)), context="test")
    assert result is not None and result.promoted_contract_ids == ()
    assert _selection_jobs(db_session, protocol) == []
    assert anchor.protocol_id == protocol.id


def test_reevaluation_with_no_new_members_enqueues_nothing(db_session, protocol):
    anchor = _anchored_member(db_session, protocol, ADDR(0x5201))
    timelock = _d2_member(db_session, protocol, ADDR(0x5202), controls=anchor)
    safe = _anchored_holder(db_session, protocol, ADDR(0x5203))
    _role_plane(db_session, timelock.address, PROPOSER_ROLE, [safe])
    ward = _contract(db_session, ADDR(0x5205), nominated=protocol.id)
    _caller_gate(db_session, ward, timelock.address)
    db_session.commit()

    gate.evaluate_committed(db_session, gate.FactsDelta(recheck_contract_ids=(ward.id,)), context="test")
    for job in _selection_jobs(db_session, protocol):
        job.status = JobStatus.completed
    db_session.commit()

    gate.evaluate_committed(db_session, gate.FactsDelta(recheck_contract_ids=(ward.id,)), context="test")
    assert len(_selection_jobs(db_session, protocol)) == 1


def test_existing_queued_pass_is_not_duplicated(db_session, protocol):
    from db.queue import create_job

    anchor = _anchored_member(db_session, protocol, ADDR(0x5301))
    timelock = _d2_member(db_session, protocol, ADDR(0x5302), controls=anchor)
    safe = _anchored_holder(db_session, protocol, ADDR(0x5303))
    _role_plane(db_session, timelock.address, PROPOSER_ROLE, [safe])
    ward = _contract(db_session, ADDR(0x5305), nominated=protocol.id)
    _caller_gate(db_session, ward, timelock.address)
    create_job(db_session, {"protocol_id": protocol.id, "name": "already-queued"}, initial_stage=JobStage.selection)
    db_session.commit()

    gate.evaluate_committed(db_session, gate.FactsDelta(recheck_contract_ids=(ward.id,)), context="test")
    assert ward.protocol_id == protocol.id
    assert len(_selection_jobs(db_session, protocol)) == 1


def test_non_worker_evaluate_never_enqueues(db_session, protocol):
    """The reconcile/re-earn CLIs call ``evaluate`` and commit themselves."""
    anchor = _anchored_member(db_session, protocol, ADDR(0x5401))
    timelock = _d2_member(db_session, protocol, ADDR(0x5402), controls=anchor)
    safe = _anchored_holder(db_session, protocol, ADDR(0x5403))
    _role_plane(db_session, timelock.address, PROPOSER_ROLE, [safe])
    ward = _contract(db_session, ADDR(0x5405), nominated=protocol.id)
    _caller_gate(db_session, ward, timelock.address)

    result = gate.evaluate(db_session, gate.FactsDelta(recheck_contract_ids=(ward.id,)))
    db_session.commit()
    assert result.promoted_contract_ids == (ward.id,)
    assert _selection_jobs(db_session, protocol) == []
