"""A member whose analysis failed or never completed is published as not_determined: listed in the overview with a
witness token, counted against the score's perimeter and confidence, and never shown as analyzed or dropped.
"""

from __future__ import annotations

import uuid
from datetime import datetime, timedelta, timezone

from sqlalchemy import select, update

from db.models import CompanyPageRevision as Revision
from db.models import EffectiveFunction, Job, JobStatus
from services.aggregations.company_overview import build_company_overview
from services.scoring.cli import distill_protocol_in_memory
from services.scoring.fold import compute_protocol_score
from services.scoring.planes import perimeter_state
from services.scoring.schema import entity_key
from tests.aggregations.test_prepared_company_pages import prepared as prepared
from tests.aggregations.test_prepared_company_pages import source
from tests.conftest import requires_postgres
from tests.support.overview_builders import _add_contract, _add_job, _add_protocol, _addr
from utils.scoring_status import PERIMETER_NOT_DETERMINED, PERIMETER_SETTLED, PERIMETER_UNSETTLED
from workers import company_pages as worker

pytestmark = requires_postgres


def _member(session, protocol, tag: str, status: JobStatus | None, *, chain: str = "ethereum", address=None):
    address = address or _addr(tag)
    job = _add_job(
        session,
        address=address,
        protocol_id=protocol.id,
        status=status or JobStatus.completed,
        request={"address": address, "chain": chain},
    )
    job.chain_id = 1 if chain == "ethereum" else 8453
    session.commit()
    contract = _add_contract(session, address=address, job=job, protocol_id=protocol.id, chain=chain, contract_name=tag)
    if status is None:
        # A member the gate admitted that no job ever analysed.
        contract.job_id = None
        session.delete(job)
        session.commit()
    return contract


def _world(session):
    protocol = _add_protocol(session, f"members-{uuid.uuid4().hex[:8]}")
    analyzed = _member(session, protocol, "analyzed", JobStatus.completed)
    failed = _member(session, protocol, "failed", JobStatus.failed_terminal)
    never = _member(session, protocol, "never", None)
    # The Base twin of a Mainnet member analysed only on Base: the Mainnet copy is still unread.
    twin_address = _addr("twin")
    base_twin = _member(session, protocol, "twin-base", JobStatus.completed, chain="base", address=twin_address)
    mainnet_twin = _member(session, protocol, "twin-mainnet", JobStatus.failed, address=twin_address)
    return protocol, analyzed, failed, never, base_twin, mainnet_twin


def test_overview_lists_unanalyzed_members_as_not_determined(db_session):
    protocol, analyzed, failed, never, base_twin, mainnet_twin = _world(db_session)

    payload = build_company_overview(db_session, protocol.name)
    block = payload["member_analysis"]
    assert (block["members"], block["analyzed"], block["not_determined"]) == (5, 2, 3)
    assert block["by_state"] == {"analysis_failed": 2, "analysis_not_completed": 1}
    listed = {(m["chain"], m["address"]): m for m in block["not_analyzed"]}
    assert set(listed) == {
        ("ethereum", failed.address.lower()),
        ("ethereum", never.address.lower()),
        ("ethereum", mainnet_twin.address.lower()),
    }
    assert listed[("ethereum", failed.address.lower())]["analysis_state"] == "analysis_failed"
    assert listed[("ethereum", failed.address.lower())]["job_status"] == "failed_terminal"
    assert listed[("ethereum", never.address.lower())] | {"job_id": None} == {
        "contract_id": never.id,
        "address": never.address.lower(),
        "chain": "ethereum",
        "name": "never",
        "analysis_state": "analysis_not_completed",
        "job_id": None,
        "job_status": None,
    }
    assert listed[("ethereum", mainnet_twin.address.lower())]["analysis_state"] == "analysis_failed"

    shown = {(c["chain"], c["address"]) for c in payload["contracts"]}
    assert ("ethereum", analyzed.address.lower()) in shown and ("base", base_twin.address.lower()) in shown
    assert not shown & set(listed)
    assert payload["contract_count"] == 2


def test_a_fully_analyzed_protocol_reports_no_gap(db_session):
    protocol = _add_protocol(db_session, f"members-whole-{uuid.uuid4().hex[:8]}")
    _member(db_session, protocol, "one", JobStatus.completed)
    _member(db_session, protocol, "two", JobStatus.completed)

    block = build_company_overview(db_session, protocol.name)["member_analysis"]
    assert block == {
        "members": 2,
        "analyzed": 2,
        "not_determined": 0,
        "by_state": {"analysis_failed": 0, "analysis_not_completed": 0},
        "not_analyzed": [],
    }
    assert perimeter_state(db_session, protocol.id)[0] == PERIMETER_SETTLED


def test_score_perimeter_is_not_determined_while_members_are_unread(db_session):
    protocol, _, failed, never, _, mainnet_twin = _world(db_session)

    state, detail = perimeter_state(db_session, protocol.id)
    assert state == PERIMETER_NOT_DETERMINED
    assert detail["members"] == 5
    assert detail["members_not_analyzed"] == {"analysis_failed": 2, "analysis_not_completed": 1}
    assert set(detail["members_not_analyzed_entities"]) == {
        entity_key("ethereum", failed.address),
        entity_key("ethereum", never.address),
        entity_key("ethereum", mainnet_twin.address),
    }

    # Work still in flight reads as unsettled, which outranks it.
    pending = _member(db_session, protocol, "pending", JobStatus.processing)
    assert perimeter_state(db_session, protocol.id)[0] == PERIMETER_UNSETTLED
    assert (
        entity_key("ethereum", pending.address)
        in perimeter_state(db_session, protocol.id)[1]["members_not_analyzed_entities"]
    )


def test_an_unread_member_is_charged_in_confidence(db_session):
    protocol = _add_protocol(db_session, f"members-conf-{uuid.uuid4().hex[:8]}")
    analyzed = _member(db_session, protocol, "analyzed", JobStatus.completed)
    db_session.add(
        EffectiveFunction(
            contract_id=analyzed.id,
            deployment_address=analyzed.address,
            function_name="pause",
            selector="0x8456cb59",
            abi_signature="pause()",
            authority_public=True,
            authority_openness="open",
            claims=[{"claim_id": "pause.set", "tier": "standard_exact", "witness": {"kind": "pause_latch"}}],
        )
    )
    db_session.commit()

    def confidence():
        signals = distill_protocol_in_memory(db_session, protocol.id)
        document = compute_protocol_score(db_session, protocol.id, signals=signals)
        return document.perimeter_state, document.model_parameters["confidence_detail"]

    whole_state, whole = confidence()
    assert whole_state == PERIMETER_SETTLED
    assert whole["reachability_answered_pct"] == 100.0

    _member(db_session, protocol, "failed", JobStatus.failed_terminal)
    gap_state, gap = confidence()
    assert gap_state == PERIMETER_NOT_DETERMINED
    assert gap["perimeter_entities"] == whole["perimeter_entities"] + 1
    assert gap["reachability_answered_pct"] < 100.0


def _tokens(session):
    return session.execute(select(Revision.key, Revision.token).order_by(Revision.key)).all()


def test_a_member_job_failing_invalidates_the_prepared_overview_but_a_heartbeat_does_not(prepared):
    session, protocol, factory = prepared
    address = _addr("in-flight")
    job = _add_job(session, address=address, protocol_id=protocol.id, status=JobStatus.processing)
    _add_contract(session, address=address, job=job, protocol_id=protocol.id)
    assert worker.refresh_one(factory) == "prepared"
    session.execute(update(Revision).values(changed_at=datetime.now(timezone.utc) - timedelta(seconds=1)))
    session.commit()

    before = _tokens(session)
    session.execute(
        update(Job).where(Job.id == job.id).values(updated_at=datetime.now(timezone.utc), lease_expires_at=None)
    )
    session.commit()
    assert _tokens(session) == before
    assert source(session, protocol.name) == "prepared"

    session.execute(update(Job).where(Job.id == job.id).values(status=JobStatus.failed_terminal))
    session.commit()
    assert _tokens(session) != before
    assert source(session, protocol.name) == "prepared-stale"
    assert worker.refresh_one(factory) == "prepared"
    after_failure = _tokens(session)

    # Requeueing the failed job is a change too: its token leaves analysis_failed.
    session.execute(update(Job).where(Job.id == job.id).values(status=JobStatus.queued))
    session.commit()
    assert _tokens(session) != after_failure
