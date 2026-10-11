"""A member whose analysis failed or never completed is published as not_determined: listed in the overview with a
witness token, counted against the score's perimeter and confidence, and never shown as analyzed or dropped.
"""

from __future__ import annotations

import uuid
from datetime import datetime, timedelta, timezone

from sqlalchemy import select, update

from db.contract_materializations import ANALYSIS_SCHEMA_VERSION
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
    assert listed[("ethereum", failed.address.lower())]["last_failed_job_status"] == "failed_terminal"
    assert listed[("ethereum", never.address.lower())] == {
        "contract_id": never.id,
        "address": never.address.lower(),
        "chain": "ethereum",
        "name": "never",
        "analysis_state": "analysis_not_completed",
        "last_failed_job_id": None,
        "last_failed_job_status": None,
        "stale_analysis_job_id": None,
        "stale_analysis_version": None,
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
        "analyzed_at_older_version": [],
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


def test_a_queued_retry_leaves_the_published_failed_attempt_and_the_page_fresh(prepared):
    session, protocol, factory = prepared
    address = _addr("retry")
    failed_job = _add_job(session, address=address, protocol_id=protocol.id, status=JobStatus.failed_terminal)
    _add_contract(session, address=address, job=failed_job, protocol_id=protocol.id)
    assert worker.refresh_one(factory) == "prepared"
    session.execute(update(Revision).values(changed_at=datetime.now(timezone.utc) - timedelta(seconds=1)))
    session.commit()

    retry = _add_job(session, address=address, protocol_id=protocol.id, status=JobStatus.queued)
    session.execute(update(Job).where(Job.id == retry.id).values(status=JobStatus.processing))
    session.commit()
    assert source(session, protocol.name) == "prepared"

    (member,) = [
        m
        for m in build_company_overview(session, protocol.name)["member_analysis"]["not_analyzed"]
        if m["address"] == address
    ]
    assert member["analysis_state"] == "analysis_failed"
    assert (member["last_failed_job_id"], member["last_failed_job_status"]) == (str(failed_job.id), "failed_terminal")


STALE_ERA = 6


def _attempt(session, protocol, contract, status: JobStatus, version: int | None, *, age_s: int = 0, donor=None):
    request = {"address": contract.address, "chain": "ethereum"}
    if donor is not None:
        request["cache_source_job_id"] = str(donor.id)
    job = _add_job(
        session,
        address=contract.address,
        protocol_id=protocol.id,
        status=status,
        request=request,
        analysis_schema_version=version,
    )
    job.chain_id = 1
    job.created_at = job.updated_at = datetime.now(timezone.utc) - timedelta(seconds=age_s)
    session.commit()
    return job


def _listed(session, protocol):
    payload = build_company_overview(session, protocol.name)
    return payload["member_analysis"], {m["address"]: m for m in payload["member_analysis"]["not_analyzed"]}


def test_a_stale_analysis_with_a_newer_failure_is_not_determined_and_names_the_stale_era(db_session):
    protocol = _add_protocol(db_session, f"members-stale-{uuid.uuid4().hex[:8]}")
    member = _member(db_session, protocol, "reanalysed", JobStatus.completed)
    db_session.execute(update(Job).where(Job.address == member.address).values(analysis_schema_version=STALE_ERA))
    db_session.commit()
    stale = db_session.execute(select(Job).where(Job.address == member.address)).scalar_one()
    stale.updated_at = datetime.now(timezone.utc) - timedelta(minutes=10)
    db_session.commit()
    retry = _attempt(db_session, protocol, member, JobStatus.failed_terminal, None)

    block, listed = _listed(db_session, protocol)
    assert (block["analyzed"], block["not_determined"]) == (0, 1)
    entry = listed[member.address.lower()]
    assert entry["analysis_state"] == "analysis_failed"
    assert (entry["last_failed_job_id"], entry["last_failed_job_status"]) == (str(retry.id), "failed_terminal")
    assert (entry["stale_analysis_job_id"], entry["stale_analysis_version"]) == (str(stale.id), STALE_ERA)

    state, detail = perimeter_state(db_session, protocol.id)
    assert state == PERIMETER_NOT_DETERMINED
    assert detail["members_stale_analysis_versions"] == {str(STALE_ERA): 1}


def test_an_older_analysis_finishing_after_a_newer_attempt_failed_is_still_superseded(db_session):
    protocol = _add_protocol(db_session, f"members-late-finish-{uuid.uuid4().hex[:8]}")
    member = _member(db_session, protocol, "late", JobStatus.failed_terminal)
    retry = db_session.execute(select(Job).where(Job.address == member.address)).scalar_one()
    stale = _attempt(db_session, protocol, member, JobStatus.completed, STALE_ERA, age_s=600)
    # The older job started first but finished after the newer attempt failed.
    retry.created_at = datetime.now(timezone.utc) - timedelta(seconds=300)
    retry.updated_at = datetime.now(timezone.utc) - timedelta(seconds=200)
    stale.updated_at = datetime.now(timezone.utc) - timedelta(seconds=100)
    db_session.commit()

    block, listed = _listed(db_session, protocol)
    entry = listed[member.address.lower()]
    assert (block["analyzed"], block["not_determined"]) == (0, 1)
    assert (entry["analysis_state"], entry["last_failed_job_id"]) == ("analysis_failed", str(retry.id))
    assert (entry["stale_analysis_job_id"], entry["stale_analysis_version"]) == (str(stale.id), STALE_ERA)


def _scored(session, protocol, contract) -> None:
    session.add(
        EffectiveFunction(
            contract_id=contract.id,
            deployment_address=contract.address,
            function_name="pause",
            selector="0x8456cb59",
            abi_signature="pause()",
            authority_public=True,
            authority_openness="open",
            claims=[{"claim_id": "pause.set", "tier": "standard_exact", "witness": {"kind": "pause_latch"}}],
        )
    )
    session.commit()


def _score(session, protocol):
    document = compute_protocol_score(session, protocol.id, signals=distill_protocol_in_memory(session, protocol.id))
    return (
        document.grade_state,
        document.grade_lambda,
        document.perimeter_state,
        document.model_parameters["confidence_detail"]["reachability_answered_pct"],
    )


def test_an_older_analysis_with_no_failed_retry_stays_analysed_and_names_its_version(db_session):
    current = _add_protocol(db_session, f"members-current-only-{uuid.uuid4().hex[:8]}")
    _scored(db_session, current, _member(db_session, current, "current", JobStatus.completed))
    _member(db_session, current, "current-unscored", JobStatus.completed)

    protocol = _add_protocol(db_session, f"members-stale-only-{uuid.uuid4().hex[:8]}")
    member = _member(db_session, protocol, "stale-only", JobStatus.failed_terminal)
    an_hour_ago = datetime.now(timezone.utc) - timedelta(hours=1)
    db_session.execute(
        update(Job).where(Job.address == member.address).values(created_at=an_hour_ago, updated_at=an_hour_ago)
    )
    db_session.commit()
    # An older failure, then the older analysis, then a retry still in flight: nothing newer has failed.
    stale = _attempt(db_session, protocol, member, JobStatus.completed, STALE_ERA, age_s=60)
    _attempt(db_session, protocol, member, JobStatus.queued, None)
    unprovable = _member(db_session, protocol, "unprovable", JobStatus.completed)
    db_session.execute(update(Job).where(Job.address == unprovable.address).values(analysis_schema_version=None))
    db_session.commit()
    _scored(db_session, protocol, member)

    block, listed = _listed(db_session, protocol)
    assert listed == {}
    assert (block["members"], block["analyzed"], block["not_determined"]) == (2, 2, 0)
    hedges = {m["address"]: m for m in block["analyzed_at_older_version"]}
    assert (
        hedges[member.address.lower()]["stale_analysis_job_id"],
        hedges[member.address.lower()]["stale_analysis_version"],
    ) == (
        str(stale.id),
        STALE_ERA,
    )
    # A completed job whose era can't be proven is older too, with its era not determined.
    assert hedges[unprovable.address.lower()]["stale_analysis_version"] is None

    state, detail = perimeter_state(db_session, protocol.id)
    assert detail["members_not_analyzed_entities"] == []
    assert detail["members_stale_analysis_versions"] == {str(STALE_ERA): 1, "not_determined": 1}
    # The pending retry makes the perimeter unsettled, as for any protocol with work in flight.
    assert state == PERIMETER_UNSETTLED

    db_session.execute(
        update(Job)
        .where(Job.status == JobStatus.queued, Job.protocol_id == protocol.id)
        .values(
            status=JobStatus.completed,
            analysis_schema_version=STALE_ERA,
            updated_at=datetime.now(timezone.utc) - timedelta(minutes=30),
        )
    )
    db_session.commit()
    assert perimeter_state(db_session, protocol.id)[0] == PERIMETER_SETTLED
    # The hedge charges nothing: the score reads as if the analysis were current.
    assert _score(db_session, protocol) == _score(db_session, current)


def test_a_current_analysis_counts_beside_stale_and_failed_attempts(db_session):
    protocol = _add_protocol(db_session, f"members-current-{uuid.uuid4().hex[:8]}")
    member = _member(db_session, protocol, "current", JobStatus.completed)
    _attempt(db_session, protocol, member, JobStatus.completed, STALE_ERA, age_s=3600)
    _attempt(db_session, protocol, member, JobStatus.failed_terminal, None)
    donor = _attempt(
        db_session,
        protocol,
        _member(db_session, protocol, "donor", JobStatus.completed),
        JobStatus.completed,
        ANALYSIS_SCHEMA_VERSION,
    )
    cache_hit = _member(db_session, protocol, "cache-hit", JobStatus.completed)
    # A cache hit carries no stamp of its own; its donor's era is what was analysed.
    db_session.execute(
        update(Job)
        .where(Job.address == cache_hit.address)
        .values(
            analysis_schema_version=None,
            request={"address": cache_hit.address, "chain": "ethereum", "cache_source_job_id": str(donor.id)},
        )
    )
    db_session.commit()

    block, listed = _listed(db_session, protocol)
    assert member.address.lower() not in listed
    assert cache_hit.address.lower() not in listed
    assert (block["members"], block["analyzed"], block["not_determined"]) == (3, 3, 0)
    assert perimeter_state(db_session, protocol.id)[0] == PERIMETER_SETTLED
