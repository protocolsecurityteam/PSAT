"""Per-entry analysis provenance, and the inventory ``analyzed`` flag agreeing with ``member_analysis``."""

from __future__ import annotations

import uuid
from datetime import datetime, timedelta, timezone

from db.contract_materializations import ANALYSIS_SCHEMA_VERSION
from db.models import JobStatus, Protocol
from services.aggregations.company_overview import all_addresses_for_protocol, build_company_overview
from tests.conftest import requires_postgres
from tests.support.overview_builders import _add_contract, _add_job, _add_protocol, _addr

pytestmark = requires_postgres

OLDER = ANALYSIS_SCHEMA_VERSION - 1
ND = "not_determined"


def _member(session, protocol, *, version: int | None = ANALYSIS_SCHEMA_VERSION, request=None, **contract_kwargs):
    addr = _addr("m").lower()
    job = _add_job(
        session,
        address=addr,
        protocol_id=protocol.id,
        name="Vault",
        analysis_schema_version=version,
        request=request,
        is_proxy=bool(contract_kwargs.get("is_proxy")),
    )
    contract = _add_contract(session, address=addr, job=job, protocol_id=protocol.id, **contract_kwargs)
    return addr, job, contract


def _provenance(session, protocol, addr):
    payload = build_company_overview(session, protocol.name)
    return next(e for e in payload["contracts"] if e["address"] == addr)["analysis_provenance"]


def test_a_current_job_names_its_analyzer_and_its_own_times(db_session):
    p = _add_protocol(db_session, f"prov-cur-{uuid.uuid4().hex[:8]}")
    addr, job, _ = _member(db_session, p)
    prov = _provenance(db_session, p, addr)
    assert prov == {
        "job": {
            "job_id": str(job.id),
            "state": "current_analyzer",
            "static_analyzer_version": ANALYSIS_SCHEMA_VERSION,
            "static_reused_from_job_id": None,
            "started_at": job.created_at.isoformat(),
            "last_pipeline_pass_at": job.updated_at.isoformat(),
        },
        "impl_job": None,
    }


def test_an_older_era_job_is_named_older(db_session):
    p = _add_protocol(db_session, f"prov-old-{uuid.uuid4().hex[:8]}")
    addr, _, _ = _member(db_session, p, version=OLDER)
    job = _provenance(db_session, p, addr)["job"]
    assert (job["state"], job["static_analyzer_version"]) == ("older_analyzer", OLDER)


def test_a_reused_static_stage_carries_its_donor_and_the_donors_era(db_session):
    p = _add_protocol(db_session, f"prov-reuse-{uuid.uuid4().hex[:8]}")
    donor = _add_job(db_session, address=_addr("donor"), analysis_schema_version=OLDER)
    addr, _, _ = _member(db_session, p, version=None, request={"cache_source_job_id": str(donor.id)})
    job = _provenance(db_session, p, addr)["job"]
    assert job["static_reused_from_job_id"] == str(donor.id)
    assert (job["state"], job["static_analyzer_version"]) == ("older_analyzer", OLDER)


def test_an_unprovable_era_is_not_determined(db_session):
    p = _add_protocol(db_session, f"prov-unproven-{uuid.uuid4().hex[:8]}")
    addr, _, _ = _member(db_session, p, version=None, request={"cache_source_job_id": str(uuid.uuid4())})
    job = _provenance(db_session, p, addr)["job"]
    assert (job["state"], job["static_analyzer_version"]) == (ND, ND)
    assert job["started_at"] != ND


def test_a_reanalysis_in_flight_is_not_determined(db_session):
    p = _add_protocol(db_session, f"prov-flight-{uuid.uuid4().hex[:8]}")
    addr, job, contract = _member(db_session, p)
    rerun = _add_job(db_session, address=addr, protocol_id=p.id, status=JobStatus.processing)
    contract.job_id = rerun.id
    db_session.commit()
    assert _provenance(db_session, p, addr)["job"] == {
        "job_id": str(job.id),
        "state": ND,
        "static_analyzer_version": ND,
        "static_reused_from_job_id": ND,
        "started_at": ND,
        "last_pipeline_pass_at": ND,
    }


def test_a_proxy_publishes_its_own_and_its_impl_jobs_provenance(db_session):
    p = _add_protocol(db_session, f"prov-proxy-{uuid.uuid4().hex[:8]}")
    impl = _addr("impl").lower()
    addr, proxy_job, _ = _member(db_session, p, is_proxy=True, implementation=impl)
    impl_job = _add_job(
        db_session,
        address=impl,
        protocol_id=p.id,
        analysis_schema_version=OLDER,
        request={"address": impl, "proxy_address": addr},
    )
    _add_contract(db_session, address=impl, job=impl_job, protocol_id=p.id, contract_name="Impl")
    prov = _provenance(db_session, p, addr)
    assert (prov["job"]["job_id"], prov["job"]["state"]) == (str(proxy_job.id), "current_analyzer")
    assert (prov["impl_job"]["job_id"], prov["impl_job"]["state"]) == (str(impl_job.id), "older_analyzer")


def _timed_job(session, protocol, addr, *, status, version, at):
    job = _add_job(session, address=addr, protocol_id=protocol.id, status=status, analysis_schema_version=version)
    job.created_at = at
    job.updated_at = at
    session.commit()
    return job


def test_inventory_analyzed_flag_agrees_with_member_analysis(db_session):
    p = _add_protocol(db_session, f"prov-inv-{uuid.uuid4().hex[:8]}")
    t0 = datetime(2026, 1, 1, tzinfo=timezone.utc)
    states: dict[str, tuple[bool, str]] = {}

    cur, _, _ = _member(db_session, p)
    states[cur] = (True, "current_analyzer")
    old, _, _ = _member(db_session, p, version=OLDER)
    states[old] = (True, "older_analyzer")

    # Re-analysis queued: the contract row points at the unfinished job, the completed one still stands.
    flight, _, flight_c = _member(db_session, p)
    rerun = _add_job(db_session, address=flight, protocol_id=p.id, status=JobStatus.processing)
    flight_c.job_id = rerun.id
    db_session.commit()
    states[flight] = (True, "current_analyzer")

    failed_after = _addr("fa").lower()
    failed_old = _timed_job(db_session, p, failed_after, status=JobStatus.completed, version=OLDER, at=t0)
    _add_contract(db_session, address=failed_after, job=failed_old, protocol_id=p.id)
    _timed_job(db_session, p, failed_after, status=JobStatus.failed, version=None, at=t0 + timedelta(days=1))
    states[failed_after] = (False, "analysis_failed")

    never = _addr("nv").lower()
    never_job = _timed_job(db_session, p, never, status=JobStatus.processing, version=None, at=t0)
    _add_contract(db_session, address=never, job=never_job, protocol_id=p.id)
    states[never] = (False, "analysis_not_completed")

    protocol = db_session.get(Protocol, p.id)
    rows = {r["address"]: r for r in all_addresses_for_protocol(db_session, protocol)}
    assert {a: (rows[a]["analyzed"], rows[a]["analysis_state"]) for a in states} == states
    assert rows[old]["stale_analysis_version"] == OLDER

    member_analysis = build_company_overview(db_session, p.name)["member_analysis"]
    not_analyzed = {m["address"] for m in member_analysis["not_analyzed"]}
    assert {a for a, (analyzed, _) in states.items() if not analyzed} == not_analyzed
