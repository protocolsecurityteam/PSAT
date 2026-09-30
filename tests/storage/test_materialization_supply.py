"""F4a - coverage is a guarantee of analysis, not a side effect of recursion.

Enrollment reads ``contract_materializations``, which only the authority recursion wrote (as a side
effect of the dependencies it visited), so 136 of 183 monitored contracts watched on the baseline
registry alone despite completed jobs holding a substantive plan. These tests pin the producer's
contract: what it writes, what it refuses to write, and that every row names its
writer and source job.
"""

from __future__ import annotations

import uuid
from datetime import datetime, timedelta, timezone
from types import SimpleNamespace
from typing import Any

import pytest
from sqlalchemy import select

from db import contract_materializations as cm
from db.contract_materializations import (
    ANALYSIS_SCHEMA_VERSION,
    PRODUCED_BY_PIPELINE,
    PRODUCED_BY_PROMOTION_SWEEP,
    PRODUCED_BY_RESOLUTION,
    PUBLISH_ADDRESS_BOUND_TO_OTHER_KECCAK,
    PUBLISH_ALREADY_CURRENT,
    PUBLISH_INCOMPLETE_BUNDLE,
    PUBLISH_KECCAK_BOUND_TO_OTHER_ADDRESS,
    PUBLISH_REFRESHED,
    PUBLISH_WRITTEN,
    build_provenance,
    builder_claim_is_stale,
    publish_materialization,
)
from db.models import ContractMaterialization, Job, JobStage, JobStatus
from db.queue import proven_analysis_schema_version
from tests.conftest import requires_postgres
from tests.support.materializations import cm_db  # noqa: F401  (fixture, registered by import)

ADDR = "0x" + "a1" * 20
OTHER_ADDR = "0x" + "b2" * 20
KECCAK = "0x" + "11" * 32
OTHER_KECCAK = "0x" + "22" * 32

ANALYSIS = {"subject": {"address": ADDR, "name": "C"}, "functions": []}
PLAN = {"contract_address": ADDR, "tracked_controllers": []}
TREES = {"schema_version": "semantic", "trees": {}}


def _publish(**overrides: Any) -> str:
    kwargs: dict[str, Any] = {
        "chain": "ethereum",
        "address": ADDR,
        "bytecode_keccak": KECCAK,
        "contract_name": "C",
        "analysis": ANALYSIS,
        "tracking_plan": PLAN,
        "predicate_trees": TREES,
        "source_content_hash": "0x" + "de" * 32,
        "provenance": build_provenance(PRODUCED_BY_PIPELINE, source_job_id="job-1"),
    }
    kwargs.update(overrides)
    return publish_materialization(**kwargs)


def _provenance(row: ContractMaterialization | None) -> dict:
    assert row is not None and isinstance(row.provenance, dict)
    return row.provenance


def _row(session, keccak: str = KECCAK) -> ContractMaterialization | None:
    return session.execute(
        select(ContractMaterialization).where(
            ContractMaterialization.chain == "1",
            ContractMaterialization.bytecode_keccak == keccak,
        )
    ).scalar_one_or_none()


@requires_postgres
def test_publish_writes_a_current_row_with_provenance(cm_db):
    assert _publish() == PUBLISH_WRITTEN

    row = _row(cm_db)
    assert row is not None
    assert row.chain == "1"
    assert row.status == "ready"
    assert row.analysis_schema_version == ANALYSIS_SCHEMA_VERSION
    assert row.tracking_plan == PLAN
    assert row.analysis == ANALYSIS
    assert _provenance(row) == {
        "produced_by": PRODUCED_BY_PIPELINE,
        "source_job_id": "job-1",
        "materialized_at": _provenance(row)["materialized_at"],
    }
    # The source job is on the row, not inferred from a name.
    assert cm.find_by_address(cm_db, chain="ethereum", address=ADDR) is not None


@requires_postgres
def test_publish_leaves_a_current_row_alone(cm_db):
    _publish()
    before = _row(cm_db)
    assert before is not None
    stamp = _provenance(before)["materialized_at"]

    # Moving the row's address would strand the address already resolving to it.
    assert _publish(address=OTHER_ADDR, provenance=build_provenance(PRODUCED_BY_PROMOTION_SWEEP)) == (
        PUBLISH_KECCAK_BOUND_TO_OTHER_ADDRESS
    )
    cm_db.expire_all()
    after = _row(cm_db)
    assert after is not None
    assert after.address == ADDR.lower()
    assert _provenance(after)["materialized_at"] == stamp

    assert _publish() == PUBLISH_ALREADY_CURRENT


@requires_postgres
def test_publish_refuses_a_bundle_without_an_analysis(cm_db):
    """``None`` would read as "no analysis", which a missing artifact never claimed."""
    assert _publish(analysis=None) == PUBLISH_INCOMPLETE_BUNDLE
    assert _publish(tracking_plan=None) == PUBLISH_INCOMPLETE_BUNDLE
    assert _row(cm_db) is None


@requires_postgres
def test_publish_refuses_an_address_already_bound_to_other_bytecode(cm_db):
    _publish()
    assert _publish(bytecode_keccak=OTHER_KECCAK) == PUBLISH_ADDRESS_BOUND_TO_OTHER_KECCAK
    assert _row(cm_db, OTHER_KECCAK) is None


@requires_postgres
@pytest.mark.parametrize(
    "status,version,builder_started_at",
    [
        ("failed", ANALYSIS_SCHEMA_VERSION, None),
        ("pending", ANALYSIS_SCHEMA_VERSION, None),
        ("ready", ANALYSIS_SCHEMA_VERSION - 1, None),
        # That builder's phase-3 recheck finds our row and drops its duplicate.
        ("building", ANALYSIS_SCHEMA_VERSION, "now"),
    ],
)
def test_publish_replaces_a_row_that_serves_nobody(cm_db, status, version, builder_started_at):
    cm_db.add(
        ContractMaterialization(
            chain="1",
            bytecode_keccak=KECCAK,
            address=ADDR.lower(),
            status=status,
            builder_started_at=datetime.now(timezone.utc) if builder_started_at else None,
            analysis_schema_version=version,
        )
    )
    cm_db.commit()

    assert _publish() == PUBLISH_WRITTEN
    cm_db.expire_all()
    row = _row(cm_db)
    assert row is not None
    assert (row.status, row.analysis_schema_version) == ("ready", ANALYSIS_SCHEMA_VERSION)
    assert _provenance(row)["produced_by"] == PRODUCED_BY_PIPELINE


@requires_postgres
def test_recursion_written_rows_name_their_producer(cm_db):
    """The walking job is not the job the dependency is of."""
    cm.materialize_or_wait(
        chain="ethereum",
        address=ADDR,
        bytecode_keccak=KECCAK,
        builder=lambda: {"contract_name": "C", "analysis": ANALYSIS, "tracking_plan": PLAN},
    )
    cm_db.expire_all()
    row = _row(cm_db)
    assert row is not None
    assert _provenance(row)["produced_by"] == PRODUCED_BY_RESOLUTION
    assert _provenance(row)["source_job_id"] is None


def test_provenance_records_an_unknown_job_as_null():
    stamp = build_provenance(PRODUCED_BY_RESOLUTION)
    # A missing key would look like a pre-provenance row.
    assert "source_job_id" in stamp
    assert stamp["source_job_id"] is None


@requires_postgres
def test_the_pipeline_refreshes_a_current_row_whose_bundle_differs(cm_db):
    """Improvements don't always bump the version, so an unrefreshed row freezes."""
    _publish()
    improved = {"contract_address": ADDR, "tracked_controllers": [{"controller_id": "state_variable:owner"}]}

    assert _publish(tracking_plan=improved, refresh_on_differ=True) == PUBLISH_REFRESHED
    cm_db.expire_all()
    row = _row(cm_db)
    assert row is not None
    assert row.tracking_plan == improved
    assert row.status == "ready"

    assert _publish(tracking_plan=improved, refresh_on_differ=True) == PUBLISH_ALREADY_CURRENT


@requires_postgres
def test_the_sweep_never_overwrites_a_current_row_with_an_older_bundle(cm_db):
    _publish()
    older = {"contract_address": ADDR, "tracked_controllers": [{"controller_id": "stale"}]}
    assert _publish(tracking_plan=older) == PUBLISH_ALREADY_CURRENT
    cm_db.expire_all()
    row = _row(cm_db)
    assert row is not None and row.tracking_plan == PLAN


@requires_postgres
def test_an_already_current_return_leaves_the_stored_payload_untouched(cm_db, monkeypatch):
    _publish()
    puts: list[str] = []
    monkeypatch.setattr(
        "db.contract_materializations._put_blob",
        lambda _c, key, _p: puts.append(key),  # pragma: no cover - guard
    )
    assert _publish() == PUBLISH_ALREADY_CURRENT
    assert puts == []


@requires_postgres
def test_a_stale_builder_claim_does_not_read_as_a_running_builder(cm_db):
    cm_db.add(
        ContractMaterialization(
            chain="1",
            bytecode_keccak=KECCAK,
            address=ADDR.lower(),
            status="building",
            builder_started_at=datetime.now(timezone.utc) - timedelta(hours=6),
            analysis_schema_version=ANALYSIS_SCHEMA_VERSION,
        )
    )
    cm_db.commit()
    assert builder_claim_is_stale("building", datetime.now(timezone.utc) - timedelta(hours=6)) is True
    assert builder_claim_is_stale("building", datetime.now(timezone.utc)) is False
    assert _publish() == PUBLISH_WRITTEN


def _job_row(session, *, version: int | None, donor: Any = None) -> Job:
    request: dict = {"address": ADDR}
    if donor is not None:
        request |= {"static_cached": True, "cache_source_job_id": str(donor)}
    job = Job(
        id=uuid.uuid4(),
        address=ADDR,
        status=JobStatus.completed,
        stage=JobStage.done,
        request=request,
        analysis_schema_version=version,
    )
    session.add(job)
    session.commit()
    return job


@requires_postgres
def test_a_cache_hit_jobs_era_is_the_donors(cm_db):
    """All 32 NULL-version cache-hit jobs resolve to a v5 donor."""
    donor = _job_row(cm_db, version=ANALYSIS_SCHEMA_VERSION)
    hit = _job_row(cm_db, version=None, donor=donor.id)
    second_hop = _job_row(cm_db, version=None, donor=hit.id)

    assert proven_analysis_schema_version(cm_db, donor) == ANALYSIS_SCHEMA_VERSION
    assert proven_analysis_schema_version(cm_db, hit) == ANALYSIS_SCHEMA_VERSION
    assert proven_analysis_schema_version(cm_db, second_hop) == ANALYSIS_SCHEMA_VERSION


@requires_postgres
def test_a_long_cache_chain_is_walked_to_its_terminus(cm_db):
    """Working-DB chains end 1-14 hops out."""
    job = _job_row(cm_db, version=ANALYSIS_SCHEMA_VERSION)
    for _ in range(20):
        job = _job_row(cm_db, version=None, donor=job.id)
    assert proven_analysis_schema_version(cm_db, job) == ANALYSIS_SCHEMA_VERSION


@requires_postgres
def test_an_unwitnessed_era_stays_unwitnessed(cm_db):
    unstamped = _job_row(cm_db, version=None)
    assert proven_analysis_schema_version(cm_db, unstamped) is None
    assert proven_analysis_schema_version(cm_db, _job_row(cm_db, version=None, donor=unstamped.id)) is None
    assert proven_analysis_schema_version(cm_db, _job_row(cm_db, version=None, donor=uuid.uuid4())) is None


@requires_postgres
def test_a_donor_cycle_terminates(cm_db):
    a = _job_row(cm_db, version=None)
    b = _job_row(cm_db, version=None, donor=a.id)
    a.request = {**(a.request or {}), "cache_source_job_id": str(b.id)}
    cm_db.commit()
    assert proven_analysis_schema_version(cm_db, a) is None


class _FakeStaticWorker:
    from workers.static_worker import StaticWorker

    _publish_materialization = StaticWorker._publish_materialization


def _fake_job(version: int | None = ANALYSIS_SCHEMA_VERSION, request: dict | None = None) -> Any:
    return SimpleNamespace(
        id=uuid.uuid4(),
        request=request if request is not None else {},
        chain_id=1,
        source_content_hash="0x" + "fe" * 32,
        analysis_schema_version=version,
    )


@pytest.fixture()
def captured_publish(monkeypatch):
    calls: list[dict] = []
    monkeypatch.setattr(
        "db.contract_materializations.publish_materialization",
        lambda **kwargs: calls.append(kwargs) or PUBLISH_WRITTEN,
    )
    monkeypatch.setattr("services.clients.rpc.get_code_with_keccak", lambda *a, **k: ("0xfeed", KECCAK))
    return calls


def _stub_artifacts(monkeypatch, mapping: dict[str, Any]) -> None:
    monkeypatch.setattr("workers.static_worker.get_artifact", lambda _s, _j, name: mapping.get(name))


def test_static_stage_publishes_the_artifacts_it_stored(monkeypatch, captured_publish):
    _stub_artifacts(
        monkeypatch,
        {"contract_analysis": ANALYSIS, "control_tracking_plan": PLAN, "predicate_trees": TREES},
    )
    job = _fake_job()
    _FakeStaticWorker()._publish_materialization(None, job, ADDR, "C")

    assert len(captured_publish) == 1
    call = captured_publish[0]
    assert call["address"] == ADDR
    assert call["bytecode_keccak"] == KECCAK
    assert call["tracking_plan"] == PLAN
    assert call["analysis"] == ANALYSIS
    assert call["predicate_trees"] == TREES
    assert call["source_content_hash"] == job.source_content_hash
    assert call["provenance"] == {
        "produced_by": PRODUCED_BY_PIPELINE,
        "source_job_id": str(job.id),
        "materialized_at": call["provenance"]["materialized_at"],
    }


def test_static_stage_publishes_nothing_for_an_unproven_analyzer_era(monkeypatch, captured_publish):
    """NULL is not "current"."""
    _stub_artifacts(
        monkeypatch,
        {"contract_analysis": ANALYSIS, "control_tracking_plan": PLAN, "predicate_trees": TREES},
    )
    monkeypatch.setattr("db.queue.proven_analysis_schema_version", lambda _s, _j: None)
    _FakeStaticWorker()._publish_materialization(None, _fake_job(version=None), ADDR, "C")
    assert captured_publish == []

    monkeypatch.setattr("db.queue.proven_analysis_schema_version", lambda _s, _j: ANALYSIS_SCHEMA_VERSION - 1)
    _FakeStaticWorker()._publish_materialization(None, _fake_job(version=None), ADDR, "C")
    assert captured_publish == []


def test_static_stage_publishes_a_cache_hit_whose_donor_proves_the_era(monkeypatch, captured_publish):
    _stub_artifacts(
        monkeypatch,
        {"contract_analysis": ANALYSIS, "control_tracking_plan": PLAN, "predicate_trees": TREES},
    )
    monkeypatch.setattr("db.queue.proven_analysis_schema_version", lambda _s, _j: ANALYSIS_SCHEMA_VERSION)
    job = _fake_job(version=None, request={"static_cached": True, "cache_source_job_id": str(uuid.uuid4())})
    _FakeStaticWorker()._publish_materialization(None, job, ADDR, "C")
    assert len(captured_publish) == 1


def test_only_a_bundle_this_job_produced_may_refresh(monkeypatch, captured_publish):
    """Cache-hit artifacts are an ancestor's; refreshing from them would flip the row back and forth."""
    _stub_artifacts(
        monkeypatch,
        {"contract_analysis": ANALYSIS, "control_tracking_plan": PLAN, "predicate_trees": TREES},
    )
    _FakeStaticWorker()._publish_materialization(None, _fake_job(), ADDR, "C")
    assert captured_publish[0]["refresh_on_differ"] is True

    cached = _fake_job(request={"static_cached": True, "cache_source_job_id": str(uuid.uuid4())})
    _FakeStaticWorker()._publish_materialization(None, cached, ADDR, "C")
    assert captured_publish[1]["refresh_on_differ"] is False


def test_static_stage_publishes_nothing_without_a_plan(monkeypatch, captured_publish):
    _stub_artifacts(monkeypatch, {"contract_analysis": ANALYSIS})
    _FakeStaticWorker()._publish_materialization(None, _fake_job(), ADDR, "C")
    assert captured_publish == []


def test_static_stage_publishes_nothing_without_a_keccak(monkeypatch, captured_publish):
    _stub_artifacts(
        monkeypatch,
        {"contract_analysis": ANALYSIS, "control_tracking_plan": PLAN, "predicate_trees": TREES},
    )

    def _boom(*_a, **_k):
        raise RuntimeError("rpc down")

    monkeypatch.setattr("services.clients.rpc.get_code_with_keccak", _boom)
    _FakeStaticWorker()._publish_materialization(None, _fake_job(), ADDR, "C")
    assert captured_publish == []


def test_static_stage_never_fails_the_job_on_a_publish_error(monkeypatch, captured_publish):
    _stub_artifacts(
        monkeypatch,
        {"contract_analysis": ANALYSIS, "control_tracking_plan": PLAN, "predicate_trees": TREES},
    )

    def _boom(**_k):
        raise RuntimeError("bucket down")

    monkeypatch.setattr("db.contract_materializations.publish_materialization", _boom)
    _FakeStaticWorker()._publish_materialization(None, _fake_job(), ADDR, "C")
