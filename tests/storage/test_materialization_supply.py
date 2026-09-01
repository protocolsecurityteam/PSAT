"""F4a — coverage is a guarantee of static_facts, not a side effect of recursion.

Enrollment reads ``contract_materializations``; until now only the authority
recursion wrote it, as a side effect of which dependencies it happened to visit.
136 of 183 monitored contracts therefore watched on the baseline registry alone
while their own completed jobs held a substantive plan.

These tests pin the producer's contract: what it writes, what it refuses to
write, and — invariant 7 — that every row it writes says who wrote it and from
which job.
"""

from __future__ import annotations

import uuid
from datetime import datetime, timedelta, timezone
from types import SimpleNamespace
from typing import Any

import pytest
from sqlalchemy import create_engine, select
from sqlalchemy.orm import Session, sessionmaker

from db import contract_materializations as cm
from db.contract_materializations import (
    PRODUCED_BY_PIPELINE,
    PRODUCED_BY_PROMOTION_SWEEP,
    PRODUCED_BY_RESOLUTION,
    PUBLISH_ADDRESS_BOUND_TO_OTHER_KECCAK,
    PUBLISH_ALREADY_CURRENT,
    PUBLISH_INCOMPLETE_BUNDLE,
    PUBLISH_KECCAK_BOUND_TO_OTHER_ADDRESS,
    PUBLISH_REFRESHED,
    PUBLISH_WRITTEN,
    STATIC_FACTS_SCHEMA_VERSION,
    build_provenance,
    builder_claim_is_stale,
    publish_materialization,
)
from db.models import ContractMaterialization, Job, JobStage, JobStatus
from db.queue import proven_static_facts_schema_version
from tests.conftest import requires_postgres
from tests.support.policy_builders import _assessment, _minimal_static_facts

ADDR = "0x" + "a1" * 20
OTHER_ADDR = "0x" + "b2" * 20
KECCAK = "0x" + "11" * 32
OTHER_KECCAK = "0x" + "22" * 32

ANALYSIS = {"subject": {"address": ADDR, "name": "C"}, "functions": []}
PLAN = {"contract_address": ADDR, "tracked_controllers": []}
TREES = {"schema_version": "semantic", "trees": {}}
EFFECTS = {"schema_version": "semantic", "functions": {}}
ASSESSMENT = _assessment(static_facts=_minimal_static_facts(address=ADDR, name="C"))


@pytest.fixture()
def cm_db(db_session, monkeypatch):
    """Route the module's own sessions at the test DB, storage off (inline JSONB)."""
    import os

    test_url = os.environ.get("TEST_DATABASE_URL")
    if not test_url:
        pytest.skip("TEST_DATABASE_URL not set")
    engine = create_engine(test_url)
    factory = sessionmaker(bind=engine, class_=Session, expire_on_commit=False)
    monkeypatch.setattr("db.contract_materializations.SessionLocal", factory)
    monkeypatch.setattr("db.contract_materializations.get_storage_client", lambda: None)
    db_session.query(ContractMaterialization).delete()
    db_session.commit()
    yield db_session
    db_session.query(ContractMaterialization).delete()
    db_session.commit()
    engine.dispose()


def _publish(**overrides: Any) -> str:
    kwargs: dict[str, Any] = {
        "chain": "ethereum",
        "address": ADDR,
        "bytecode_keccak": KECCAK,
        "contract_name": "C",
        "static_facts": ANALYSIS,
        "observation_plan": PLAN,
        "predicate_trees": TREES,
        "effects": EFFECTS,
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


# ---------------------------------------------------------------------------
# publish_materialization
# ---------------------------------------------------------------------------


@requires_postgres
def test_publish_writes_a_current_row_with_provenance(cm_db):
    assert _publish() == PUBLISH_WRITTEN

    row = _row(cm_db)
    assert row is not None
    # The chain key is the id token, never the name it was passed.
    assert row.chain == "1"
    assert row.status == "ready"
    assert row.static_facts_schema_version == STATIC_FACTS_SCHEMA_VERSION
    assert row.observation_plan == PLAN
    assert row.static_facts == ANALYSIS
    assert row.effects == EFFECTS
    assert _provenance(row) == {
        "produced_by": PRODUCED_BY_PIPELINE,
        "source_job_id": "job-1",
        "materialized_at": _provenance(row)["materialized_at"],
    }
    # Invariant 7: the source job is on the row, not inferred from a name.
    assert cm.find_by_address(cm_db, chain="ethereum", address=ADDR) is not None


@requires_postgres
def test_publish_leaves_a_current_row_alone(cm_db):
    _publish()
    before = _row(cm_db)
    assert before is not None
    stamp = _provenance(before)["materialized_at"]

    # Same bytecode, different address: identical code, so nothing is gained by
    # rewriting — and moving the row's address would strand the address that
    # already resolves to it.
    assert _publish(address=OTHER_ADDR, provenance=build_provenance(PRODUCED_BY_PROMOTION_SWEEP)) == (
        PUBLISH_KECCAK_BOUND_TO_OTHER_ADDRESS
    )
    cm_db.expire_all()
    after = _row(cm_db)
    assert after is not None
    assert after.address == ADDR.lower()
    assert _provenance(after)["materialized_at"] == stamp

    # Same address again is the plain no-op.
    assert _publish() == PUBLISH_ALREADY_CURRENT


@requires_postgres
def test_publish_refuses_a_bundle_without_an_analysis(cm_db):
    """A ready row whose static_facts hydrates to None reads to the resolution stage
    as *this contract has no static_facts* — a claim a missing artifact never made."""
    assert _publish(static_facts=None) == PUBLISH_INCOMPLETE_BUNDLE
    assert _publish(observation_plan=None) == PUBLISH_INCOMPLETE_BUNDLE
    assert _publish(effects=None) == PUBLISH_INCOMPLETE_BUNDLE
    assert _row(cm_db) is None


@requires_postgres
def test_publish_refuses_an_address_already_bound_to_other_bytecode(cm_db):
    _publish()
    # Same address, different keccak: which bytecode is current there is not
    # something this writer witnessed, and the unique index holds one row.
    assert _publish(bytecode_keccak=OTHER_KECCAK) == PUBLISH_ADDRESS_BOUND_TO_OTHER_KECCAK
    assert _row(cm_db, OTHER_KECCAK) is None


@requires_postgres
@pytest.mark.parametrize(
    "status,version,builder_started_at",
    [
        ("failed", STATIC_FACTS_SCHEMA_VERSION, None),
        ("pending", STATIC_FACTS_SCHEMA_VERSION, None),
        ("ready", STATIC_FACTS_SCHEMA_VERSION - 1, None),
        # A live builder claim included deliberately: that builder's phase-3
        # recheck finds our ready row and drops its duplicate build.
        ("building", STATIC_FACTS_SCHEMA_VERSION, "now"),
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
            static_facts_schema_version=version,
        )
    )
    cm_db.commit()

    assert _publish() == PUBLISH_WRITTEN
    cm_db.expire_all()
    row = _row(cm_db)
    assert row is not None
    assert (row.status, row.static_facts_schema_version) == ("ready", STATIC_FACTS_SCHEMA_VERSION)
    assert _provenance(row)["produced_by"] == PRODUCED_BY_PIPELINE


@requires_postgres
def test_recursion_written_rows_name_their_producer(cm_db):
    """``materialize_or_wait`` is the third producer; its rows say so, with the
    source job left explicitly null — the recursion materializes whatever
    dependency it walks onto, so the walking job is not the job it is *of*."""
    cm.materialize_or_wait(
        chain="ethereum",
        address=ADDR,
        bytecode_keccak=KECCAK,
        builder=lambda: {
            "contract_name": "C",
            "static_facts": ANALYSIS,
            "observation_plan": PLAN,
            "effects": EFFECTS,
        },
    )
    cm_db.expire_all()
    row = _row(cm_db)
    assert row is not None
    assert _provenance(row)["produced_by"] == PRODUCED_BY_RESOLUTION
    assert _provenance(row)["source_job_id"] is None


def test_provenance_records_an_unknown_job_as_null():
    stamp = build_provenance(PRODUCED_BY_RESOLUTION)
    # Present-and-null, not absent: "the producer is known and the job is not"
    # is a fact, and a missing key would be indistinguishable from a row written
    # before provenance existed.
    assert "source_job_id" in stamp
    assert stamp["source_job_id"] is None


@requires_postgres
def test_the_pipeline_refreshes_a_current_row_whose_bundle_differs(cm_db):
    """Byte-identical code does not imply an identical bundle: the analyzer
    improves without every improvement earning a version bump, and without this
    a ready row is frozen forever and later analyzer work never reaches the
    store enrollment reads."""
    _publish()
    improved = {"contract_address": ADDR, "tracked_controllers": [{"controller_id": "state_variable:owner"}]}

    assert _publish(observation_plan=improved, refresh_on_differ=True) == PUBLISH_REFRESHED
    cm_db.expire_all()
    row = _row(cm_db)
    assert row is not None
    assert row.observation_plan == improved
    assert row.status == "ready"

    # Identical bundle, same flag: nothing to say, nothing written.
    assert _publish(observation_plan=improved, refresh_on_differ=True) == PUBLISH_ALREADY_CURRENT


@requires_postgres
def test_the_sweep_never_overwrites_a_current_row_with_an_older_bundle(cm_db):
    """The promotion sweep's source is an older job's artifact; refreshing from
    it would be a downgrade, so the row stands."""
    _publish()
    older = {"contract_address": ADDR, "tracked_controllers": [{"controller_id": "stale"}]}
    assert _publish(observation_plan=older) == PUBLISH_ALREADY_CURRENT
    cm_db.expire_all()
    row = _row(cm_db)
    assert row is not None and row.observation_plan == PLAN


@requires_postgres
def test_an_already_current_return_leaves_the_stored_payload_untouched(cm_db, monkeypatch):
    """``already_current`` is a claim about what the row still holds, so the
    decision has to precede the upload — not follow it."""
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
            static_facts_schema_version=STATIC_FACTS_SCHEMA_VERSION,
        )
    )
    cm_db.commit()
    assert builder_claim_is_stale("building", datetime.now(timezone.utc) - timedelta(hours=6)) is True
    assert builder_claim_is_stale("building", datetime.now(timezone.utc)) is False
    assert _publish() == PUBLISH_WRITTEN


# ---------------------------------------------------------------------------
# The analyzer era a job's artifacts were produced under
# ---------------------------------------------------------------------------


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
        static_facts_schema_version=version,
    )
    session.add(job)
    session.commit()
    return job


@requires_postgres
def test_a_cache_hit_jobs_era_is_the_donors(cm_db):
    """discovery stamps the era only on the fetch path, so a same-address cache
    hit leaves the column NULL on a job whose artifacts are perfectly current.
    The stamp is still findable where it was witnessed: all 32 of the working
    DB's NULL-version cache-hit jobs resolve to a stamped v5 donor."""
    donor = _job_row(cm_db, version=STATIC_FACTS_SCHEMA_VERSION)
    hit = _job_row(cm_db, version=None, donor=donor.id)
    second_hop = _job_row(cm_db, version=None, donor=hit.id)

    assert proven_static_facts_schema_version(cm_db, donor) == STATIC_FACTS_SCHEMA_VERSION
    assert proven_static_facts_schema_version(cm_db, hit) == STATIC_FACTS_SCHEMA_VERSION
    assert proven_static_facts_schema_version(cm_db, second_hop) == STATIC_FACTS_SCHEMA_VERSION


@requires_postgres
def test_a_long_cache_chain_is_walked_to_its_terminus(cm_db):
    """Every cache-hit re-run appends a hop, so the chain grows on exactly the
    addresses that get re-analyzed most. The working DB's chains terminate
    between 1 and 14 hops out; a fixed hop budget would silently convert the far
    end of that distribution into "no witnessed era" and refuse supply for the
    busiest contracts."""
    job = _job_row(cm_db, version=STATIC_FACTS_SCHEMA_VERSION)
    for _ in range(20):
        job = _job_row(cm_db, version=None, donor=job.id)
    assert proven_static_facts_schema_version(cm_db, job) == STATIC_FACTS_SCHEMA_VERSION


@requires_postgres
def test_an_unwitnessed_era_stays_unwitnessed(cm_db):
    """A chain that ends without a stamp anywhere is the third state, not
    "current"."""
    unstamped = _job_row(cm_db, version=None)
    assert proven_static_facts_schema_version(cm_db, unstamped) is None
    assert proven_static_facts_schema_version(cm_db, _job_row(cm_db, version=None, donor=unstamped.id)) is None
    # A dangling donor reference resolves to nothing rather than raising.
    assert proven_static_facts_schema_version(cm_db, _job_row(cm_db, version=None, donor=uuid.uuid4())) is None


@requires_postgres
def test_a_donor_cycle_terminates(cm_db):
    a = _job_row(cm_db, version=None)
    b = _job_row(cm_db, version=None, donor=a.id)
    a.request = {**(a.request or {}), "cache_source_job_id": str(b.id)}
    cm_db.commit()
    assert proven_static_facts_schema_version(cm_db, a) is None


# ---------------------------------------------------------------------------
# F4a wiring — the static stage publishes what it just produced
# ---------------------------------------------------------------------------


class _FakeStaticWorker:
    """Just enough to bind the method under test."""

    from workers.static_worker import StaticWorker

    _publish_materialization = StaticWorker._publish_materialization


def _fake_job(version: int | None = STATIC_FACTS_SCHEMA_VERSION, request: dict | None = None) -> Any:
    return SimpleNamespace(
        id=uuid.uuid4(),
        request=request if request is not None else {},
        chain_id=1,
        source_content_hash="0x" + "fe" * 32,
        static_facts_schema_version=version,
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
        {"static_facts": ANALYSIS, "assessment": ASSESSMENT, "predicate_trees": TREES, "effects": EFFECTS},
    )
    job = _fake_job()
    _FakeStaticWorker()._publish_materialization(None, job, ADDR, "C")

    assert len(captured_publish) == 1
    call = captured_publish[0]
    assert call["address"] == ADDR
    assert call["bytecode_keccak"] == KECCAK
    assert call["observation_plan"]["contract_address"] == ADDR
    assert call["observation_plan"]["tracked_controllers"] == []
    assert call["static_facts"] == ANALYSIS
    assert call["predicate_trees"] == TREES
    assert call["effects"] == EFFECTS
    assert call["source_content_hash"] == job.source_content_hash
    assert call["provenance"] == {
        "produced_by": PRODUCED_BY_PIPELINE,
        "source_job_id": str(job.id),
        "materialized_at": call["provenance"]["materialized_at"],
    }


def test_static_stage_publishes_nothing_for_an_unproven_analyzer_era(monkeypatch, captured_publish):
    """A row is stamped with the current version, so it may only be written for
    a bundle proven to be of that era. A same-address cache hit returns before
    discovery's stamp, leaving the column NULL — and NULL is not "current"."""
    _stub_artifacts(
        monkeypatch,
        {"static_facts": ANALYSIS, "assessment": ASSESSMENT, "predicate_trees": TREES, "effects": EFFECTS},
    )
    monkeypatch.setattr("db.queue.proven_static_facts_schema_version", lambda _s, _j: None)
    _FakeStaticWorker()._publish_materialization(None, _fake_job(version=None), ADDR, "C")
    assert captured_publish == []

    monkeypatch.setattr("db.queue.proven_static_facts_schema_version", lambda _s, _j: STATIC_FACTS_SCHEMA_VERSION - 1)
    _FakeStaticWorker()._publish_materialization(None, _fake_job(version=None), ADDR, "C")
    assert captured_publish == []


def test_static_stage_publishes_a_cache_hit_whose_donor_proves_the_era(monkeypatch, captured_publish):
    """The era is recoverable for a cache-hit job: copy_static_cache copied the
    donor's artifacts, so the donor's stamp IS this job's artifacts' era."""
    _stub_artifacts(
        monkeypatch,
        {"static_facts": ANALYSIS, "assessment": ASSESSMENT, "predicate_trees": TREES, "effects": EFFECTS},
    )
    monkeypatch.setattr("db.queue.proven_static_facts_schema_version", lambda _s, _j: STATIC_FACTS_SCHEMA_VERSION)
    job = _fake_job(version=None, request={"static_cached": True, "cache_source_job_id": str(uuid.uuid4())})
    _FakeStaticWorker()._publish_materialization(None, job, ADDR, "C")
    assert len(captured_publish) == 1


def test_only_a_bundle_this_job_produced_may_refresh(monkeypatch, captured_publish):
    """A static-cache job's artifacts are an ancestor's, copied. They pass the
    era gate (era equality is not recency) but they are not the later record: let
    them refresh and a fresh static_facts and a later cache hit reproducing its
    ancestor take turns overwriting each other, each flip moving where monitoring
    watches."""
    _stub_artifacts(
        monkeypatch,
        {"static_facts": ANALYSIS, "assessment": ASSESSMENT, "predicate_trees": TREES, "effects": EFFECTS},
    )
    _FakeStaticWorker()._publish_materialization(None, _fake_job(), ADDR, "C")
    assert captured_publish[0]["refresh_on_differ"] is True

    cached = _fake_job(request={"static_cached": True, "cache_source_job_id": str(uuid.uuid4())})
    _FakeStaticWorker()._publish_materialization(None, cached, ADDR, "C")
    assert captured_publish[1]["refresh_on_differ"] is False


@requires_postgres
def test_a_copied_bundle_does_not_overwrite_a_freshly_analyzed_row(cm_db):
    """End to end on the row itself: the fresh static_facts stands, and the cache
    hit reports ``already_current`` rather than flipping it back."""
    fresh_plan = {"contract_address": ADDR, "tracked_controllers": [{"controller_id": "state_variable:authority"}]}
    ancestor_plan = {"contract_address": ADDR, "tracked_controllers": [{"controller_id": "ancestors_authority"}]}
    assert _publish(observation_plan=fresh_plan, refresh_on_differ=True) == PUBLISH_WRITTEN

    assert _publish(observation_plan=ancestor_plan, refresh_on_differ=False) == PUBLISH_ALREADY_CURRENT
    cm_db.expire_all()
    row = _row(cm_db)
    assert row is not None and row.observation_plan == fresh_plan


def test_static_stage_publishes_nothing_without_a_plan(monkeypatch, captured_publish):
    _stub_artifacts(monkeypatch, {"static_facts": ANALYSIS})
    _FakeStaticWorker()._publish_materialization(None, _fake_job(), ADDR, "C")
    assert captured_publish == []


def test_static_stage_publishes_nothing_without_a_keccak(monkeypatch, captured_publish):
    """The row is keyed on bytecode; a key we could not read is not a key."""
    _stub_artifacts(
        monkeypatch,
        {"static_facts": ANALYSIS, "assessment": ASSESSMENT, "predicate_trees": TREES, "effects": EFFECTS},
    )

    def _boom(*_a, **_k):
        raise RuntimeError("rpc down")

    monkeypatch.setattr("services.clients.rpc.get_code_with_keccak", _boom)
    _FakeStaticWorker()._publish_materialization(None, _fake_job(), ADDR, "C")
    assert captured_publish == []


def test_static_stage_never_fails_the_job_on_a_publish_error(monkeypatch, captured_publish):
    """Supply is not the static_facts: a failed publish must not sink a job whose
    static_facts succeeded."""
    _stub_artifacts(
        monkeypatch,
        {"static_facts": ANALYSIS, "assessment": ASSESSMENT, "predicate_trees": TREES, "effects": EFFECTS},
    )

    def _boom(**_k):
        raise RuntimeError("bucket down")

    monkeypatch.setattr("db.contract_materializations.publish_materialization", _boom)
    _FakeStaticWorker()._publish_materialization(None, _fake_job(), ADDR, "C")
