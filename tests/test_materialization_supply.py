"""F4a — coverage is a guarantee of analysis, not a side effect of recursion.

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
from types import SimpleNamespace
from typing import Any

import pytest
from sqlalchemy import create_engine, select
from sqlalchemy.orm import Session, sessionmaker

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
    PUBLISH_WRITTEN,
    build_provenance,
    publish_materialization,
)
from db.models import ContractMaterialization
from tests.conftest import requires_postgres

ADDR = "0x" + "a1" * 20
OTHER_ADDR = "0x" + "b2" * 20
KECCAK = "0x" + "11" * 32
OTHER_KECCAK = "0x" + "22" * 32

ANALYSIS = {"subject": {"address": ADDR, "name": "C"}, "functions": []}
PLAN = {"contract_address": ADDR, "tracked_controllers": []}
TREES = {"schema_version": "semantic", "trees": {}}


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
    assert row.analysis_schema_version == ANALYSIS_SCHEMA_VERSION
    assert row.tracking_plan == PLAN
    assert row.analysis == ANALYSIS
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
    """A ready row whose analysis hydrates to None reads to the resolution stage
    as *this contract has no analysis* — a claim a missing artifact never made."""
    assert _publish(analysis=None) == PUBLISH_INCOMPLETE_BUNDLE
    assert _publish(tracking_plan=None) == PUBLISH_INCOMPLETE_BUNDLE
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
    "status,version",
    [("failed", ANALYSIS_SCHEMA_VERSION), ("pending", ANALYSIS_SCHEMA_VERSION), ("ready", ANALYSIS_SCHEMA_VERSION - 1)],
)
def test_publish_replaces_a_row_that_serves_nobody(cm_db, status, version):
    cm_db.add(
        ContractMaterialization(
            chain="1",
            bytecode_keccak=KECCAK,
            address=ADDR.lower(),
            status=status,
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
    """``materialize_or_wait`` is the third producer; its rows say so, with the
    source job left explicitly null — the recursion materializes whatever
    dependency it walks onto, so the walking job is not the job it is *of*."""
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
    # Present-and-null, not absent: "the producer is known and the job is not"
    # is a fact, and a missing key would be indistinguishable from a row written
    # before provenance existed.
    assert "source_job_id" in stamp
    assert stamp["source_job_id"] is None


# ---------------------------------------------------------------------------
# F4a wiring — the static stage publishes what it just produced
# ---------------------------------------------------------------------------


class _FakeStaticWorker:
    """Just enough to bind the method under test."""

    from workers.static_worker import StaticWorker

    _publish_materialization = StaticWorker._publish_materialization


def _fake_job() -> Any:
    return SimpleNamespace(id=uuid.uuid4(), request={}, chain_id=1, source_content_hash="0x" + "fe" * 32)


@pytest.fixture()
def captured_publish(monkeypatch):
    calls: list[dict] = []
    monkeypatch.setattr(
        "db.contract_materializations.publish_materialization",
        lambda **kwargs: calls.append(kwargs) or PUBLISH_WRITTEN,
    )
    monkeypatch.setattr("utils.rpc.get_code_with_keccak", lambda *a, **k: ("0xfeed", KECCAK))
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


def test_static_stage_publishes_nothing_without_a_plan(monkeypatch, captured_publish):
    _stub_artifacts(monkeypatch, {"contract_analysis": ANALYSIS})
    _FakeStaticWorker()._publish_materialization(None, _fake_job(), ADDR, "C")
    assert captured_publish == []


def test_static_stage_publishes_nothing_without_a_keccak(monkeypatch, captured_publish):
    """The row is keyed on bytecode; a key we could not read is not a key."""
    _stub_artifacts(
        monkeypatch,
        {"contract_analysis": ANALYSIS, "control_tracking_plan": PLAN, "predicate_trees": TREES},
    )

    def _boom(*_a, **_k):
        raise RuntimeError("rpc down")

    monkeypatch.setattr("utils.rpc.get_code_with_keccak", _boom)
    _FakeStaticWorker()._publish_materialization(None, _fake_job(), ADDR, "C")
    assert captured_publish == []


def test_static_stage_never_fails_the_job_on_a_publish_error(monkeypatch, captured_publish):
    """Supply is not the analysis: a failed publish must not sink a job whose
    analysis succeeded."""
    _stub_artifacts(
        monkeypatch,
        {"contract_analysis": ANALYSIS, "control_tracking_plan": PLAN, "predicate_trees": TREES},
    )

    def _boom(**_k):
        raise RuntimeError("bucket down")

    monkeypatch.setattr("db.contract_materializations.publish_materialization", _boom)
    _FakeStaticWorker()._publish_materialization(None, _fake_job(), ADDR, "C")
