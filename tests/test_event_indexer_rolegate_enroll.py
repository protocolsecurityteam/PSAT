"""The event-log indexer enrolls a delegated role-gate's RoleSet cursor at the
authority PROXY, off the caller's outer descriptor — the registry's own predicate
trees compile to zero descriptors, so the caller side is the only trigger.

Mirrors the Solmate-enroll tests: unit checks on the descriptor predicate + the
standards-detecting topic0 selection, then a DB integration proving the cursor
lands at the proxy seeded at creation-1.
"""

from __future__ import annotations

import os
import sys
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, cast

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from sqlalchemy import func, select  # noqa: E402

import services.resolution.role_store_standards as rss  # noqa: E402
import workers.event_log_indexer as eli  # noqa: E402
from services.resolution.role_store_standards import (  # noqa: E402
    OZ_ACCESS_CONTROL_ENUMERABLE,
    SOLADY_ENUMERABLE_ROLES,
    all_topic0s,
)
from workers.event_log_indexer import (  # noqa: E402
    _is_delegated_role_gate_descriptor,
    _is_single_address_param_signature,
    enroll_from_completed_jobs,
)

_PROXY = "0x" + "62" * 20  # the registry proxy — where RoleSet is emitted
_IMPL = "0x" + "3b" * 20  # Solady EnumerableRoles impl behind the proxy
_PROTECTED = "0x" + "11" * 20  # the gated contract (job.address) — emits nothing
_ROLE_SET = SOLADY_ENUMERABLE_ROLES.grant_events[0].topic0


def _gate_descriptor(authority_address: str | None = _PROXY) -> dict[str, Any]:
    authority = {"address": authority_address} if authority_address else {}
    return {
        "kind": "external_set",
        "callee_signature": "onlyOperatingMultisig(address)",
        "key_sources": [{"source": "msg_sender"}],
        "authority_contract": authority,
    }


# --- unit: the descriptor predicate ----------------------------------------


def test_single_address_param_signature():
    assert _is_single_address_param_signature("onlyOperatingMultisig(address)")
    assert not _is_single_address_param_signature("canCall(address,address,bytes4)")
    assert not _is_single_address_param_signature("foo()")
    assert not _is_single_address_param_signature("foo(uint256)")
    assert not _is_single_address_param_signature(None)


def test_matches_delegated_role_gate():
    assert _is_delegated_role_gate_descriptor(_gate_descriptor())


def test_rejects_solmate_cancall():
    desc = {
        "kind": "external_set",
        "callee_signature": "canCall(address,address,bytes4)",
        "key_sources": [{"source": "msg_sender"}],
    }
    assert not _is_delegated_role_gate_descriptor(desc)


def test_rejects_non_caller_keyed():
    # onlyX(owner) — the arg is not the caller, so this is not a caller-gate.
    desc = _gate_descriptor()
    desc["key_sources"] = [{"source": "state_variable", "state_variable_name": "owner"}]
    assert not _is_delegated_role_gate_descriptor(desc)


def test_rejects_non_external_set():
    desc = _gate_descriptor()
    desc["kind"] = "mapping_membership"
    assert not _is_delegated_role_gate_descriptor(desc)


# --- unit: topic0 selection (detect vs union-enroll) ------------------------


def test_topic0s_uses_detected_standard(monkeypatch):
    monkeypatch.setattr(eli, "resolve_probe_code", lambda *a, **k: "0xdeadbeef")
    monkeypatch.setattr(eli, "detect_standards", lambda code: [SOLADY_ENUMERABLE_ROLES])
    assert eli._role_store_topic0s(cast(Any, None), _PROXY, 1) == [_ROLE_SET]


def test_topic0s_unions_when_inconclusive(monkeypatch):
    monkeypatch.setattr(eli, "resolve_probe_code", lambda *a, **k: "0x00")
    monkeypatch.setattr(eli, "detect_standards", lambda code: [])
    assert eli._role_store_topic0s(cast(Any, None), _PROXY, 1) == all_topic0s()


def test_topic0s_unions_when_probe_raises(monkeypatch):
    def _boom(*a, **k):
        raise RuntimeError("wire down")

    monkeypatch.setattr(eli, "resolve_probe_code", _boom)
    assert eli._role_store_topic0s(cast(Any, None), _PROXY, 1) == all_topic0s()


# --- integration: enroll_from_completed_jobs -------------------------------

_DB_URL: str = os.environ.get("TEST_DATABASE_URL", os.environ.get("DATABASE_URL", "")) or ""


def _can_connect() -> bool:
    if not _DB_URL:
        return False
    try:
        from sqlalchemy import create_engine, text

        engine = create_engine(_DB_URL)
        with engine.connect() as conn:
            conn.execute(text("SELECT 1"))
        engine.dispose()
        return True
    except Exception:
        return False


requires_postgres = pytest.mark.skipif(not _can_connect(), reason="PostgreSQL not available")


@pytest.fixture()
def session():
    if not _can_connect():
        pytest.skip("PostgreSQL not available")
    from sqlalchemy import create_engine
    from sqlalchemy.orm import Session

    from db.models import Contract, IndexedEventCursor, IndexedEventLog, Job, Protocol

    engine = create_engine(_DB_URL)
    s = Session(engine, expire_on_commit=False)

    def _wipe():
        for model in (IndexedEventLog, IndexedEventCursor, Contract):
            s.query(model).delete()
        s.query(Job).delete()
        s.query(Protocol).delete()
        s.commit()

    _wipe()
    try:
        yield s
    finally:
        s.rollback()
        _wipe()
        s.close()
        engine.dispose()


def _completed_job_with_gate(session, descriptor: dict[str, Any]):
    from db.models import Job, JobStage, JobStatus
    from db.queue import store_artifact

    job = Job(
        address=_PROTECTED,
        request={"address": _PROTECTED, "name": "GatedContract"},
        status=JobStatus.completed,
        stage=JobStage.done,
        created_at=datetime.now(timezone.utc),
        updated_at=datetime.now(timezone.utc),
    )
    session.add(job)
    session.flush()
    store_artifact(
        session,
        job.id,
        "predicate_trees",
        data={"trees": {"doThing()": {"op": "LEAF", "leaf": {"set_descriptor": descriptor}}}},
    )
    session.commit()
    return job


def _seed_creation_block(monkeypatch, deploy: int):
    monkeypatch.setattr(eli, "get_contract_creation_block", lambda address, **_kw: deploy)


def _stub_probe_code(monkeypatch, code_for_impl: str, impl: str = _IMPL):
    """Route resolve_probe_code's wire through a stub: get_code returns the given
    code for the impl address, and the EIP-1967 slot read is disabled (the DB
    Contract row supplies the proxy→impl hop)."""

    def _fake_get_code(rpc_url, address, *, chain_id=None):
        return code_for_impl if address.lower() == impl.lower() else "0x00"

    monkeypatch.setattr(rss, "get_code", _fake_get_code)
    monkeypatch.setattr(rss, "rpc_request", lambda *a, **k: None)


def _code_with(*selectors: str) -> str:
    return "0x" + "".join("63" + s.removeprefix("0x") for s in selectors)


@requires_postgres
def test_enrolls_roleset_at_proxy_via_proxy_hop(session, monkeypatch):
    from db.models import Contract, IndexedEventCursor

    deploy = 22_039_954
    _seed_creation_block(monkeypatch, deploy)
    _stub_probe_code(monkeypatch, _code_with(*SOLADY_ENUMERABLE_ROLES.marker_selectors))
    # DB linkage proxy → impl so resolve_probe_code detects Solady behind the proxy.
    session.add(Contract(address=_PROXY, implementation=_IMPL, is_proxy=True, chain="ethereum"))
    session.commit()

    _completed_job_with_gate(session, _gate_descriptor())
    inserted = enroll_from_completed_jobs(session, chain_id=1)
    assert inserted >= 1

    row = session.execute(
        select(IndexedEventCursor.last_indexed_block)
        .where(IndexedEventCursor.chain_id == 1)
        .where(func.lower(IndexedEventCursor.event_address) == _PROXY)
        .where(func.lower(IndexedEventCursor.topic0) == _ROLE_SET)
    ).first()
    assert row is not None, "RoleSet cursor must be enrolled at the authority proxy"
    assert row[0] == deploy - 1

    # Never at the protected contract (job.address), which emits nothing.
    impl_side = session.execute(
        select(IndexedEventCursor.event_address).where(func.lower(IndexedEventCursor.event_address) == _PROTECTED)
    ).first()
    assert impl_side is None


@requires_postgres
def test_union_enrolls_when_undetectable(session, monkeypatch):
    from db.models import IndexedEventCursor

    _seed_creation_block(monkeypatch, 22_000_000)
    # No Contract linkage + non-marker code → detection inconclusive → union.
    _stub_probe_code(monkeypatch, "0x00")
    _completed_job_with_gate(session, _gate_descriptor())

    enroll_from_completed_jobs(session, chain_id=1)
    enrolled = {
        t
        for (t,) in session.execute(
            select(IndexedEventCursor.topic0).where(func.lower(IndexedEventCursor.event_address) == _PROXY)
        ).all()
    }
    assert enrolled == set(all_topic0s())
    assert OZ_ACCESS_CONTROL_ENUMERABLE.grant_events[0].topic0 in enrolled  # both standards enrolled


@requires_postgres
def test_enrollment_is_idempotent(session, monkeypatch):
    _seed_creation_block(monkeypatch, 22_000_000)
    _stub_probe_code(monkeypatch, "0x00")
    _completed_job_with_gate(session, _gate_descriptor())

    first = enroll_from_completed_jobs(session, chain_id=1)
    second = enroll_from_completed_jobs(session, chain_id=1)
    assert first >= 1
    assert second == 0


@requires_postgres
def test_zero_address_authority_skips(session, monkeypatch):
    from db.models import IndexedEventCursor

    _seed_creation_block(monkeypatch, 22_000_000)
    _stub_probe_code(monkeypatch, _code_with(*SOLADY_ENUMERABLE_ROLES.marker_selectors))
    _completed_job_with_gate(session, _gate_descriptor(authority_address="0x" + "00" * 20))

    enroll_from_completed_jobs(session, chain_id=1)
    any_cursor = session.execute(select(func.count()).select_from(IndexedEventCursor)).scalar_one()
    assert any_cursor == 0


@requires_postgres
def test_unresolved_authority_skips(session, monkeypatch):
    from db.models import IndexedEventCursor

    _seed_creation_block(monkeypatch, 22_000_000)
    _stub_probe_code(monkeypatch, "0x00")
    # Authority is a state_variable that never resolved (no ControllerValue feed)
    # and there is no job fallback for the delegated path → no cursor.
    desc = _gate_descriptor(authority_address=None)
    desc["authority_contract"] = {"address_source": {"source": "state_variable", "state_variable_name": "roleRegistry"}}
    _completed_job_with_gate(session, desc)

    enroll_from_completed_jobs(session, chain_id=1)
    any_cursor = session.execute(select(func.count()).select_from(IndexedEventCursor)).scalar_one()
    assert any_cursor == 0


@requires_postgres
def test_enrolls_via_state_variable_controllervalue(session, monkeypatch):
    # The production descriptor shape: authority is NOT a literal address but a
    # state_variable ("roleRegistry") resolved from the job's captured
    # ControllerValue. Proves the real _event_address_for_descriptor path (not the
    # hardcoded-address shortcut the other happy-path test uses) lands the cursor
    # at the resolved proxy.
    from db.models import Contract, ControllerValue, IndexedEventCursor

    deploy = 22_039_954
    _seed_creation_block(monkeypatch, deploy)
    _stub_probe_code(monkeypatch, _code_with(*SOLADY_ENUMERABLE_ROLES.marker_selectors))
    session.add(Contract(address=_PROXY, implementation=_IMPL, is_proxy=True, chain="ethereum"))
    session.commit()

    desc = _gate_descriptor(authority_address=None)
    desc["authority_contract"] = {"address_source": {"source": "state_variable", "state_variable_name": "roleRegistry"}}
    job = _completed_job_with_gate(session, desc)
    # The job's own Contract row + a captured ControllerValue supplying roleRegistry.
    contract = Contract(address=_PROTECTED, job_id=job.id, chain="ethereum")
    session.add(contract)
    session.flush()
    session.add(
        ControllerValue(contract_id=contract.id, controller_id="state_variable:roleRegistry", value=_PROXY)
    )
    session.commit()

    enroll_from_completed_jobs(session, chain_id=1)
    row = session.execute(
        select(IndexedEventCursor.last_indexed_block)
        .where(func.lower(IndexedEventCursor.event_address) == _PROXY)
        .where(func.lower(IndexedEventCursor.topic0) == _ROLE_SET)
    ).first()
    assert row is not None and row[0] == deploy - 1


@requires_postgres
def test_solmate_cancall_still_enrolls_its_topics(session, monkeypatch):
    # Regression: the delegated branch excludes canCall, so a canCall descriptor
    # keeps enrolling the three Solmate role topics unchanged.
    from db.models import IndexedEventCursor

    _seed_creation_block(monkeypatch, 22_000_000)
    _stub_probe_code(monkeypatch, "0x00")
    desc = {
        "kind": "external_set",
        "callee_signature": "canCall(address,address,bytes4)",
        "authority_contract": {"address": _PROXY},
    }
    _completed_job_with_gate(session, desc)

    enroll_from_completed_jobs(session, chain_id=1)
    enrolled = {
        t
        for (t,) in session.execute(
            select(IndexedEventCursor.topic0).where(func.lower(IndexedEventCursor.event_address) == _PROXY)
        ).all()
    }
    assert enrolled == {t.lower() for t in eli._SOLMATE_ROLE_TOPICS}
