"""A delegated role-gate's RoleSet cursor enrolls at the authority proxy off the caller's descriptor, since the
registry's own trees compile to zero descriptors.
"""

from __future__ import annotations

from datetime import datetime, timezone
from typing import Any, cast

import pytest
from sqlalchemy import func, select

import services.resolution.role_store_standards as rss
import workers.event_log_indexer as eli
from services.resolution.role_store_standards import (
    OZ_ACCESS_CONTROL_ENUMERABLE,
    SOLADY_ENUMERABLE_ROLES,
    all_topic0s,
)
from tests.conftest import DATABASE_URL as _DB_URL
from tests.conftest import _can_connect, requires_postgres
from workers.event_log_indexer import (
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


def test_single_address_param_signature():
    assert _is_single_address_param_signature("onlyOperatingMultisig(address)")
    assert not _is_single_address_param_signature("canCall(address,address,bytes4)")
    assert not _is_single_address_param_signature("foo()")
    assert not _is_single_address_param_signature("foo(uint256)")
    assert not _is_single_address_param_signature(None)


def _gate_with(**over: Any) -> dict[str, Any]:
    desc = _gate_descriptor()
    desc.update(over)
    return desc


@pytest.mark.parametrize(
    "desc,expected",
    [
        pytest.param(_gate_descriptor(), True, id="matches_delegated_role_gate"),
        pytest.param(
            {
                "kind": "external_set",
                "callee_signature": "canCall(address,address,bytes4)",
                "key_sources": [{"source": "msg_sender"}],
            },
            False,
            id="rejects_solmate_cancall",
        ),
        pytest.param(
            _gate_with(key_sources=[{"source": "state_variable", "state_variable_name": "owner"}]),
            False,
            id="rejects_non_caller_keyed",
        ),
        pytest.param(_gate_with(kind="mapping_membership"), False, id="rejects_non_external_set"),
    ],
)
def test_delegated_role_gate_predicate(desc, expected):
    assert _is_delegated_role_gate_descriptor(desc) is expected


def _boom(*a, **k):
    raise RuntimeError("wire down")


_REAL_DETECT = eli.detect_standards


@pytest.mark.parametrize(
    "probe,detect,expected",
    [
        pytest.param(
            lambda *a, **k: "0xdeadbeef",
            lambda code: [SOLADY_ENUMERABLE_ROLES],
            [_ROLE_SET],
            id="uses_detected_standard",
        ),
        pytest.param(lambda *a, **k: "0x00", lambda code: [], all_topic0s(), id="unions_when_inconclusive"),
        # Probe failure over-indexes to the union, never an empty topic list.
        pytest.param(_boom, _REAL_DETECT, all_topic0s(), id="unions_when_probe_raises"),
    ],
)
def test_topic0_selection(monkeypatch, probe, detect, expected):
    monkeypatch.setattr(eli, "resolve_probe_code", probe)
    monkeypatch.setattr(eli, "detect_standards", detect)
    assert eli._role_store_topic0s(cast(Any, None), _PROXY, 1, {}) == expected


def test_topic0s_cache_dedups_detection(monkeypatch):
    # One eth_getCode for a whole registry family.
    calls = {"n": 0}

    def _counting(*a, **k):
        calls["n"] += 1
        return "0xdeadbeef"

    monkeypatch.setattr(eli, "resolve_probe_code", _counting)
    monkeypatch.setattr(eli, "detect_standards", lambda code: [SOLADY_ENUMERABLE_ROLES])
    cache: dict[tuple[int, str], list[str]] = {}
    first = eli._role_store_topic0s(cast(Any, None), _PROXY, 1, cache)
    second = eli._role_store_topic0s(cast(Any, None), _PROXY, 1, cache)
    assert first == second == [_ROLE_SET]
    assert calls["n"] == 1


@pytest.fixture(autouse=True)
def _no_creation_witness(monkeypatch):
    """This module asserts which topics enroll, not the grade."""

    def _no_wire(*_a, **_kw):
        raise RuntimeError("no rpc")

    monkeypatch.setattr(eli, "rpc_request", _no_wire)


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
    """The DB Contract row supplies the proxy -> impl hop."""

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
    session.add(Contract(address=_PROXY, implementation=_IMPL, is_proxy=True, chain="ethereum"))
    session.commit()

    _completed_job_with_gate(session, _gate_descriptor())
    inserted = enroll_from_completed_jobs(session)
    assert inserted >= 1

    row = session.execute(
        select(IndexedEventCursor.last_indexed_block)
        .where(IndexedEventCursor.chain_id == 1)
        .where(func.lower(IndexedEventCursor.event_address) == _PROXY)
        .where(func.lower(IndexedEventCursor.topic0) == _ROLE_SET)
    ).first()
    assert row is not None, "RoleSet cursor must be enrolled at the authority proxy"
    assert row[0] == deploy - 1

    impl_side = session.execute(
        select(IndexedEventCursor.event_address).where(func.lower(IndexedEventCursor.event_address) == _PROTECTED)
    ).first()
    assert impl_side is None


@requires_postgres
def test_union_enrolls_when_undetectable(session, monkeypatch):
    from db.models import IndexedEventCursor

    _seed_creation_block(monkeypatch, 22_000_000)
    _stub_probe_code(monkeypatch, "0x00")
    _completed_job_with_gate(session, _gate_descriptor())

    enroll_from_completed_jobs(session)
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

    first = enroll_from_completed_jobs(session)
    second = enroll_from_completed_jobs(session)
    assert first >= 1
    assert second == 0


@requires_postgres
@pytest.mark.parametrize(
    "probe_code,authority",
    [
        pytest.param(
            _code_with(*SOLADY_ENUMERABLE_ROLES.marker_selectors), {"address": "0x" + "00" * 20}, id="zero_address"
        ),
        pytest.param(
            "0x00",
            {"address_source": {"source": "state_variable", "state_variable_name": "roleRegistry"}},
            id="unresolved",
        ),
    ],
)
def test_unusable_authority_skips(session, monkeypatch, probe_code, authority):
    from db.models import IndexedEventCursor

    _seed_creation_block(monkeypatch, 22_000_000)
    _stub_probe_code(monkeypatch, probe_code)
    _completed_job_with_gate(session, _gate_with(authority_contract=authority))

    enroll_from_completed_jobs(session)
    any_cursor = session.execute(select(func.count()).select_from(IndexedEventCursor)).scalar_one()
    assert any_cursor == 0


@requires_postgres
def test_enrolls_via_state_variable_controllervalue(session, monkeypatch):
    # The production shape: the authority is a state_variable resolved from the job's ControllerValue.
    from db.models import Contract, ControllerValue, IndexedEventCursor

    deploy = 22_039_954
    _seed_creation_block(monkeypatch, deploy)
    _stub_probe_code(monkeypatch, _code_with(*SOLADY_ENUMERABLE_ROLES.marker_selectors))
    session.add(Contract(address=_PROXY, implementation=_IMPL, is_proxy=True, chain="ethereum"))
    session.commit()

    desc = _gate_descriptor(authority_address=None)
    desc["authority_contract"] = {"address_source": {"source": "state_variable", "state_variable_name": "roleRegistry"}}
    job = _completed_job_with_gate(session, desc)
    contract = Contract(address=_PROTECTED, job_id=job.id, chain="ethereum")
    session.add(contract)
    session.flush()
    session.add(ControllerValue(contract_id=contract.id, controller_id="state_variable:roleRegistry", value=_PROXY))
    session.commit()

    enroll_from_completed_jobs(session)
    row = session.execute(
        select(IndexedEventCursor.last_indexed_block)
        .where(func.lower(IndexedEventCursor.event_address) == _PROXY)
        .where(func.lower(IndexedEventCursor.topic0) == _ROLE_SET)
    ).first()
    assert row is not None and row[0] == deploy - 1


def _completed_job_with_two_gates(session, descriptors: list[dict[str, Any]]):
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
    trees = {f"fn{i}()": {"op": "LEAF", "leaf": {"set_descriptor": d}} for i, d in enumerate(descriptors)}
    store_artifact(session, job.id, "predicate_trees", data={"trees": trees})
    session.commit()
    return job


@requires_postgres
def test_shared_authority_detects_standard_once(session, monkeypatch):
    # A2/F1: one detection per shared authority proxy.
    from db.models import Contract

    _seed_creation_block(monkeypatch, 22_039_954)
    _stub_probe_code(monkeypatch, _code_with(*SOLADY_ENUMERABLE_ROLES.marker_selectors))
    session.add(Contract(address=_PROXY, implementation=_IMPL, is_proxy=True, chain="ethereum"))
    session.commit()

    calls = {"n": 0}
    real = eli.resolve_probe_code

    def _counting(*a, **k):
        calls["n"] += 1
        return real(*a, **k)

    monkeypatch.setattr(eli, "resolve_probe_code", _counting)

    gate_a = _gate_descriptor()
    gate_b = _gate_descriptor()
    gate_b["callee_signature"] = "onlyOperatingTimelock(address)"  # distinct gate, same authority
    _completed_job_with_two_gates(session, [gate_a, gate_b])

    enroll_from_completed_jobs(session)
    assert calls["n"] == 1


@requires_postgres
def test_second_pass_with_cursor_skips_detection(session, monkeypatch):
    from db.models import Contract
    from tests.support.witness_wire import stub_seed_witness

    stub_seed_witness(monkeypatch, creation_block=22_039_954)
    _stub_probe_code(monkeypatch, _code_with(*SOLADY_ENUMERABLE_ROLES.marker_selectors))
    session.add(Contract(address=_PROXY, implementation=_IMPL, is_proxy=True, chain="ethereum"))
    session.commit()
    _completed_job_with_gate(session, _gate_descriptor())

    enroll_from_completed_jobs(session)  # first pass seeds the cursor

    calls = {"n": 0}
    real = eli.resolve_probe_code

    def _counting(*a, **k):
        calls["n"] += 1
        return real(*a, **k)

    monkeypatch.setattr(eli, "resolve_probe_code", _counting)
    enroll_from_completed_jobs(session)  # cursor present → skip detection
    assert calls["n"] == 0


@requires_postgres
def test_unwitnessed_cursor_does_not_skip_detection(session, monkeypatch):
    # A cursor with no witnessed lower bound can't license exactness, so it doesn't count as the authority's
    # role-store cursor.
    from db.models import Contract
    from tests.support.witness_wire import stub_seed_witness

    stub_seed_witness(monkeypatch, creation_block=22_039_954, fail=True)
    _stub_probe_code(monkeypatch, _code_with(*SOLADY_ENUMERABLE_ROLES.marker_selectors))
    session.add(Contract(address=_PROXY, implementation=_IMPL, is_proxy=True, chain="ethereum"))
    session.commit()
    _completed_job_with_gate(session, _gate_descriptor())

    enroll_from_completed_jobs(session)

    calls = {"n": 0}
    real = eli.resolve_probe_code

    def _counting(*a, **k):
        calls["n"] += 1
        return real(*a, **k)

    monkeypatch.setattr(eli, "resolve_probe_code", _counting)
    enroll_from_completed_jobs(session)
    assert calls["n"] == 1


@requires_postgres
def test_solmate_cancall_still_enrolls_its_topics(session, monkeypatch):
    from db.models import IndexedEventCursor

    _seed_creation_block(monkeypatch, 22_000_000)
    _stub_probe_code(monkeypatch, "0x00")
    desc = {
        "kind": "external_set",
        "callee_signature": "canCall(address,address,bytes4)",
        "authority_contract": {"address": _PROXY},
    }
    _completed_job_with_gate(session, desc)

    enroll_from_completed_jobs(session)
    enrolled = {
        t
        for (t,) in session.execute(
            select(IndexedEventCursor.topic0).where(func.lower(IndexedEventCursor.event_address) == _PROXY)
        ).all()
    }
    assert enrolled == {t.lower() for t in eli._SOLMATE_ROLE_TOPICS}
