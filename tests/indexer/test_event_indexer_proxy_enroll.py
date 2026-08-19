"""Regression: the event-log indexer enrolls a proxy-linked impl job's
self-administered role/authority cursors at the **proxy** — where the events are
emitted and where ``capability_resolver`` reads them — not at ``job.address``
(the impl, which delegatecalls and emits nothing under its own address).

The bug: ``_event_address_for_descriptor`` fell through to ``job.address`` for a
self-administered OZ AccessControl descriptor (no ``authority_contract``, no
``event_address`` on the hint — KING Distributor's exact shape: all 40 hints had
both ``None``). For an ``(impl)`` job that is the implementation address, so the
cursor landed on an address that emits nothing and the proxy stayed permanently
un-indexed. Every privileged function then fell back to a ~30–40 s HyperSync
full-history scan — driving both the ~13-min policy stage AND run-to-run
controller drift (a cold fold lands on the full set / a truncated subset /
``external_check`` depending on how the scan races the 45 s timeout). The fix
routes the fallback through the same ``runtime_addr`` the resolver uses
(``request['proxy_address']`` when set). See POLICY_STAGE_ROOTCAUSE_VERDICT.md.
"""

from __future__ import annotations

from datetime import datetime, timezone
from types import SimpleNamespace
from typing import Any, cast

import pytest
from eth_utils.crypto import keccak
from sqlalchemy import func, select

from tests.conftest import DATABASE_URL as _DB_URL
from tests.conftest import _can_connect, requires_postgres
from workers.event_log_indexer import (
    _event_address_for_descriptor,
    _job_runtime_address,
    enroll_from_completed_jobs,
)

_IMPL = "0x" + "5e" * 20  # job.address — the implementation, emits nothing itself
_PROXY = "0x" + "6d" * 20  # request.proxy_address — where the events are emitted
_EXTERNAL = "0x" + "a2" * 20  # a distinct external authority contract

_ROLE_GRANTED = "0x" + keccak(text="RoleGranted(bytes32,address,address)").hex()
_ROLE_REVOKED = "0x" + keccak(text="RoleRevoked(bytes32,address,address)").hex()


def _self_admin_descriptor() -> dict[str, Any]:
    """A self-administered OZ AccessControl role set: no ``authority_contract``
    (the contract administers its own roles) and the hint carries no
    ``event_address`` — so address resolution falls through to the job-runtime
    fallback. This is KING Distributor's exact descriptor shape."""
    return {
        "kind": "event_indexed",
        "enumeration_hint": [
            {"topic0": _ROLE_GRANTED, "direction": "add"},
            {"topic0": _ROLE_REVOKED, "direction": "remove"},
        ],
    }


def _impl_job_with_proxy() -> Any:
    return cast(Any, SimpleNamespace(address=_IMPL, request={"proxy_address": _PROXY}))


# --- unit: _job_runtime_address mirrors capability_resolver's runtime_addr ---


def test_runtime_address_is_proxy_when_proxy_linked():
    assert _job_runtime_address(_impl_job_with_proxy()) == _PROXY


def test_runtime_address_is_job_address_when_standalone():
    job = cast(Any, SimpleNamespace(address=_IMPL, request={"address": _IMPL}))
    assert _job_runtime_address(job) == _IMPL


def test_runtime_address_tolerates_missing_request():
    assert _job_runtime_address(cast(Any, SimpleNamespace(address=_IMPL))) == _IMPL


# --- unit: _event_address_for_descriptor picks the proxy for self-admin events ---


def test_self_administered_role_enrolls_at_proxy_not_impl():
    # THE BUG: this returned _IMPL (job.address) before the fix, leaving the
    # proxy's event index cold ⇒ per-function HyperSync fallback.
    addr = _event_address_for_descriptor(
        _self_admin_descriptor(), {"topic0": _ROLE_GRANTED, "direction": "add"}, _impl_job_with_proxy(), {}
    )
    assert addr == _PROXY


def test_standalone_contract_still_enrolls_at_job_address():
    job = cast(Any, SimpleNamespace(address=_IMPL, request={}))
    addr = _event_address_for_descriptor(_self_admin_descriptor(), {"topic0": _ROLE_GRANTED}, job, {})
    assert addr == _IMPL


def test_explicit_hint_event_address_wins_over_proxy():
    # An emitter named on the hint is authoritative; the proxy fallback only
    # fills the self-administered gap.
    addr = _event_address_for_descriptor(
        _self_admin_descriptor(),
        {"topic0": _ROLE_GRANTED, "event_address": _EXTERNAL},
        _impl_job_with_proxy(),
        {},
    )
    assert addr == _EXTERNAL


def test_external_authority_address_wins_over_proxy():
    # An external authority (e.g. a shared RolesAuthority) emits its own events;
    # the proxy fallback must not override an explicit authority address.
    desc = {
        "kind": "external_set",
        "authority_contract": {"address": _EXTERNAL},
        "enumeration_hint": [{"topic0": _ROLE_GRANTED, "direction": "add"}],
    }
    addr = _event_address_for_descriptor(desc, {"topic0": _ROLE_GRANTED}, _impl_job_with_proxy(), {})
    assert addr == _EXTERNAL


# --- integration: enroll_from_completed_jobs seeds the cursor at the proxy ---


@pytest.fixture(autouse=True)
def _no_creation_witness(monkeypatch):
    """Enrollment grades its seed with three pinned chain reads before writing
    the cursor. Nothing here asserts that grade — the subject is which ADDRESS
    the cursor lands on — so the wire is stubbed to the unreachable-RPC failure,
    whose documented outcome is ``(None, not_determined)``."""
    import workers.event_log_indexer as eli

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

    _wipe()  # start from a clean slate so the negative assertion is sound
    try:
        yield s
    finally:
        s.rollback()
        _wipe()
        s.close()
        engine.dispose()


@requires_postgres
def test_enroll_proxy_linked_impl_seeds_cursor_at_proxy(session, monkeypatch):
    import workers.event_log_indexer as eli
    from db.models import IndexedEventCursor, Job, JobStage, JobStatus
    from db.queue import store_artifact

    deploy = 21_000_000
    seen: list[str] = []

    def _fake_creation_block(address, **_kw):
        seen.append(address.lower())
        return deploy if address.lower() == _PROXY else None

    monkeypatch.setattr(eli, "get_contract_creation_block", _fake_creation_block)

    job = Job(
        address=_IMPL,
        request={"address": _IMPL, "proxy_address": _PROXY, "name": "KINGlike"},
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
        data={
            "trees": {
                "grantRole(bytes32,address)": {"op": "LEAF", "leaf": {"set_descriptor": _self_admin_descriptor()}}
            }
        },
    )
    session.commit()

    inserted = enroll_from_completed_jobs(session)
    assert inserted >= 2  # RoleGranted + RoleRevoked, both at the proxy

    # The role cursors are enrolled at the PROXY (which emits the events), seeded
    # one below its deploy block — never at the impl (job.address).
    for topic0 in (_ROLE_GRANTED, _ROLE_REVOKED):
        row = session.execute(
            select(IndexedEventCursor.last_indexed_block)
            .where(IndexedEventCursor.chain_id == 1)
            .where(func.lower(IndexedEventCursor.event_address) == _PROXY)
            .where(func.lower(IndexedEventCursor.topic0) == topic0.lower())
        ).first()
        assert row is not None, f"{topic0} must be enrolled at the proxy"
        assert row[0] == deploy - 1

    impl_cursor = session.execute(
        select(IndexedEventCursor.event_address)
        .where(IndexedEventCursor.chain_id == 1)
        .where(func.lower(IndexedEventCursor.event_address) == _IMPL)
    ).first()
    assert impl_cursor is None, "must NOT enroll at the impl (job.address) — it emits nothing"

    # The creation-block seed was looked up for the proxy, not the impl.
    assert _PROXY in seen
    assert _IMPL not in seen
