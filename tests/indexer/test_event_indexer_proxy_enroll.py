"""Regression: the event-log indexer enrolls a proxy-linked impl job's self-administered role/authority
cursors at the **proxy** (where events are emitted and ``capability_resolver`` reads them), not ``job.address``.

The bug: ``_event_address_for_descriptor`` fell through to ``job.address`` (the impl, which emits nothing) for a
self-administered OZ AccessControl descriptor (KING Distributor's shape: no ``authority_contract``, no hint
``event_address``). The proxy stayed un-indexed, every privileged function fell back to a ~30-40 s HyperSync scan,
inflating the policy stage to ~13 min and causing run-to-run controller drift. The fix routes the fallback through
the resolver's ``runtime_addr``.
"""

from __future__ import annotations

from types import SimpleNamespace
from typing import Any, cast

import pytest
from eth_utils.crypto import keccak

from tests.conftest import DATABASE_URL as _DB_URL
from tests.conftest import _can_connect
from workers.event_log_indexer import (
    _event_address_for_descriptor,
    _job_runtime_address,
)

_IMPL = "0x" + "5e" * 20  # job.address — the implementation, emits nothing itself
_PROXY = "0x" + "6d" * 20  # request.proxy_address — where the events are emitted
_EXTERNAL = "0x" + "a2" * 20  # a distinct external authority contract

_ROLE_GRANTED = "0x" + keccak(text="RoleGranted(bytes32,address,address)").hex()
_ROLE_REVOKED = "0x" + keccak(text="RoleRevoked(bytes32,address,address)").hex()


def _self_admin_descriptor() -> dict[str, Any]:
    """KING Distributor's shape."""
    return {
        "kind": "event_indexed",
        "enumeration_hint": [
            {"topic0": _ROLE_GRANTED, "direction": "add"},
            {"topic0": _ROLE_REVOKED, "direction": "remove"},
        ],
    }


def _impl_job_with_proxy() -> Any:
    return cast(Any, SimpleNamespace(address=_IMPL, request={"proxy_address": _PROXY}))


@pytest.mark.parametrize(
    "job, expected",
    [
        pytest.param(_impl_job_with_proxy(), _PROXY, id="proxy-linked"),
        pytest.param(cast(Any, SimpleNamespace(address=_IMPL, request={"address": _IMPL})), _IMPL, id="standalone"),
        pytest.param(cast(Any, SimpleNamespace(address=_IMPL)), _IMPL, id="missing-request"),
    ],
)
def test_job_runtime_address(job, expected):
    assert _job_runtime_address(job) == expected


_EXTERNAL_AUTHORITY_DESCRIPTOR = {
    "kind": "external_set",
    "authority_contract": {"address": _EXTERNAL},
    "enumeration_hint": [{"topic0": _ROLE_GRANTED, "direction": "add"}],
}


@pytest.mark.parametrize(
    "descriptor, hint, job, expected",
    [
        # The bug: returned the impl, leaving the proxy's index cold.
        pytest.param(
            _self_admin_descriptor(),
            {"topic0": _ROLE_GRANTED, "direction": "add"},
            _impl_job_with_proxy(),
            _PROXY,
            id="self-administered-role-enrolls-at-proxy-not-impl",
        ),
        pytest.param(
            _self_admin_descriptor(),
            {"topic0": _ROLE_GRANTED},
            cast(Any, SimpleNamespace(address=_IMPL, request={})),
            _IMPL,
            id="standalone-contract-enrolls-at-job-address",
        ),
        pytest.param(
            _self_admin_descriptor(),
            {"topic0": _ROLE_GRANTED, "event_address": _EXTERNAL},
            _impl_job_with_proxy(),
            _EXTERNAL,
            id="explicit-hint-event-address-wins-over-proxy",
        ),
        # An explicit external authority emits its own events.
        pytest.param(
            _EXTERNAL_AUTHORITY_DESCRIPTOR,
            {"topic0": _ROLE_GRANTED},
            _impl_job_with_proxy(),
            _EXTERNAL,
            id="external-authority-address-wins-over-proxy",
        ),
    ],
)
def test_event_address_for_descriptor(descriptor, hint, job, expected):
    assert _event_address_for_descriptor(descriptor, hint, job, {}) == expected


@pytest.fixture(autouse=True)
def _no_creation_witness(monkeypatch):
    """This module asserts which address the cursor lands on, not the grade."""
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
