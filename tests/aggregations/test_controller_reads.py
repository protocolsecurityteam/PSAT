"""``controller_reads`` carries each published controller value with how and at which block it was read."""

from __future__ import annotations

import uuid

import pytest

from db.models import ControllerValue
from services.aggregations.company_overview import build_company_overview
from tests.conftest import requires_postgres
from tests.support.overview_builders import _add_contract, _add_job, _add_protocol, _addr

pytestmark = requires_postgres


@pytest.mark.parametrize(
    ("observed_via", "block", "has_value", "basis"),
    [
        pytest.param("eth_call", 100, True, "head_before_read", id="eth_call"),
        pytest.param("eth_call_error", 100, False, "head_before_read", id="eth_call_error"),
        pytest.param("eth_call_impl_fallback", 100, True, "head_before_read", id="impl_fallback"),
        pytest.param("beacon_owner", 100, True, "head_before_read", id="beacon_owner"),
        pytest.param("event_log", 250, True, "log_block", id="event_log"),
        pytest.param("storage_poll", None, True, "not_determined", id="storage_poll"),
        pytest.param("eth_call", None, True, "not_determined", id="resolution-null-block"),
        pytest.param("event_log", None, True, "not_determined", id="event-null-block"),
        pytest.param(None, 100, True, "not_determined", id="unknown-route"),
    ],
)
def test_controller_read_basis(db_session, observed_via, block, has_value, basis):
    p = _add_protocol(db_session, f"cv-reads-{uuid.uuid4().hex[:8]}")
    addr = _addr("ct")
    job = _add_job(db_session, address=addr, protocol_id=p.id, name="Vault")
    contract = _add_contract(db_session, address=addr, job=job, protocol_id=p.id, contract_name="Vault")
    value = _addr("own").lower() if has_value else None
    db_session.add(
        ControllerValue(
            contract_id=contract.id,
            controller_id="owner",
            value=value,
            block_number=block,
            observed_via=observed_via,
        )
    )
    db_session.commit()

    payload = build_company_overview(db_session, p.name)
    entry = next(e for e in payload["contracts"] if e["address"] == addr.lower())
    assert entry["controllers"] == {"owner": value}
    assert entry["controller_reads"] == {
        "owner": {"value": value, "block_number": block, "block_basis": basis, "observed_via": observed_via}
    }


def test_controller_reads_follow_the_per_deployment_selection(db_session):
    p = _add_protocol(db_session, f"cv-reads-shared-{uuid.uuid4().hex[:8]}")
    impl = _addr("impl")
    proxies = [_addr("pxa").lower(), _addr("pxb").lower()]
    for proxy in proxies:
        job = _add_job(db_session, address=proxy, protocol_id=p.id, name="Proxy", is_proxy=True)
        _add_contract(
            db_session, address=proxy, job=job, protocol_id=p.id, is_proxy=True, implementation=impl, contract_name="P"
        )
    impl_job = _add_job(
        db_session, address=impl, protocol_id=p.id, request={"address": impl, "proxy_address": proxies[0]}
    )
    impl_c = _add_contract(db_session, address=impl, job=impl_job, protocol_id=p.id, contract_name="Impl")
    for block, proxy in ((10, proxies[0]), (20, proxies[1]), (30, None)):
        db_session.add(
            ControllerValue(
                contract_id=impl_c.id,
                deployment_address=proxy,
                controller_id="owner",
                value=_addr("o").lower(),
                block_number=block,
                observed_via="eth_call",
            )
        )
    db_session.commit()

    payload = build_company_overview(db_session, p.name)
    reads = {e["address"]: e["controller_reads"] for e in payload["contracts"] if e["address"] in proxies}
    assert {addr: r["owner"]["block_number"] for addr, r in reads.items()} == {proxies[0]: 10, proxies[1]: 20}
