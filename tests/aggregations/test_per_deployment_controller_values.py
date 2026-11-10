"""A shared implementation row holds one controller-value set per proxy; each proxy entry publishes only its own."""

from __future__ import annotations

import uuid

from db.deployment import resolved_against
from db.models import Contract, ControllerValue, EffectiveFunction, FunctionPrincipal
from services.aggregations.company_overview import build_company_overview
from tests.conftest import requires_postgres
from tests.support.overview_builders import _add_contract, _add_job, _add_protocol, _addr

pytestmark = requires_postgres


def _cv(session, contract, controller_id, value, *, deployment=None):
    session.add(
        ControllerValue(
            contract_id=contract.id,
            deployment_address=deployment.lower() if deployment else None,
            controller_id=controller_id,
            value=value.lower(),
            resolved_type="contract",
            source=controller_id,
            block_number=100,
            observed_via="eth_call",
        )
    )


def _gate(session, contract, fname, caller):
    ef = EffectiveFunction(
        contract_id=contract.id,
        function_name=fname,
        selector="0x" + uuid.uuid4().hex[:8],
        abi_signature=f"{fname}()",
        effect_labels=[],
        effect_targets=[],
        action_summary=fname,
        authority_public=False,
        authority_roles=[],
    )
    session.add(ef)
    session.flush()
    session.add(
        FunctionPrincipal(
            function_id=ef.id,
            address=caller.lower(),
            resolved_type="contract",
            origin="guardian",
            principal_type="controller",
        )
    )


def _member(session, protocol, seed, name):
    addr = _addr(seed)
    job = _add_job(session, address=addr, protocol_id=protocol.id, name=name)
    _add_contract(session, address=addr, job=job, protocol_id=protocol.id, contract_name=name)
    return addr.lower()


def _entry(payload, addr):
    return next(c for c in payload["contracts"] if c["address"] == addr.lower())


def _flows(payload, to_addr, flow_type):
    return {f["from"] for f in payload["fund_flows"] if f["to"] == to_addr.lower() and f["type"] == flow_type}


def _shared_impl_protocol(session):
    p = _add_protocol(session, f"shared-impl-{uuid.uuid4().hex[:8]}")
    impl = _addr("impl")
    proxies = [_addr("pxa"), _addr("pxb")]
    for proxy in proxies:
        job = _add_job(session, address=proxy, protocol_id=p.id, name="Proxy", is_proxy=True)
        _add_contract(
            session,
            address=proxy,
            job=job,
            protocol_id=p.id,
            is_proxy=True,
            implementation=impl,
            contract_name="Proxy",
        )
    impl_job = _add_job(
        session,
        address=impl,
        protocol_id=p.id,
        name="VaultImpl",
        request={"address": impl, "proxy_address": proxies[0]},
    )
    impl_c = _add_contract(session, address=impl, job=impl_job, protocol_id=p.id, contract_name="VaultImpl")
    return p, impl_c, proxies


def test_proxies_sharing_an_implementation_publish_their_own_controller_values(db_session):
    s = db_session
    p, impl_c, (proxy_a, proxy_b) = _shared_impl_protocol(s)
    owner_a, owner_b = _member(s, p, "owa", "OwnerA"), _member(s, p, "owb", "OwnerB")
    guard_a, guard_b = _member(s, p, "gda", "GuardA"), _member(s, p, "gdb", "GuardB")
    legacy = _member(s, p, "leg", "Legacy")

    _cv(s, impl_c, "owner", owner_a, deployment=proxy_a)
    _cv(s, impl_c, "state_variable:guardian", guard_a, deployment=proxy_a)
    _cv(s, impl_c, "owner", owner_b, deployment=proxy_b)
    _cv(s, impl_c, "state_variable:guardian", guard_b, deployment=proxy_b)
    # Untagged on the shared impl: its deployment can't be established.
    _cv(s, impl_c, "state_variable:legacyAdmin", legacy)
    _gate(s, impl_c, "setGuardianA", guard_a)
    _gate(s, impl_c, "setGuardianB", guard_b)
    s.commit()

    payload = build_company_overview(s, p.name)
    for proxy, owner, guard, other_owner, other_guard in (
        (proxy_a, owner_a, guard_a, owner_b, guard_b),
        (proxy_b, owner_b, guard_b, owner_a, guard_a),
    ):
        entry = _entry(payload, proxy)
        assert entry["owner"] == owner
        assert entry["controllers"] == {"owner": owner, "state_variable:guardian": guard}
        assert _flows(payload, proxy, "controls") == {owner}
        controller_sources = _flows(payload, proxy, "controller")
        assert guard in controller_sources
        assert other_guard not in controller_sources
        assert other_owner not in controller_sources
        assert legacy not in _flows(payload, proxy, "controller") | _flows(payload, proxy, "controls")


def test_a_proxy_without_its_own_impl_rows_falls_back_to_its_own_storage_reads(db_session):
    s = db_session
    p, impl_c, (proxy_a, proxy_b) = _shared_impl_protocol(s)
    owner_b, own_admin = _member(s, p, "owb", "OwnerB"), _member(s, p, "adm", "ProxyAdmin")
    _cv(s, impl_c, "owner", owner_b, deployment=proxy_b)
    proxy_a_row = s.query(Contract).filter(Contract.address == proxy_a).one()
    _cv(s, proxy_a_row, "admin", own_admin)
    s.commit()

    payload = build_company_overview(s, p.name)
    assert _entry(payload, proxy_a)["controllers"] == {"admin": own_admin}
    assert _entry(payload, proxy_a)["owner"] is None
    # The logic contract's set was never read for this proxy, so its own reads are not the whole set.
    assert _entry(payload, proxy_a)["controller_values_state"] == "not_determined"
    assert _entry(payload, proxy_b)["controllers"] == {"owner": owner_b}
    assert _entry(payload, proxy_b)["controller_values_state"] is None


def test_unattributable_logic_rows_are_not_published_as_no_controllers(db_session):
    s = db_session
    p, impl_c, (proxy_a, proxy_b) = _shared_impl_protocol(s)
    _cv(s, impl_c, "owner", _addr("legacy"))
    s.commit()

    payload = build_company_overview(s, p.name)
    for proxy in (proxy_a, proxy_b):
        entry = _entry(payload, proxy)
        assert (entry["controllers"], entry["controller_reads"]) == ({}, {})
        assert entry["controller_values_state"] == "not_determined"


def test_a_contract_with_no_rows_makes_no_claim(db_session):
    s = db_session
    p, _impl_c, (proxy_a, _proxy_b) = _shared_impl_protocol(s)
    entry = _entry(build_company_overview(s, p.name), proxy_a)
    assert (entry["controllers"], entry["controller_values_state"]) == ({}, None)


def test_secondary_impl_rows_join_only_when_resolved_against_the_proxy(db_session):
    s = db_session
    p, impl_c, (proxy_a, proxy_b) = _shared_impl_protocol(s)
    secondary = _addr("sec")
    proxy_a_row = s.query(Contract).filter(Contract.address == proxy_a).one()
    proxy_a_row.secondary_implementations = [secondary.lower()]
    sec_job = _add_job(
        s, address=secondary, protocol_id=p.id, name="Admin", request={"address": secondary, "proxy_address": proxy_a}
    )
    sec_c = _add_contract(s, address=secondary, job=sec_job, protocol_id=p.id, contract_name="Admin")
    pauser_a, pauser_b = _member(s, p, "psa", "PauserA"), _member(s, p, "psb", "PauserB")
    _cv(s, sec_c, "state_variable:pauser", pauser_a, deployment=proxy_a)
    _cv(s, sec_c, "state_variable:pauser", pauser_b, deployment=proxy_b)
    _cv(s, sec_c, "state_variable:legacyPauser", pauser_b)
    s.commit()

    payload = build_company_overview(s, p.name)
    assert _entry(payload, proxy_a)["controllers"] == {"state_variable:pauser": pauser_a}


def test_a_standalone_contract_publishes_its_own_untagged_rows_only(db_session):
    s = db_session
    p = _add_protocol(s, f"standalone-{uuid.uuid4().hex[:8]}")
    addr = _addr("solo")
    job = _add_job(s, address=addr, protocol_id=p.id, name="Solo")
    solo = _add_contract(s, address=addr, job=job, protocol_id=p.id, contract_name="Solo")
    own_owner, elsewhere = _addr("own"), _addr("else")
    _cv(s, solo, "owner", own_owner)
    _cv(s, solo, "state_variable:guardian", elsewhere, deployment=_addr("other"))
    s.commit()

    entry = _entry(build_company_overview(s, p.name), addr)
    assert entry["controllers"] == {"owner": own_owner.lower()}
    assert entry["owner"] == own_owner.lower()
    assert entry["controller_values_state"] is None


def test_a_standalone_contract_holding_only_other_deployments_rows_is_not_determined(db_session):
    s = db_session
    p = _add_protocol(s, f"standalone-other-{uuid.uuid4().hex[:8]}")
    addr = _addr("solo")
    job = _add_job(s, address=addr, protocol_id=p.id, name="Solo")
    solo = _add_contract(s, address=addr, job=job, protocol_id=p.id, contract_name="Solo")
    _cv(s, solo, "owner", _addr("else"), deployment=_addr("other"))
    s.commit()

    entry = _entry(build_company_overview(s, p.name), addr)
    assert (entry["controllers"], entry["controller_values_state"]) == ({}, "not_determined")


def test_resolved_against_rule():
    proxy, impl = "0x" + "a" * 40, "0x" + "b" * 40
    assert resolved_against(proxy, impl, proxy.upper().replace("0X", "0x"))
    assert not resolved_against("0x" + "c" * 40, impl, proxy)
    assert not resolved_against(None, impl, proxy)
    assert resolved_against(None, proxy, proxy)
    assert not resolved_against(None, proxy, None)
