"""Mirrors ether.fi LRTSquared: a UUPSProxy whose split-proxy secondary impl holds a Safe-gated ``setPauser``."""

from __future__ import annotations

import uuid
from datetime import datetime, timezone

from db.models import ControlGraphNode, EffectiveFunction, FunctionPrincipal
from services.aggregations.company_overview import (
    _entity_key,
    build_company_overview,
    build_functions_for_protocol,
    prefetch_contracts,
    resolve_implementation_contracts,
)
from tests.aggregations.test_company_overview import (
    _add_contract,
    _add_job,
    _add_protocol,
    _addr,
)
from tests.conftest import requires_postgres

pytestmark = requires_postgres


def _ef(session, contract, fname, *, effect_labels=None):
    ef = EffectiveFunction(
        contract_id=contract.id,
        function_name=fname,
        selector="0x" + uuid.uuid4().hex[:8],
        abi_signature=f"{fname}()",
        effect_labels=effect_labels or [],
        effect_targets=[],
        action_summary=fname,
        authority_public=False,
        authority_roles=[],
    )
    session.add(ef)
    session.flush()
    return ef


def test_secondary_impl_absorbed_into_proxy(db_session):
    s = db_session
    p = _add_protocol(s, f"lrt-{uuid.uuid4().hex[:8]}")
    proxy_addr = _addr("px")
    core_addr = _addr("core")
    admin_addr = _addr("admin")
    governor = _addr("gov")  # external Safe, not a protocol contract

    proxy_job = _add_job(s, address=proxy_addr, protocol_id=p.id, name="UUPSProxy")
    proxy_c = _add_contract(
        s,
        address=proxy_addr,
        job=proxy_job,
        protocol_id=p.id,
        is_proxy=True,
        implementation=core_addr,
        contract_name="UUPSProxy",
    )
    proxy_c.proxy_type = "eip1967"
    proxy_c.secondary_implementations = [admin_addr.lower()]
    s.commit()

    core_job = _add_job(
        s,
        address=core_addr,
        protocol_id=p.id,
        name="LRTSquaredCore",
        request={"address": core_addr, "proxy_address": proxy_addr},
    )
    core_c = _add_contract(s, address=core_addr, job=core_job, protocol_id=p.id, contract_name="LRTSquaredCore")

    # Modelled the old way (no proxy_address); the aggregation must dedupe it out by address.
    admin_job = _add_job(s, address=admin_addr, protocol_id=p.id, name="LRTSquaredAdmin")
    admin_c = _add_contract(s, address=admin_addr, job=admin_job, protocol_id=p.id, contract_name="LRTSquaredAdmin")

    _ef(s, core_c, "deposit", effect_labels=["asset_pull"])
    set_pauser = _ef(s, admin_c, "setPauser", effect_labels=["pause_toggle"])
    s.add(
        FunctionPrincipal(
            function_id=set_pauser.id,
            address=governor,
            resolved_type="safe",
            origin="governor",
            principal_type="authority_role",
            details={"owners": [_addr("o1")], "threshold": 1},
        )
    )
    s.commit()

    overview = build_company_overview(s, p.name)
    rendered = {c["address"].lower() for c in overview["contracts"]}
    assert admin_addr.lower() not in rendered, "split-proxy admin impl must not render standalone"
    assert core_addr.lower() not in rendered, "EIP-1967 impl must collapse into the proxy"
    assert proxy_addr.lower() in rendered

    proxy_entry = next(c for c in overview["contracts"] if c["address"].lower() == proxy_addr.lower())
    assert admin_addr.lower() in [a.lower() for a in proxy_entry.get("secondary_implementations", [])]

    # The Safe only gates the admin impl's function, which maps up to the proxy.
    gov = next((pr for pr in overview["principals"] if (pr.get("address") or "").lower() == governor.lower()), None)
    assert gov is not None, "governor Safe (gates the admin impl) must surface as a principal"
    assert proxy_addr.lower() in [a.lower() for a in gov.get("primary_for", [])]

    funcs = build_functions_for_protocol(s, p.name)
    proxy_fns = {f["function"] for f in funcs.get(f"ethereum::{proxy_addr.lower()}", [])}
    assert {"deposit()", "setPauser()"} <= proxy_fns
    assert f"ethereum::{admin_addr.lower()}" not in funcs


def test_secondary_impl_fp_all_addrs_folds_into_primary_gate(db_session):
    """resolved_type=NULL is load-bearing: a ``safe`` FP row would surface through the fp_governance backstop
    instead. With NULL the only path is the second-pass CGN gate, which admits the address only once the
    secondary impl's ``fp_all_addrs`` is folded into the primary bucket. This pins the fold.
    """
    s = db_session
    p = _add_protocol(s, f"fpfold-{uuid.uuid4().hex[:8]}")
    proxy_addr = _addr("px")
    core_addr = _addr("core")
    admin_addr = _addr("admin")
    safe = _addr("safe")  # external Safe: gates only the admin impl's fn

    proxy_job = _add_job(s, address=proxy_addr, protocol_id=p.id, name="UUPSProxy")
    proxy_c = _add_contract(
        s,
        address=proxy_addr,
        job=proxy_job,
        protocol_id=p.id,
        is_proxy=True,
        implementation=core_addr,
        contract_name="UUPSProxy",
    )
    proxy_c.proxy_type = "eip1967"
    proxy_c.secondary_implementations = [admin_addr.lower()]
    s.commit()

    core_job = _add_job(
        s,
        address=core_addr,
        protocol_id=p.id,
        name="Core",
        request={"address": core_addr, "proxy_address": proxy_addr},
    )
    core_c = _add_contract(s, address=core_addr, job=core_job, protocol_id=p.id, contract_name="Core")

    admin_job = _add_job(s, address=admin_addr, protocol_id=p.id, name="Admin")
    admin_c = _add_contract(s, address=admin_addr, job=admin_job, protocol_id=p.id, contract_name="Admin")

    _ef(s, core_c, "deposit", effect_labels=["asset_pull"])
    set_pauser = _ef(s, admin_c, "setPauser", effect_labels=["pause_toggle"])
    s.add(
        FunctionPrincipal(
            function_id=set_pauser.id,
            address=safe,
            resolved_type=None,
            origin="acl",
            principal_type="authority_role",
            details={"owners": [_addr("o1")], "threshold": 1},
        )
    )
    s.add(
        ControlGraphNode(
            contract_id=core_c.id,
            address=safe.lower(),
            node_type="contract",
            resolved_type="safe",
            label="GovSafe",
            details={"owners": [_addr("o1")], "threshold": 1},
        )
    )
    s.commit()

    overview = build_company_overview(s, p.name)
    principals = {(pr.get("address") or "").lower(): pr for pr in overview["principals"]}
    assert safe.lower() in principals, (
        "governor gating only the secondary impl (FP resolved_type NULL) must surface "
        "via the folded fp_all_addrs primary-impl gate"
    )
    assert proxy_addr.lower() in [a.lower() for a in principals[safe.lower()].get("controls", [])]
    assert principals[safe.lower()].get("controls_detail"), "surfaced principal must carry controls_detail"


def test_resolve_implementation_contracts_deterministic_pick(db_session):
    """1C: with more than one completed job for an impl address, the proxy-linked job wins deterministically."""
    s = db_session
    p = _add_protocol(s, f"detpick-{uuid.uuid4().hex[:8]}")
    proxy_addr = _addr("px")
    impl_addr = _addr("im")

    proxy_job = _add_job(s, address=proxy_addr, protocol_id=p.id, is_proxy=True)
    _add_contract(s, address=proxy_addr, job=proxy_job, protocol_id=p.id, is_proxy=True, implementation=impl_addr)

    # Linked preference must beat a newer unlinked job.
    linked_job = _add_job(
        s,
        address=impl_addr,
        protocol_id=p.id,
        name="linked",
        request={"address": impl_addr, "proxy_address": proxy_addr},
    )
    linked_job.updated_at = datetime(2020, 1, 1, tzinfo=timezone.utc)
    linked_job.created_at = datetime(2020, 1, 1, tzinfo=timezone.utc)
    unlinked_job = _add_job(s, address=impl_addr, protocol_id=p.id, name="unlinked")
    unlinked_job.updated_at = datetime(2024, 1, 1, tzinfo=timezone.utc)
    _add_contract(s, address=impl_addr, job=linked_job, protocol_id=p.id, contract_name="Impl")
    s.commit()

    jobs = [proxy_job, linked_job, unlinked_job]
    cbj = prefetch_contracts(s, jobs)
    impl_job_by_entity, _ = resolve_implementation_contracts(s, jobs, cbj)
    assert impl_job_by_entity[_entity_key("ethereum", impl_addr)].id == linked_job.id
