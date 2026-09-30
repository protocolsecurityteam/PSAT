"""Proxy -> implementation resolution must key by the composite entity token, not a bare address.

Mode 1 (cross-attach): an impl behind a proxy on two chains gave one chain's verdicts to both proxies.
Mode 2 (drop-entry): a chain-B standalone sharing an address with a chain-A secondary impl was swallowed.
"""

from __future__ import annotations

import uuid
from datetime import datetime, timezone

from db.models import FunctionPrincipal
from services.aggregations.company_overview import (
    all_addresses_for_protocol,
    build_company_overview,
    build_functions_for_protocol,
)
from tests.aggregations.test_company_overview import (
    _add_contract,
    _add_job,
    _add_protocol,
    _addr,
)
from tests.aggregations.test_secondary_impl_aggregation import _ef
from tests.conftest import requires_postgres

pytestmark = requires_postgres


def _newer(job, when=datetime(2030, 1, 1, tzinfo=timezone.utc)):
    """Force the deterministic wrong-chain winner of the bare-address pick (ORDER BY updated_at DESC)."""
    job.updated_at = when
    job.created_at = when


def test_mode1_cross_attach_functions(db_session):
    s = db_session
    p = _add_protocol(s, f"m1fn-{uuid.uuid4().hex[:8]}")
    proxy_eth = _addr("pxeth")
    proxy_base = _addr("pxbase")
    impl = _addr("impl")  # same impl address on both chains (CREATE2 twin)

    proxy_eth_job = _add_job(s, address=proxy_eth, protocol_id=p.id, is_proxy=True)
    _add_contract(
        s, address=proxy_eth, job=proxy_eth_job, protocol_id=p.id, chain="ethereum", is_proxy=True, implementation=impl
    )
    eth_impl_job = _add_job(
        s,
        address=impl,
        protocol_id=p.id,
        name="EthImpl",
        request={"address": impl, "proxy_address": proxy_eth},
    )
    eth_impl_c = _add_contract(s, address=impl, job=eth_impl_job, protocol_id=p.id, chain="ethereum")

    # Forced newest so the bare-address pick selects it for both proxies.
    proxy_base_job = _add_job(
        s, address=proxy_base, protocol_id=p.id, is_proxy=True, request={"address": proxy_base, "chain": "base"}
    )
    _add_contract(
        s, address=proxy_base, job=proxy_base_job, protocol_id=p.id, chain="base", is_proxy=True, implementation=impl
    )
    base_impl_job = _add_job(
        s,
        address=impl,
        protocol_id=p.id,
        name="BaseImpl",
        request={"address": impl, "proxy_address": proxy_base, "chain": "base"},
    )
    _newer(base_impl_job)
    base_impl_c = _add_contract(s, address=impl, job=base_impl_job, protocol_id=p.id, chain="base")

    _ef(s, eth_impl_c, "ethOnly", effect_labels=["pause_toggle"])
    _ef(s, base_impl_c, "baseOnly", effect_labels=["pause_toggle"])
    s.commit()

    funcs = build_functions_for_protocol(s, p.name)
    eth_fns = {f["function"] for f in funcs.get(f"ethereum::{proxy_eth.lower()}", [])}
    base_fns = {f["function"] for f in funcs.get(f"base::{proxy_base.lower()}", [])}

    assert "ethOnly()" in eth_fns and "baseOnly()" not in eth_fns, (
        f"ethereum proxy must carry ethereum impl verdicts, got {eth_fns}"
    )
    assert "baseOnly()" in base_fns and "ethOnly()" not in base_fns, (
        f"base proxy must carry base impl verdicts, got {base_fns}"
    )


def test_mode2_drop_entry_functions(db_session):
    s = db_session
    p = _add_protocol(s, f"m2fn-{uuid.uuid4().hex[:8]}")
    proxy_eth = _addr("pxeth")
    core = _addr("core")  # EIP-1967 primary impl
    shared = _addr("shared")  # secondary impl on eth; standalone on base

    proxy_job = _add_job(s, address=proxy_eth, protocol_id=p.id, is_proxy=True)
    proxy_c = _add_contract(
        s, address=proxy_eth, job=proxy_job, protocol_id=p.id, chain="ethereum", is_proxy=True, implementation=core
    )
    proxy_c.proxy_type = "eip1967"
    proxy_c.secondary_implementations = [shared.lower()]
    s.commit()

    core_job = _add_job(
        s, address=core, protocol_id=p.id, name="Core", request={"address": core, "proxy_address": proxy_eth}
    )
    core_c = _add_contract(s, address=core, job=core_job, protocol_id=p.id, chain="ethereum")

    # Modelled as a standalone job (the old shape), which the aggregation dedupes into the proxy.
    admin_job = _add_job(s, address=shared, protocol_id=p.id, name="AdminImpl")
    admin_c = _add_contract(s, address=shared, job=admin_job, protocol_id=p.id, chain="ethereum")

    # Forced newest so a bare pick would fold it into the proxy and drop its own entry.
    base_job = _add_job(
        s, address=shared, protocol_id=p.id, name="BaseStandalone", request={"address": shared, "chain": "base"}
    )
    _newer(base_job)
    base_c = _add_contract(s, address=shared, job=base_job, protocol_id=p.id, chain="base")

    _ef(s, core_c, "coreFn", effect_labels=["asset_pull"])
    _ef(s, admin_c, "adminFn", effect_labels=["pause_toggle"])
    _ef(s, base_c, "baseFn", effect_labels=["mint"])
    s.commit()

    funcs = build_functions_for_protocol(s, p.name)
    proxy_fns = {f["function"] for f in funcs.get(f"ethereum::{proxy_eth.lower()}", [])}
    base_fns = {f["function"] for f in funcs.get(f"base::{shared.lower()}", [])}

    assert f"base::{shared.lower()}" in funcs, "base standalone at a secondary-impl twin address must not be suppressed"
    assert "baseFn()" in base_fns, f"base standalone must carry its own function, got {base_fns}"
    assert {"coreFn()", "adminFn()"} <= proxy_fns, (
        f"ethereum proxy must fold its own core+admin impl functions, got {proxy_fns}"
    )
    assert "baseFn()" not in proxy_fns, "base standalone's function must not cross-attach to the ethereum proxy"


def test_mode1_cross_attach_overview(db_session):
    s = db_session
    p = _add_protocol(s, f"m1ov-{uuid.uuid4().hex[:8]}")
    proxy_eth = _addr("pxeth")
    proxy_base = _addr("pxbase")
    impl = _addr("impl")

    proxy_eth_job = _add_job(s, address=proxy_eth, protocol_id=p.id, is_proxy=True)
    _add_contract(
        s, address=proxy_eth, job=proxy_eth_job, protocol_id=p.id, chain="ethereum", is_proxy=True, implementation=impl
    )
    eth_impl_job = _add_job(
        s, address=impl, protocol_id=p.id, name="EthImpl", request={"address": impl, "proxy_address": proxy_eth}
    )
    eth_impl_c = _add_contract(s, address=impl, job=eth_impl_job, protocol_id=p.id, chain="ethereum")

    proxy_base_job = _add_job(
        s, address=proxy_base, protocol_id=p.id, is_proxy=True, request={"address": proxy_base, "chain": "base"}
    )
    _add_contract(
        s, address=proxy_base, job=proxy_base_job, protocol_id=p.id, chain="base", is_proxy=True, implementation=impl
    )
    base_impl_job = _add_job(
        s,
        address=impl,
        protocol_id=p.id,
        name="BaseImpl",
        request={"address": impl, "proxy_address": proxy_base, "chain": "base"},
    )
    _newer(base_impl_job)
    base_impl_c = _add_contract(s, address=impl, job=base_impl_job, protocol_id=p.id, chain="base")

    _ef(s, eth_impl_c, "deposit", effect_labels=["asset_pull"])
    _ef(s, base_impl_c, "wrap", effect_labels=["mint"])
    s.commit()

    overview = build_company_overview(s, p.name)
    by_addr = {c["address"].lower(): c for c in overview["contracts"]}
    eth_entry = by_addr[proxy_eth.lower()]
    base_entry = by_addr[proxy_base.lower()]

    assert "asset_pull" in eth_entry["value_effects"] and "mint" not in eth_entry["value_effects"], (
        f"ethereum proxy must surface ethereum impl effects, got {eth_entry['value_effects']}"
    )
    assert "mint" in base_entry["value_effects"] and "asset_pull" not in base_entry["value_effects"], (
        f"base proxy must surface base impl effects, got {base_entry['value_effects']}"
    )


def test_mode2_drop_entry_overview(db_session):
    s = db_session
    p = _add_protocol(s, f"m2ov-{uuid.uuid4().hex[:8]}")
    proxy_eth = _addr("pxeth")
    core = _addr("core")
    shared = _addr("shared")

    proxy_job = _add_job(s, address=proxy_eth, protocol_id=p.id, is_proxy=True)
    proxy_c = _add_contract(
        s, address=proxy_eth, job=proxy_job, protocol_id=p.id, chain="ethereum", is_proxy=True, implementation=core
    )
    proxy_c.proxy_type = "eip1967"
    proxy_c.secondary_implementations = [shared.lower()]
    s.commit()

    core_job = _add_job(
        s, address=core, protocol_id=p.id, name="Core", request={"address": core, "proxy_address": proxy_eth}
    )
    _add_contract(s, address=core, job=core_job, protocol_id=p.id, chain="ethereum")

    admin_job = _add_job(s, address=shared, protocol_id=p.id, name="AdminImpl")
    _add_contract(s, address=shared, job=admin_job, protocol_id=p.id, chain="ethereum")

    base_job = _add_job(
        s, address=shared, protocol_id=p.id, name="BaseStandalone", request={"address": shared, "chain": "base"}
    )
    _newer(base_job)
    base_c = _add_contract(s, address=shared, job=base_job, protocol_id=p.id, chain="base")
    _ef(s, base_c, "baseFn", effect_labels=["mint"])
    s.commit()

    overview = build_company_overview(s, p.name)
    rendered = {(c["address"].lower(), (c.get("chain") or "").lower()) for c in overview["contracts"]}

    assert (shared.lower(), "base") in rendered, (
        "base standalone must render (not deduped by an eth secondary-impl twin)"
    )
    assert (shared.lower(), "ethereum") not in rendered, (
        "the ethereum secondary impl must still collapse into the proxy"
    )
    assert proxy_eth.lower() in {a for a, _ in rendered}


def test_nullchain_linkage_preserved(db_session):
    """NULL chain coalesces to ethereum, so both rows resolve to the same composite token."""
    s = db_session
    p = _add_protocol(s, f"nullchain-{uuid.uuid4().hex[:8]}")
    proxy_addr = _addr("px")
    impl = _addr("impl")

    proxy_job = _add_job(s, address=proxy_addr, protocol_id=p.id, is_proxy=True)
    _add_contract(
        s, address=proxy_addr, job=proxy_job, protocol_id=p.id, chain=None, is_proxy=True, implementation=impl
    )
    impl_job = _add_job(
        s, address=impl, protocol_id=p.id, name="LegacyImpl", request={"address": impl, "proxy_address": proxy_addr}
    )
    impl_c = _add_contract(s, address=impl, job=impl_job, protocol_id=p.id, chain=None)
    _ef(s, impl_c, "legacyFn", effect_labels=["pause_toggle"])
    s.commit()

    funcs = build_functions_for_protocol(s, p.name)
    proxy_fns = {f["function"] for f in funcs.get(f"ethereum::{proxy_addr.lower()}", [])}
    assert "legacyFn()" in proxy_fns, f"NULL-chain impl must fold into the ethereum proxy entry, got {proxy_fns}"
    assert f"ethereum::{impl.lower()}" not in funcs, "NULL-chain impl must not also render standalone"


def _fp_safe(session, ef, safe_addr):
    session.add(
        FunctionPrincipal(
            function_id=ef.id,
            address=safe_addr,
            resolved_type="safe",
            origin="governor",
            principal_type="authority_role",
            details={"owners": [_addr("owner")], "threshold": 1},
        )
    )


def test_f1_controller_attribution_no_cross_chain_fold(db_session):
    """Controller attribution must resolve the impl on the proxy's own chain."""
    s = db_session
    p = _add_protocol(s, f"f1-{uuid.uuid4().hex[:8]}")
    proxy_eth = _addr("pxeth")
    impl = _addr("impl")
    eth_safe = _addr("ethsafe")
    base_safe = _addr("basesafe")

    proxy_job = _add_job(s, address=proxy_eth, protocol_id=p.id, is_proxy=True)
    _add_contract(
        s, address=proxy_eth, job=proxy_job, protocol_id=p.id, chain="ethereum", is_proxy=True, implementation=impl
    )
    eth_impl_job = _add_job(
        s, address=impl, protocol_id=p.id, name="EthImpl", request={"address": impl, "proxy_address": proxy_eth}
    )
    eth_impl_c = _add_contract(s, address=impl, job=eth_impl_job, protocol_id=p.id, chain="ethereum")
    eth_ef = _ef(s, eth_impl_c, "ethGov", effect_labels=["pause_toggle"])
    _fp_safe(s, eth_ef, eth_safe)

    base_job = _add_job(
        s, address=impl, protocol_id=p.id, name="BaseStandalone", request={"address": impl, "chain": "base"}
    )
    _newer(base_job)
    base_c = _add_contract(s, address=impl, job=base_job, protocol_id=p.id, chain="base")
    base_ef = _ef(s, base_c, "baseGov", effect_labels=["pause_toggle"])
    _fp_safe(s, base_ef, base_safe)
    s.commit()

    overview = build_company_overview(s, p.name)
    principals = {(pr.get("address") or "").lower(): pr for pr in overview["principals"]}

    assert base_safe.lower() in principals, "base standalone's Safe must surface as a principal"
    base_attr = set(principals[base_safe.lower()].get("primary_for") or []) | set(
        principals[base_safe.lower()].get("co_controls") or []
    )
    assert proxy_eth.lower() not in {a.lower() for a in base_attr}, (
        f"base standalone's Safe must NOT govern the ethereum proxy (cross-chain fold), got {base_attr}"
    )
    assert impl.lower() in {a.lower() for a in base_attr}, "base Safe must govern the base standalone (0xI)"
    eth_attr = {a.lower() for a in (principals.get(eth_safe.lower(), {}).get("primary_for") or [])}
    assert proxy_eth.lower() in eth_attr, "ethereum Safe must govern the ethereum proxy"


def test_f3_implementation_name_chain_scoped(db_session):
    s = db_session
    p = _add_protocol(s, f"f3-{uuid.uuid4().hex[:8]}")
    proxy_eth = _addr("pxeth")
    proxy_base = _addr("pxbase")
    impl = _addr("impl")

    proxy_eth_job = _add_job(s, address=proxy_eth, protocol_id=p.id, is_proxy=True)
    _add_contract(
        s,
        address=proxy_eth,
        job=proxy_eth_job,
        protocol_id=p.id,
        chain="ethereum",
        is_proxy=True,
        implementation=impl,
        contract_name="EthProxy",
    )
    eth_impl_job = _add_job(s, address=impl, protocol_id=p.id, request={"address": impl, "proxy_address": proxy_eth})
    _add_contract(s, address=impl, job=eth_impl_job, protocol_id=p.id, chain="ethereum", contract_name="EthImplName")

    proxy_base_job = _add_job(
        s, address=proxy_base, protocol_id=p.id, is_proxy=True, request={"address": proxy_base, "chain": "base"}
    )
    _add_contract(
        s,
        address=proxy_base,
        job=proxy_base_job,
        protocol_id=p.id,
        chain="base",
        is_proxy=True,
        implementation=impl,
        contract_name="BaseProxy",
    )
    base_impl_job = _add_job(
        s, address=impl, protocol_id=p.id, request={"address": impl, "proxy_address": proxy_base, "chain": "base"}
    )
    _add_contract(s, address=impl, job=base_impl_job, protocol_id=p.id, chain="base", contract_name="BaseImplName")
    s.commit()

    rows = all_addresses_for_protocol(s, p)
    by_key = {(r["address"].lower(), (r.get("chain") or "").lower()): r for r in rows}
    eth_row = by_key[(proxy_eth.lower(), "ethereum")]
    base_row = by_key[(proxy_base.lower(), "base")]

    assert eth_row["implementation_name"] == "EthImplName", (
        f"ethereum proxy must show its own impl name, got {eth_row['implementation_name']}"
    )
    assert base_row["implementation_name"] == "BaseImplName", (
        f"base proxy must show its own impl name, got {base_row['implementation_name']}"
    )
