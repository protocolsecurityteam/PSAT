"""Chain-threading regression tests for the proxy→implementation resolution
layer (``resolve_implementation_contracts`` + its consumers).

PR #157 made the ``/functions`` payload's *output keys* chain-composite, but the
internal proxy→impl linkage (``impl_job_by_entity``, the secondary-impl
suppression set, and the overview dedup) still ran on chainless bare addresses.
Two failure modes on multichain protocols with the same address on ≥2 chains
where one side is an implementation:

  * **Mode 1 (cross-attach)**: an impl address deployed behind a proxy on two
    chains — one chain's impl job wins the bare map, so the other chain's proxy
    gets the winner chain's function verdicts.
  * **Mode 2 (drop-entry)**: a standalone contract on chain B sharing an address
    with a chain-A proxy's secondary impl is swallowed by the chainless
    suppression set → no entry at all.

Each test below fails against the pre-fix bare-address code (verified by forcing
iteration order so the wrong chain wins the bare pick) and passes once the
resolution layer keys by the composite entity token.
"""

from __future__ import annotations

import sys
import uuid
from datetime import datetime, timezone
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[2]))

from services.aggregations.company_overview import (  # noqa: E402
    build_company_overview,
    build_functions_for_protocol,
)
from tests.aggregations.test_company_overview import (  # noqa: E402
    _add_contract,
    _add_job,
    _add_protocol,
    _addr,
)
from tests.aggregations.test_secondary_impl_aggregation import _ef  # noqa: E402
from tests.conftest import requires_postgres  # noqa: E402

pytestmark = requires_postgres


def _newer(job, when=datetime(2030, 1, 1, tzinfo=timezone.utc)):
    """Force a job to be the newest candidate so the bare-address pick (ORDER BY
    updated_at DESC) selects it — the deterministic wrong-chain winner."""
    job.updated_at = when
    job.created_at = when


def test_mode1_cross_attach_functions(db_session):
    """Mode 1 via ``build_functions_for_protocol``: an impl address ``0xI`` sits
    behind a proxy on BOTH ethereum and base (CREATE2 impl twin), each analysed
    with different functions. Each proxy's entry must carry ITS OWN chain's impl
    verdicts.

    Pre-fix: the base impl job (forced newest) wins the bare ``impl_job_by_addr``
    for ``0xI``, so the ethereum proxy's entry carries base's function — fails
    the ``ethOnly`` assertion below.
    """
    s = db_session
    p = _add_protocol(s, f"m1fn-{uuid.uuid4().hex[:8]}")
    proxy_eth = _addr("pxeth")
    proxy_base = _addr("pxbase")
    impl = _addr("impl")  # same impl address on both chains (CREATE2 twin)

    # Ethereum proxy → impl 0xI, impl analysed as a proxy-child on ethereum.
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

    # Base proxy → impl 0xI, impl analysed as a proxy-child on base. Forced newest
    # so the bare-address pick selects it for BOTH proxies.
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
    """Mode 2 via ``build_functions_for_protocol``: an ethereum proxy has a
    SECONDARY impl ``0xI``; base has an unrelated standalone contract at ``0xI``
    with its own functions. The payload must contain BOTH the ethereum proxy
    entry (folding the secondary impl's functions) AND the base standalone entry.

    Pre-fix: ``secondary_impl_addrs`` holds bare ``0xI``, so the base standalone
    is suppressed entirely — ``base::0xI`` never appears.
    """
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

    # Ethereum secondary impl — modelled as a standalone job (old shape), so the
    # aggregation dedupes it into the proxy by (chain, address).
    admin_job = _add_job(s, address=shared, protocol_id=p.id, name="AdminImpl")
    admin_c = _add_contract(s, address=shared, job=admin_job, protocol_id=p.id, chain="ethereum")

    # Base standalone at the same address — unrelated, forced newest so the bare
    # pick would fold IT into the proxy while dropping its own entry.
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
    """Mode 1 via ``build_company_overview``: same twin-impl shape as the
    functions test, asserted on the overview contract entries' ``value_effects``
    (which read from the resolved impl contract).

    Pre-fix: the ethereum proxy resolves to base's impl and surfaces base's
    ``mint`` effect instead of ethereum's ``asset_pull``.
    """
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
    """Mode 2 via ``build_company_overview``: the base standalone sharing an
    address with an ethereum proxy's secondary impl must still render as its own
    contract entry (it is on a different chain).

    Pre-fix: the overview dedup's bare ``impl_addresses`` set drops the base
    standalone because its address matches the ethereum secondary impl.
    """
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
    """Legacy NULL-chain linkage: a NULL-chain impl row must still fold into an
    ethereum proxy's entry (the coalesce makes NULL ≡ ethereum ≡ mainnet, so
    both resolve to the same composite token)."""
    s = db_session
    p = _add_protocol(s, f"nullchain-{uuid.uuid4().hex[:8]}")
    proxy_addr = _addr("px")
    impl = _addr("impl")

    proxy_job = _add_job(s, address=proxy_addr, protocol_id=p.id, is_proxy=True)
    # Proxy contract carries NO chain (legacy row) — coalesces to ethereum.
    _add_contract(
        s, address=proxy_addr, job=proxy_job, protocol_id=p.id, chain=None, is_proxy=True, implementation=impl
    )
    impl_job = _add_job(
        s, address=impl, protocol_id=p.id, name="LegacyImpl", request={"address": impl, "proxy_address": proxy_addr}
    )
    # Impl contract also NULL-chain (legacy).
    impl_c = _add_contract(s, address=impl, job=impl_job, protocol_id=p.id, chain=None)
    _ef(s, impl_c, "legacyFn", effect_labels=["pause_toggle"])
    s.commit()

    funcs = build_functions_for_protocol(s, p.name)
    proxy_fns = {f["function"] for f in funcs.get(f"ethereum::{proxy_addr.lower()}", [])}
    assert "legacyFn()" in proxy_fns, f"NULL-chain impl must fold into the ethereum proxy entry, got {proxy_fns}"
    assert f"ethereum::{impl.lower()}" not in funcs, "NULL-chain impl must not also render standalone"
