"""Aggregation regression tests for split-proxy secondary impls (1A) + the
deterministic impl-job pick (1C).

Mirrors the real ether.fi LRTSquared shape on a real test Postgres: a UUPSProxy
whose EIP-1967 impl is ``LRTSquaredCore`` and whose split-proxy *secondary* impl
is ``LRTSquaredAdmin`` (recorded in ``Contract.secondary_implementations``). The
admin impl holds ``setPauser`` gated by a governor Safe.

Before the fix the admin impl rendered as a standalone ownerless node and its
functions never attributed to the proxy. After the fix the proxy node absorbs
the admin impl: no standalone node, both impls' functions surface on the proxy,
and the governor Safe resolves as the proxy's controller.
"""

from __future__ import annotations

import sys
import uuid
from datetime import datetime, timezone
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[2]))

from db.models import ControlGraphNode, EffectiveFunction, FunctionPrincipal  # noqa: E402
from services.aggregations.company_overview import (  # noqa: E402
    build_company_overview,
    build_functions_for_protocol,
    prefetch_contracts,
    resolve_implementation_contracts,
)
from tests.aggregations.test_company_overview import (  # noqa: E402
    _add_contract,
    _add_job,
    _add_protocol,
    _addr,
)
from tests.conftest import requires_postgres  # noqa: E402

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
    """The split-proxy admin impl is absorbed into the proxy node: not rendered
    standalone, its functions surface on the proxy, and the governor Safe (which
    only gates the admin impl's functions) controls the proxy."""
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

    # Core impl — analysed as a proxy-child job (proxy_address set).
    core_job = _add_job(
        s,
        address=core_addr,
        protocol_id=p.id,
        name="LRTSquaredCore",
        request={"address": core_addr, "proxy_address": proxy_addr},
    )
    core_c = _add_contract(s, address=core_addr, job=core_job, protocol_id=p.id, contract_name="LRTSquaredCore")

    # Admin secondary impl — modelled the OLD way: a standalone job (NO
    # proxy_address), which the aggregation must now dedupe out by address.
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
    # 1A: admin secondary impl is NOT a standalone node; core impl is collapsed;
    # the proxy IS rendered.
    assert admin_addr.lower() not in rendered, "split-proxy admin impl must not render standalone"
    assert core_addr.lower() not in rendered, "EIP-1967 impl must collapse into the proxy"
    assert proxy_addr.lower() in rendered

    # The proxy entry advertises its secondary impl.
    proxy_entry = next(c for c in overview["contracts"] if c["address"].lower() == proxy_addr.lower())
    assert admin_addr.lower() in [a.lower() for a in proxy_entry.get("secondary_implementations", [])]

    # The governor Safe surfaces as a principal and controls the proxy (its
    # authority over the admin impl's setPauser maps up to the proxy node).
    gov = next((pr for pr in overview["principals"] if (pr.get("address") or "").lower() == governor.lower()), None)
    assert gov is not None, "governor Safe (gates the admin impl) must surface as a principal"
    assert proxy_addr.lower() in [a.lower() for a in gov.get("primary_for", [])]

    # Functions payload: the proxy exposes BOTH the impl's and the secondary
    # impl's functions; the admin address has no separate entry.
    funcs = build_functions_for_protocol(s, p.name)
    proxy_fns = {f["function"] for f in funcs.get(proxy_addr, [])}
    assert {"deposit()", "setPauser()"} <= proxy_fns
    assert admin_addr not in funcs


def test_secondary_impl_fp_all_addrs_folds_into_primary_gate(db_session):
    """A governor that gates only the SECONDARY impl's functions, carried on a
    FunctionPrincipal row with resolved_type NULL, must still surface as a
    principal of the proxy.

    resolved_type=NULL is deliberate and load-bearing: a ``safe`` FP row would
    surface vacuously through the third-pass ``fp_governance`` backstop (which
    filters resolved_type at query time), masking the gate. With NULL, the only
    path to the surface is the second-pass CGN gate at
    ``_build_flows_and_principals`` (``node_addr in fp_all_addrs_by_cid[primary]``)
    — which admits the address only once the secondary impl's ``fp_all_addrs`` is
    folded into the primary-impl bucket. The safe-typed identity comes from a
    ControlGraphNode on the PRIMARY impl (cgn_by_cid is not folded). Reverting
    the fold drops the principal, so this pins the fold, not the backstop."""
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
    # The FP row lives on the SECONDARY impl with resolved_type NULL (so the
    # fp_governance third pass excludes it) — it enters fp_all_addrs only.
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
    # The safe-typed identity is a ControlGraphNode on the PRIMARY impl.
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
    # controls_detail must be non-empty (structural: a gate-admitted addr carries FP rows).
    assert principals[safe.lower()].get("controls_detail"), "surfaced principal must carry controls_detail"


def test_resolve_implementation_contracts_deterministic_pick(db_session):
    """1C: with >1 completed job for an impl address, the proxy-linked job is
    chosen deterministically (not arbitrarily). Pins the ORDER BY +
    linked-preference fix."""
    s = db_session
    p = _add_protocol(s, f"detpick-{uuid.uuid4().hex[:8]}")
    proxy_addr = _addr("px")
    impl_addr = _addr("im")

    proxy_job = _add_job(s, address=proxy_addr, protocol_id=p.id, is_proxy=True)
    _add_contract(s, address=proxy_addr, job=proxy_job, protocol_id=p.id, is_proxy=True, implementation=impl_addr)

    # An OLDER job linked to the proxy (request.proxy_address) and a NEWER but
    # UNLINKED job at the same impl address. Linked preference must win even
    # though it is older — and the choice must be deterministic.
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
    impl_job_by_addr, _ = resolve_implementation_contracts(s, jobs, cbj)
    assert impl_job_by_addr[impl_addr.lower()].id == linked_job.id
