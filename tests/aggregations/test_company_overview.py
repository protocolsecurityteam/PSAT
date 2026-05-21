"""Integration tests for ``services.aggregations.company_overview``.

Hits a real Postgres via ``db_session`` so the resolver code paths
(legacy company fallback, address/chain Contract fallback, impl
resolution) actually exercise the SQLAlchemy queries.
"""

from __future__ import annotations

import sys
import uuid
from datetime import datetime, timezone
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[2]))

from sqlalchemy import select  # noqa: E402

from db.models import (  # noqa: E402
    Contract,
    ContractBalance,
    ControlGraphEdge,
    ControlGraphNode,
    ControllerValue,
    EffectiveFunction,
    FunctionPrincipal,
    Job,
    JobStage,
    JobStatus,
    Protocol,
    UpgradeEvent,
)
from services.aggregations.company_overview import (  # noqa: E402
    CompanyNotFound,
    _build_principal_lookup,
    _prefetch_child_tables,
    _principal_lookup_meta,
    _trim_control_graph,
    build_company_overview,
    build_functions_for_protocol,
    prefetch_contracts,
    resolve_company_jobs,
    resolve_implementation_contracts,
)
from tests.conftest import requires_postgres  # noqa: E402

pytestmark = requires_postgres


def _addr(seed: str) -> str:
    """Deterministic-but-test-unique 0x address keyed by ``seed``.

    The conftest db_session fixture cleans up Protocol but not Contract or
    Job rows (they have ON DELETE SET NULL). Hardcoding addresses across
    tests collides on uq_contract_address_chain — UUID-derive instead.
    """
    return "0x" + (uuid.uuid4().hex + seed.encode().hex())[:40]


def _add_protocol(session, name: str) -> Protocol:
    p = Protocol(name=name)
    session.add(p)
    session.commit()
    session.refresh(p)
    return p


def _add_job(
    session,
    *,
    address: str,
    name: str | None = None,
    company: str | None = None,
    protocol_id: int | None = None,
    status: JobStatus = JobStatus.completed,
    request: dict | None = None,
    is_proxy: bool = False,
) -> Job:
    job = Job(
        id=uuid.uuid4(),
        address=address,
        company=company,
        protocol_id=protocol_id,
        name=name or address,
        status=status,
        stage=JobStage.done,
        request=request or {"address": address},
        is_proxy=is_proxy,
        created_at=datetime.now(timezone.utc),
        updated_at=datetime.now(timezone.utc),
    )
    session.add(job)
    session.commit()
    session.refresh(job)
    return job


def _add_contract(
    session,
    *,
    address: str,
    job: Job,
    protocol_id: int | None = None,
    chain: str = "ethereum",
    is_proxy: bool = False,
    implementation: str | None = None,
    contract_name: str | None = None,
) -> Contract:
    c = Contract(
        address=address,
        job_id=job.id,
        protocol_id=protocol_id,
        chain=chain,
        contract_name=contract_name or address,
        is_proxy=is_proxy,
        implementation=implementation,
    )
    session.add(c)
    session.commit()
    session.refresh(c)
    return c


def test_resolve_company_jobs_protocol_path(db_session):
    """Modern data: Protocol row exists, jobs carry ``protocol_id``, AND
    the analyzed subject has a Contract row whose ``protocol_id`` matches.

    The Contract row is the authoritative ownership signal (gated by
    services/discovery/source_confidence on every write); ``Job.protocol_id``
    alone is insufficient because dependency-expansion jobs inherit
    protocol_id from their parent without proving ownership.
    """
    p = _add_protocol(db_session, f"alpha-{uuid.uuid4().hex[:8]}")
    addr_a1 = _addr("a1")
    j1 = _add_job(db_session, address=addr_a1, protocol_id=p.id)
    _add_contract(db_session, address=addr_a1, job=j1, protocol_id=p.id, contract_name="A1")
    _add_job(db_session, address=_addr("a2"), protocol_id=p.id, status=JobStatus.queued)

    protocol, jobs = resolve_company_jobs(db_session, p.name)
    assert protocol is not None and protocol.id == p.id
    # Only completed + has-address + has owned-Contract jobs are returned
    assert {j.id for j in jobs} == {j1.id}


def test_resolve_company_jobs_excludes_orphan_contracts(db_session):
    """Regression for the surface-page leak: an analyzed job whose subject
    Contract row is orphan (protocol_id=NULL) must NOT show under the
    protocol — even when the job itself carries protocol_id.

    Repro: static analysis of a confirmed etherfi contract spawns a
    dependency-expansion job for WstETH; the job inherits
    protocol_id=etherfi from its parent, but the WstETH Contract row
    stays orphan (only dapp_crawl as a source) because the discovery-
    source gate refuses to stamp ownership from a low-confidence signal.
    Pre-fix, the surface page joined on Job.protocol_id and rendered
    WstETH as an etherfi contract.
    """
    p = _add_protocol(db_session, f"orphan-{uuid.uuid4().hex[:8]}")
    owned_addr = _addr("aa")
    orphan_addr = _addr("bb")

    j_owned = _add_job(db_session, address=owned_addr, protocol_id=p.id)
    _add_contract(db_session, address=owned_addr, job=j_owned, protocol_id=p.id, contract_name="Owned")

    # Dependency-expansion shape: job has protocol_id, Contract does not.
    j_orphan = _add_job(db_session, address=orphan_addr, protocol_id=p.id)
    _add_contract(db_session, address=orphan_addr, job=j_orphan, protocol_id=None, contract_name="WstETH")

    _protocol, jobs = resolve_company_jobs(db_session, p.name)
    assert {j.id for j in jobs} == {j_owned.id}, (
        "orphan Contract leaked into resolve_company_jobs — the surface page "
        "would render the dependency as a protocol contract"
    )


def test_resolve_company_jobs_legacy_fallback_with_parent_chain(db_session):
    """Legacy data: no Protocol row. Parent → child via ``parent_job_id``."""
    company = f"legacy-{uuid.uuid4().hex[:8]}"
    parent_addr = _addr("p")
    child_addr = _addr("c")
    parent = _add_job(db_session, address=parent_addr, company=company, name="parent")
    child = _add_job(
        db_session,
        address=child_addr,
        name="child",
        request={"address": child_addr, "parent_job_id": str(parent.id)},
    )
    # Unrelated job — should NOT be included.
    _add_job(db_session, address=_addr("o"), name="other")

    protocol, jobs = resolve_company_jobs(db_session, company)
    assert protocol is None
    assert {j.id for j in jobs} == {parent.id, child.id}


def test_resolve_company_jobs_unknown_returns_empty(db_session):
    protocol, jobs = resolve_company_jobs(db_session, f"missing-{uuid.uuid4().hex[:8]}")
    assert protocol is None
    assert jobs == []


def test_prefetch_contracts_address_chain_fallback(db_session):
    """When a Contract row has been re-keyed to a newer job, the address+chain
    fallback locates it for the original requesting job."""
    p = _add_protocol(db_session, f"fallback-{uuid.uuid4().hex[:8]}")
    addr = _addr("d")
    original = _add_job(db_session, address=addr, protocol_id=p.id)
    newer = _add_job(db_session, address=addr, protocol_id=p.id)
    # Contract row is keyed to the newer job — original would normally see no row.
    contract = _add_contract(db_session, address=addr, job=newer, protocol_id=p.id, contract_name="Vault")

    out = prefetch_contracts(db_session, [original, newer])
    assert out[original.id].id == contract.id
    assert out[newer.id].id == contract.id


def test_resolve_implementation_contracts_links_proxy_to_impl(db_session):
    """Proxy job → impl Contract row keyed by impl address."""
    p = _add_protocol(db_session, f"proxy-resolver-{uuid.uuid4().hex[:8]}")
    proxy_addr = _addr("px")
    impl_addr = _addr("im")

    proxy_job = _add_job(db_session, address=proxy_addr, protocol_id=p.id, is_proxy=True)
    impl_job = _add_job(db_session, address=impl_addr, protocol_id=p.id)
    _add_contract(
        db_session,
        address=proxy_addr,
        job=proxy_job,
        protocol_id=p.id,
        is_proxy=True,
        implementation=impl_addr,
        contract_name="MyProxy",
    )
    impl_contract = _add_contract(
        db_session, address=impl_addr, job=impl_job, protocol_id=p.id, contract_name="VaultImpl"
    )

    contracts_by_job = prefetch_contracts(db_session, [proxy_job, impl_job])
    impl_job_by_addr, contracts_by_job = resolve_implementation_contracts(
        db_session, [proxy_job, impl_job], contracts_by_job
    )

    assert impl_addr.lower() in impl_job_by_addr
    assert impl_job_by_addr[impl_addr.lower()].id == impl_job.id
    # contracts_by_job_id picked up the impl contract under its own job id.
    assert contracts_by_job[impl_job.id].id == impl_contract.id


def test_build_company_overview_end_to_end_protocol_path(db_session):
    """Top-level: protocol + a single non-proxy contract returns a sane payload."""
    p = _add_protocol(db_session, f"e2e-alpha-{uuid.uuid4().hex[:8]}")
    addr = _addr("e2e1")
    job = _add_job(db_session, address=addr, protocol_id=p.id, name="Vault")
    _add_contract(db_session, address=addr, job=job, protocol_id=p.id, contract_name="Vault")

    payload = build_company_overview(db_session, p.name)

    assert payload["company"] == p.name
    assert payload["protocol_id"] == p.id
    assert payload["contract_count"] == 1
    addrs = {c["address"] for c in payload["contracts"]}
    assert addr in addrs
    # The full inventory moved to /api/company/{name}/addresses; the main
    # payload only carries the count.
    assert payload["all_addresses_count"] == 1


def test_build_company_overview_raises_when_unknown(db_session):
    with pytest.raises(CompanyNotFound):
        build_company_overview(db_session, f"missing-{uuid.uuid4().hex[:8]}")


def test_build_company_overview_omits_functions_field(db_session):
    """``functions`` no longer ships in the main payload — it's served by
    ``/api/company/{name}/functions`` and fetched lazily by the frontend.
    """
    p = _add_protocol(db_session, f"e2e-nofn-{uuid.uuid4().hex[:8]}")
    addr = _addr("nofn1")
    job = _add_job(db_session, address=addr, protocol_id=p.id, name="Vault")
    c = _add_contract(db_session, address=addr, job=job, protocol_id=p.id, contract_name="Vault")
    # Seed an EF row so the lightweight projection has something to walk.
    db_session.add(
        EffectiveFunction(
            contract_id=c.id,
            function_name="pause",
            selector="0xabcdef01",
            abi_signature="pause()",
            effect_labels=["pause_toggle"],
            effect_targets=[],
            action_summary="pause",
            authority_public=False,
            authority_roles=[],
        )
    )
    db_session.commit()

    payload = build_company_overview(db_session, p.name)
    entry = next(c for c in payload["contracts"] if c["address"] == addr)
    assert "functions" not in entry
    # value_effects / capabilities should still derive from the lightweight
    # ef_effects projection — pause_toggle → "pause" capability.
    assert "pause" in entry["capabilities"]


def test_build_functions_for_protocol_returns_keyed_function_list(db_session):
    """``build_functions_for_protocol`` returns ``{address: [function_entries]}``
    using the same shape that previously lived on each contract entry.
    """
    p = _add_protocol(db_session, f"functions-{uuid.uuid4().hex[:8]}")
    addr = _addr("fn1")
    job = _add_job(db_session, address=addr, protocol_id=p.id, name="Vault")
    contract = _add_contract(db_session, address=addr, job=job, protocol_id=p.id, contract_name="Vault")
    ef = EffectiveFunction(
        contract_id=contract.id,
        function_name="transfer",
        selector="0xa9059cbb",
        abi_signature="transfer(address,uint256)",
        effect_labels=["asset_send"],
        effect_targets=[],
        action_summary="transfer assets",
        authority_public=True,
        authority_roles=[],
    )
    db_session.add(ef)
    db_session.flush()
    db_session.add(
        FunctionPrincipal(
            function_id=ef.id,
            address=_addr("safe1"),
            resolved_type="safe",
            origin="role 0",
            principal_type="authority_role",
            details={"owners": [_addr("o1"), _addr("o2")], "threshold": 2},
        )
    )
    db_session.commit()

    out = build_functions_for_protocol(db_session, p.name)
    assert addr in out
    entries = out[addr]
    assert len(entries) == 1
    entry = entries[0]
    assert entry["function"] == "transfer(address,uint256)"
    assert entry["selector"] == "0xa9059cbb"
    assert entry["effect_labels"] == ["asset_send"]
    assert entry["authority_public"] is True
    # The FP row was principal_type=authority_role, so it should bucket
    # under authority_roles rather than direct_owner.
    assert entry["authority_roles"], "authority_roles should be populated"
    assert entry["direct_owner"] is None


def test_build_functions_for_protocol_unknown_company_raises(db_session):
    with pytest.raises(CompanyNotFound):
        build_functions_for_protocol(db_session, f"missing-{uuid.uuid4().hex[:8]}")


def test_build_functions_for_protocol_proxy_uses_impl(db_session):
    """Proxy entries inherit functions from the impl contract's EF rows."""
    p = _add_protocol(db_session, f"functions-proxy-{uuid.uuid4().hex[:8]}")
    proxy_addr = _addr("pxfn")
    impl_addr = _addr("imfn")

    proxy_job = _add_job(db_session, address=proxy_addr, protocol_id=p.id, is_proxy=True)
    impl_job = _add_job(db_session, address=impl_addr, protocol_id=p.id)
    _add_contract(
        db_session,
        address=proxy_addr,
        job=proxy_job,
        protocol_id=p.id,
        is_proxy=True,
        implementation=impl_addr,
        contract_name="ERC1967Proxy",
    )
    impl_contract = _add_contract(
        db_session, address=impl_addr, job=impl_job, protocol_id=p.id, contract_name="VaultImpl"
    )
    db_session.add(
        EffectiveFunction(
            contract_id=impl_contract.id,
            function_name="upgradeTo",
            selector="0x3659cfe6",
            abi_signature="upgradeTo(address)",
            effect_labels=["implementation_update"],
            effect_targets=[],
            action_summary="upgrade",
            authority_public=False,
            authority_roles=[],
        )
    )
    db_session.commit()

    out = build_functions_for_protocol(db_session, p.name)
    # Function is keyed to the proxy's address (what the user sees), not
    # the impl's address.
    assert proxy_addr in out
    assert any(entry["function"] == "upgradeTo(address)" for entry in out[proxy_addr])


def test_build_company_overview_proxy_uses_impl_name(db_session):
    """A proxy contract's overview entry inherits the impl's contract name
    instead of the generic ``ERC1967Proxy``-style template name.
    """
    p = _add_protocol(db_session, f"e2e-proxy-{uuid.uuid4().hex[:8]}")
    proxy_addr = _addr("px2")
    impl_addr = _addr("im2")

    proxy_job = _add_job(db_session, address=proxy_addr, protocol_id=p.id, is_proxy=True)
    impl_job = _add_job(db_session, address=impl_addr, protocol_id=p.id)
    _add_contract(
        db_session,
        address=proxy_addr,
        job=proxy_job,
        protocol_id=p.id,
        is_proxy=True,
        implementation=impl_addr,
        contract_name="ERC1967Proxy",
    )
    _add_contract(db_session, address=impl_addr, job=impl_job, protocol_id=p.id, contract_name="VaultImpl")

    payload = build_company_overview(db_session, p.name)
    proxy_entry = next(c for c in payload["contracts"] if c["address"] == proxy_addr)
    assert proxy_entry["is_proxy"] is True
    assert proxy_entry["implementation"] == impl_addr
    # Inherited name from the impl, not the generic proxy name
    assert proxy_entry["name"] == "VaultImpl"


def _reference_trim_for_contract(
    session,
    contract_id: int,
    contracts_by_job_id: dict,
    cv_by_cid_full: dict,
    cgn_by_cid_full: dict,
) -> dict:
    """Replicate the pre-SQL-trim path: load every CGN/CGE row for ``contract_id``
    (unfiltered), build the same nodes_payload/edges_payload the production
    serializer would emit, then apply ``_trim_control_graph``.

    Used as the reference output the SQL-prefiltered path must match.
    """
    all_cgn = (
        session.execute(select(ControlGraphNode).where(ControlGraphNode.contract_id == contract_id)).scalars().all()
    )
    all_cge = (
        session.execute(select(ControlGraphEdge).where(ControlGraphEdge.contract_id == contract_id)).scalars().all()
    )
    lookup = _build_principal_lookup(contracts_by_job_id, cv_by_cid_full, cgn_by_cid_full)
    node_meta = {n.address: _principal_lookup_meta(lookup, n.address, n.details) for n in all_cgn}
    nodes_payload = [
        {
            "address": n.address,
            "type": node_meta[n.address].get("resolved_type") or n.resolved_type,
            "label": node_meta[n.address].get("label") or n.contract_name or n.label,
            "details": node_meta[n.address]["details"],
        }
        for n in all_cgn
    ]
    edges_payload = [
        {
            "from": e.from_node_id.replace("address:", ""),
            "to": e.to_node_id.replace("address:", ""),
            "relation": e.relation,
        }
        for e in all_cge
    ]
    return _trim_control_graph(nodes_payload, edges_payload)


def test_trim_control_graph_sql_parity(db_session):
    """SQL-prefiltered control_graph queries return the same (nodes, edges)
    set as the pre-refactor "load everything, trim in Python" path.

    The seed covers every override case the principal_lookup can apply:
      - principal-typed CGN row (direct keep)
      - non-principal CGN row that is the FROM of an edge (edge-source keep)
      - non-principal CGN whose address is one of the analyzed contracts
        (lookup upgrades to "contract")
      - non-principal CGN whose address has a principal-typed CGN row on
        another contract in the batch (lookup cross-contract upgrade)
      - non-principal CGN whose address appears in a ControllerValue with
        a principal resolved_type (lookup CV upgrade)
      - non-principal CGN with ``details.delay`` set (lookup timelock-delay)
      - non-principal CGN with no inbound nor outbound edges (drop case)
      - edge whose target is dropped (edge drop)
      - edge whose target is not in the contract's CGN at all (edge keep)
    """
    p = _add_protocol(db_session, f"trim-parity-{uuid.uuid4().hex[:8]}")
    addr_a = _addr("ca")
    addr_b = _addr("cb")
    job_a = _add_job(db_session, address=addr_a, protocol_id=p.id, name="ContractA")
    job_b = _add_job(db_session, address=addr_b, protocol_id=p.id, name="ContractB")
    contract_a = _add_contract(db_session, address=addr_a, job=job_a, protocol_id=p.id, contract_name="ContractA")
    contract_b = _add_contract(db_session, address=addr_b, job=job_b, protocol_id=p.id, contract_name="ContractB")

    safe_addr = _addr("safe").lower()
    tl_addr = _addr("tl").lower()
    eoa_addr = _addr("eoa").lower()
    leaf_drop = _addr("drop").lower()
    leaf_src = _addr("src").lower()
    delay_addr = _addr("dly").lower()
    cv_safe = _addr("cvs").lower()
    cross_safe = _addr("xsafe").lower()
    external_addr = _addr("ext").lower()

    # Contract A's CGN — mix of kept and dropped cases.
    db_session.add(ControlGraphNode(contract_id=contract_a.id, address=safe_addr, resolved_type="safe"))
    db_session.add(ControlGraphNode(contract_id=contract_a.id, address=tl_addr, resolved_type="timelock"))
    db_session.add(ControlGraphNode(contract_id=contract_a.id, address=eoa_addr, resolved_type="eoa"))
    db_session.add(ControlGraphNode(contract_id=contract_a.id, address=leaf_drop, resolved_type="unknown"))
    db_session.add(ControlGraphNode(contract_id=contract_a.id, address=leaf_src, resolved_type="unknown"))
    db_session.add(
        ControlGraphNode(
            contract_id=contract_a.id, address=delay_addr, resolved_type="unknown", details={"delay": 3600}
        )
    )
    db_session.add(ControlGraphNode(contract_id=contract_a.id, address=cv_safe, resolved_type="unknown"))
    # Cross-contract reference: addr_b is an analyzed contract → lookup upgrade.
    db_session.add(ControlGraphNode(contract_id=contract_a.id, address=addr_b.lower(), resolved_type="unknown"))
    # cross_safe appears as "safe" on contract_b but "unknown" on contract_a.
    db_session.add(ControlGraphNode(contract_id=contract_a.id, address=cross_safe, resolved_type="unknown"))

    # Contract B's CGN — seeds the cross-contract upgrade for cross_safe.
    db_session.add(ControlGraphNode(contract_id=contract_b.id, address=cross_safe, resolved_type="safe"))

    # Edges in contract A.
    db_session.add(
        ControlGraphEdge(
            contract_id=contract_a.id,
            from_node_id=f"address:{leaf_src}",
            to_node_id=f"address:{safe_addr}",
            relation="ref",
        )
    )
    # Edge to leaf_drop — should be dropped along with the node.
    db_session.add(
        ControlGraphEdge(
            contract_id=contract_a.id,
            from_node_id=f"address:{safe_addr}",
            to_node_id=f"address:{leaf_drop}",
            relation="ref",
        )
    )
    db_session.add(
        ControlGraphEdge(
            contract_id=contract_a.id,
            from_node_id=f"address:{tl_addr}",
            to_node_id=f"address:{safe_addr}",
            relation="controls",
        )
    )
    # Edge to external_addr — target not in contract A's CGN, kept.
    db_session.add(
        ControlGraphEdge(
            contract_id=contract_a.id,
            from_node_id=f"address:{safe_addr}",
            to_node_id=f"address:{external_addr}",
            relation="ext",
        )
    )

    # ControllerValue: cv_safe → resolved_type "safe" → lookup upgrade for cv_safe CGN row.
    db_session.add(
        ControllerValue(contract_id=contract_a.id, controller_id="role", value=cv_safe, resolved_type="safe")
    )
    db_session.commit()

    payload = build_company_overview(db_session, p.name)
    actual_entry = next(c for c in payload["contracts"] if c["address"] == addr_a)
    actual_cg = actual_entry["control_graph"]

    contracts_by_job_id = {job_a.id: contract_a, job_b.id: contract_b}
    cv_full = {
        contract_a.id: list(
            db_session.execute(select(ControllerValue).where(ControllerValue.contract_id == contract_a.id)).scalars()
        ),
        contract_b.id: list(
            db_session.execute(select(ControllerValue).where(ControllerValue.contract_id == contract_b.id)).scalars()
        ),
    }
    cgn_full = {
        contract_a.id: list(
            db_session.execute(select(ControlGraphNode).where(ControlGraphNode.contract_id == contract_a.id)).scalars()
        ),
        contract_b.id: list(
            db_session.execute(select(ControlGraphNode).where(ControlGraphNode.contract_id == contract_b.id)).scalars()
        ),
    }
    reference = _reference_trim_for_contract(db_session, contract_a.id, contracts_by_job_id, cv_full, cgn_full)

    actual_nodes = {n["address"].lower() for n in actual_cg["nodes"]}
    reference_nodes = {n["address"].lower() for n in reference["nodes"]}
    assert actual_nodes == reference_nodes, (
        f"SQL-prefiltered nodes diverge from Python-trim reference.\n"
        f"  only in actual: {actual_nodes - reference_nodes}\n"
        f"  only in reference: {reference_nodes - actual_nodes}"
    )

    actual_edges = {(e["from"].lower(), e["to"].lower(), e["relation"]) for e in actual_cg["edges"]}
    reference_edges = {(e["from"].lower(), e["to"].lower(), e["relation"]) for e in reference["edges"]}
    assert actual_edges == reference_edges, (
        f"SQL-prefiltered edges diverge from Python-trim reference.\n"
        f"  only in actual: {actual_edges - reference_edges}\n"
        f"  only in reference: {reference_edges - actual_edges}"
    )

    # Spot-check the override branches explicitly so a future regression that
    # silently drops the analyzed-contract address (the largest override class
    # in production) doesn't get masked by a parallel reference change.
    assert addr_b.lower() in actual_nodes, "analyzed-contract address must survive (lookup upgrade)"
    assert cv_safe in actual_nodes, "CV-principal address must survive (lookup upgrade)"
    assert cross_safe in actual_nodes, "cross-contract principal address must survive (lookup upgrade)"
    assert delay_addr in actual_nodes, "details.delay address must survive (lookup timelock-delay)"
    assert leaf_src in actual_nodes, "non-principal but edge-source address must survive"
    assert leaf_drop not in actual_nodes, "true leaf must be dropped"
    assert external_addr in {e["to"].lower() for e in actual_cg["edges"]}, (
        "edge whose target is outside this contract's CGN must survive"
    )


def _normalize_prefetch(result: dict) -> dict:
    """Reduce ``_prefetch_child_tables`` output to a hashable, order-independent
    structure so equality comparison is robust to per-session row order.

    ORM rows are reduced to tuples of the columns the downstream pipeline
    actually reads; lists are sorted so we test as multisets, not sequences.
    """

    def cv_key(cv):
        return (cv.controller_id, cv.value, cv.resolved_type, cv.source, cv.block_number)

    def bal_key(b):
        return (
            b.token_address,
            b.token_symbol,
            b.raw_balance,
            b.decimals,
            float(b.usd_value) if b.usd_value is not None else None,
            float(b.price_usd) if b.price_usd is not None else None,
        )

    def cgn_key(n):
        return (
            n.address,
            n.resolved_type,
            n.contract_name,
            n.label,
            tuple(sorted((n.details or {}).items())) if isinstance(n.details, dict) else n.details,
        )

    def cge_key(e):
        return (e.from_node_id, e.to_node_id, e.relation)

    return {
        "controller_values": {
            cid: sorted(cv_key(r) for r in rows) for cid, rows in result["controller_values"].items()
        },
        "ef_effects": {cid: sorted(tuple(lbls) for lbls in rows) for cid, rows in result["ef_effects"].items()},
        "fp_governance_rows": {
            cid: sorted((d["address"], d["resolved_type"], repr(d["details"])) for d in rows)
            for cid, rows in result["fp_governance_rows"].items()
        },
        "fp_in_contract_principals": {cid: sorted(addrs) for cid, addrs in result["fp_in_contract_principals"].items()},
        "upgrade_events_count": dict(result["upgrade_events_count"]),
        "upgrade_events_last": dict(result["upgrade_events_last"]),
        "balances": {cid: sorted(bal_key(b) for b in rows) for cid, rows in result["balances"].items()},
        "cgn": {cid: sorted(cgn_key(n) for n in rows) for cid, rows in result["cgn"].items()},
        "cge": {cid: sorted(cge_key(e) for e in rows) for cid, rows in result["cge"].items()},
    }


def test_prefetch_child_tables_parallel_sequential_parity(db_session):
    """``_prefetch_child_tables`` returns byte-identical output between the
    parallel fan-out (default ``max_workers=4``) and the sequential path
    (``max_workers=1``).

    Seeds one row of every child-table type across two contracts so every
    key in the returned dict has something to merge — the test fails if a
    parallel-only path corrupts the merge, drops rows, or attaches a
    session-local row to the wrong contract_id bucket.
    """
    p = _add_protocol(db_session, f"parity-par-{uuid.uuid4().hex[:8]}")
    addr_a = _addr("pa")
    addr_b = _addr("pb")
    job_a = _add_job(db_session, address=addr_a, protocol_id=p.id, name="ContractA")
    job_b = _add_job(db_session, address=addr_b, protocol_id=p.id, name="ContractB")
    contract_a = _add_contract(db_session, address=addr_a, job=job_a, protocol_id=p.id, contract_name="ContractA")
    contract_b = _add_contract(db_session, address=addr_b, job=job_b, protocol_id=p.id, contract_name="ContractB")

    safe_addr = _addr("psafe").lower()
    tl_addr = _addr("ptl").lower()
    cv_principal = _addr("pcv").lower()
    ef_principal = _addr("pfp").lower()
    leaf_drop = _addr("pdrop").lower()
    leaf_src = _addr("psrc").lower()

    # Contract A: every child-table type populated.
    db_session.add(
        ControllerValue(
            contract_id=contract_a.id,
            controller_id="owner",
            value=cv_principal,
            resolved_type="safe",
            source="onchain",
            block_number=100,
        )
    )
    db_session.add(
        ControllerValue(
            contract_id=contract_a.id,
            controller_id="admin",
            value=tl_addr,
            resolved_type="timelock",
            source=None,
            block_number=101,
        )
    )
    db_session.add(ControlGraphNode(contract_id=contract_a.id, address=safe_addr, resolved_type="safe", label="A safe"))
    db_session.add(ControlGraphNode(contract_id=contract_a.id, address=tl_addr, resolved_type="timelock"))
    db_session.add(ControlGraphNode(contract_id=contract_a.id, address=leaf_drop, resolved_type="unknown"))
    db_session.add(ControlGraphNode(contract_id=contract_a.id, address=leaf_src, resolved_type="unknown"))
    db_session.add(
        ControlGraphEdge(
            contract_id=contract_a.id,
            from_node_id=f"address:{leaf_src}",
            to_node_id=f"address:{safe_addr}",
            relation="ref",
        )
    )
    db_session.add(
        ControlGraphEdge(
            contract_id=contract_a.id,
            from_node_id=f"address:{safe_addr}",
            to_node_id=f"address:{leaf_drop}",
            relation="ref",
        )
    )
    db_session.add(
        ContractBalance(
            contract_id=contract_a.id,
            token_address=None,
            token_symbol="ETH",
            token_name="Ether",
            decimals=18,
            raw_balance="1000000000000000000",
            usd_value=2500.00,
            price_usd=2500.00,
        )
    )
    ef_a = EffectiveFunction(
        contract_id=contract_a.id,
        function_name="pause",
        selector="0x8456cb59",
        abi_signature="pause()",
        effect_labels=["pause_toggle"],
        effect_targets=[],
        action_summary="pause",
        authority_public=False,
        authority_roles=[],
    )
    db_session.add(ef_a)
    db_session.flush()
    db_session.add(
        FunctionPrincipal(
            function_id=ef_a.id,
            address=ef_principal,
            resolved_type="safe",
            origin="role 0",
            principal_type="authority_role",
            details={"threshold": 2},
        )
    )
    db_session.add(
        UpgradeEvent(
            contract_id=contract_a.id,
            proxy_address=addr_a,
            new_impl=_addr("pimpl"),
            block_number=12345,
            timestamp=datetime(2024, 6, 1, tzinfo=timezone.utc),
        )
    )
    db_session.add(
        UpgradeEvent(
            contract_id=contract_a.id,
            proxy_address=addr_a,
            new_impl=_addr("pimpl2"),
            block_number=22345,
            timestamp=datetime(2025, 1, 1, tzinfo=timezone.utc),
        )
    )

    # Contract B: a subset, plus a row whose only purpose is to validate
    # that each contract_id bucket stays separate across threads.
    db_session.add(
        ControllerValue(
            contract_id=contract_b.id,
            controller_id="owner",
            value=safe_addr,
            resolved_type="safe",
        )
    )
    db_session.add(
        ContractBalance(
            contract_id=contract_b.id,
            token_address=_addr("ptok"),
            token_symbol="USDC",
            decimals=6,
            raw_balance="50000000",
            usd_value=50.00,
            price_usd=1.00,
        )
    )
    ef_b = EffectiveFunction(
        contract_id=contract_b.id,
        function_name="transfer",
        selector="0xa9059cbb",
        abi_signature="transfer(address,uint256)",
        effect_labels=["asset_send"],
        effect_targets=[],
        action_summary="transfer",
        authority_public=True,
        authority_roles=[],
    )
    db_session.add(ef_b)
    db_session.commit()

    contract_ids = {contract_a.id, contract_b.id}
    parallel = _prefetch_child_tables(db_session, contract_ids, max_workers=4)
    sequential = _prefetch_child_tables(db_session, contract_ids, max_workers=1)

    assert _normalize_prefetch(parallel) == _normalize_prefetch(sequential), (
        "parallel fan-out diverged from the sequential reference"
    )

    # Sanity: every dict key has content from the seed so the equality
    # check above wasn't trivially {} == {}.
    norm = _normalize_prefetch(parallel)
    assert norm["controller_values"][contract_a.id], "controller_values missing for contract A"
    assert norm["balances"][contract_a.id], "balances missing for contract A"
    assert norm["cgn"][contract_a.id], "cgn missing for contract A"
    assert norm["cge"][contract_a.id], "cge missing for contract A"
    assert norm["ef_effects"][contract_a.id], "ef_effects missing for contract A"
    assert norm["fp_governance_rows"][contract_a.id], "fp_governance_rows missing for contract A"
    assert norm["upgrade_events_count"][contract_a.id] == 2
    assert norm["upgrade_events_last"][contract_a.id]["block"] == 22345


def test_fund_flows_principal_requires_authorization_edge(db_session):
    """A bare ``ControlGraphNode`` row pointing at another in-protocol
    contract must NOT produce a ``type=principal`` fund_flow on its own.

    Regression for the etherfi/WstETH overreach: the in-contract pass of
    ``_build_flows_and_principals`` walks ``ControlGraphNode`` rows and
    emits ``type=principal`` for every in-protocol address it finds —
    with no ``relation`` / ``resolved_type`` / ``depth`` filter. CGN
    rows include transitive lineage (e.g. EtherFi's contracts pull in
    Lido's WstETH via ``WithdrawalQueueERC721 -> WstETH -> Lido stETH``),
    so unrelated tokens get falsely surfaced as principals controlling
    every contract whose graph happens to traverse them.

    Real authorization should be evidenced by a ``ControlGraphEdge`` with
    a meaningful ``relation`` (controller_value, direct_owner, …) — the
    node row alone is not sufficient. The non-contract pass at
    ``company_overview.py:1063-1072`` already filters by
    ``resolved_type``; the in-contract pass needs an equivalent guard.
    """
    p = _add_protocol(db_session, f"principal-overreach-{uuid.uuid4().hex[:8]}")

    target_addr = _addr("target")
    token_addr = _addr("token")

    target_job = _add_job(db_session, address=target_addr, protocol_id=p.id, name="LiquidityPool")
    token_job = _add_job(db_session, address=token_addr, protocol_id=p.id, name="WstETH")
    target_contract = _add_contract(
        db_session, address=target_addr, job=target_job, protocol_id=p.id, contract_name="LiquidityPool"
    )
    _add_contract(db_session, address=token_addr, job=token_job, protocol_id=p.id, contract_name="WstETH")

    # Only seed a CGN row — the kind that gets written for any address
    # in the resolved control graph, including transitive nodes. No CV,
    # no owner, no ControlGraphEdge with an authorization relation. A
    # real principal would also have an edge; this row by itself is
    # lineage, not authorization.
    db_session.add(
        ControlGraphNode(
            contract_id=target_contract.id,
            address=token_addr.lower(),
            resolved_type="contract",
            depth=2,
        )
    )
    db_session.commit()

    payload = build_company_overview(db_session, p.name)
    fund_flows = payload["fund_flows"]

    overreach = [
        f
        for f in fund_flows
        if f["from"] == token_addr.lower() and f["to"] == target_addr.lower() and f["type"] == "principal"
    ]
    assert overreach == [], (
        "A ControlGraphNode row without any authorization edge must not "
        "produce a type=principal fund_flow. Found spurious overreach: "
        f"{overreach}"
    )


def test_fund_flows_principal_emitted_for_in_contract_function_principal(db_session):
    """Positive complement to the CGN-overreach pin above: when an
    in-protocol contract holds an actual ``FunctionPrincipal`` row on
    the target's function, the principal flow **is** emitted.

    The post-fix in-contract pass at company_overview.py:1122-1128
    iterates ``fp_in_contract_principals`` (the prefetch projection at
    :419-464) rather than walking raw CGN rows. Without this test the
    only coverage of the new code path is the negative
    test_fund_flows_principal_requires_authorization_edge above, which
    deliberately seeds *no* FP row — so the success branch never runs
    and the fix could regress silently to "always empty".

    Concretely: the target's ``transferFrom`` is gated by a
    ``FunctionPrincipal`` row pointing at the authority contract. That
    is the authoritative per-function access-control record the
    capability resolver writes; an in-protocol address only appears
    here if it can actually call the function. The principal flow
    ``authority -> target`` must be in fund_flows.
    """
    p = _add_protocol(db_session, f"principal-positive-{uuid.uuid4().hex[:8]}")

    target_addr = _addr("target")
    authority_addr = _addr("authority")

    target_job = _add_job(db_session, address=target_addr, protocol_id=p.id, name="Vault")
    authority_job = _add_job(db_session, address=authority_addr, protocol_id=p.id, name="Operator")
    target_contract = _add_contract(
        db_session, address=target_addr, job=target_job, protocol_id=p.id, contract_name="Vault"
    )
    _add_contract(db_session, address=authority_addr, job=authority_job, protocol_id=p.id, contract_name="Operator")

    ef = EffectiveFunction(
        contract_id=target_contract.id,
        function_name="transferFrom",
        selector="0x23b872dd",
        abi_signature="transferFrom(address,address,uint256)",
        authority_public=False,
    )
    db_session.add(ef)
    db_session.commit()
    db_session.refresh(ef)

    db_session.add(
        FunctionPrincipal(
            function_id=ef.id,
            address=authority_addr.lower(),
            resolved_type=None,
            origin="semantic_capability:finite_set",
            principal_type="controller",
        )
    )
    db_session.commit()

    payload = build_company_overview(db_session, p.name)
    fund_flows = payload["fund_flows"]

    principal_flow = [
        f
        for f in fund_flows
        if f["from"] == authority_addr.lower() and f["to"] == target_addr.lower() and f["type"] == "principal"
    ]
    assert principal_flow, (
        "Expected a type=principal fund_flow from authority -> target when a "
        "FunctionPrincipal row links them. Got fund_flows="
        f"{[f for f in fund_flows if f['to'] == target_addr.lower()]}"
    )


def test_fund_flows_controller_requires_authorization_relation(db_session):
    """A ControllerValue row pointing at another in-protocol contract
    must NOT produce a ``type=controller`` fund_flow unless the storage
    variable actually denotes authorization.

    Sibling of the WstETH/CGN overreach, narrower blast radius.
    ``_build_flows_and_principals`` (company_overview.py:1019-1023)
    walks the contract entry's ``controllers`` dict, which is populated
    at lines 752-753 from *every* ControllerValue row regardless of
    semantics. CV rows include any address-typed tracked state variable
    (per ``tracking_plan._is_address_like_read_spec``):

      - real authorizers (``owner``, ``admin``, ``governor``)
      - money-routing targets (``treasury``, ``feeRecipient``)
      - external deps (``weth``, ``oracle``, ``priceFeed``, ``swapRouter``)
      - composability anchors (``vault``, ``pool``, ``stEth``)

    Emitting ``type=controller`` for the latter three categories falsely
    asserts that an integration target authorizes its consumer. Both
    ``cv.controller_id`` (state-var name) and ``cv.resolved_type`` are
    visible to the loop — a real fix would gate on one of them.
    """
    p = _add_protocol(db_session, f"controller-overreach-{uuid.uuid4().hex[:8]}")

    target_addr = _addr("target")
    token_addr = _addr("token")

    target_job = _add_job(db_session, address=target_addr, protocol_id=p.id, name="LiquidityPool")
    token_job = _add_job(db_session, address=token_addr, protocol_id=p.id, name="WstETH")
    target_contract = _add_contract(
        db_session, address=target_addr, job=target_job, protocol_id=p.id, contract_name="LiquidityPool"
    )
    _add_contract(db_session, address=token_addr, job=token_job, protocol_id=p.id, contract_name="WstETH")

    # A CV row of the form an integration variable produces — controller_id
    # is a non-authorization name (so the owner-substring heuristic does
    # not false-positive and confuse the bug isolation), value resolves to
    # an in-protocol contract, and resolved_type matches what
    # ``classify_resolved_address`` writes for a regular token.
    db_session.add(
        ControllerValue(
            contract_id=target_contract.id,
            controller_id="wstEth",
            value=token_addr.lower(),
            resolved_type="contract",
            source="wstEth()",
        )
    )
    db_session.commit()

    payload = build_company_overview(db_session, p.name)
    fund_flows = payload["fund_flows"]

    overreach = [
        f
        for f in fund_flows
        if f["from"] == token_addr.lower() and f["to"] == target_addr.lower() and f["type"] == "controller"
    ]
    assert overreach == [], (
        "An integration ControllerValue (e.g. wstEth(), weth(), oracle(), "
        "treasury()) must not be reported as a type=controller fund_flow. "
        f"Found: {overreach}"
    )


def test_owner_detection_prefers_active_owner_over_pending_owner(db_session):
    """The active owner — not pendingOwner — must be returned as the
    contract's ``owner`` field.

    Regression for the substring-match heuristic at
    company_overview.py:749-755:

        if "owner" in cv.controller_id.lower() and cv.value and ...:
            owner = cv.value.lower()

    ``"owner" in "pendingowner"`` is True, ``"owner" in "previousowner"``
    is True, ``"owner" in "roleowner"`` is True. Combined with
    last-write-wins assignment (no precedence), the chosen ``owner`` is
    whichever owner-substring CV row the iteration sees last. For any
    OpenZeppelin Ownable2Step contract (canonical post-2022 pattern,
    both ``owner()`` and ``pendingOwner()`` exist as tracked state
    variables), this routinely latches onto the not-yet-accepted
    pending owner.

    The wrong ``owner`` then cascades into:
      - ``_build_ownership_hierarchy`` — groups under the wrong principal
      - the controls_value/controls flow at line 1011-1017 — wrong source
      - the ``!= owner`` filter at line 1022 — fails to exclude the real
        owner from controller-flow emission, double-emitting an edge
    """
    p = _add_protocol(db_session, f"owner-pending-{uuid.uuid4().hex[:8]}")

    target_addr = _addr("target")
    real_owner_addr = _addr("realowner")
    pending_owner_addr = _addr("pendingowner")

    target_job = _add_job(db_session, address=target_addr, protocol_id=p.id, name="Vault")
    target_contract = _add_contract(
        db_session, address=target_addr, job=target_job, protocol_id=p.id, contract_name="Vault"
    )

    # ``owner()`` inserted first, ``pendingOwner()`` second. Postgres
    # returns rows in physical (insertion) order absent an ORDER BY, so
    # the buggy last-wins iteration assigns owner = pendingOwner.
    db_session.add(
        ControllerValue(
            contract_id=target_contract.id,
            controller_id="owner",
            value=real_owner_addr.lower(),
            resolved_type="safe",
            source="owner()",
        )
    )
    db_session.add(
        ControllerValue(
            contract_id=target_contract.id,
            controller_id="pendingOwner",
            value=pending_owner_addr.lower(),
            resolved_type="eoa",
            source="pendingOwner()",
        )
    )
    db_session.commit()

    payload = build_company_overview(db_session, p.name)
    target_entry = next(c for c in payload["contracts"] if c["address"] == target_addr)

    # Sanity: both CV rows reached the entry — proves the bug is in the
    # owner heuristic, not in data loading.
    assert "owner" in target_entry["controllers"], "owner CV row should be in controllers dict"
    assert "pendingOwner" in target_entry["controllers"], "pendingOwner CV row should be in controllers dict"

    assert target_entry["owner"] == real_owner_addr.lower(), (
        "owner() must take precedence over pendingOwner(). "
        f"Expected {real_owner_addr.lower()}, got {target_entry['owner']}."
    )
