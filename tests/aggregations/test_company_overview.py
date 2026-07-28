"""Integration tests for ``services.aggregations.company_overview``.

Hits a real Postgres via ``db_session`` so the resolver code paths
(legacy company fallback, address/chain Contract fallback, impl
resolution) actually exercise the SQLAlchemy queries.
"""

from __future__ import annotations

import sys
import uuid
from datetime import datetime, timedelta, timezone
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[2]))

from sqlalchemy import select  # noqa: E402

from db.models import (  # noqa: E402
    Contract,
    ContractBalance,
    ContractSummary,
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
    _entity_key,
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
    chain: str | None = "ethereum",
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


def test_resolve_company_jobs_collapses_duplicate_entity_jobs(db_session):
    """Two completed jobs at the same (chain, address) — a re-analysis, or a
    cascade child that raced the spawn dedup — must yield ONE job (the newest),
    so the overview renders one card per entity, never per job."""
    p = _add_protocol(db_session, f"dupent-{uuid.uuid4().hex[:8]}")
    addr = _addr("dupentity")
    older = _add_job(db_session, address=addr[:2] + addr[2:].upper(), protocol_id=p.id, name="older")
    older.updated_at = datetime.now(timezone.utc) - timedelta(minutes=10)
    db_session.commit()
    newer = _add_job(db_session, address=addr, protocol_id=p.id, name="newer")
    _add_contract(db_session, address=addr, job=newer, protocol_id=p.id, contract_name="Dup")

    _protocol, jobs = resolve_company_jobs(db_session, p.name)
    assert [j.id for j in jobs] == [newer.id]


def test_overview_entry_address_is_canonical_lowercase(db_session):
    """A job stored with a checksummed address (legacy admin submission) must
    serialize a lowercase card address — node ids and selection keys downstream
    assume one canonical form."""
    p = _add_protocol(db_session, f"csum-{uuid.uuid4().hex[:8]}")
    lower = _addr("checksummed")
    mixed = lower[:2] + lower[2:].upper()
    j = _add_job(db_session, address=mixed, protocol_id=p.id, request={"address": mixed})
    _add_contract(db_session, address=lower, job=j, protocol_id=p.id, contract_name="Csum")

    overview = build_company_overview(db_session, p.name)
    entry = next(c for c in overview["contracts"] if (c["address"] or "").lower() == lower)
    assert entry["address"] == lower


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
    impl_job_by_entity, contracts_by_job = resolve_implementation_contracts(
        db_session, [proxy_job, impl_job], contracts_by_job
    )

    # impl_job_by_entity is keyed by the composite token of the impl job's own
    # chain (both proxy and impl default to ethereum here).
    impl_token = _entity_key("ethereum", impl_addr)
    assert impl_token in impl_job_by_entity
    assert impl_job_by_entity[impl_token].id == impl_job.id
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


def _claim(claim_id: str, tier: str = "standard_exact") -> dict:
    return {"claim_id": claim_id, "tier": tier, "witness": {}}


def test_capability_chips_key_on_claims(db_session):
    """Contract capability chips key off Plane-1 claims (with the new
    ``timelock`` / ``safe`` chips and a finally-producible ``arbitrary-call``);
    the hook/external exclusion is structural — a claim-bearing row's legacy
    hook_update/external label contributes no chip, and claims win over legacy
    labels on the same row. A claim-less row falls back to the legacy map.
    """
    p = _add_protocol(db_session, f"cap-claims-{uuid.uuid4().hex[:8]}")
    addr = _addr("capc1")
    job = _add_job(db_session, address=addr, protocol_id=p.id, name="Governor")
    c = _add_contract(db_session, address=addr, job=job, protocol_id=p.id, contract_name="Governor")

    def _ef(fname, selector, *, claims=None, effect_labels=None):
        db_session.add(
            EffectiveFunction(
                contract_id=c.id,
                function_name=fname,
                selector=selector,
                abi_signature=f"{fname}()",
                effect_labels=effect_labels or [],
                claims=claims,
                effect_targets=[],
                action_summary=fname,
                authority_public=False,
                authority_roles=[],
            )
        )

    # New chips from claim families that had no legacy label.
    _ef("schedule", "0x01000001", claims=[_claim("timelock.schedule")], effect_labels=["external_contract_call"])
    _ef("addSigner", "0x01000002", claims=[_claim("safe.signer_mgmt")], effect_labels=["hook_update"])
    _ef("manage", "0x01000003", claims=[_claim("exec.arbitrary")], effect_labels=["external_contract_call"])
    # Claims win over legacy labels on the same row: flow.out → fund-out, and the
    # ownership_transfer legacy label must NOT surface an "ownership" chip.
    _ef("sweep", "0x01000004", claims=[_claim("flow.out")], effect_labels=["ownership_transfer"])
    # A claim-less row falls back to the legacy map (chip + value_effects).
    _ef("pause", "0x01000005", effect_labels=["pause_toggle"])
    _ef("payout", "0x01000006", effect_labels=["asset_send"])
    db_session.commit()

    payload = build_company_overview(db_session, p.name)
    entry = next(e for e in payload["contracts"] if e["address"] == addr)
    caps = set(entry["capabilities"])

    assert {"timelock", "safe", "arbitrary-call", "fund-out", "pause"} <= caps
    # Structural exclusion: hook_update / external_contract_call carry no chip.
    # Claims-first: the ownership_transfer legacy label on the sweep row is
    # ignored because that row has a claim.
    assert "ownership" not in caps
    # value_effects stays a Plane-0 fact off the legacy labels.
    assert "asset_send" in entry["value_effects"]


def test_controls_detail_capabilities_from_claims(db_session):
    """A principal's ``controls_detail`` capability chips flow from the
    ``fp_function_detail`` projection's Plane-1 claims: a Safe holding a
    ``safe.signer_mgmt`` function surfaces the ``safe`` chip, and the row's
    legacy hook_update label contributes nothing.
    """
    p = _add_protocol(db_session, f"cap-detail-{uuid.uuid4().hex[:8]}")
    addr = _addr("capd1")
    safe_addr = _addr("capdsafe").lower()
    job = _add_job(db_session, address=addr, protocol_id=p.id, name="Safe-Governed")
    c = _add_contract(db_session, address=addr, job=job, protocol_id=p.id, contract_name="SafeGoverned")

    ef = EffectiveFunction(
        contract_id=c.id,
        function_name="addSigner",
        selector="0x02000001",
        abi_signature="addSigner(address)",
        effect_labels=["hook_update"],  # legacy label must not surface a chip
        claims=[_claim("safe.signer_mgmt")],
        effect_targets=[],
        action_summary="add signer",
        authority_public=False,
        authority_roles=[],
    )
    db_session.add(ef)
    db_session.flush()
    db_session.add(
        FunctionPrincipal(
            function_id=ef.id,
            address=safe_addr,
            resolved_type="safe",
            origin="role 0",
            principal_type="authority_role",
            details={"owners": [_addr("o1")], "threshold": 1},
        )
    )
    db_session.add(ControlGraphNode(contract_id=c.id, address=safe_addr, resolved_type="safe"))
    db_session.commit()

    payload = build_company_overview(db_session, p.name)
    principals = {(pr.get("address") or "").lower(): pr for pr in payload["principals"]}
    assert safe_addr in principals, "the FP-backed Safe must surface as a principal"

    detail = principals[safe_addr].get("controls_detail") or []
    row = next((r for r in detail if (r.get("address") or "").lower() == addr.lower()), None)
    assert row is not None, f"expected a controls_detail row for {addr}, got {detail}"
    assert row["capabilities"] == ["safe"], (
        f"safe.signer_mgmt claim must surface the 'safe' chip and hook_update must "
        f"contribute nothing; got {row['capabilities']}"
    )
    assert "addSigner" in row["functions"]


def test_build_functions_for_protocol_returns_keyed_function_list(db_session):
    """``build_functions_for_protocol`` returns
    ``{"<chain>::<address>": [function_entries]}`` using the same per-function
    shape that previously lived on each contract entry.
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
    key = f"ethereum::{addr.lower()}"
    assert key in out
    entries = out[key]
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
    # Function is keyed to the proxy's (chain, address) — what the user sees —
    # not the impl's address.
    proxy_key = f"ethereum::{proxy_addr.lower()}"
    assert proxy_key in out
    assert any(entry["function"] == "upgradeTo(address)" for entry in out[proxy_key])


def test_build_functions_for_protocol_two_chains_shared_address(db_session):
    """Same address on two chains under one protocol keeps BOTH chains'
    function analyses, keyed by the composite ``<chain>::<address>`` token
    (invariant 13).

    A CREATE2 twin deployed at the same address on ethereum and base can carry
    a different per-chain authority verdict — ``pause()`` gated on mainnet,
    earned-public on base. The flat ``{address: functions}`` map collapsed the
    two last-wins while building the response, so the second chain's analysis
    never left the server. Composite keying keeps both.
    """
    p = _add_protocol(db_session, f"twochain-{uuid.uuid4().hex[:8]}")
    addr = _addr("dual")

    eth_job = _add_job(db_session, address=addr, protocol_id=p.id, name="Vault")
    eth_contract = _add_contract(
        db_session, address=addr, job=eth_job, protocol_id=p.id, chain="ethereum", contract_name="Vault"
    )
    base_job = _add_job(
        db_session,
        address=addr,
        protocol_id=p.id,
        name="Vault",
        request={"address": addr, "chain": "base"},
    )
    base_contract = _add_contract(
        db_session, address=addr, job=base_job, protocol_id=p.id, chain="base", contract_name="Vault"
    )
    # Same selector, opposite verdict: gated on ethereum, earned-public on base.
    db_session.add(
        EffectiveFunction(
            contract_id=eth_contract.id,
            function_name="pause",
            selector="0x8456cb59",
            abi_signature="pause()",
            effect_labels=["pause_toggle"],
            effect_targets=[],
            action_summary="pause",
            authority_public=False,
            authority_roles=[],
        )
    )
    db_session.add(
        EffectiveFunction(
            contract_id=base_contract.id,
            function_name="pause",
            selector="0x8456cb59",
            abi_signature="pause()",
            effect_labels=["pause_toggle"],
            effect_targets=[],
            action_summary="pause",
            authority_public=True,
            authority_roles=[],
        )
    )
    db_session.commit()

    out = build_functions_for_protocol(db_session, p.name)
    eth_key = f"ethereum::{addr.lower()}"
    base_key = f"base::{addr.lower()}"
    assert eth_key in out, sorted(out.keys())
    assert base_key in out, sorted(out.keys())
    eth_entries = out[eth_key]
    base_entries = out[base_key]
    assert len(eth_entries) == 1 and len(base_entries) == 1
    # Both chains' verdicts survive, distinct — the whole point of the fix.
    assert eth_entries[0]["authority_public"] is False
    assert base_entries[0]["authority_public"] is True


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
        "ef_effects": {
            cid: sorted((tuple(rec["labels"]), tuple(rec["claims"])) for rec in rows)
            for cid, rows in result["ef_effects"].items()
        },
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


def test_primary_for_resolves_safe_through_in_protocol_timelock(db_session):
    """End-to-end pin for the ether.fi Surface ownership regression.

    Shape under test (the timelock-mediated governance pattern that broke):

        governance Safe --FP--> Timelock (in-protocol) --FP--> Vault (proxy)

    The Vault's owner-gated functions resolve, in ``FunctionPrincipal``, to an
    in-protocol Timelock contract; the Timelock's own functions resolve to an
    external governance Safe. Because the Timelock is itself a protocol
    contract it is never a *principal*, so a one-hop FP-membership check
    attributes nothing and the canvas shows no owner — the reported bug.

    Two things must hold after the fix, and both are protocol-agnostic:

      1. The Vault's **proxy** address (not the implementation address its FP
         rows physically live on) is attributed to the governance Safe,
         resolved *through* the Timelock.

      2. A fee-destination Safe — typed ``safe`` in the control graph but
         holding no ``FunctionPrincipal`` row on any contract — is FP-gated
         out of the principals list entirely. It is a ``payoutAddress``
         fee-sink, not a controller: the second-pass CGN walk keeps a
         safe/eoa/timelock principal only when it holds real call-authority
         (an FP row) on the contract, so this beneficiary never becomes a
         principal nor appears in any principal's ``controls``.
    """
    p = _add_protocol(db_session, f"timelock-gov-{uuid.uuid4().hex[:8]}")

    proxy_addr = _addr("vaultpx")
    impl_addr = _addr("vaultim")
    timelock_addr = _addr("timelock")
    gov_safe = _addr("govsafe").lower()
    fee_safe = _addr("feesafe").lower()

    # Vault: proxy + implementation (FP rows live on the impl, as in prod).
    proxy_job = _add_job(db_session, address=proxy_addr, protocol_id=p.id, is_proxy=True, name="Vault")
    impl_job = _add_job(db_session, address=impl_addr, protocol_id=p.id, name="VaultImpl")
    _add_contract(
        db_session,
        address=proxy_addr,
        job=proxy_job,
        protocol_id=p.id,
        is_proxy=True,
        implementation=impl_addr,
        contract_name="Vault",
    )
    impl_contract = _add_contract(
        db_session, address=impl_addr, job=impl_job, protocol_id=p.id, contract_name="VaultImpl"
    )

    # In-protocol Timelock contract.
    tl_job = _add_job(db_session, address=timelock_addr, protocol_id=p.id, name="Timelock")
    tl_contract = _add_contract(
        db_session, address=timelock_addr, job=tl_job, protocol_id=p.id, contract_name="ProtocolTimelock"
    )

    # Vault.setFee is owner-gated; its caller resolves to the Timelock. The FP
    # row sits on the IMPL contract — the canvas keys off the proxy address.
    ef_vault = EffectiveFunction(
        contract_id=impl_contract.id,
        function_name="setFee",
        selector="0x11111111",
        abi_signature="setFee(uint256)",
        authority_public=False,
    )
    db_session.add(ef_vault)
    db_session.flush()
    db_session.add(
        FunctionPrincipal(
            function_id=ef_vault.id,
            address=timelock_addr.lower(),
            resolved_type=None,
            origin="semantic_capability:finite_set",
            principal_type="controller",
        )
    )

    # Timelock.execute caller resolves to the governance Safe.
    ef_tl = EffectiveFunction(
        contract_id=tl_contract.id,
        function_name="execute",
        selector="0x22222222",
        abi_signature="execute(address,uint256,bytes)",
        authority_public=False,
    )
    db_session.add(ef_tl)
    db_session.flush()
    db_session.add(
        FunctionPrincipal(
            function_id=ef_tl.id,
            address=gov_safe,
            resolved_type=None,
            origin="semantic_capability:finite_set",
            principal_type="controller",
        )
    )

    # Typing comes from the control graph: the Timelock is typed ``timelock``
    # (so it is a pass-through), and both Safes are typed ``safe`` (so they
    # surface as principals). The fee Safe is deliberately given NO FP row.
    db_session.add(
        ControlGraphNode(contract_id=impl_contract.id, address=timelock_addr.lower(), resolved_type="timelock")
    )
    db_session.add(ControlGraphNode(contract_id=tl_contract.id, address=gov_safe, resolved_type="safe"))
    db_session.add(ControlGraphNode(contract_id=impl_contract.id, address=fee_safe, resolved_type="safe"))
    db_session.commit()

    payload = build_company_overview(db_session, p.name)
    principals = {(pr.get("address") or "").lower(): pr for pr in payload["principals"]}

    assert gov_safe in principals, "governance Safe should surface as a principal"
    assert fee_safe not in principals, (
        "a fee-destination Safe with no FunctionPrincipal authority must be FP-gated out of the "
        "principals list entirely — it is a payoutAddress beneficiary, not a controller"
    )

    gov_primary = {a.lower() for a in (principals[gov_safe].get("primary_for") or [])}
    assert proxy_addr.lower() in gov_primary, (
        "governance Safe must be primary controller of the Vault PROXY address, "
        "resolved through the in-protocol Timelock. "
        f"Got primary_for={sorted(gov_primary)}"
    )
    assert impl_addr.lower() not in gov_primary, (
        "primary_for must be keyed on the rendered proxy address, never the "
        "implementation address the FunctionPrincipal rows physically live on"
    )
    assert all(fee_safe not in (pr.get("controls") or []) for pr in payload["principals"]), (
        "the FP-gated fee-destination Safe must not appear in any surviving principal's controls"
    )


def test_second_pass_cgn_principal_requires_function_principal_authority(db_session):
    """The second-pass ControlGraphNode walk in ``_build_flows_and_principals``
    must FP-gate the principals it emits: a safe/eoa/timelock CGN node earns a
    ``principals`` entry (and a ``controls`` edge) only when it holds a real
    ``FunctionPrincipal`` call-right on the contract.

    Without the gate, every safe-typed CGN node becomes a principal regardless
    of authority — re-introducing the ether.fi over-attribution where fee /
    treasury / payout beneficiaries (``treasury`` / ``feeRecipient`` /
    ``_owner`` / ``accountantState.payoutAddress``) were listed as controllers
    of contracts they cannot call. This exercises BOTH branches of the gate:

      * ``drop_safe`` — typed ``safe`` in the control graph, NO FP row → skipped
        (the regression assertion; fails if the gate is reverted).
      * ``keep_safe`` — typed ``safe`` AND holding an FP row on the contract →
        survives, with ``controls`` containing ONLY that contract.
    """
    p = _add_protocol(db_session, f"fp-gate-secondpass-{uuid.uuid4().hex[:8]}")

    vault_addr = _addr("vault").lower()
    keep_safe = _addr("keepsafe").lower()
    drop_safe = _addr("dropsafe").lower()

    vault_job = _add_job(db_session, address=vault_addr, protocol_id=p.id, name="Vault")
    vault_contract = _add_contract(
        db_session, address=vault_addr, job=vault_job, protocol_id=p.id, contract_name="Vault"
    )

    # Vault.setFee is owner-gated and resolves, in FunctionPrincipal, to
    # ``keep_safe`` — a real call-right on this contract.
    ef = EffectiveFunction(
        contract_id=vault_contract.id,
        function_name="setFee",
        selector="0x33333333",
        abi_signature="setFee(uint256)",
        authority_public=False,
    )
    db_session.add(ef)
    db_session.flush()
    db_session.add(
        FunctionPrincipal(
            function_id=ef.id,
            address=keep_safe,
            resolved_type="safe",
            origin="semantic_capability:finite_set",
            principal_type="controller",
        )
    )

    # Both addresses are typed ``safe`` in the control graph, but only
    # ``keep_safe`` backs that with an FP call-right. ``drop_safe`` is a bare
    # beneficiary node (the payoutAddress-style fee sink).
    db_session.add(ControlGraphNode(contract_id=vault_contract.id, address=keep_safe, resolved_type="safe"))
    db_session.add(ControlGraphNode(contract_id=vault_contract.id, address=drop_safe, resolved_type="safe"))
    db_session.commit()

    payload = build_company_overview(db_session, p.name)
    principals = {(pr.get("address") or "").lower(): pr for pr in payload["principals"]}

    assert keep_safe in principals, (
        "a safe-typed CGN node WITH a FunctionPrincipal call-right on the contract must surface as a principal"
    )
    assert principals[keep_safe].get("controls") == [vault_addr], (
        "the FP-backed principal's controls must contain ONLY the contract it can actually call. "
        f"Got controls={principals[keep_safe].get('controls')}"
    )

    assert drop_safe not in principals, (
        "a safe-typed CGN node with NO FunctionPrincipal row must be FP-gated out of the principals "
        "list — reverting the gate re-adds it (the over-attribution regression)"
    )
    assert all(drop_safe not in (pr.get("controls") or []) for pr in payload["principals"]), (
        "the FP-gated beneficiary Safe must not appear in any principal's controls"
    )


def test_primary_for_surfaces_safe_typed_only_via_function_principal(db_session):
    """The faithful ether.fi shape: the governing Safe is **not** a control-graph
    node — it is known to be a Safe only because its ``FunctionPrincipal`` row
    on the in-protocol Timelock carries ``resolved_type='safe'`` (populated at
    write time by the policy stage's address classifier).

    This pins the consumption half of the typing fix: a Safe reachable solely
    through typed per-function authority (no CGN safe node, the exact reason
    ether.fi's multisig was invisible) must still surface as a principal and,
    via the Timelock pass-through, own the proxied Vault. If FP typing
    regresses to NULL, ``_fp_governance`` drops the row and this fails.
    """
    p = _add_protocol(db_session, f"fp-typed-owner-{uuid.uuid4().hex[:8]}")

    proxy_addr = _addr("vpx")
    impl_addr = _addr("vim")
    timelock_addr = _addr("tl")
    gov_safe = _addr("gsafe").lower()

    proxy_job = _add_job(db_session, address=proxy_addr, protocol_id=p.id, is_proxy=True, name="Vault")
    impl_job = _add_job(db_session, address=impl_addr, protocol_id=p.id, name="VaultImpl")
    _add_contract(
        db_session,
        address=proxy_addr,
        job=proxy_job,
        protocol_id=p.id,
        is_proxy=True,
        implementation=impl_addr,
        contract_name="Vault",
    )
    impl_contract = _add_contract(
        db_session, address=impl_addr, job=impl_job, protocol_id=p.id, contract_name="VaultImpl"
    )
    tl_job = _add_job(db_session, address=timelock_addr, protocol_id=p.id, name="Timelock")
    tl_contract = _add_contract(
        db_session, address=timelock_addr, job=tl_job, protocol_id=p.id, contract_name="ProtocolTimelock"
    )

    # Vault.setFee -> Timelock (caller resolves to the in-protocol timelock; the
    # finite_set row itself is untyped, exactly as the writer leaves it).
    ef_vault = EffectiveFunction(
        contract_id=impl_contract.id,
        function_name="setFee",
        selector="0x11111111",
        abi_signature="setFee(uint256)",
        authority_public=False,
    )
    db_session.add(ef_vault)
    db_session.flush()
    db_session.add(
        FunctionPrincipal(
            function_id=ef_vault.id,
            address=timelock_addr.lower(),
            resolved_type=None,
            origin="semantic_capability:finite_set",
            principal_type="controller",
        )
    )

    # Timelock.execute -> gov_safe, TYPED 'safe' on the FP row (what the writer
    # now does). gov_safe has NO control-graph node at all.
    ef_tl = EffectiveFunction(
        contract_id=tl_contract.id,
        function_name="execute",
        selector="0x22222222",
        abi_signature="execute(address,uint256,bytes)",
        authority_public=False,
    )
    db_session.add(ef_tl)
    db_session.flush()
    db_session.add(
        FunctionPrincipal(
            function_id=ef_tl.id,
            address=gov_safe,
            resolved_type="safe",
            origin="semantic_capability:finite_set",
            principal_type="controller",
        )
    )

    # Only the Timelock is typed in the control graph (so it is a pass-through);
    # the Safe is intentionally absent from CGN.
    db_session.add(
        ControlGraphNode(contract_id=impl_contract.id, address=timelock_addr.lower(), resolved_type="timelock")
    )
    db_session.commit()

    payload = build_company_overview(db_session, p.name)
    principals = {(pr.get("address") or "").lower(): pr for pr in payload["principals"]}

    assert gov_safe in principals, (
        "a Safe known only via a typed FunctionPrincipal row (no CGN node) must still surface as a principal"
    )
    gov_primary = {a.lower() for a in (principals[gov_safe].get("primary_for") or [])}
    assert proxy_addr.lower() in gov_primary, (
        "the FP-typed Safe must own the Vault proxy through the Timelock pass-through. "
        f"Got primary_for={sorted(gov_primary)}"
    )


def test_standalone_twins_do_not_merge_controller_attribution(db_session):
    """Two standalone (non-proxy) CREATE2 twins deployed at the SAME address on
    ethereum and base, each governed by a DIFFERENT Safe, must not have their
    controller attribution merged (multichain invariant 13).

    The attribution fold used to render every contract to a BARE address before
    ``assign_primary_controllers`` ran, so the two twins collapsed onto one key
    and their ``FunctionPrincipal`` authority sets unioned. The primary-controller
    contest then saw both Safes competing for one contract and one lost — its
    ``primary_for`` came back empty even though it is the sole controller of its
    own chain's twin. Keying the fold on the composite ``<chain>::<address>``
    entity keeps the two contests separate: each Safe primary-controls its own
    twin, so BOTH surface as a primary controller.
    """
    p = _add_protocol(db_session, f"twin-attr-{uuid.uuid4().hex[:8]}")
    vault_addr = _addr("twinvault")
    eth_safe = _addr("ethsafe").lower()
    base_safe = _addr("basesafe").lower()

    eth_job = _add_job(db_session, address=vault_addr, protocol_id=p.id, name="Vault")
    eth_contract = _add_contract(
        db_session, address=vault_addr, job=eth_job, protocol_id=p.id, chain="ethereum", contract_name="Vault"
    )
    base_job = _add_job(
        db_session,
        address=vault_addr,
        protocol_id=p.id,
        name="Vault",
        request={"address": vault_addr, "chain": "base"},
    )
    base_contract = _add_contract(
        db_session, address=vault_addr, job=base_job, protocol_id=p.id, chain="base", contract_name="Vault"
    )

    # Each chain's twin has its OWN owner-gated setFee, controlled by a
    # chain-local Safe (different address per chain).
    for contract, safe, selector in (
        (eth_contract, eth_safe, "0x44444441"),
        (base_contract, base_safe, "0x44444442"),
    ):
        ef = EffectiveFunction(
            contract_id=contract.id,
            function_name="setFee",
            selector=selector,
            abi_signature="setFee(uint256)",
            effect_labels=["pause_toggle"],
            authority_public=False,
        )
        db_session.add(ef)
        db_session.flush()
        db_session.add(
            FunctionPrincipal(
                function_id=ef.id,
                address=safe,
                resolved_type="safe",
                origin="semantic_capability:finite_set",
                principal_type="controller",
            )
        )
        db_session.add(ControlGraphNode(contract_id=contract.id, address=safe, resolved_type="safe"))
    db_session.commit()

    payload = build_company_overview(db_session, p.name)
    principals = {(pr.get("address") or "").lower(): pr for pr in payload["principals"]}

    assert eth_safe in principals and base_safe in principals, (
        f"both chain-local Safes should surface as principals; got {sorted(principals)}"
    )

    eth_primary = {a.lower() for a in (principals[eth_safe].get("primary_for") or [])}
    base_primary = {a.lower() for a in (principals[base_safe].get("primary_for") or [])}
    assert vault_addr.lower() in eth_primary, (
        "the ethereum Safe must primary-control the ethereum twin; a merged fold lets the "
        f"base Safe win the shared bare key and empties this one. Got primary_for={sorted(eth_primary)}"
    )
    assert vault_addr.lower() in base_primary, (
        "the base Safe must primary-control the base twin; a merged fold lets the ethereum "
        f"Safe win the shared bare key and empties this one. Got primary_for={sorted(base_primary)}"
    )

    # Additive chain axis (B4a): each principal reports the chain(s) it governs on.
    assert principals[eth_safe].get("chains") == ["ethereum"], principals[eth_safe].get("chains")
    assert principals[base_safe].get("chains") == ["base"], principals[base_safe].get("chains")


def test_flows_and_principals_carry_chain_fields(db_session):
    """Single-chain byte-compat pin for the additive chain axis (B4a): every
    ``fund_flows`` edge gains ``from_chain``/``to_chain`` and every principal
    gains ``chains`` — and NOTHING else about their shape changes. A mainnet-only
    protocol keeps its previous keys verbatim, with the new fields coalesced to
    ``"ethereum"``.
    """
    p = _add_protocol(db_session, f"chain-fields-{uuid.uuid4().hex[:8]}")
    vault_addr = _addr("cfvault").lower()
    safe_addr = _addr("cfsafe").lower()

    vault_job = _add_job(db_session, address=vault_addr, protocol_id=p.id, name="Vault")
    vault_contract = _add_contract(
        db_session, address=vault_addr, job=vault_job, protocol_id=p.id, contract_name="Vault"
    )
    ef = EffectiveFunction(
        contract_id=vault_contract.id,
        function_name="setFee",
        selector="0x55555555",
        abi_signature="setFee(uint256)",
        authority_public=False,
    )
    db_session.add(ef)
    db_session.flush()
    db_session.add(
        FunctionPrincipal(
            function_id=ef.id,
            address=safe_addr,
            resolved_type="safe",
            origin="semantic_capability:finite_set",
            principal_type="controller",
        )
    )
    db_session.add(ControlGraphNode(contract_id=vault_contract.id, address=safe_addr, resolved_type="safe"))
    db_session.commit()

    payload = build_company_overview(db_session, p.name)

    fund_flows = payload["fund_flows"]
    assert fund_flows, "expected at least one control-relation flow (safe -> vault)"
    for flow in fund_flows:
        assert set(flow.keys()) == {"from", "to", "type", "lane", "capabilities", "from_chain", "to_chain"}, (
            f"fund_flow shape drifted beyond the additive chain fields: {sorted(flow.keys())}"
        )
        assert flow["from_chain"] == "ethereum" and flow["to_chain"] == "ethereum", flow

    principals = payload["principals"]
    assert principals, "expected the FP-backed Safe to surface as a principal"
    for pr in principals:
        assert pr.get("chains") == ["ethereum"], (pr.get("address"), pr.get("chains"))
        # controls_detail rows gain exactly ``chain`` alongside the bare
        # ``address`` — nothing else about the row shape drifts (byte-compat pin).
        for row in pr.get("controls_detail") or []:
            assert set(row.keys()) == {"address", "functions", "capabilities", "chain"}, (
                f"controls_detail row shape drifted beyond the additive chain field: {sorted(row.keys())}"
            )
            assert row["chain"] == "ethereum", row


def test_controls_detail_rows_carry_chain_for_twins(db_session):
    """One Safe governing same-address CREATE2 twins on two chains yields two
    ``controls_detail`` rows with the SAME bare ``address`` but distinct
    ``chain`` tokens — so a consumer can tell the two governed contracts apart
    (multichain invariant 13). Without the chain discriminator the two rows are
    indistinguishable.
    """
    p = _add_protocol(db_session, f"twin-detail-{uuid.uuid4().hex[:8]}")
    vault_addr = _addr("twindetailvault")
    safe_addr = _addr("twindetailsafe").lower()

    eth_job = _add_job(db_session, address=vault_addr, protocol_id=p.id, name="Vault")
    eth_contract = _add_contract(
        db_session, address=vault_addr, job=eth_job, protocol_id=p.id, chain="ethereum", contract_name="Vault"
    )
    base_job = _add_job(
        db_session,
        address=vault_addr,
        protocol_id=p.id,
        name="Vault",
        request={"address": vault_addr, "chain": "base"},
    )
    base_contract = _add_contract(
        db_session, address=vault_addr, job=base_job, protocol_id=p.id, chain="base", contract_name="Vault"
    )

    # The SAME Safe holds an owner-gated setFee on both chains' twins.
    for contract, selector in ((eth_contract, "0x46464641"), (base_contract, "0x46464642")):
        ef = EffectiveFunction(
            contract_id=contract.id,
            function_name="setFee",
            selector=selector,
            abi_signature="setFee(uint256)",
            effect_labels=["pause_toggle"],
            authority_public=False,
        )
        db_session.add(ef)
        db_session.flush()
        db_session.add(
            FunctionPrincipal(
                function_id=ef.id,
                address=safe_addr,
                resolved_type="safe",
                origin="semantic_capability:finite_set",
                principal_type="controller",
            )
        )
        db_session.add(ControlGraphNode(contract_id=contract.id, address=safe_addr, resolved_type="safe"))
    db_session.commit()

    payload = build_company_overview(db_session, p.name)
    principals = {(pr.get("address") or "").lower(): pr for pr in payload["principals"]}
    assert safe_addr in principals, f"the FP-backed Safe must surface as a principal; got {sorted(principals)}"

    detail = principals[safe_addr].get("controls_detail") or []
    rows_for_vault = [r for r in detail if (r.get("address") or "").lower() == vault_addr.lower()]
    chains = sorted(r.get("chain") for r in rows_for_vault)
    assert chains == ["base", "ethereum"], (
        "the Safe must have one controls_detail row per governed twin, each tagged with its own "
        f"chain; got rows={rows_for_vault}"
    )


def test_summary_flags_are_three_state_through_the_payload(db_session):
    """Row ABSENCE is not a proven negative (W3-E item 1 / L-30).

    62 of 147 company-overview entries on the local corpus have no
    ContractSummary row at all, and every one of them used to publish
    ``is_pausable: false`` / ``has_timelock: false`` / ``is_factory: false`` —
    three proven negatives derived from never having looked. The three shapes
    below are the three states, and the payload has to keep them apart.
    """
    p = _add_protocol(db_session, f"e2e-3state-{uuid.uuid4().hex[:8]}")

    # 1. No summary row at all — nobody answered, and the reason is row absence.
    a_absent = _addr("3sA")
    job_a = _add_job(db_session, address=a_absent, protocol_id=p.id, name="NoSummary")
    _add_contract(db_session, address=a_absent, job=job_a, protocol_id=p.id, contract_name="NoSummary")

    # 2. Summary row present, every flag NULL — the detectors ran and declined.
    a_null = _addr("3sB")
    job_b = _add_job(db_session, address=a_null, protocol_id=p.id, name="NullFlags")
    c_null = _add_contract(db_session, address=a_null, job=job_b, protocol_id=p.id, contract_name="NullFlags")
    db_session.add(ContractSummary(contract_id=c_null.id, is_pausable=None, has_timelock=None, is_factory=None))

    # 3. Summary row present, every flag proven False — a real negative.
    a_false = _addr("3sC")
    job_c = _add_job(db_session, address=a_false, protocol_id=p.id, name="ProvenPlain")
    c_false = _add_contract(db_session, address=a_false, job=job_c, protocol_id=p.id, contract_name="ProvenPlain")
    db_session.add(ContractSummary(contract_id=c_false.id, is_pausable=False, has_timelock=False, is_factory=False))

    # 4. Summary row present, proven pausable + proven timelock — the positive
    #    control for every hedge above.
    a_true = _addr("3sD")
    job_d = _add_job(db_session, address=a_true, protocol_id=p.id, name="ProvenPausable")
    c_true = _add_contract(db_session, address=a_true, job=job_d, protocol_id=p.id, contract_name="ProvenPausable")
    db_session.add(ContractSummary(contract_id=c_true.id, is_pausable=True, has_timelock=True, is_factory=True))
    db_session.commit()

    payload = build_company_overview(db_session, p.name)
    by_addr = {c["address"]: c for c in payload["contracts"]}

    absent = by_addr[a_absent]
    assert absent["is_pausable"] is None
    assert absent["has_timelock"] is None
    assert absent["is_factory"] is None
    assert absent["summary_evidence"] == "absent"
    # The derived fields must not launder the absence into a positive claim.
    assert "pause" not in absent["capabilities"]
    assert absent["role_evidence"] == "not_determined"

    nulls = by_addr[a_null]
    assert nulls["is_pausable"] is None
    assert nulls["has_timelock"] is None
    assert nulls["is_factory"] is None
    # Same answer about the contract, different answer about why — a consumer
    # deciding whether to re-run the stage or fix the detector needs both.
    assert nulls["summary_evidence"] == "present"
    assert "pause" not in nulls["capabilities"]
    assert nulls["role_evidence"] == "not_determined"

    proven_false = by_addr[a_false]
    assert proven_false["is_pausable"] is False
    assert proven_false["has_timelock"] is False
    assert proven_false["is_factory"] is False
    assert proven_false["summary_evidence"] == "present"
    # POSITIVE CONTROL for role_evidence: a role derived from ANSWERED flags is
    # evidence even when the answer is "no" and the role lands on ``utility``.
    assert proven_false["role"] == "utility"
    assert proven_false["role_evidence"] == "witnessed"

    proven_true = by_addr[a_true]
    assert proven_true["is_pausable"] is True
    assert proven_true["has_timelock"] is True
    assert proven_true["is_factory"] is True
    # POSITIVE CONTROL: the pause chip and the governance role still fire on a
    # proven flag — the ``is True`` narrowing must not have removed them.
    assert "pause" in proven_true["capabilities"]
    assert proven_true["role"] == "governance"
    assert proven_true["role_evidence"] == "witnessed"


def test_principal_lookup_promotes_only_a_proven_timelock(db_session):
    """``_build_principal_lookup`` types a contract ``timelock`` only on a proven
    flag: ``timelock`` is a SETTLED key (priority 3) for the terminal-controller
    renderer, and a NULL flag must leave the address a non-terminal way-point."""
    p = _add_protocol(db_session, f"e2e-pltl-{uuid.uuid4().hex[:8]}")
    proven_addr = _addr("pltlA")
    unknown_addr = _addr("pltlB")
    job_p = _add_job(db_session, address=proven_addr, protocol_id=p.id, name="Timelock")
    job_u = _add_job(db_session, address=unknown_addr, protocol_id=p.id, name="Unknown")
    c_p = _add_contract(db_session, address=proven_addr, job=job_p, protocol_id=p.id, contract_name="Timelock")
    c_u = _add_contract(db_session, address=unknown_addr, job=job_u, protocol_id=p.id, contract_name="Unknown")
    db_session.add(ContractSummary(contract_id=c_p.id, has_timelock=True))
    db_session.add(ContractSummary(contract_id=c_u.id, has_timelock=None))
    db_session.commit()

    lookup = _build_principal_lookup({job_p.id: c_p, job_u.id: c_u}, {}, {})
    assert lookup[proven_addr.lower()]["resolved_type"] == "timelock"
    assert lookup[unknown_addr.lower()]["resolved_type"] == "contract"


def test_balance_payload_splits_unpriced_from_a_measured_zero(db_session):
    """``usd_value: null`` and ``usd_value: 0`` mean opposite things and are one
    truthiness test apart in the renderer (W3-E item 2 / G6-11 / L-45).

    Also pins the holdings-coverage disclosure: at-the-page-cap is the only
    positive statement available about completeness, and the other arm is
    not-determined — never "whole".
    """
    p = _add_protocol(db_session, f"e2e-bal-{uuid.uuid4().hex[:8]}")
    addr = _addr("bal1")
    job = _add_job(db_session, address=addr, protocol_id=p.id, name="Vault")
    c = _add_contract(db_session, address=addr, job=job, protocol_id=p.id, contract_name="Vault")
    db_session.add_all(
        [
            # Priced and worth real money.
            ContractBalance(
                contract_id=c.id,
                token_address=_addr("bt1"),
                token_symbol="BIG",
                decimals=18,
                raw_balance="1000000000000000000",
                usd_value=5000,
                price_usd=5000,
            ),
            # Priced and worth nothing — a MEASUREMENT.
            ContractBalance(
                contract_id=c.id,
                token_address=_addr("bt2"),
                token_symbol="DUST",
                decimals=18,
                raw_balance="1",
                usd_value=0,
                price_usd=0,
            ),
            # Never valued. The producer writes price_usd=0 for "no price known",
            # so price_usd alone reads this as worthless; usd_value is the honest
            # discriminator and the payload must publish the state explicitly.
            ContractBalance(
                contract_id=c.id,
                token_address=_addr("bt3"),
                token_symbol="UNK",
                decimals=18,
                raw_balance="1000000000000000000",
                usd_value=None,
                price_usd=0,
            ),
        ]
    )
    db_session.commit()

    payload = build_company_overview(db_session, p.name)
    entry = next(e for e in payload["contracts"] if e["address"] == addr)
    by_symbol = {b["token_symbol"]: b for b in entry["balances"]}

    assert by_symbol["BIG"]["usd_value_state"] == "measured"
    assert by_symbol["DUST"]["usd_value"] == 0
    assert by_symbol["DUST"]["usd_value_state"] == "measured"
    assert by_symbol["UNK"]["usd_value"] is None
    assert by_symbol["UNK"]["usd_value_state"] == "not_determined"

    cov = entry["holdings_coverage"]
    assert cov["rows"] == 3
    assert cov["unvalued_rows"] == 1
    # Three stored rows cannot prove a short page: the state is not-determined,
    # and "complete" is not a member of the vocabulary at all.
    assert cov["state"] == "not_determined"
    assert cov["page_cap"] == 100
    # The total skips the unvalued row, so it is a lower bound — which is exactly
    # what ``unvalued_rows`` lets a consumer say.
    assert entry["total_usd"] == 5000.0


def test_holdings_at_the_page_cap_are_flagged_as_possibly_incomplete(db_session):
    """POSITIVE CONTROL for the coverage state: 7 local contracts sit exactly at
    the 100-row cap (one holding $8.6B) and nothing could say so."""
    from utils.etherscan import TOKEN_BALANCE_PAGE_SIZE

    p = _add_protocol(db_session, f"e2e-cap-{uuid.uuid4().hex[:8]}")
    addr = _addr("cap1")
    job = _add_job(db_session, address=addr, protocol_id=p.id, name="Whale")
    c = _add_contract(db_session, address=addr, job=job, protocol_id=p.id, contract_name="Whale")
    db_session.add_all(
        [
            ContractBalance(
                contract_id=c.id,
                token_address=_addr(f"cap{i}"),
                token_symbol=f"T{i}",
                decimals=18,
                raw_balance="1000000000000000000",
                usd_value=100,
                price_usd=100,
            )
            for i in range(TOKEN_BALANCE_PAGE_SIZE)
        ]
    )
    db_session.commit()

    payload = build_company_overview(db_session, p.name)
    entry = next(e for e in payload["contracts"] if e["address"] == addr)
    assert entry["holdings_coverage"]["rows"] == TOKEN_BALANCE_PAGE_SIZE
    assert entry["holdings_coverage"]["state"] == "may_be_incomplete"
