"""Cross-chain job-level static-cache reuse (invariant 1).

The job-level static cache (``find_completed_static_cache`` + copy) reuses a
completed job's CODE plane for a new ``(chain, address)`` deployment of the same
verified source — the analog of the ``contract_materializations`` reuse for the
per-job ROOT analysis. Primary ``(address, chain)`` behaviour is untouched; the
source-hash path is a fallback that fires only on a primary miss, and the copy
re-stamps the one deployment-specific field (the contract address) while leaving
chain/on-chain-derived artifacts to be re-derived per chain.
"""

from __future__ import annotations

from sqlalchemy import select

from db.contract_materializations import STATIC_FACTS_SCHEMA_VERSION
from db.models import Contract, ContractSummary, JobStage, JobStatus, RoleDefinition
from db.queue import (
    copy_static_cache_cross_chain,
    create_job,
    find_completed_static_cache,
    get_artifact,
    store_artifact,
    store_source_files,
)
from tests.cache_helpers import db_session, requires_postgres  # noqa: F401
from tests.support.policy_builders import _assessment, _minimal_static_facts

pytestmark = requires_postgres

ADDR_MAINNET = "0x" + "a1" * 20
ADDR_BASE = "0x" + "b2" * 20
ADDR_OTHER = "0x" + "c3" * 20
HASH = "0x" + "de" * 32

_SOURCES = {
    "src/Vault.sol": "pragma solidity ^0.8.24;\ncontract Vault {}",
    "src/Lib.sol": "pragma solidity ^0.8.24;\nlibrary Lib {}",
}


def _analysis(address: str) -> dict:
    facts = _minimal_static_facts(address=address, name="Vault")
    facts["summary"] = {**facts["summary"], "control_model": "ownable", "standards": ["ERC20"]}
    facts["semantic_control"] = {
        **facts["semantic_control"],
        "role_definitions": [{"role": "ADMIN_ROLE", "declared_in": "Vault.sol"}],
    }
    return facts


_PREDICATE_TREES = {"schema_version": "semantic", "trees": {"pause()": {"node_type": "caller"}}}
_EFFECTS = {"schema_version": "semantic", "effects": {"transfer()": [{"kind": "value_flow"}]}}


def _make_donor(
    session,
    *,
    address: str = ADDR_MAINNET,
    chain: str = "ethereum",
    source_content_hash: str | None = HASH,
    schema_version: int | None = STATIC_FACTS_SCHEMA_VERSION,
    with_analysis: bool = True,
    extra_artifacts: dict | None = None,
):
    """A completed job with a full static artifact set, stamped with a source hash."""
    job = create_job(session, {"address": address, "chain": chain, "name": "Vault"})
    job.status = JobStatus.completed
    job.stage = JobStage.done
    job.source_content_hash = source_content_hash
    job.static_facts_schema_version = schema_version
    session.commit()

    contract = Contract(
        job_id=job.id,
        address=address.lower(),
        chain=chain,
        contract_name="Vault",
        compiler_version="v0.8.24",
        language="solidity",
        source_format="flat",
        source_file_count=len(_SOURCES),
    )
    session.add(contract)
    session.flush()
    session.add(
        ContractSummary(
            contract_id=contract.id,
            control_model="ownable",
            is_upgradeable=False,
            is_pausable=True,
            standards=["ERC20"],
        )
    )
    session.add(RoleDefinition(contract_id=contract.id, role_name="ADMIN_ROLE", declared_in="Vault.sol"))
    session.commit()

    store_source_files(session, job.id, dict(_SOURCES))
    if with_analysis:
        facts = _analysis(address.lower())
        store_artifact(
            session,
            job.id,
            "assessment",
            data=_assessment(
                static_facts=facts,
                predicate_trees=dict(_PREDICATE_TREES),
                effects=dict(_EFFECTS),
                chain_id=job.chain_id or 1,
            ),
        )
    else:
        # Proxy donor: contract_flags, no assessment.
        store_artifact(session, job.id, "contract_flags", data={"is_proxy": True, "proxy_type": "eip1967"})
    for name, data in (extra_artifacts or {}).items():
        store_artifact(session, job.id, name, data=data)
    return job, contract


def _make_target(session, *, address: str = ADDR_BASE, chain: str = "base"):
    """A discovery-created target: job + its own per-chain Contract row (no analysis yet)."""
    job = create_job(session, {"address": address, "chain": chain, "name": "Vault"})
    session.commit()
    contract = Contract(
        job_id=job.id,
        address=address.lower(),
        chain=chain,
        contract_name="Vault",
        compiler_version="v0.8.24",
        language="solidity",
        source_format="flat",
        source_file_count=len(_SOURCES),
    )
    session.add(contract)
    session.commit()
    return job, contract


# ---------------------------------------------------------------------------
# copy_static_cache_cross_chain — restamp + scoping + donor isolation
# ---------------------------------------------------------------------------


def test_copy_restamps_address_scopes_artifacts_and_leaves_donor_untouched(db_session):
    donor_job, donor_contract = _make_donor(
        db_session,
        extra_artifacts={
            # Deployment/chain-specific artifacts that must NOT be reused cross-chain.
            "static_dependencies": {"address": ADDR_MAINNET.lower(), "dependencies": ["0x" + "42" * 20]},
            "enrichment_cache": {"0x" + "42" * 20: {"name": "MainnetDep"}},
            "upgrade_history": {"target_address": ADDR_MAINNET.lower(), "total_upgrades": 3},
        },
    )
    target_job, target_contract = _make_target(db_session)

    cid = copy_static_cache_cross_chain(db_session, donor_job.id, target_job.id, target_address=ADDR_BASE)
    assert cid == target_contract.id

    # Address re-stamped on the copied code plane.
    from db.queue.typed import load_assessment
    from services.assessment import static_inputs

    assessment = load_assessment(get_artifact, db_session, target_job.id)
    assert assessment is not None
    ca, predicate_trees, effects = static_inputs(assessment)
    assert ca["subject"]["address"] == ADDR_BASE.lower()
    assert assessment["contract"]["address"] == ADDR_BASE.lower()
    assert assessment["contract"]["chain_id"] == 8453

    # Source-only artifacts reused byte-for-byte.
    assert predicate_trees == _PREDICATE_TREES
    assert effects == _EFFECTS
    for retired in ("static_facts", "predicate_trees", "effects"):
        assert get_artifact(db_session, target_job.id, retired) is None

    # Deployment/chain-specific artifacts NOT copied — re-derived per chain.
    assert get_artifact(db_session, target_job.id, "static_dependencies") is None
    assert get_artifact(db_session, target_job.id, "enrichment_cache") is None
    assert get_artifact(db_session, target_job.id, "upgrade_history") is None

    # Summary + roles copied and linked to the TARGET contract.
    summary = db_session.execute(
        select(ContractSummary).where(ContractSummary.contract_id == target_contract.id)
    ).scalar_one()
    assert summary.control_model == "ownable"
    assert summary.standards == ["ERC20"]
    roles = (
        db_session.execute(select(RoleDefinition).where(RoleDefinition.contract_id == target_contract.id))
        .scalars()
        .all()
    )
    assert [r.role_name for r in roles] == ["ADMIN_ROLE"]

    # Donor untouched: its analysis still points at its own address, its contract
    # still belongs to the donor job (NOT reassigned like same-chain copy).
    donor_assessment = load_assessment(get_artifact, db_session, donor_job.id)
    assert donor_assessment is not None
    donor_ca, _donor_trees, _donor_effects = static_inputs(donor_assessment)
    assert donor_ca["subject"]["address"] == ADDR_MAINNET.lower()
    db_session.refresh(donor_contract)
    assert donor_contract.job_id == donor_job.id


def test_parity_fresh_vs_cross_chain_copy(db_session):
    """The copied artifact set is byte-equivalent to what a fresh analysis of the
    same source on the target chain would produce, modulo the re-stamped address."""
    donor_job, _ = _make_donor(db_session)
    target_job, _ = _make_target(db_session)
    copy_static_cache_cross_chain(db_session, donor_job.id, target_job.id, target_address=ADDR_BASE)

    # What a fresh static analysis of the identical source at ADDR_BASE emits.
    from db.queue.typed import load_assessment
    from services.assessment import static_inputs

    assessment = load_assessment(get_artifact, db_session, target_job.id)
    assert assessment is not None
    assert static_inputs(assessment) == (_analysis(ADDR_BASE.lower()), _PREDICATE_TREES, _EFFECTS)
    assert assessment["contract"]["chain_id"] == 8453


def test_copy_returns_none_without_target_contract(db_session):
    donor_job, _ = _make_donor(db_session)
    empty_target = create_job(db_session, {"address": ADDR_BASE, "chain": "base"})
    db_session.commit()
    assert copy_static_cache_cross_chain(db_session, donor_job.id, empty_target.id, target_address=ADDR_BASE) is None


# ---------------------------------------------------------------------------
# find_completed_static_cache — fallback semantics
# ---------------------------------------------------------------------------


def test_fallback_fires_only_on_primary_miss(db_session):
    # A same-(address, chain) completed job AND a cross-chain hash donor both exist.
    primary_job, _ = _make_donor(db_session, address=ADDR_MAINNET, chain="ethereum", source_content_hash=HASH)
    hash_donor, _ = _make_donor(db_session, address=ADDR_OTHER, chain="base", source_content_hash=HASH)

    # Primary hit: (ADDR_MAINNET, ethereum) exists → returns it, not the hash donor.
    hit = find_completed_static_cache(db_session, ADDR_MAINNET, chain="ethereum", source_content_hash=HASH)
    assert hit is not None and hit.id == primary_job.id

    # Primary miss (unknown address) + hash present → fallback returns the hash donor.
    fb = find_completed_static_cache(db_session, ADDR_BASE, chain="base", source_content_hash=HASH)
    assert fb is not None and fb.id == hash_donor.id


def test_version_mismatch_misses(db_session):
    _make_donor(
        db_session,
        address=ADDR_OTHER,
        chain="base",
        source_content_hash=HASH,
        schema_version=STATIC_FACTS_SCHEMA_VERSION + 1000,
    )
    assert find_completed_static_cache(db_session, ADDR_BASE, chain="base", source_content_hash=HASH) is None


def test_legacy_null_hash_never_donor(db_session):
    _make_donor(db_session, address=ADDR_OTHER, chain="base", source_content_hash=None, schema_version=None)
    # A hash lookup can't match a NULL-hash row.
    assert find_completed_static_cache(db_session, ADDR_BASE, chain="base", source_content_hash=HASH) is None
    # No hash supplied → no fallback at all.
    assert find_completed_static_cache(db_session, ADDR_BASE, chain="base") is None


def test_proxy_donor_not_reused(db_session):
    """A donor with the hash but only contract_flags (a proxy, no analysis) is
    not a code-plane reuse source."""
    _make_donor(db_session, address=ADDR_OTHER, chain="base", source_content_hash=HASH, with_analysis=False)
    assert find_completed_static_cache(db_session, ADDR_BASE, chain="base", source_content_hash=HASH) is None


# ---------------------------------------------------------------------------
# Discovery wiring: a Base job with a mainnet same-source donor reuses it
# ---------------------------------------------------------------------------


def test_discovery_reuses_cross_chain_donor(db_session, monkeypatch):
    from unittest.mock import MagicMock

    from services.discovery.fetch import source_content_hash
    from workers.discovery import DiscoveryWorker

    stub_result = {
        "ContractName": "Vault",
        "SourceCode": "pragma solidity ^0.8.24;\ncontract Vault {}",
        "CompilerVersion": "v0.8.24",
        "OptimizationUsed": "1",
        "Runs": "200",
        "EVMVersion": "shanghai",
        "LicenseType": "MIT",
    }
    donor_hash = source_content_hash(stub_result)

    # Mainnet donor analyzed the same source.
    donor_job, _ = _make_donor(db_session, address=ADDR_MAINNET, chain="ethereum", source_content_hash=donor_hash)

    # A fresh Base job at a DIFFERENT address (weETH mainnet vs Base pattern).
    target_job = create_job(db_session, {"address": ADDR_BASE, "chain": "base"})
    db_session.commit()

    monkeypatch.setattr(
        "workers.discovery.etherscan.parallel_get",
        lambda thunks: {"fetch": stub_result, "creators": {ADDR_BASE.lower(): None}},
    )
    worker = DiscoveryWorker()
    worker.update_detail = MagicMock()
    worker._process_address(db_session, target_job)

    db_session.refresh(target_job)
    req = target_job.request
    assert isinstance(req, dict)
    assert req.get("static_cached") is True
    assert req.get("cross_chain_cache_source_job_id") == str(donor_job.id)
    # No same-chain proxy-cache key: proxy state must re-resolve on Base.
    assert "cache_source_job_id" not in req
    assert target_job.source_content_hash == donor_hash

    # The reused analysis is re-stamped to the Base deployment.
    from db.queue.typed import load_assessment
    from services.assessment import static_inputs

    target_assessment = load_assessment(get_artifact, db_session, target_job.id)
    assert target_assessment is not None
    ca, _trees, _effects = static_inputs(target_assessment)
    assert ca["subject"]["address"] == ADDR_BASE.lower()
    # The Base deployment got its own per-chain Contract row.
    base_contract = db_session.execute(select(Contract).where(Contract.job_id == target_job.id)).scalar_one()
    assert base_contract.chain == "base"
