"""Latent NULL-chain dedup sites in ``db.queue`` (MULTICHAIN_INVARIANTS.md 1/6/12).

Phase 2 (#154) fixed the bulk discovery writer so a chainless write derives a
real chain name and dedups against legacy ``chain=NULL`` rows via a mainnet-
coalesced key. These tests cover the same-class sites left latent at that time:

  - ``upsert_discovered_contract`` — the single-row variant, now aligned with
    ``bulk_upsert_discovered_contracts`` (``default_chain`` + coalesced dedup).
  - ``find_completed_static_cache`` / ``is_known_proxy`` / ``copy_static_cache``
    — Contract lookups whose ``chain == <value>`` predicate missed legacy NULL
    rows.

Each site is proven in both directions: a mainnet lookup now finds legacy
NULL-chain rows, and a non-mainnet lookup stays isolated (no cross-chain
bleed). No data backfill — reads keep the NULL≡mainnet convention.
"""

from __future__ import annotations

import uuid

import pytest

from tests.conftest import requires_postgres


def _addr() -> str:
    return "0x" + (uuid.uuid4().hex + uuid.uuid4().hex)[:40]


@pytest.fixture()
def proto_id(db_session):
    from db.models import Protocol

    p = Protocol(name=f"queue-coalesce-{uuid.uuid4().hex[:10]}")
    db_session.add(p)
    db_session.commit()
    return p.id


# ---------------------------------------------------------------------------
# upsert_discovered_contract (single-row) — aligned with the bulk variant
# ---------------------------------------------------------------------------


@requires_postgres
def test_single_upsert_dedups_against_legacy_null_row(db_session, proto_id):
    """A legacy ``chain=NULL`` stub already exists (pre-fix write). A later
    mainnet single-row upsert must enrich it via the coalesced key, not mint a
    second row."""
    from db.models import Contract
    from db.queue import upsert_discovered_contract

    addr = _addr()
    db_session.add(Contract(address=addr, chain=None, protocol_id=proto_id, discovery_sources=["defillama"]))
    db_session.commit()

    upsert_discovered_contract(
        db_session,
        address=addr,
        chain=None,
        protocol_id=proto_id,
        new_sources=["dapp_crawl"],
        default_chain="ethereum",
    )
    db_session.commit()

    rows = db_session.query(Contract).filter(Contract.address == addr).all()
    assert len(rows) == 1  # enriched the legacy NULL row, not a duplicate
    row = rows[0]
    assert row.chain is None  # decided: no backfill; NULL≡mainnet convention kept
    assert set(row.discovery_sources or []) == {"defillama", "dapp_crawl"}


@requires_postgres
def test_single_upsert_inherits_default_chain_when_entry_chainless(db_session, proto_id):
    """No evidence chain on the entry → inherit the job's ``default_chain`` so a
    fresh row persists ``'ethereum'`` rather than a new NULL stub."""
    from db.models import Contract
    from db.queue import upsert_discovered_contract

    addr = _addr()
    upsert_discovered_contract(
        db_session,
        address=addr,
        chain=None,
        protocol_id=proto_id,
        new_sources=["defillama"],
        default_chain="ethereum",
    )
    db_session.commit()

    row = db_session.query(Contract).filter(Contract.address == addr).one()
    assert row.chain == "ethereum"


@requires_postgres
def test_single_upsert_base_entry_does_not_collapse_onto_legacy_null(db_session, proto_id):
    """A non-mainnet single-row upsert must NOT dedup against a legacy NULL
    (mainnet) stub: coalescing maps NULL→'ethereum', and 'base' ≠ 'ethereum'."""
    from db.models import Contract
    from db.queue import upsert_discovered_contract

    addr = _addr()
    db_session.add(Contract(address=addr, chain=None, protocol_id=proto_id, discovery_sources=["defillama"]))
    db_session.commit()

    upsert_discovered_contract(
        db_session,
        address=addr,
        chain="base",
        protocol_id=proto_id,
        new_sources=["defillama"],
        default_chain="base",
    )
    db_session.commit()

    rows = db_session.query(Contract).filter(Contract.address == addr).all()
    assert {r.chain for r in rows} == {None, "base"}


# ---------------------------------------------------------------------------
# is_known_proxy — coalesced Contract lookup
# ---------------------------------------------------------------------------


@requires_postgres
def test_is_known_proxy_finds_legacy_null_row_on_mainnet_lookup(db_session, proto_id):
    from db.models import Contract
    from db.queue import is_known_proxy

    addr = _addr()
    db_session.add(Contract(address=addr, chain=None, protocol_id=proto_id, is_proxy=True))
    db_session.commit()

    # Mainnet lookup coalesces NULL→'ethereum' and finds the legacy proxy row.
    assert is_known_proxy(db_session, addr, chain="ethereum") is True


@requires_postgres
def test_is_known_proxy_isolated_from_legacy_null_row_on_l2_lookup(db_session, proto_id):
    from db.models import Contract
    from db.queue import is_known_proxy

    addr = _addr()
    db_session.add(Contract(address=addr, chain=None, protocol_id=proto_id, is_proxy=True))
    db_session.commit()

    # A Base lookup must not see the legacy (mainnet) NULL proxy row.
    assert is_known_proxy(db_session, addr, chain="base") is False


# ---------------------------------------------------------------------------
# find_completed_static_cache — coalesced Contract lookup on a NULL-chain row
# ---------------------------------------------------------------------------


@requires_postgres
def test_static_cache_hit_on_legacy_null_chain_contract(db_session):
    """A completed job (chain_id=1) whose Contract row was persisted
    ``chain=NULL`` (legacy) is now a mainnet cache hit; the raw
    ``Contract.chain == 'ethereum'`` predicate previously missed it."""
    from db.queue import find_completed_static_cache
    from tests.cache_helpers import ADDR_A, _create_completed_job_with_static_data

    job = _create_completed_job_with_static_data(db_session)  # Contract.chain is NULL
    found = find_completed_static_cache(db_session, ADDR_A, chain="ethereum")
    assert found is not None
    assert found.id == job.id


@requires_postgres
def test_static_cache_miss_for_l2_against_legacy_null_contract(db_session):
    """The same legacy mainnet cache must not answer a Base request."""
    from db.queue import find_completed_static_cache
    from tests.cache_helpers import ADDR_A, _create_completed_job_with_static_data

    _create_completed_job_with_static_data(db_session)  # mainnet (chain_id=1) job + NULL Contract
    found = find_completed_static_cache(db_session, ADDR_A, chain="base")
    assert found is None


# ---------------------------------------------------------------------------
# copy_static_cache — coalesced source-Contract lookup
# ---------------------------------------------------------------------------


def _completed_source_with_null_contract(session, address, request_chain):
    """A completed source job whose request declares *request_chain* but whose
    Contract row was persisted ``chain=NULL`` (the legacy write shape)."""
    from db.models import Contract, ContractSummary, JobStage, JobStatus
    from db.queue import create_job, store_artifact, store_source_files

    job = create_job(session, {"address": address, "name": "LegacyContract", "chain": request_chain})
    job.status = JobStatus.completed
    job.stage = JobStage.done
    session.commit()

    contract = Contract(
        job_id=job.id,
        address=address.lower(),
        chain=None,  # legacy NULL despite the mainnet request
        contract_name="LegacyContract",
        compiler_version="v0.8.24",
        language="solidity",
        evm_version="shanghai",
        source_format="flat",
        source_file_count=1,
        remappings=[],
    )
    session.add(contract)
    session.flush()
    session.add(ContractSummary(contract_id=contract.id, control_model="ownable"))
    session.commit()

    store_source_files(session, job.id, {"src/Legacy.sol": "contract Legacy {}"})
    from tests.support.policy_builders import _assessment, _minimal_static_facts

    store_artifact(
        session,
        job.id,
        "assessment",
        data=_assessment(static_facts=_minimal_static_facts(address=address)),
    )
    return job


@requires_postgres
def test_copy_static_cache_matches_legacy_null_source_row(db_session):
    """``copy_static_cache`` resolves the source Contract by (address, chain).
    With the source request on mainnet but the row persisted ``chain=NULL``,
    the coalesced predicate finds it; the raw equality previously returned
    None and the copy silently produced nothing."""
    from db.models import Contract
    from db.queue import copy_static_cache, create_job
    from tests.cache_helpers import ADDR_A

    src_job = _completed_source_with_null_contract(db_session, ADDR_A, "ethereum")
    target_job = create_job(db_session, {"address": ADDR_A, "chain": "ethereum", "name": "Target"})

    new_contract_id = copy_static_cache(db_session, src_job.id, target_job.id)
    assert new_contract_id is not None
    # The source row was reassigned to the target job (copy_static_cache moves it).
    copied = db_session.query(Contract).filter(Contract.id == new_contract_id).one()
    assert copied.job_id == target_job.id
