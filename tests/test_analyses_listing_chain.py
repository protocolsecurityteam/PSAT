"""Chain-awareness of the ``/api/analyses`` listing for CREATE2 twins.

A single address deployed on two chains (a CREATE2 twin) has one completed
Job and one Contract row per chain. The listing must pair each job with its
*own* chain's Contract row and hide/fold impls only within a chain — never
let one chain's metadata (rank_score, name, proxy_type, implementation) or
impl entry bleed into the other chain's listing entry.
"""

from __future__ import annotations

import sys
from datetime import datetime, timedelta, timezone
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from tests.conftest import requires_postgres  # noqa: E402

ADDR = "0x1111111111111111111111111111111111111111"
PROXY = "0x2222222222222222222222222222222222222222"
IMPL = "0x3333333333333333333333333333333333333333"


def _seed_job(db_session, *, address, chain_id, is_proxy=False, request=None, updated_at):
    from db.models import Job, JobStage, JobStatus

    job = Job(
        address=address,
        chain_id=chain_id,
        request=request or {"address": address},
        status=JobStatus.completed,
        stage=JobStage.done,
        is_proxy=is_proxy,
        created_at=updated_at,
        updated_at=updated_at,
    )
    db_session.add(job)
    db_session.flush()
    return job


def _seed_contract(db_session, job, *, address, chain, **kw):
    from db.models import Contract

    contract = Contract(
        job_id=job.id,
        address=address,
        chain=chain,
        source_verified=True,
        **kw,
    )
    db_session.add(contract)
    db_session.flush()
    return contract


@requires_postgres
def test_twin_listing_entries_carry_own_chain_metadata(api_client, db_session):
    """Two non-proxy jobs at one address on ethereum + base each surface with
    their own chain's rank_score and contract_name — no cross-chain bleed."""
    now = datetime.now(timezone.utc)
    j_eth = _seed_job(db_session, address=ADDR, chain_id=1, request={"chain": "ethereum"}, updated_at=now)
    j_base = _seed_job(
        db_session, address=ADDR, chain_id=8453, request={"chain": "base"}, updated_at=now - timedelta(hours=1)
    )
    _seed_contract(db_session, j_eth, address=ADDR, chain="ethereum", contract_name="VaultEth", rank_score=0.9)
    _seed_contract(db_session, j_base, address=ADDR, chain="base", contract_name="VaultBase", rank_score=0.1)
    db_session.commit()

    resp = api_client.get("/api/analyses")
    assert resp.status_code == 200
    entries = {e["chain"]: e for e in resp.json() if e["address"] == ADDR}

    assert set(entries) == {"ethereum", "base"}
    assert entries["ethereum"]["contract_name"] == "VaultEth"
    assert entries["ethereum"]["rank_score"] == 0.9
    assert entries["base"]["contract_name"] == "VaultBase"
    assert entries["base"]["rank_score"] == 0.1


@requires_postgres
def test_twin_proxy_impl_fold_stays_within_chain(api_client, db_session):
    """A proxy/impl twin folds each proxy with its own chain's impl — the
    ethereum proxy must not display the base impl (and vice versa)."""
    now = datetime.now(timezone.utc)
    # ethereum impl newest, base impl oldest → base impl is last in the
    # updated_at-desc iteration, so the buggy last-wins fold would attach
    # the base impl to *both* proxies.
    p_eth = _seed_job(
        db_session, address=PROXY, chain_id=1, is_proxy=True, request={"chain": "ethereum"}, updated_at=now
    )
    i_eth = _seed_job(
        db_session,
        address=IMPL,
        chain_id=1,
        request={"chain": "ethereum", "address": IMPL, "proxy_address": PROXY},
        updated_at=now - timedelta(minutes=1),
    )
    p_base = _seed_job(
        db_session,
        address=PROXY,
        chain_id=8453,
        is_proxy=True,
        request={"chain": "base"},
        updated_at=now - timedelta(hours=1),
    )
    i_base = _seed_job(
        db_session,
        address=IMPL,
        chain_id=8453,
        request={"chain": "base", "address": IMPL, "proxy_address": PROXY},
        updated_at=now - timedelta(hours=2),
    )
    _seed_contract(
        db_session, p_eth, address=PROXY, chain="ethereum", is_proxy=True, proxy_type="eip1967", implementation=IMPL
    )
    _seed_contract(db_session, i_eth, address=IMPL, chain="ethereum", contract_name="EthImpl", rank_score=0.8)
    _seed_contract(
        db_session, p_base, address=PROXY, chain="base", is_proxy=True, proxy_type="eip1967", implementation=IMPL
    )
    _seed_contract(db_session, i_base, address=IMPL, chain="base", contract_name="BaseImpl", rank_score=0.05)
    db_session.commit()

    resp = api_client.get("/api/analyses")
    assert resp.status_code == 200
    entries = {e["chain"]: e for e in resp.json() if str(e.get("proxy_address_display") or "").lower() == PROXY}

    assert set(entries) == {"ethereum", "base"}
    assert entries["ethereum"]["display_name"] == "EthImpl"
    assert entries["base"]["display_name"] == "BaseImpl"


@requires_postgres
def test_proxy_hidden_when_impl_completed_only_on_other_chain(api_client, db_session):
    """An ethereum proxy whose impl completed only on *base* stays hidden —
    the presence of a base impl job must not un-hide the ethereum proxy."""
    now = datetime.now(timezone.utc)
    p_eth = _seed_job(
        db_session, address=PROXY, chain_id=1, is_proxy=True, request={"chain": "ethereum"}, updated_at=now
    )
    # A standalone base job exists at IMPL (not an impl-of-this-proxy); there
    # is no ethereum impl job. It must not un-hide the ethereum proxy.
    i_base = _seed_job(
        db_session,
        address=IMPL,
        chain_id=8453,
        request={"chain": "base", "address": IMPL},
        updated_at=now - timedelta(hours=1),
    )
    _seed_contract(
        db_session, p_eth, address=PROXY, chain="ethereum", is_proxy=True, proxy_type="eip1967", implementation=IMPL
    )
    _seed_contract(db_session, i_base, address=IMPL, chain="base", contract_name="BaseImpl", rank_score=0.05)
    db_session.commit()

    resp = api_client.get("/api/analyses")
    assert resp.status_code == 200
    body = resp.json()

    # The ethereum proxy at PROXY has no completed ethereum impl → hidden.
    eth_proxy = [e for e in body if e["address"] == PROXY and e["chain"] == "ethereum"]
    assert eth_proxy == []
