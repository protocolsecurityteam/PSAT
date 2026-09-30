from __future__ import annotations

from datetime import datetime, timedelta, timezone

from tests.conftest import requires_postgres

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
    now = datetime.now(timezone.utc)
    # The base impl is last in updated_at-desc order, so a last-wins fold would attach it to both proxies.
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
    now = datetime.now(timezone.utc)
    p_eth = _seed_job(
        db_session, address=PROXY, chain_id=1, is_proxy=True, request={"chain": "ethereum"}, updated_at=now
    )
    # A standalone base job at IMPL must not un-hide the ethereum proxy.
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

    eth_proxy = [e for e in body if e["address"] == PROXY and e["chain"] == "ethereum"]
    assert eth_proxy == []
