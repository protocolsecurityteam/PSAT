"""Allowlist gating at internal work-origination sites. ``require_supported_chain`` guards the
router edges, but the selection worker's analysis-child spawns and monitoring auto-enroll enforced nothing, so a
company scan whose DeFiLlama evidence named a non-enabled chain spawned analysis jobs and
``monitored_contracts`` rows there. Pinned: off-allowlist discoveries keep their evidence (Contract rows,
``Protocol.chains``) but originate no job or monitoring row; widening ``PSAT_SUPPORTED_CHAIN_IDS`` lets the
evidence be picked up; mainnet-only default ``{1}`` behaves as before. Only the wire is stubbed, never the workers.
"""

from __future__ import annotations

import uuid
from unittest.mock import patch

import pytest
from sqlalchemy import select

from tests.conftest import requires_postgres
from workers.base import JobHandledDirectly

pytestmark = [requires_postgres]


# ---------------------------------------------------------------------------
# chain_enabled unit coverage
# ---------------------------------------------------------------------------


@pytest.mark.parametrize(
    ("allowlist", "expected"),
    [
        # Unset allowlist = mainnet-only, so only chain 1 (and the NULL≡mainnet coalescing of
        # None/empty) is enabled.
        pytest.param(
            None,
            {
                1: True,
                "ethereum": True,
                "mainnet": True,
                None: True,  # NULL≡mainnet
                "": True,
                8453: False,
                "base": False,
                "optimism": False,
            },
            id="mainnet_default",
        ),
        pytest.param(
            "1,8453",
            {"base": True, 8453: True, "8453": True, "optimism": False, 10: False},
            id="widened_allowlist",
        ),
        # A non-empty but unresolvable name returns False rather than coalescing to mainnet: an unknown
        # chain can never be 'enabled'.
        pytest.param("1", {"not-a-real-chain": False}, id="unknown_chain_never_enabled"),
    ],
)
def test_chain_enabled(monkeypatch, allowlist, expected):
    from utils.chains import chain_enabled

    if allowlist is None:
        monkeypatch.delenv("PSAT_SUPPORTED_CHAIN_IDS", raising=False)
    else:
        monkeypatch.setenv("PSAT_SUPPORTED_CHAIN_IDS", allowlist)
    assert {chain: chain_enabled(chain) for chain in expected} == expected


# ---------------------------------------------------------------------------
# Selection worker — analysis-child spawns
# ---------------------------------------------------------------------------


@pytest.fixture(autouse=True)
def _stub_activity_fetch(monkeypatch):
    from services.discovery import activity as activity_module

    def fake_etherscan_get(module, action, **params):
        return {"result": [{"timeStamp": "1700000000"}]}

    monkeypatch.setattr(activity_module.etherscan, "get", fake_etherscan_get)


def _add_contract(session, *, protocol_id, address, chain, confidence=0.9):
    from db.models import Contract

    row = Contract(
        protocol_id=protocol_id,
        address=address.lower(),
        chain=chain,
        contract_name=f"c_{address[2:8]}",
        confidence=confidence,
        discovery_sources=["defillama"],
    )
    session.add(row)
    session.commit()
    session.refresh(row)
    return row


def _add_selection_job(session, *, protocol_id, company, analyze_limit=5):
    from db.models import Job, JobStage, JobStatus

    job = Job(
        company=company,
        protocol_id=protocol_id,
        stage=JobStage.selection,
        status=JobStatus.queued,
        request={
            "company": company,
            "protocol_id": protocol_id,
            "analyze_limit": analyze_limit,
            "rpc_url": "https://rpc.example",
            "chain": "ethereum",
        },
    )
    session.add(job)
    session.commit()
    session.refresh(job)
    return job


@pytest.fixture()
def _seed(db_session):
    from db.models import Contract, Job, Protocol

    name = f"allowgate-{uuid.uuid4().hex[:10]}"
    proto = Protocol(name=name)
    db_session.add(proto)
    db_session.commit()
    pid = proto.id

    def addr():
        return ("0x" + uuid.uuid4().hex + "0" * 8).lower()

    try:
        yield pid, name, addr
    finally:
        db_session.rollback()
        db_session.query(Job).filter_by(protocol_id=pid).delete()
        db_session.query(Contract).filter_by(protocol_id=pid).delete()
        db_session.query(Protocol).filter_by(id=pid).delete()
        db_session.commit()


def _run_selection(db_session, pid, company):
    from workers.selection_worker import SelectionWorker

    job = _add_selection_job(db_session, protocol_id=pid, company=company)
    with patch("signal.signal"):
        worker = SelectionWorker()
    with pytest.raises(JobHandledDirectly):
        worker.process(db_session, job)
    db_session.refresh(job)
    from db.models import Job

    children = (
        db_session.execute(select(Job).where(Job.request["parent_job_id"].as_string() == str(job.id))).scalars().all()
    )
    return {c.address for c in children}


@requires_postgres
def test_selection_gates_off_allowlist_chain_but_spawns_enabled(db_session, monkeypatch, _seed):
    """With base enabled but optimism not, an inventory that mixes both spawns a
    base child and skips the optimism one — its Contract evidence is retained."""
    from db.models import Contract

    monkeypatch.setenv("PSAT_SUPPORTED_CHAIN_IDS", "1,8453")
    pid, company, addr = _seed

    base_addr = addr()
    op_addr = addr()
    _add_contract(db_session, protocol_id=pid, address=base_addr, chain="base")
    _add_contract(db_session, protocol_id=pid, address=op_addr, chain="optimism")

    spawned = _run_selection(db_session, pid, company)

    assert base_addr in spawned
    assert op_addr not in spawned

    op_row = db_session.execute(
        select(Contract).where(Contract.address == op_addr, Contract.chain == "optimism")
    ).scalar_one()
    assert op_row is not None


@requires_postgres
def test_selection_widened_allowlist_picks_up_retained_evidence(db_session, monkeypatch, _seed):
    """The same optimism Contract that was skipped spawns once optimism is added
    to the allowlist — proving the retained evidence is sufficient for a future
    scan to pick it up."""
    monkeypatch.setenv("PSAT_SUPPORTED_CHAIN_IDS", "1,8453,10")
    pid, company, addr = _seed

    op_addr = addr()
    _add_contract(db_session, protocol_id=pid, address=op_addr, chain="optimism")

    spawned = _run_selection(db_session, pid, company)
    assert op_addr in spawned


# ---------------------------------------------------------------------------
# Auto-enrollment — monitored_contracts / watched_proxies rows
# ---------------------------------------------------------------------------


@requires_postgres
def test_enrollment_gates_off_allowlist_chain_within_one_protocol(db_session, monkeypatch):
    """A single protocol whose contracts span base (enabled) and optimism (not)
    enrolls only the base contract — no MonitoredContract row is created for the
    optimism deployment."""
    from db.models import Contract, Job, JobStage, JobStatus, MonitoredContract, Protocol
    from services.monitoring.enrollment import enroll_protocol_contracts

    monkeypatch.setenv("PSAT_SUPPORTED_CHAIN_IDS", "1,8453")
    monkeypatch.setattr(
        "services.monitoring.enrollment.rpc_request",
        lambda *a, **k: "0x100",
    )

    proto = Protocol(name=f"__enrollgate_{uuid.uuid4().hex[:8]}__")
    db_session.add(proto)
    db_session.flush()

    base_addr = ("0x" + "b" * 40).lower()
    op_addr = "0x" + "0" * 39 + "a"  # distinct, valid optimism address
    for a, chain in ((base_addr, "base"), (op_addr, "optimism")):
        db_session.add(Contract(address=a, chain=chain, protocol_id=proto.id, contract_name=f"C_{chain}"))
        db_session.add(Job(address=a, protocol_id=proto.id, status=JobStatus.completed, stage=JobStage.done))
    db_session.commit()

    enroll_protocol_contracts(db_session, proto.id, "http://seed", "ethereum")

    enrolled = {
        (mc.address, mc.chain)
        for mc in db_session.execute(
            select(MonitoredContract).where(MonitoredContract.protocol_id == proto.id)
        ).scalars()
    }
    assert (base_addr, "base") in enrolled
    assert (op_addr, "optimism") not in enrolled

    db_session.query(MonitoredContract).filter_by(protocol_id=proto.id).delete()
    db_session.query(Job).filter_by(protocol_id=proto.id).delete()
    db_session.query(Contract).filter_by(protocol_id=proto.id).delete()
    db_session.query(Protocol).filter_by(id=proto.id).delete()
    db_session.commit()
