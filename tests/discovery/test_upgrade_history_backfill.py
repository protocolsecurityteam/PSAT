"""Runs against real Postgres so uniqueness, case handling and idempotency are exercised.

Also covers the pollution guards: analyze-remaining must not enqueue backfilled rows, and coverage must link audits to
them.
"""

from __future__ import annotations

import uuid
from datetime import datetime, timezone

import pytest

from tests.conftest import requires_postgres

pytestmark = [
    requires_postgres,
    # offline: no RPC for the coverage upsert's eth_getCode bytecode-drift anchor
    pytest.mark.usefixtures("_stub_rpc_bytecode"),
]


@pytest.fixture(autouse=True)
def _stub_membership_probe(monkeypatch):
    """Stub-the-wire: the backfill's near-line probe never leaves the
    machine — tests seed code facts directly via ``_seed_code_fact``."""
    monkeypatch.setattr("services.discovery.membership_gate.probe", lambda session, contract: None)


@pytest.fixture()
def worker():
    yield None


def _backfill(session, *, protocol_id, chain, impl_addrs, current_impl_address=None):
    from services.discovery.upgrade_history import backfill_historical_impl_contracts

    backfill_historical_impl_contracts(
        session,
        protocol_id=protocol_id,
        chain=chain,
        impl_addrs=impl_addrs,
        current_impl_address=current_impl_address,
    )


def _seed_code_fact(session, addr, *, chain_id=1, block=90, absent=False):
    """Persist the W1 code-probe fact the gate requires for every promotion
    — the offline stand-in for the probe."""
    from db.models import ContractCreationWitness

    session.add(
        ContractCreationWitness(
            chain_id=chain_id,
            address=addr.lower(),
            code_probe_block=block,
            code_absent_at_probe=absent,
        )
    )
    session.commit()


def _run_pipeline(session, *, contract, artifact_data, protocol_id=None):
    """Mirrors ``static_worker._finalize_upgrade_history``."""
    from services.discovery.upgrade_history import (
        backfill_historical_impl_contracts,
        project_to_events,
    )

    stats = project_to_events(
        session,
        subject_contract_id=contract.id,
        subject_chain=contract.chain,
        artifact_data=artifact_data,
    )
    session.commit()
    pid = protocol_id if protocol_id is not None else contract.protocol_id
    if pid is not None and stats["impl_addrs"]:
        backfill_historical_impl_contracts(
            session,
            protocol_id=pid,
            chain=contract.chain,
            impl_addrs=stats["impl_addrs"],
        )
    return stats


@pytest.fixture()
def seed_protocol(db_session):
    """The default db_session cleanup misses unlinked Contracts."""
    from db.models import (
        AuditContractCoverage,
        AuditReport,
        Contract,
        Job,
        Protocol,
        UpgradeEvent,
    )

    name = f"uh-backfill-{uuid.uuid4().hex[:10]}"
    p = Protocol(name=name)
    db_session.add(p)
    db_session.commit()
    protocol_id = p.id
    try:
        yield protocol_id, name
    finally:
        db_session.rollback()
        db_session.query(AuditContractCoverage).filter_by(protocol_id=protocol_id).delete()
        contract_ids = [c.id for c in db_session.query(Contract).filter_by(protocol_id=protocol_id).all()]
        if contract_ids:
            db_session.query(UpgradeEvent).filter(UpgradeEvent.contract_id.in_(contract_ids)).delete(
                synchronize_session=False
            )
        job_ids = {c.job_id for c in db_session.query(Contract).filter_by(protocol_id=protocol_id).all() if c.job_id}
        db_session.query(Contract).filter_by(protocol_id=protocol_id).delete()
        db_session.query(AuditReport).filter_by(protocol_id=protocol_id).delete()
        if job_ids:
            db_session.query(Job).filter(Job.id.in_(job_ids)).delete(synchronize_session=False)
        db_session.query(Job).filter_by(protocol_id=protocol_id).delete()
        db_session.query(Protocol).filter_by(id=protocol_id).delete()
        db_session.commit()


@pytest.fixture()
def stub_etherscan(monkeypatch):
    """Set a value to ``_RAISE`` to raise."""
    _RAISE = object()
    names: dict[str, object] = {}

    def fake(address: str, **_kw):
        val = names.get(address.lower(), None)
        if val is _RAISE:
            raise RuntimeError("simulated etherscan outage")
        if val is None:
            return (f"StubImpl-{address[2:6]}", {})
        return (val, {})

    import services.clients.etherscan as etherscan_mod

    monkeypatch.setattr(etherscan_mod, "get_contract_info", fake)
    return types_namespace(names=names, RAISE=_RAISE)


def types_namespace(**kwargs):
    from types import SimpleNamespace

    return SimpleNamespace(**kwargs)


def _addr(n: int) -> str:
    return "0x" + hex(n)[2:].zfill(40)


def _add_contract(session, **fields):
    from db.models import Contract

    c = Contract(**fields)
    session.add(c)
    session.commit()
    return c


def test_backfill_creates_rows_as_candidates_without_evidence(db_session, seed_protocol, worker, stub_etherscan):
    """No member proxy names these impls in an UpgradeEvent and no code fact
    exists, so the rows land as NOMINATED candidates — never members."""
    from db.models import Contract

    protocol_id, _ = seed_protocol
    addrs = {_addr(0xA1), _addr(0xB2)}
    stub_etherscan.names[_addr(0xA1)] = "PoolV1"
    stub_etherscan.names[_addr(0xB2)] = "PoolV2"

    _backfill(
        db_session,
        protocol_id=protocol_id,
        chain="ethereum",
        impl_addrs=addrs,
    )

    rows = db_session.query(Contract).filter(Contract.address.in_(addrs)).all()
    assert len(rows) == 2
    for row in rows:
        assert row.protocol_id is None
        assert row.nominated_protocol_id == protocol_id
        assert "upgrade_history" in (row.discovery_sources or [])
        assert row.is_proxy is False
        assert row.job_id is None
        assert row.chain == "ethereum"
        assert row.source_verified is True  # name resolved → verified
    names = {r.contract_name for r in rows}
    assert names == {"PoolV1", "PoolV2"}


def test_backfill_is_idempotent(db_session, seed_protocol, worker, stub_etherscan):
    from db.models import Contract

    protocol_id, _ = seed_protocol
    addrs = {_addr(0xE5), _addr(0xF6)}

    _backfill(db_session, protocol_id=protocol_id, chain="ethereum", impl_addrs=addrs)
    count_after_first = db_session.query(Contract).filter_by(nominated_protocol_id=protocol_id).count()

    _backfill(db_session, protocol_id=protocol_id, chain="ethereum", impl_addrs=addrs)
    count_after_second = db_session.query(Contract).filter_by(nominated_protocol_id=protocol_id).count()

    assert count_after_first == count_after_second == 2


def test_backfill_treats_cross_chain_same_address_as_distinct(db_session, seed_protocol, worker, stub_etherscan):
    """CREATE2 repeats addresses across chains."""
    from db.models import Contract, Protocol

    our_protocol_id, _ = seed_protocol
    other = Protocol(name=f"other-chain-{uuid.uuid4().hex[:8]}")
    db_session.add(other)
    db_session.commit()
    other_id = other.id
    addr = _addr(0xABC)
    try:
        _add_contract(
            db_session,
            protocol_id=other_id,
            address=addr,
            chain="polygon",
            contract_name="PolygonDeployment",
            is_proxy=False,
            discovery_sources=["inventory"],
        )
        stub_etherscan.names[addr] = "EthereumImpl"

        _backfill(
            db_session,
            protocol_id=our_protocol_id,
            chain="ethereum",
            impl_addrs={addr},
        )

        polygon_row = db_session.query(Contract).filter_by(address=addr, chain="polygon").one()
        assert polygon_row.protocol_id == other_id
        assert polygon_row.contract_name == "PolygonDeployment"
        assert "inventory" in (polygon_row.discovery_sources or [])

        ethereum_row = db_session.query(Contract).filter_by(address=addr, chain="ethereum").one()
        assert ethereum_row.nominated_protocol_id == our_protocol_id
        assert ethereum_row.protocol_id is None
        assert ethereum_row.contract_name == "EthereumImpl"
        assert "upgrade_history" in (ethereum_row.discovery_sources or [])
    finally:
        db_session.query(Contract).filter_by(address=addr, chain="polygon").delete()
        db_session.query(Protocol).filter_by(id=other_id).delete()
        db_session.commit()


def test_backfill_degrades_gracefully_on_etherscan_failure(db_session, seed_protocol, worker, stub_etherscan):
    from db.models import Contract

    protocol_id, _ = seed_protocol
    addr_ok = _addr(0x111)
    addr_fail = _addr(0x222)
    stub_etherscan.names[addr_ok] = "GoodImpl"
    stub_etherscan.names[addr_fail] = stub_etherscan.RAISE

    _backfill(
        db_session,
        protocol_id=protocol_id,
        chain="ethereum",
        impl_addrs={addr_ok, addr_fail},
    )

    ok = db_session.query(Contract).filter_by(address=addr_ok).one()
    assert ok.contract_name == "GoodImpl"
    assert ok.source_verified is True

    bad = db_session.query(Contract).filter_by(address=addr_fail).one()
    assert bad.contract_name == "UnknownImpl"
    assert bad.source_verified is False
    assert "upgrade_history" in (bad.discovery_sources or [])


def test_run_upgrade_history_writes_events_and_backfills_impls(
    db_session, seed_protocol, worker, stub_etherscan, monkeypatch
):
    from db.models import Contract, Job, JobStage, JobStatus, UpgradeEvent

    protocol_id, _ = seed_protocol

    job = Job(
        id=uuid.uuid4(),
        address=_addr(0x1),
        status=JobStatus.processing,
        stage=JobStage.resolution,
        protocol_id=protocol_id,
    )
    db_session.add(job)
    db_session.commit()
    proxy = _add_contract(
        db_session,
        protocol_id=protocol_id,
        address=_addr(0x1),
        chain="ethereum",
        contract_name="ProxyShell",
        is_proxy=True,
        job_id=job.id,
    )

    impl_a = _addr(0xA)
    impl_b = _addr(0xB)
    stub_etherscan.names[impl_a] = "ImplA"
    stub_etherscan.names[impl_b] = "ImplB"
    _seed_code_fact(db_session, impl_a)
    _seed_code_fact(db_session, impl_b)

    artifact = {
        "proxies": {
            proxy.address: {
                "proxy_address": proxy.address,
                "events": [
                    {
                        "event_type": "upgraded",
                        "implementation": impl_a,
                        "block_number": 100,
                        "tx_hash": "0x" + "a" * 64,
                    },
                    {
                        "event_type": "upgraded",
                        "implementation": impl_b,
                        "block_number": 200,
                        "tx_hash": "0x" + "b" * 64,
                    },
                ],
            }
        }
    }

    _run_pipeline(db_session, contract=proxy, artifact_data=artifact)

    events = db_session.query(UpgradeEvent).filter_by(contract_id=proxy.id).all()
    assert len(events) == 2
    assert {e.new_impl for e in events} == {impl_a, impl_b}

    impl_rows = db_session.query(Contract).filter(Contract.address.in_({impl_a, impl_b})).all()
    assert len(impl_rows) == 2
    for row in impl_rows:
        assert "upgrade_history" in (row.discovery_sources or [])
        assert row.protocol_id == protocol_id
        assert row.job_id is None
        assert row.is_proxy is False
    assert {r.contract_name for r in impl_rows} == {"ImplA", "ImplB"}


def test_run_upgrade_history_keys_events_to_proxy_not_subject(
    db_session, seed_protocol, worker, stub_etherscan, monkeypatch
):
    """A non-proxy subject (EtherFiRewardsRouter) got 20+ phantom events, rendering non-existent audit eras."""
    from db.models import Contract, Job, JobStage, JobStatus, UpgradeEvent

    protocol_id, _ = seed_protocol

    # The static worker snapshots dependencies, including other contracts' proxies.
    subject_job = Job(
        id=uuid.uuid4(),
        address=_addr(0xAAA),
        status=JobStatus.processing,
        stage=JobStage.resolution,
        protocol_id=protocol_id,
    )
    db_session.add(subject_job)
    db_session.commit()
    subject = _add_contract(
        db_session,
        protocol_id=protocol_id,
        address=_addr(0xAAA),
        chain="ethereum",
        contract_name="RewardsRouter",
        is_proxy=False,
        job_id=subject_job.id,
    )

    proxy_a = _add_contract(
        db_session,
        protocol_id=protocol_id,
        address=_addr(0xB01),
        chain="ethereum",
        contract_name="LiquidityPoolProxy",
        is_proxy=True,
    )
    proxy_b = _add_contract(
        db_session,
        protocol_id=protocol_id,
        address=_addr(0xB02),
        chain="ethereum",
        contract_name="EethProxy",
        is_proxy=True,
    )

    impl_1 = _addr(0xC01)
    impl_2 = _addr(0xC02)
    stub_etherscan.names[impl_1] = "Impl1"
    stub_etherscan.names[impl_2] = "Impl2"

    artifact = {
        "proxies": {
            proxy_a.address: {
                "proxy_address": proxy_a.address,
                "events": [
                    {
                        "event_type": "upgraded",
                        "implementation": impl_1,
                        "block_number": 100,
                        "tx_hash": "0x" + "1" * 64,
                    },
                ],
            },
            proxy_b.address: {
                "proxy_address": proxy_b.address,
                "events": [
                    {
                        "event_type": "upgraded",
                        "implementation": impl_2,
                        "block_number": 200,
                        "tx_hash": "0x" + "2" * 64,
                    },
                ],
            },
        }
    }

    _run_pipeline(db_session, contract=subject, artifact_data=artifact)

    subject_events = db_session.query(UpgradeEvent).filter_by(contract_id=subject.id).all()
    assert subject_events == []

    events_a = db_session.query(UpgradeEvent).filter_by(contract_id=proxy_a.id).all()
    events_b = db_session.query(UpgradeEvent).filter_by(contract_id=proxy_b.id).all()
    assert len(events_a) == 1 and events_a[0].new_impl == impl_1
    assert len(events_b) == 1 and events_b[0].new_impl == impl_2

    impls = db_session.query(Contract).filter(Contract.address.in_({impl_1, impl_2})).all()
    assert {r.contract_name for r in impls} == {"Impl1", "Impl2"}


def test_analyze_remaining_skips_backfilled_historical_impls(api_client, db_session, seed_protocol, stub_etherscan):
    from db.models import Contract

    protocol_id, name = seed_protocol

    _add_contract(
        db_session,
        protocol_id=protocol_id,
        address=_addr(0x777),
        chain="ethereum",
        contract_name="Normal",
        is_proxy=False,
        discovery_sources=["inventory"],
    )
    _add_contract(
        db_session,
        protocol_id=protocol_id,
        address=_addr(0x888),
        chain="ethereum",
        contract_name="OldImpl",
        is_proxy=False,
        discovery_sources=["upgrade_history"],
    )

    r = api_client.post(f"/api/company/{name}/analyze-remaining")
    assert r.status_code == 200, r.text
    body = r.json()
    assert body["queued"] == 1
    assert body["jobs"][0]["address"] == _addr(0x777)

    db_session.expire_all()
    normal_row = db_session.query(Contract).filter_by(address=_addr(0x777)).one()
    if normal_row.job_id:
        from db.models import Job

        db_session.query(Job).filter_by(id=normal_row.job_id).delete()
        normal_row.job_id = None
        db_session.commit()


def test_coverage_matcher_links_audit_to_backfilled_impl(db_session, seed_protocol):
    """The motivation for the backfill."""
    from db.models import AuditContractCoverage, AuditReport, UpgradeEvent
    from services.audits.coverage import upsert_coverage_for_protocol

    protocol_id, _ = seed_protocol

    proxy = _add_contract(
        db_session,
        protocol_id=protocol_id,
        address=_addr(0x1),
        chain="ethereum",
        contract_name="Proxy",
        is_proxy=True,
    )
    historical_impl = _add_contract(
        db_session,
        protocol_id=protocol_id,
        address=_addr(0xAA),
        chain="ethereum",
        contract_name="HistoricalImpl",
        is_proxy=False,
        discovery_sources=["upgrade_history"],
    )
    db_session.add(
        UpgradeEvent(
            contract_id=proxy.id,
            proxy_address=proxy.address,
            new_impl=historical_impl.address,
            block_number=100,
            timestamp=datetime(2024, 1, 1, tzinfo=timezone.utc),
            tx_hash="0x" + "1" * 64,
        )
    )
    audit = AuditReport(
        protocol_id=protocol_id,
        url=f"https://example.com/{uuid.uuid4().hex}.pdf",
        auditor="X",
        title="T",
        date="2024-03-01",
        scope_extraction_status="success",
        scope_contracts=["HistoricalImpl"],
    )
    db_session.add(audit)
    db_session.commit()

    inserted = upsert_coverage_for_protocol(db_session, protocol_id)
    db_session.commit()
    assert inserted == 1

    row = db_session.query(AuditContractCoverage).filter_by(protocol_id=protocol_id).one()
    assert row.contract_id == historical_impl.id
    assert row.match_type == "impl_era"
    assert row.match_confidence == "high"
    assert row.covered_from_block == 100


def test_backfill_triggers_coverage_refresh_for_created_rows(db_session, seed_protocol, worker, stub_etherscan):
    """Scope extraction ran before the impl row existed, so the backfill must upsert coverage itself ("RoleRegistry
    shows unaudited").
    """
    from db.models import (
        AuditContractCoverage,
        AuditReport,
        Contract,
        UpgradeEvent,
    )
    from services.audits.coverage import upsert_coverage_for_audit

    protocol_id, _ = seed_protocol

    proxy = _add_contract(
        db_session,
        protocol_id=protocol_id,
        address=_addr(0x100),
        chain="ethereum",
        contract_name="Proxy",
        is_proxy=True,
    )
    impl_addr = _addr(0xAAAA)
    db_session.add(
        UpgradeEvent(
            contract_id=proxy.id,
            proxy_address=proxy.address,
            new_impl=impl_addr,
            block_number=100,
            timestamp=datetime(2024, 1, 1, tzinfo=timezone.utc),
            tx_hash="0x" + "a" * 64,
        )
    )

    audit = AuditReport(
        protocol_id=protocol_id,
        url=f"https://example.com/{uuid.uuid4().hex}.pdf",
        auditor="Certora",
        title="Reaudit Core Contracts",
        date="2024-03-01",
        scope_extraction_status="success",
        scope_contracts=["HistoricalImpl"],
    )
    db_session.add(audit)
    db_session.commit()

    inserted = upsert_coverage_for_audit(db_session, audit.id)
    db_session.commit()
    assert inserted == 0
    assert db_session.query(AuditContractCoverage).filter_by(protocol_id=protocol_id).count() == 0

    # Late backfill; code fact seeded so the gate can promote.
    stub_etherscan.names[impl_addr] = "HistoricalImpl"
    _seed_code_fact(db_session, impl_addr)
    _backfill(
        db_session,
        protocol_id=protocol_id,
        chain="ethereum",
        impl_addrs={impl_addr},
    )
    db_session.commit()

    created = db_session.query(Contract).filter_by(protocol_id=protocol_id, address=impl_addr).one()
    assert created.contract_name == "HistoricalImpl"
    assert "upgrade_history" in (created.discovery_sources or [])

    rows = db_session.query(AuditContractCoverage).filter_by(protocol_id=protocol_id, contract_id=created.id).all()
    assert len(rows) == 1, (
        "backfill created the Contract row but did not refresh coverage — audit ↔ historical-impl link is missing"
    )
    r = rows[0]
    assert r.audit_report_id == audit.id
    assert r.matched_name == "HistoricalImpl"
    assert r.match_type == "impl_era"
    assert r.match_confidence == "high"
    assert r.covered_from_block == 100
    assert r.covered_to_block is None


def test_backfill_coverage_refresh_covers_adopted_rows_too(db_session, seed_protocol, worker, stub_etherscan):
    from db.models import AuditContractCoverage, AuditReport, UpgradeEvent
    from services.audits.coverage import upsert_coverage_for_audit

    protocol_id, _ = seed_protocol

    proxy = _add_contract(
        db_session,
        protocol_id=protocol_id,
        address=_addr(0x200),
        chain="ethereum",
        contract_name="Proxy2",
        is_proxy=True,
    )
    orphan_addr = _addr(0xBBBB)
    orphan = _add_contract(
        db_session,
        protocol_id=None,
        address=orphan_addr,
        chain="ethereum",
        contract_name="OrphanImpl",
        is_proxy=False,
    )
    db_session.add(
        UpgradeEvent(
            contract_id=proxy.id,
            proxy_address=proxy.address,
            new_impl=orphan_addr,
            block_number=50,
            timestamp=datetime(2024, 1, 1, tzinfo=timezone.utc),
            tx_hash="0x" + "b" * 64,
        )
    )
    audit = AuditReport(
        protocol_id=protocol_id,
        url=f"https://example.com/{uuid.uuid4().hex}.pdf",
        auditor="Nethermind",
        title="Adoption Path",
        date="2024-04-01",
        scope_extraction_status="success",
        scope_contracts=["OrphanImpl"],
    )
    db_session.add(audit)
    db_session.commit()

    inserted = upsert_coverage_for_audit(db_session, audit.id)
    db_session.commit()
    assert inserted == 0

    _seed_code_fact(db_session, orphan_addr)
    _backfill(
        db_session,
        protocol_id=protocol_id,
        chain="ethereum",
        impl_addrs={orphan_addr},
    )
    db_session.commit()

    db_session.refresh(orphan)
    assert orphan.protocol_id == protocol_id  # adopted
    assert "upgrade_history" in (orphan.discovery_sources or [])

    rows = db_session.query(AuditContractCoverage).filter_by(protocol_id=protocol_id, contract_id=orphan.id).all()
    assert len(rows) == 1, (
        "adoption path didn't refresh coverage — orphan was pulled into "
        "the protocol but the audit link was not materialized"
    )
    assert rows[0].audit_report_id == audit.id
    assert rows[0].matched_name == "OrphanImpl"


def test_run_upgrade_history_persists_event_timestamp(db_session, seed_protocol, worker, stub_etherscan, monkeypatch):
    """Without the timestamp ``ImplWindow.from_ts`` is None and every window is skipped ("LiquidityPool shows no
    audit coverage").
    """
    from db.models import Contract, Job, JobStage, JobStatus, UpgradeEvent

    protocol_id, _ = seed_protocol

    proxy_job = Job(
        id=uuid.uuid4(),
        address=_addr(0x1111),
        status=JobStatus.processing,
        stage=JobStage.resolution,
        protocol_id=protocol_id,
    )
    db_session.add(proxy_job)
    db_session.commit()
    proxy = _add_contract(
        db_session,
        protocol_id=protocol_id,
        address=_addr(0x1111),
        chain="ethereum",
        contract_name="ProxyShell",
        is_proxy=True,
        job_id=proxy_job.id,
    )

    impl_addr = _addr(0xFEE1)
    stub_etherscan.names[impl_addr] = "LiquidityPool"

    unix_ts = 1700000000
    expected_dt = datetime(2023, 11, 14, 22, 13, 20, tzinfo=timezone.utc)

    artifact = {
        "proxies": {
            proxy.address: {
                "proxy_address": proxy.address,
                "events": [
                    {
                        "event_type": "upgraded",
                        "implementation": impl_addr,
                        "block_number": 24671560,
                        "timestamp": unix_ts,
                        "tx_hash": "0x" + "a" * 64,
                    },
                ],
            }
        }
    }

    _run_pipeline(db_session, contract=proxy, artifact_data=artifact)

    events = db_session.query(UpgradeEvent).filter_by(contract_id=proxy.id).all()
    assert len(events) == 1
    evt = events[0]
    assert evt.timestamp is not None, (
        "UpgradeEvent.timestamp was not persisted — the artifact carries "
        "timestamp (unix seconds) but the projection writes only block_number + tx_hash"
    )
    assert evt.timestamp == expected_dt

    impl_contract = db_session.query(Contract).filter_by(address=impl_addr).one()
    from services.audits.coverage import _compute_impl_windows_for_contract

    windows = _compute_impl_windows_for_contract(db_session, impl_contract)
    assert len(windows) == 1
    assert windows[0].from_ts is not None
    assert windows[0].from_ts == expected_dt


def test_run_upgrade_history_handles_missing_timestamp(db_session, seed_protocol, worker, stub_etherscan, monkeypatch):
    from db.models import Job, JobStage, JobStatus, UpgradeEvent

    protocol_id, _ = seed_protocol

    proxy_job = Job(
        id=uuid.uuid4(),
        address=_addr(0x2222),
        status=JobStatus.processing,
        stage=JobStage.resolution,
        protocol_id=protocol_id,
    )
    db_session.add(proxy_job)
    db_session.commit()
    proxy = _add_contract(
        db_session,
        protocol_id=protocol_id,
        address=_addr(0x2222),
        chain="ethereum",
        contract_name="ProxyShell",
        is_proxy=True,
        job_id=proxy_job.id,
    )

    impl_addr = _addr(0xFEE2)
    stub_etherscan.names[impl_addr] = "LiquidityPool"

    artifact = {
        "proxies": {
            proxy.address: {
                "proxy_address": proxy.address,
                "events": [
                    {
                        "event_type": "upgraded",
                        "implementation": impl_addr,
                        "block_number": 100,
                        "tx_hash": "0x" + "c" * 64,
                    },
                ],
            }
        }
    }

    _run_pipeline(db_session, contract=proxy, artifact_data=artifact)

    events = db_session.query(UpgradeEvent).filter_by(contract_id=proxy.id).all()
    assert len(events) == 1
    assert events[0].timestamp is None


# ---------------------------------------------------------------------------
# 7. Regression — backfill enqueues verifiable rows for the deferred verify
#    worker instead of running source-equivalence inline (#82)
# ---------------------------------------------------------------------------


def test_backfill_coverage_refresh_defers_source_equivalence(
    db_session, seed_protocol, worker, stub_etherscan, monkeypatch
):
    """#82: inline verify fanned out Etherscan + GitHub bursts that 429'd the global limit; rows now land 'pending'."""
    from db.models import (
        AuditContractCoverage,
        AuditReport,
        Contract,
        UpgradeEvent,
    )

    protocol_id, _ = seed_protocol

    proxy = _add_contract(
        db_session,
        protocol_id=protocol_id,
        address=_addr(0x3001),
        chain="ethereum",
        contract_name="ProxyShell",
        is_proxy=True,
    )
    impl_addr = _addr(0xF001)
    stub_etherscan.names[impl_addr] = "LiquidityPool"
    db_session.add(
        UpgradeEvent(
            contract_id=proxy.id,
            proxy_address=proxy.address,
            new_impl=impl_addr,
            block_number=24671560,
            timestamp=datetime(2026, 3, 16, tzinfo=timezone.utc),
            tx_hash="0x" + "a" * 64,
        )
    )
    # Otherwise the row is terminal-stamped and the worker skips it.
    audit = AuditReport(
        protocol_id=protocol_id,
        url=f"https://example.com/{uuid.uuid4().hex}.pdf",
        auditor="Cantina",
        title="LiquidityPool Pre-Deployment Review",
        date="2026-02-01",
        scope_extraction_status="success",
        scope_contracts=["LiquidityPool"],
        reviewed_commits=["3b6b81b", "7fc5100"],
        source_repo="etherfi-protocol/smart-contracts",
    )
    db_session.add(audit)
    db_session.commit()

    # Trip-wires against reintroducing inline verify.
    import services.audits.source_equivalence as se_mod

    inline_calls: list[str] = []

    def _trip(name: str):
        def _f(*_a, **_kw):
            inline_calls.append(name)
            raise AssertionError(
                f"{name} called inline during backfill — verify must be deferred to CoverageVerifyWorker (#82)"
            )

        return _f

    monkeypatch.setattr(se_mod, "verify_audit_covers_impl", _trip("verify_audit_covers_impl"))
    monkeypatch.setattr(se_mod, "fetch_etherscan_source_files", _trip("fetch_etherscan_source_files"))

    _seed_code_fact(db_session, impl_addr)
    _backfill(
        db_session,
        protocol_id=protocol_id,
        chain="ethereum",
        impl_addrs={impl_addr},
    )
    db_session.commit()

    impl_row = db_session.query(Contract).filter_by(address=impl_addr).one()
    rows = (
        db_session.query(AuditContractCoverage)
        .filter_by(protocol_id=protocol_id, contract_id=impl_row.id, audit_report_id=audit.id)
        .all()
    )
    assert len(rows) == 1, (
        "backfill created the Contract row but did not enqueue the audit ↔ "
        "impl pair for verification — the deferred-verify hand-off is broken"
    )
    r = rows[0]
    # A NOW() stamp on a never-attempted row would lie.
    assert r.equivalence_status == "pending", (
        f"verifiable audit landed with status={r.equivalence_status!r}, expected 'pending' for deferred verification"
    )
    assert r.equivalence_checked_at is None
    assert inline_calls == [], (
        f"inline source-equivalence ran during backfill: {inline_calls} — "
        "verify_source_equivalence=False contract was not honored"
    )
