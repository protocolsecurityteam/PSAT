"""Integration tests for the historical-impl backfill.

Exercises the artifact → ``UpgradeEvent`` projection and the historical
impl ``Contract`` backfill against a real test Postgres so the SQL
uniqueness constraints, case handling, and idempotency all run.
Etherscan is stubbed — every test monkeypatches
``utils.etherscan.get_contract_info`` so nothing leaves the machine.

The actual functions under test live in
``services.discovery.upgrade_history``:
  - ``project_to_events`` — artifact dict → UpgradeEvent rows.
  - ``backfill_historical_impl_contracts`` — ensures a Contract row
    exists for every historical impl address.
The ``_run_pipeline`` helper below wires them together the same way
``static_worker._resolve_upgrade_history`` does in production.

Also covers the two pollution-guard consumers:
  - ``POST /api/company/{name}/analyze-remaining`` must NOT enqueue
    analysis jobs for backfilled rows.
  - ``services.audits.coverage.upsert_coverage_for_protocol`` must
    link audits to backfilled historical impls (the whole point of
    creating the rows in the first place).
"""

from __future__ import annotations

import sys
import uuid
from datetime import datetime, timezone
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from tests.conftest import requires_postgres  # noqa: E402

pytestmark = [requires_postgres]


# ---------------------------------------------------------------------------
# Shared fixtures
# ---------------------------------------------------------------------------


@pytest.fixture()
def worker():
    """No-op fixture kept for source-compatibility with existing tests.

    The artifact → events projection no longer lives on the worker; tests
    call the service-level functions directly via ``_run_pipeline`` /
    ``backfill_historical_impl_contracts``. Yielded value isn't used.
    """
    yield None


def _backfill(session, *, protocol_id, chain, impl_addrs, parent_proxy_sources=None):
    """Direct call into the backfill helper, kept short for test ergonomics.

    ``parent_proxy_sources`` defaults to ``['inventory']`` (high-
    confidence) so tests written before the ownership gate keep their
    semantics. Tests of the gate itself pass a low-confidence value
    like ``['dapp_crawl']`` explicitly.
    """
    from services.discovery.upgrade_history import backfill_historical_impl_contracts

    backfill_historical_impl_contracts(
        session,
        protocol_id=protocol_id,
        chain=chain,
        impl_addrs=impl_addrs,
        parent_proxy_sources=parent_proxy_sources if parent_proxy_sources is not None else ["inventory"],
    )


def _run_pipeline(session, *, contract, artifact_data, protocol_id=None):
    """Project an artifact into UpgradeEvent rows + backfill impl Contracts.

    Mirrors what ``static_worker._resolve_upgrade_history`` does in production
    after ``store_artifact`` — the same two service-level calls in the same
    order, exercising the same code paths the live pipeline exercises.
    """
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
        # Default to high-confidence ['inventory'] when the subject
        # proxy has no discovery_sources set. Most tests in this file
        # predate the ownership gate and just want to exercise the
        # backfill mechanics; the gate is tested separately.
        sources = contract.discovery_sources or ["inventory"]
        backfill_historical_impl_contracts(
            session,
            protocol_id=pid,
            chain=contract.chain,
            impl_addrs=stats["impl_addrs"],
            parent_proxy_sources=sources,
        )
    return stats


@pytest.fixture()
def seed_protocol(db_session):
    """Fresh protocol + cascading cleanup that also sweeps jobs/contracts
    we seed during the test (which the default db_session cleanup misses
    when the Contract never gets linked to a Protocol we own)."""
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
    """Return a dict the test can mutate to control what get_contract_info returns.

    By default every address resolves to ('StubImpl-<short>', {}). Individual
    addresses can be overridden; raising is triggered by setting the value
    to the sentinel ``_RAISE``.
    """
    _RAISE = object()
    names: dict[str, object] = {}

    def fake(address: str):
        val = names.get(address.lower(), None)
        if val is _RAISE:
            raise RuntimeError("simulated etherscan outage")
        if val is None:
            return (f"StubImpl-{address[2:6]}", {})
        return (val, {})

    import utils.etherscan as etherscan_mod

    monkeypatch.setattr(etherscan_mod, "get_contract_info", fake)
    return types_namespace(names=names, RAISE=_RAISE)


def types_namespace(**kwargs):
    """Tiny SimpleNamespace-alike so tests can do ``stub.names[...]=``."""
    from types import SimpleNamespace

    return SimpleNamespace(**kwargs)


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _addr(n: int) -> str:
    return "0x" + hex(n)[2:].zfill(40)


def _add_contract(session, **fields):
    from db.models import Contract

    c = Contract(**fields)
    session.add(c)
    session.commit()
    return c


# ---------------------------------------------------------------------------
# 1. _backfill_historical_impls — the core unit
# ---------------------------------------------------------------------------


def test_backfill_creates_rows_with_upgrade_history_tag(db_session, seed_protocol, worker, stub_etherscan):
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
        assert row.protocol_id == protocol_id
        assert "upgrade_history" in (row.discovery_sources or [])
        assert row.is_proxy is False
        assert row.job_id is None
        assert row.chain == "ethereum"
        assert row.source_verified is True  # name resolved → verified
    names = {r.contract_name for r in rows}
    assert names == {"PoolV1", "PoolV2"}


def test_backfill_adopts_orphan_row(db_session, seed_protocol, worker, stub_etherscan):
    """Pre-existing Contract with protocol_id=None → gets adopted,
    tagged, name preserved."""
    from db.models import Contract

    protocol_id, _ = seed_protocol
    addr = _addr(0xC3)
    _add_contract(
        db_session,
        protocol_id=None,
        address=addr,
        chain="ethereum",
        contract_name="ExistingName",
        is_proxy=False,
    )

    _backfill(
        db_session,
        protocol_id=protocol_id,
        chain="ethereum",
        impl_addrs={addr},
    )

    row = db_session.query(Contract).filter_by(address=addr).one()
    assert row.protocol_id == protocol_id
    assert "upgrade_history" in (row.discovery_sources or [])
    # Existing name must not be overwritten.
    assert row.contract_name == "ExistingName"
    # No duplicate created.
    assert db_session.query(Contract).filter_by(address=addr).count() == 1


def test_backfill_does_not_stomp_foreign_protocol_row(db_session, seed_protocol, worker, stub_etherscan):
    """Historical impl already owned by a DIFFERENT protocol is left alone.

    Rare case — impl bytecode is usually protocol-specific — but silently
    reassigning would corrupt the other protocol's inventory. A warning
    gets logged; coverage won't link through this row for our protocol,
    but the data remains honest.
    """
    from db.models import Contract, Protocol

    our_protocol_id, _ = seed_protocol
    foreign = Protocol(name=f"foreign-{uuid.uuid4().hex[:8]}")
    db_session.add(foreign)
    db_session.commit()
    foreign_id = foreign.id
    try:
        addr = _addr(0xD4)
        _add_contract(
            db_session,
            protocol_id=foreign_id,
            address=addr,
            chain="ethereum",
            contract_name="ForeignImpl",
            is_proxy=False,
            discovery_sources=["inventory"],  # explicitly not upgrade_history
        )

        _backfill(
            db_session,
            protocol_id=our_protocol_id,
            chain="ethereum",
            impl_addrs={addr},
        )

        row = db_session.query(Contract).filter_by(address=addr).one()
        # Untouched.
        assert row.protocol_id == foreign_id
        assert "inventory" in (row.discovery_sources or [])
        assert row.contract_name == "ForeignImpl"
        # No new row for our protocol (would fail uniqueness anyway).
        assert db_session.query(Contract).filter_by(address=addr).count() == 1
    finally:
        db_session.query(Contract).filter_by(protocol_id=foreign_id).delete()
        db_session.query(Protocol).filter_by(id=foreign_id).delete()
        db_session.commit()


def test_backfill_is_idempotent(db_session, seed_protocol, worker, stub_etherscan):
    """Running the backfill twice yields exactly the same rows."""
    from db.models import Contract

    protocol_id, _ = seed_protocol
    addrs = {_addr(0xE5), _addr(0xF6)}

    _backfill(db_session, protocol_id=protocol_id, chain="ethereum", impl_addrs=addrs)
    count_after_first = db_session.query(Contract).filter_by(protocol_id=protocol_id).count()

    _backfill(db_session, protocol_id=protocol_id, chain="ethereum", impl_addrs=addrs)
    count_after_second = db_session.query(Contract).filter_by(protocol_id=protocol_id).count()

    assert count_after_first == count_after_second == 2


def test_backfill_treats_cross_chain_same_address_as_distinct(db_session, seed_protocol, worker, stub_etherscan):
    """Same impl address on a different chain is NOT an existing row for
    our purposes. The natural key is ``(address, chain)`` — deterministic
    deployments (CREATE2) can produce identical addresses across chains,
    and conflating them would either stomp the other-chain row or skip a
    backfill that should have created a fresh row for our chain.
    """
    from db.models import Contract, Protocol

    our_protocol_id, _ = seed_protocol
    # A pre-existing polygon row for the same address — belongs to an
    # entirely different protocol. Backfill on ethereum must neither
    # touch this row nor treat it as a collision.
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

        # Polygon row untouched.
        polygon_row = db_session.query(Contract).filter_by(address=addr, chain="polygon").one()
        assert polygon_row.protocol_id == other_id
        assert polygon_row.contract_name == "PolygonDeployment"
        assert "inventory" in (polygon_row.discovery_sources or [])

        # Fresh ethereum row created for our protocol.
        ethereum_row = db_session.query(Contract).filter_by(address=addr, chain="ethereum").one()
        assert ethereum_row.protocol_id == our_protocol_id
        assert ethereum_row.contract_name == "EthereumImpl"
        assert "upgrade_history" in (ethereum_row.discovery_sources or [])
    finally:
        db_session.query(Contract).filter_by(address=addr, chain="polygon").delete()
        db_session.query(Protocol).filter_by(id=other_id).delete()
        db_session.commit()


def test_backfill_degrades_gracefully_on_etherscan_failure(db_session, seed_protocol, worker, stub_etherscan):
    """Etherscan raising mid-backfill: the affected row still lands with
    contract_name='UnknownImpl', and the other address in the same call
    still gets its real name. One flaky lookup doesn't wreck the batch.
    """
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
    # Still tagged so it's filter-outable.
    assert "upgrade_history" in (bad.discovery_sources or [])


# ---------------------------------------------------------------------------
# 2. _run_upgrade_history — the caller that pulls everything together
# ---------------------------------------------------------------------------


def test_run_upgrade_history_writes_events_and_backfills_impls(
    db_session, seed_protocol, worker, stub_etherscan, monkeypatch
):
    """End-to-end: given an upgrade_history artifact, writes UpgradeEvent
    rows AND backfills Contract rows for each unique new_impl.
    """
    from db.models import Contract, Job, JobStage, JobStatus, UpgradeEvent

    protocol_id, _ = seed_protocol

    # A proxy Contract (will be the "root" whose job we pretend to run).
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
    """Regression: when the subject Contract isn't itself the proxy
    described in the artifact, ``UpgradeEvent.contract_id`` must point
    at the PROXY's Contract row, not the subject's.

    Before the fix, every event was keyed to the subject's ``contract_id``,
    which meant a non-proxy subject (e.g., EtherFiRewardsRouter) ended
    up with 20+ phantom UpgradeEvent rows describing unrelated proxies
    (LiquidityPool, eETH, etc.). That in turn made
    ``/api/contracts/{id}/audit_timeline`` emit bogus ``impl_windows``
    for non-proxy contracts, and the Audits tab rendered eras that
    didn't exist.
    """
    from db.models import Contract, Job, JobStage, JobStatus, UpgradeEvent

    protocol_id, _ = seed_protocol

    # Subject of the job: a regular, non-proxy contract. Its upgrade_history
    # artifact happens to include proxies that belong to other contracts
    # (matches the static-worker behavior of snapshotting dependencies).
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

    # Two pre-existing proxy Contract rows in the same protocol.
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

    # The subject is not a proxy — it must end up with zero UpgradeEvent
    # rows. Before the fix, it would have 2 (one per proxy in the
    # artifact, mis-keyed to the subject).
    subject_events = db_session.query(UpgradeEvent).filter_by(contract_id=subject.id).all()
    assert subject_events == []

    # Events must land under each proxy's own contract_id.
    events_a = db_session.query(UpgradeEvent).filter_by(contract_id=proxy_a.id).all()
    events_b = db_session.query(UpgradeEvent).filter_by(contract_id=proxy_b.id).all()
    assert len(events_a) == 1 and events_a[0].new_impl == impl_1
    assert len(events_b) == 1 and events_b[0].new_impl == impl_2

    # Impls still get backfilled as usual (regardless of keying).
    impls = db_session.query(Contract).filter(Contract.address.in_({impl_1, impl_2})).all()
    assert {r.contract_name for r in impls} == {"Impl1", "Impl2"}


def test_run_upgrade_history_skips_proxies_not_in_inventory(
    db_session, seed_protocol, worker, stub_etherscan, monkeypatch
):
    """If the artifact mentions a proxy whose Contract row doesn't exist,
    silently skip those events — nothing to key them to, and writing
    with a NULL contract_id would violate the NOT NULL constraint. The
    next run after the proxy is discovered will pick them up.
    """
    from db.models import Job, JobStage, JobStatus, UpgradeEvent

    protocol_id, _ = seed_protocol
    subject_job = Job(
        id=uuid.uuid4(),
        address=_addr(0xDDD),
        status=JobStatus.processing,
        stage=JobStage.resolution,
        protocol_id=protocol_id,
    )
    db_session.add(subject_job)
    db_session.commit()
    subject = _add_contract(
        db_session,
        protocol_id=protocol_id,
        address=_addr(0xDDD),
        chain="ethereum",
        contract_name="Subject",
        is_proxy=False,
        job_id=subject_job.id,
    )

    unknown_proxy = _addr(0xBEEF)  # no Contract row for this address
    impl = _addr(0xFACE)
    stub_etherscan.names[impl] = "SomeImpl"

    artifact = {
        "proxies": {
            unknown_proxy: {
                "proxy_address": unknown_proxy,
                "events": [
                    {"event_type": "upgraded", "implementation": impl, "block_number": 50, "tx_hash": "0x" + "e" * 64},
                ],
            }
        }
    }

    _run_pipeline(db_session, contract=subject, artifact_data=artifact)

    # No events written anywhere — the proxy isn't resolvable and we
    # don't have a meaningful Contract.id to key them to.
    assert db_session.query(UpgradeEvent).filter_by(contract_id=subject.id).count() == 0


# The previous test in this slot — "skip when job has no Contract row" —
# tested static_worker's pre-projection guard, which is structural rather
# than a service-level concern. It's enforced by the
# ``contract_row = session.execute(...); if contract_row is None: return``
# block in ``static_worker._resolve_upgrade_history`` and is unreachable
# from the service entry points exercised here, so we no longer assert it
# at this layer. The static-worker integration tests cover that path.


# ---------------------------------------------------------------------------
# 3. Pollution guard — /api/company/{name}/analyze-remaining
# ---------------------------------------------------------------------------


def test_analyze_remaining_skips_backfilled_historical_impls(api_client, db_session, seed_protocol, stub_etherscan):
    """Seed protocol with one normal unanalyzed Contract and one
    backfilled historical-impl Contract. The analyze-remaining endpoint
    must enqueue a job only for the normal one.
    """
    from db.models import Contract

    protocol_id, name = seed_protocol

    # Normal (frontend-surfaced) contract awaiting analysis.
    _add_contract(
        db_session,
        protocol_id=protocol_id,
        address=_addr(0x777),
        chain="ethereum",
        contract_name="Normal",
        is_proxy=False,
        discovery_sources=["inventory"],
    )
    # Backfilled historical impl — should be filtered out.
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

    # Clean up the job the endpoint created (outside our seed_protocol cleanup path).
    db_session.expire_all()
    normal_row = db_session.query(Contract).filter_by(address=_addr(0x777)).one()
    if normal_row.job_id:
        from db.models import Job

        db_session.query(Job).filter_by(id=normal_row.job_id).delete()
        normal_row.job_id = None
        db_session.commit()


# ---------------------------------------------------------------------------
# 4. Coverage matcher — the payoff
# ---------------------------------------------------------------------------


def test_coverage_matcher_links_audit_to_backfilled_impl(db_session, seed_protocol):
    """With a backfilled historical-impl Contract row, an audit whose
    scope names that impl produces a coverage row — which is exactly
    what motivated the whole backfill.
    """
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
    # One upgrade event placing HistoricalImpl at block 100 of the proxy.
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
    # An audit whose scope mentions the historical impl by name.
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
    # Audit dated 2024-03-01 is in the open-ended [100, None) window → high.
    assert row.match_confidence == "high"
    assert row.covered_from_block == 100


# ---------------------------------------------------------------------------
# 5. Regression — backfill must trigger a coverage refresh for the new rows
# ---------------------------------------------------------------------------


def test_backfill_triggers_coverage_refresh_for_created_rows(db_session, seed_protocol, worker, stub_etherscan):
    """Regression for the "RoleRegistry shows unaudited" bug: when
    ``_backfill_historical_impls`` creates a new historical-impl Contract
    row, coverage for every existing audit whose scope names that impl
    must be upserted in the same pass.

    Before the fix, scope extraction ran before the impl row existed, so
    ``upsert_coverage_for_audit`` at that point matched zero contracts.
    The backfill later created the Contract row but nothing re-ran the
    matcher, leaving the audit ↔ impl pair with no coverage row — the UI
    reported "not audited" even though the matcher, invoked live, would
    have produced a match.
    """
    from db.models import (
        AuditContractCoverage,
        AuditReport,
        Contract,
        UpgradeEvent,
    )
    from services.audits.coverage import upsert_coverage_for_audit

    protocol_id, _ = seed_protocol

    # 1. Proxy exists. Its historical impl has NOT been backfilled yet —
    # this mirrors the race that caused the bug.
    proxy = _add_contract(
        db_session,
        protocol_id=protocol_id,
        address=_addr(0x100),
        chain="ethereum",
        contract_name="Proxy",
        is_proxy=True,
    )
    impl_addr = _addr(0xAAAA)
    # The proxy's upgrade history references the impl that will later
    # be backfilled. Block 100 → currently-active window (no successor).
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

    # 2. Audit whose scope names the impl — already through scope
    # extraction, as if it ran before the backfill fired.
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

    # 3. Scope extraction's side effect at the time it ran: zero matches,
    # because no Contract had the name "HistoricalImpl" yet.
    inserted = upsert_coverage_for_audit(db_session, audit.id)
    db_session.commit()
    assert inserted == 0
    assert db_session.query(AuditContractCoverage).filter_by(protocol_id=protocol_id).count() == 0

    # 4. Backfill happens — late. Stub Etherscan to return the name the
    # audit scope is looking for, so the match is possible once the row
    # exists.
    stub_etherscan.names[impl_addr] = "HistoricalImpl"
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

    # 5. The regression check: after backfill, a coverage row linking
    # the audit to the newly-created impl must exist. Before the fix
    # this count was 0 and the "audited?" UI pulled "no".
    rows = db_session.query(AuditContractCoverage).filter_by(protocol_id=protocol_id, contract_id=created.id).all()
    assert len(rows) == 1, (
        "backfill created the Contract row but did not refresh coverage — audit ↔ historical-impl link is missing"
    )
    r = rows[0]
    assert r.audit_report_id == audit.id
    assert r.matched_name == "HistoricalImpl"
    # Block 100 is the open-ended current window, audit dated inside it
    # → impl_era / high. Same semantics as the fresh-path coverage test
    # above; proves the late-arriving row reaches the same terminal state.
    assert r.match_type == "impl_era"
    assert r.match_confidence == "high"
    assert r.covered_from_block == 100
    assert r.covered_to_block is None


def test_backfill_coverage_refresh_covers_adopted_rows_too(db_session, seed_protocol, worker, stub_etherscan):
    """The adoption branch (pre-existing orphan row adopted into the
    protocol) must also trigger a coverage refresh. Without the refresh
    the row would join the protocol but stay unlinked to matching audits.
    """
    from db.models import AuditContractCoverage, AuditReport, UpgradeEvent
    from services.audits.coverage import upsert_coverage_for_audit

    protocol_id, _ = seed_protocol

    # Proxy in our protocol.
    proxy = _add_contract(
        db_session,
        protocol_id=protocol_id,
        address=_addr(0x200),
        chain="ethereum",
        contract_name="Proxy2",
        is_proxy=True,
    )
    # Orphan Contract row (protocol_id=None) that happens to match a
    # scope name. Will be adopted by backfill.
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

    # Pre-adoption: the orphan isn't in our protocol, so the matcher
    # can't link it.
    inserted = upsert_coverage_for_audit(db_session, audit.id)
    db_session.commit()
    assert inserted == 0

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

    # Adoption must pull coverage through too.
    rows = db_session.query(AuditContractCoverage).filter_by(protocol_id=protocol_id, contract_id=orphan.id).all()
    assert len(rows) == 1, (
        "adoption path didn't refresh coverage — orphan was pulled into "
        "the protocol but the audit link was not materialized"
    )
    assert rows[0].audit_report_id == audit.id
    assert rows[0].matched_name == "OrphanImpl"


# ---------------------------------------------------------------------------
# 6. Regression — UpgradeEvent.timestamp must be persisted from the artifact
# ---------------------------------------------------------------------------


def test_run_upgrade_history_persists_event_timestamp(db_session, seed_protocol, worker, stub_etherscan, monkeypatch):
    """Regression for the "LiquidityPool shows no audit coverage" bug:
    the artifact carries a unix-seconds timestamp per event, and
    ``UpgradeEvent.timestamp`` is ``DateTime(timezone=True)``. The worker
    must convert and persist it — downstream
    ``_compute_impl_windows_for_contract`` surfaces it as
    ``ImplWindow.from_ts``, and ``_confidence_for_impl_era`` skips every
    window with ``from_ts=None`` when evaluating grace-zone fit, which
    collapses every post-upgrade audit to ``low`` with NULL block bounds.
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

    # Known unix-seconds timestamp → datetime(2023, 11, 14, 22, 13, 20, tzinfo=UTC).
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
    # The primary assertion — before the fix this is None because the
    # projection dropped the timestamp on write.
    assert evt.timestamp is not None, (
        "UpgradeEvent.timestamp was not persisted — the artifact carries "
        "timestamp (unix seconds) but the projection writes only block_number + tx_hash"
    )
    assert evt.timestamp == expected_dt

    # Downstream signal the coverage matcher actually cares about:
    # ImplWindow.from_ts must be non-None so
    # _confidence_for_impl_era's grace-zone branch can fire.
    impl_contract = db_session.query(Contract).filter_by(address=impl_addr).one()
    from services.audits.coverage import _compute_impl_windows_for_contract

    windows = _compute_impl_windows_for_contract(db_session, impl_contract)
    assert len(windows) == 1
    assert windows[0].from_ts is not None
    assert windows[0].from_ts == expected_dt


def test_run_upgrade_history_handles_missing_timestamp(db_session, seed_protocol, worker, stub_etherscan, monkeypatch):
    """Defensive: if the artifact omits the timestamp (older artifact, RPC
    returned None, etc.), the write must still succeed with a NULL
    timestamp — not raise on a ``fromtimestamp(None)``.
    """
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
                        # no timestamp key at all
                        "tx_hash": "0x" + "c" * 64,
                    },
                ],
            }
        }
    }

    _run_pipeline(db_session, contract=proxy, artifact_data=artifact)

    events = db_session.query(UpgradeEvent).filter_by(contract_id=proxy.id).all()
    assert len(events) == 1
    # NULL timestamp is allowed; the column is nullable.
    assert events[0].timestamp is None


# ---------------------------------------------------------------------------
# 7. Regression — backfill enqueues verifiable rows for the deferred verify
#    worker instead of running source-equivalence inline (#82)
# ---------------------------------------------------------------------------


def test_backfill_coverage_refresh_defers_source_equivalence(
    db_session, seed_protocol, worker, stub_etherscan, monkeypatch
):
    """Backfill must enqueue verifiable coverage rows for ``CoverageVerifyWorker``
    instead of running source-equivalence inline.

    When ``_backfill_historical_impls`` creates a Contract row for a
    historical impl, there's no downstream Job for this impl
    (``job_id=None``), so ``workers.coverage_worker`` never runs for it.
    The backfill's inline ``upsert_coverage_for_contract`` call is the
    only coverage path for these rows — but the verify HTTP pass must
    NOT run inline here. Holding it inline fanned out 4-way Etherscan +
    GitHub bursts per backfilled impl, which 429'd the global rate-limit
    window and cascaded into Resolution / Static (#82). Verifiable rows
    instead land with ``equivalence_status='pending'`` so the dedicated
    ``CoverageVerifyWorker`` drains them at a controlled rate; promotion
    to ``reviewed_commit`` / ``high`` is exercised by
    ``tests/test_coverage_verify_worker.py::test_process_row_proves_pending_to_proven``.
    """
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
    # Audit has the inputs the verify worker needs: reviewed_commits +
    # source_repo. Per ``_stamp_pending_when_verifiable`` that's enough
    # to land the row as ``equivalence_status='pending'`` so the worker
    # picks it up; without those it would terminal-stamp immediately
    # (no_reviewed_commit / no_source_repo) and the worker would skip.
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

    # Trip-wires on the inline verify seams. With the deferred contract
    # neither should be touched during backfill; if a future regression
    # re-enables ``verify_source_equivalence=True`` here these will
    # surface immediately rather than silently re-introducing the
    # rate-limit cascade in prod.
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
    # Verifiable audit → row lands as 'pending' so the verify worker
    # drains it. equivalence_checked_at stays NULL until the worker
    # actually runs (a NOW() stamp on a never-attempted row would lie).
    assert r.equivalence_status == "pending", (
        f"verifiable audit landed with status={r.equivalence_status!r}, expected 'pending' for deferred verification"
    )
    assert r.equivalence_checked_at is None
    assert inline_calls == [], (
        f"inline source-equivalence ran during backfill: {inline_calls} — "
        "verify_source_equivalence=False contract was not honored"
    )
