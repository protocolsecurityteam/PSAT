"""Regression pins for the membership gate's historic leak shapes, plus the
frozen legacy orphan-adoption migrations.

Leak paths: ``dapp_crawl`` scraping widely-held/shared contracts (WETH, stETH,
EigenLayer cores) into a protocol's rows, and ``upgrade_history`` multiplying a
foreign proxy's impls (one EigenPodManager proxy -> 7 impls tagged etherfi).
Under the membership gate every write is a nomination and
promotion needs a recorded witness. The migrations ``3a8f4d1c9b07`` and
``4d72e9b1f035`` inline frozen deploy-time snapshots of the retired tiers.
"""

from __future__ import annotations

import uuid

import pytest

from tests.conftest import requires_postgres

# ---------------------------------------------------------------------------
# 2. Writer-side gate — db/queue/discovery.py
# ---------------------------------------------------------------------------


def _addr(n: int) -> str:
    return "0x" + hex(n)[2:].zfill(40)


@pytest.fixture()
def seed_protocol(db_session):
    from db.models import Protocol

    p = Protocol(name=f"gate-reg-{uuid.uuid4().hex[:10]}")
    db_session.add(p)
    db_session.commit()
    return p.id


@pytest.fixture()
def stub_etherscan(monkeypatch):
    """Stub etherscan name lookup AND the near-line probe so tests stay
    offline (stub-the-wire rule).

    Duplicated from ``test_upgrade_history_backfill.py`` to stay self-contained.
    """
    import services.clients.etherscan as etherscan_mod

    def fake(address: str):
        return (f"StubImpl-{address[2:6]}", {})

    monkeypatch.setattr(etherscan_mod, "get_contract_info", fake)
    monkeypatch.setattr("services.discovery.membership_gate.probe", lambda session, contract: None)


@requires_postgres
class TestBackfillMembershipGate:
    """Member only via a member-proxy UpgradeEvent edge (W2) plus a persisted code fact (W1)."""

    @staticmethod
    def _seed_code_fact(session, addr, block=90):
        from db.models import ContractCreationWitness

        session.add(
            ContractCreationWitness(
                chain_id=1, address=addr.lower(), code_probe_block=block, code_absent_at_probe=False
            )
        )
        session.commit()

    def test_backfill_without_member_edge_produces_candidates(self, db_session, seed_protocol, stub_etherscan):
        """The EigenPodManager multiplier shape."""
        from db.models import Contract
        from services.discovery.upgrade_history import backfill_historical_impl_contracts

        impl_addrs = {_addr(0xE100 + i) for i in range(3)}
        backfill_historical_impl_contracts(
            db_session, protocol_id=seed_protocol, chain="ethereum", impl_addrs=impl_addrs
        )
        db_session.commit()

        rows = db_session.query(Contract).filter(Contract.address.in_(impl_addrs)).all()
        assert len(rows) == 3, "rows should still be created — only membership is gated"
        for r in rows:
            assert r.protocol_id is None
            assert r.nominated_protocol_id == seed_protocol
            assert "upgrade_history" in (r.discovery_sources or [])

    def test_backfill_with_member_edge_and_code_fact_promotes(self, db_session, seed_protocol, stub_etherscan):
        from db.models import Contract, ContractMembershipWitness, UpgradeEvent
        from services.discovery.upgrade_history import backfill_historical_impl_contracts

        proxy = Contract(address=_addr(0xE200), chain="ethereum", protocol_id=seed_protocol, is_proxy=True)
        db_session.add(proxy)
        db_session.flush()
        impl_addrs = {_addr(0xE201), _addr(0xE202)}
        for i, addr in enumerate(sorted(impl_addrs)):
            db_session.add(
                UpgradeEvent(
                    contract_id=proxy.id,
                    proxy_address=proxy.address,
                    new_impl=addr,
                    block_number=100 + i,
                    tx_hash="0x" + ("%064x" % (0xABC0 + i)),
                )
            )
        db_session.commit()
        for addr in impl_addrs:
            self._seed_code_fact(db_session, addr)

        backfill_historical_impl_contracts(
            db_session, protocol_id=seed_protocol, chain="ethereum", impl_addrs=impl_addrs
        )
        db_session.commit()

        rows = db_session.query(Contract).filter(Contract.address.in_(impl_addrs)).all()
        assert len(rows) == 2
        for r in rows:
            assert r.protocol_id == seed_protocol
            witness_rules = {
                w.rule for w in db_session.query(ContractMembershipWitness).filter_by(contract_id=r.id, revoked_at=None)
            }
            assert witness_rules == {"w1_code", "w2_structural"}


@requires_postgres
class TestEigenLayerLeakShape:
    """A proxy that is not itself a member licenses nothing, even with stored upgrade events and code facts."""

    def test_dapp_crawl_proxy_plus_upgrade_history_does_not_pollute(self, db_session, seed_protocol, stub_etherscan):
        from db.models import Contract, ContractCreationWitness, UpgradeEvent
        from db.queue import bulk_upsert_discovered_contracts
        from services.discovery.upgrade_history import backfill_historical_impl_contracts

        proxy_addr = _addr(0xEEEE)
        bulk_upsert_discovered_contracts(
            db_session,
            protocol_id=seed_protocol,
            entries=[
                {
                    "address": proxy_addr,
                    "chain": "ethereum",
                    "new_sources": ["dapp_crawl"],
                    "discovery_url": "https://www.ether.fi/app/cash/referral",
                }
            ],
        )
        db_session.commit()
        proxy = db_session.query(Contract).filter_by(address=proxy_addr).one()
        assert proxy.protocol_id is None, "writer gate failed at step 1"

        impl_addrs = {_addr(0xE001), _addr(0xE002), _addr(0xE003)}
        for i, addr in enumerate(sorted(impl_addrs)):
            db_session.add(
                UpgradeEvent(
                    contract_id=proxy.id,
                    proxy_address=proxy.address,
                    new_impl=addr,
                    block_number=50 + i,
                    tx_hash="0x" + ("%064x" % (0xDEAD0 + i)),
                )
            )
            db_session.add(
                ContractCreationWitness(chain_id=1, address=addr, code_probe_block=40, code_absent_at_probe=False)
            )
        db_session.commit()
        backfill_historical_impl_contracts(
            db_session,
            protocol_id=seed_protocol,
            chain="ethereum",
            impl_addrs=impl_addrs,
        )
        db_session.commit()

        owned = db_session.query(Contract).filter_by(protocol_id=seed_protocol).all()
        leaked = [c for c in owned if c.address == proxy_addr or c.address in impl_addrs]
        assert leaked == [], (
            f"{len(leaked)} foreign row(s) stamped with protocol_id — "
            "this is the EigenLayer leak: foreign proxy via dapp_crawl + "
            "its historical impls all attributed to the protocol"
        )

        assert db_session.query(Contract).filter_by(address=proxy_addr).count() == 1
        assert db_session.query(Contract).filter(Contract.address.in_(impl_addrs)).count() == 3


@requires_postgres
class TestProxyMembershipOnClassification:
    """Event 2a: a proxy is promoted only on a verified W2 edge to its nominated protocol plus W1."""

    @staticmethod
    def _seed_proxy_job(db_session, proxy_addr, *, nominated_protocol_id=None):
        from db.models import Contract, ContractCreationWitness, Job, JobStage, JobStatus

        proxy_job = Job(
            id=uuid.uuid4(),
            stage=JobStage.static,
            status=JobStatus.processing,
            request={"rpc_url": "rpc"},
        )
        db_session.add(proxy_job)
        db_session.flush()
        db_session.add(
            Contract(
                address=proxy_addr,
                chain="ethereum",
                protocol_id=None,
                nominated_protocol_id=nominated_protocol_id,
                contract_name="Proxy",
                job_id=proxy_job.id,
            )
        )
        db_session.add(
            ContractCreationWitness(chain_id=1, address=proxy_addr, code_probe_block=10, code_absent_at_probe=False)
        )
        db_session.commit()
        return proxy_job

    @staticmethod
    def _stub_classifier(monkeypatch, impl_addr):
        monkeypatch.setattr(
            "services.discovery.classifier.classify_single",
            lambda address, rpc_url, **_kw: {
                "address": address,
                "type": "proxy",
                "proxy_type": "eip1967",
                "implementation": impl_addr,
            },
        )
        monkeypatch.setattr("workers.static_worker.store_artifact", lambda *a, **kw: None)
        monkeypatch.setattr(
            "workers.static_worker.create_job",
            lambda *a, **kw: type("J", (), {"id": "child"})(),
        )
        monkeypatch.setattr("workers.static_worker.reconcile_impl_job_for_proxy", lambda *a, **kw: "skip")
        monkeypatch.setattr("workers.static_worker._redirect_proxy_policy_dependencies", lambda *a, **kw: None)

    def test_nominated_proxy_with_member_impl_promotes(self, db_session, seed_protocol, monkeypatch):
        from types import SimpleNamespace

        from db.models import Contract, ContractMembershipWitness
        from workers.static_worker import StaticWorker

        impl_addr = _addr(0xF000)
        proxy_addr = _addr(0xF001)
        db_session.add(
            Contract(address=impl_addr, chain="ethereum", protocol_id=seed_protocol, contract_name="MemberImpl")
        )
        db_session.commit()
        proxy_job = self._seed_proxy_job(db_session, proxy_addr, nominated_protocol_id=seed_protocol)
        self._stub_classifier(monkeypatch, impl_addr)

        worker_job = SimpleNamespace(
            id=proxy_job.id, address=proxy_addr, name="Proxy", request={"rpc_url": "rpc", "chain_id": 1}
        )
        StaticWorker()._resolve_proxy(db_session, worker_job, proxy_addr, "Proxy")
        db_session.commit()

        row = db_session.query(Contract).filter_by(address=proxy_addr).one()
        assert row.protocol_id == seed_protocol
        witness_rules = {
            w.rule for w in db_session.query(ContractMembershipWitness).filter_by(contract_id=row.id, revoked_at=None)
        }
        assert witness_rules == {"w1_code", "w2_structural"}
