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
    """Fresh protocol whose contracts get cleaned up by db_session teardown."""
    from db.models import Protocol

    p = Protocol(name=f"gate-reg-{uuid.uuid4().hex[:10]}")
    db_session.add(p)
    db_session.commit()
    return p.id


# ---------------------------------------------------------------------------
# 3. Backfill-side gate — services/discovery/upgrade_history.py
# ---------------------------------------------------------------------------


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
    """Backfilled impls route through the gate: always NOMINATED; MEMBER only
    via a member-proxy UpgradeEvent edge (W2 ``historical_implementation``) plus
    a persisted code fact (W1)."""

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
        """The EigenPodManager multiplier shape: impls with no proven
        member-proxy edge stay candidates — a company-page query keyed on
        ``protocol_id`` returns none of them."""
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


# ---------------------------------------------------------------------------
# 5. End-to-end shape — the EigenLayer leak in miniature
# ---------------------------------------------------------------------------


@requires_postgres
class TestEigenLayerLeakShape:
    """The real-world shape that motivated the gate: a foreign proxy enters
    via dapp_crawl and its upgrade history adds N impls. Even WITH stored
    upgrade events and code facts, a proxy that is not itself a MEMBER
    licenses nothing — zero pollution in the protocol's rollup."""

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

        # Step 2: upgrade events + code facts exist for the impls — the
        # strongest version of the shape. The via proxy is NOT a member, so
        # the W2 edge does not verify and every impl stays a candidate.
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


# ---------------------------------------------------------------------------
# 6b. Call-target / NULL-provenance overreach — the WETH9/EndpointV2 leak
# ---------------------------------------------------------------------------


@requires_postgres
class TestCallTargetOverreachShape:
    """The dev-DB shape behind the WETH9 / EndpointV2 / DepositContract / Lido
    admissions: members carry ControllerValue rows naming the externals they
    integrate with. ``call_target`` is an operand and NULL is not-determined —
    neither admits a D2 controller (``W3_D2_SOURCES``). The third
    refused provenance, ``caller_gate``, is pinned with the full EndpointV2
    shape in test_membership_caller_gate_admission.py."""

    @staticmethod
    def _seed(db_session, seed_protocol, tag):
        from db.models import Contract, ContractCreationWitness

        member = Contract(address=_addr(0xF000 + tag), chain="ethereum", protocol_id=seed_protocol)
        candidate = Contract(address=_addr(0xF100 + tag), chain="ethereum", nominated_protocol_id=seed_protocol)
        db_session.add_all([member, candidate])
        db_session.flush()
        db_session.add(
            ContractCreationWitness(
                chain_id=1, address=candidate.address, code_probe_block=90, code_absent_at_probe=False
            )
        )
        db_session.flush()
        return member, candidate

    @staticmethod
    def _evaluate(db_session, candidate):
        from services.discovery import membership_gate as gate

        gate.evaluate(db_session, gate.FactsDelta(recheck_contract_ids=(candidate.id,)))
        db_session.commit()

    # CRITICAL: a ControllerValue whose provenance is refused never admits a D2 controller.
    @pytest.mark.parametrize(
        ("tag", "controller_id", "provenance"),
        [
            pytest.param(0, "nativeWrapper", "call_target", id="call_target"),
            pytest.param(1, "endpoint", None, id="null_provenance"),
        ],
    )
    def test_refused_controller_value_provenance_never_admits(
        self, db_session, seed_protocol, tag, controller_id, provenance
    ):
        from db.models import ContractMembershipWitness, ControllerValue

        member, foreign = self._seed(db_session, seed_protocol, tag)
        db_session.add(
            ControllerValue(
                contract_id=member.id,
                controller_id=controller_id,
                value=foreign.address,
                authority_provenance=provenance,
            )
        )
        self._evaluate(db_session, foreign)

        assert foreign.protocol_id is None
        assert (
            db_session.query(ContractMembershipWitness).filter_by(contract_id=foreign.id, rule="w3_control").count()
            == 0
        )

    def test_w2_cascade_dies_with_the_refused_w3_root(self, db_session, seed_protocol):
        """The Lido shape: the stETH proxy entered via a call_target CV, then
        its implementation rode in on W2. Refusing the W3 root must starve the
        W2 edge — neither row may become a member."""
        from db.models import Contract, ContractCreationWitness, ControllerValue

        member, foreign_proxy = self._seed(db_session, seed_protocol, 3)
        impl = Contract(address=_addr(0xF200), chain="ethereum", nominated_protocol_id=seed_protocol)
        db_session.add(impl)
        db_session.flush()
        foreign_proxy.implementation = impl.address
        db_session.add(
            ContractCreationWitness(chain_id=1, address=impl.address, code_probe_block=90, code_absent_at_probe=False)
        )
        db_session.add(
            ControllerValue(
                contract_id=member.id,
                controller_id="stETH",
                value=foreign_proxy.address,
                authority_provenance="call_target",
            )
        )
        db_session.flush()

        from services.discovery import membership_gate as gate

        gate.evaluate(db_session, gate.FactsDelta(recheck_contract_ids=(foreign_proxy.id, impl.id)))
        db_session.commit()

        assert foreign_proxy.protocol_id is None
        assert impl.protocol_id is None

    def test_exclusivity_observed_set_counts_caller_gate_only(self, db_session, seed_protocol):
        """Owner ruling: a call_target operand is not an observation of
        control, so it neither licenses exclusivity nor refuses it — the
        exclusivity verdict is computed over caller_gate rows alone."""
        from db.models import Contract, ControllerValue, Protocol
        from services.discovery.membership_gate import _controller_is_exclusive

        member, _ = self._seed(db_session, seed_protocol, 4)
        operator = _addr(0xF300)
        db_session.add(
            ControllerValue(
                contract_id=member.id, controller_id="owner", value=operator, authority_provenance="caller_gate"
            )
        )
        other = Protocol(name=f"ct-excl-{uuid.uuid4().hex[:10]}")
        db_session.add(other)
        db_session.flush()
        foreign = Contract(address=_addr(0xF301), chain="ethereum", protocol_id=other.id)
        db_session.add(foreign)
        db_session.flush()
        # A call_target row naming the operator on a FOREIGN contract is not
        # an observation of control and must not decide the verdict either way.
        db_session.add(
            ControllerValue(
                contract_id=foreign.id, controller_id="router", value=operator, authority_provenance="call_target"
            )
        )
        db_session.flush()

        assert _controller_is_exclusive(
            db_session,
            protocol_id=seed_protocol,
            controller_address=operator,
            chain_key="ethereum",
            exclude_contract_ids=set(),
        )

        # The same observation with caller_gate provenance IS control — and
        # being foreign, it kills exclusivity (the two-hop shape).
        db_session.query(ControllerValue).filter_by(contract_id=foreign.id).update(
            {"authority_provenance": "caller_gate"}
        )
        db_session.flush()
        assert not _controller_is_exclusive(
            db_session,
            protocol_id=seed_protocol,
            controller_address=operator,
            chain_key="ethereum",
            exclude_contract_ids=set(),
        )


# ---------------------------------------------------------------------------
# 7. Structural-orphan adoption migration (3a8f4d1c9b07)
# ---------------------------------------------------------------------------


@requires_postgres
class TestProxyMembershipOnClassification:
    """Membership-gate event 2a at ``static_worker._resolve_proxy``: a proxy is
    promoted only on a verified W2 edge (its resolved impl IS a member of its
    NOMINATED protocol) plus W1."""

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

    def test_unnominated_proxy_never_promotes(self, db_session, seed_protocol, monkeypatch):
        """No nomination -> no membership, whatever the impl points at
        (stranger-fork / ERC-6551 TBA shape)."""
        from types import SimpleNamespace

        from db.models import Contract
        from workers.static_worker import StaticWorker

        impl_addr = _addr(0xF100)
        proxy_addr = _addr(0xF101)
        db_session.add(
            Contract(address=impl_addr, chain="ethereum", protocol_id=seed_protocol, contract_name="MemberImpl2")
        )
        db_session.commit()
        proxy_job = self._seed_proxy_job(db_session, proxy_addr, nominated_protocol_id=None)
        self._stub_classifier(monkeypatch, impl_addr)

        worker_job = SimpleNamespace(
            id=proxy_job.id, address=proxy_addr, name="StrangerFork", request={"rpc_url": "rpc", "chain_id": 1}
        )
        StaticWorker()._resolve_proxy(db_session, worker_job, proxy_addr, "StrangerFork")
        db_session.commit()

        row = db_session.query(Contract).filter_by(address=proxy_addr).one()
        assert row.protocol_id is None

    def test_proxy_nominated_elsewhere_stays_candidate(self, db_session, seed_protocol, monkeypatch):
        """The impl is a member of protocol B; the proxy is nominated to A.
        The W2 edge only verifies against the NOMINATED protocol, so nothing
        promotes — no cross-protocol adoption through a shared impl."""
        from types import SimpleNamespace

        from db.models import Contract, Protocol
        from workers.static_worker import StaticWorker

        other = Protocol(name=f"proxy-foreign-{uuid.uuid4().hex[:10]}")
        db_session.add(other)
        db_session.commit()

        impl_addr = _addr(0xF200)
        proxy_addr = _addr(0xF201)
        db_session.add(Contract(address=impl_addr, chain="ethereum", protocol_id=other.id, contract_name="ForeignImpl"))
        db_session.commit()
        proxy_job = self._seed_proxy_job(db_session, proxy_addr, nominated_protocol_id=seed_protocol)
        self._stub_classifier(monkeypatch, impl_addr)

        worker_job = SimpleNamespace(
            id=proxy_job.id, address=proxy_addr, name="Proxy", request={"rpc_url": "rpc", "chain_id": 1}
        )
        StaticWorker()._resolve_proxy(db_session, worker_job, proxy_addr, "Proxy")
        db_session.commit()

        row = db_session.query(Contract).filter_by(address=proxy_addr).one()
        assert row.protocol_id is None
        assert row.nominated_protocol_id == seed_protocol


# ---------------------------------------------------------------------------
# 7. Remaining-orphan adoption — the fifth and sixth ownership branches.
#
# Branch A — deployer-cascade: an orphan whose deployer also deployed a
# HIGH-sourced contract attributed to a protocol inherits it. The
# HIGH-sourced-sibling requirement keeps WETH / USDC / OZ libs out. Motivated
# by PR-87 orphans spawned at ``workers/resolution_worker.py:499-513`` with
# NULL ``discovery_sources``.
#
# Branch B — historical impls behind a HIGH-impl proxy, anchored on the
# proxy's CURRENT impl so the proxy itself may be LOW-only
# (``structural_adoption``). Scope: the 5 LRTSquare* impls behind
# LRTSquaredCore + UUPSProxy on PR-87.
# ---------------------------------------------------------------------------
