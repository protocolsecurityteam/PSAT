"""Regression pins for the membership gate's historic leak shapes, plus the
frozen legacy orphan-adoption migrations.

Two leak paths motivated gating membership, and both are exercised here:

  1. ``dapp_crawl`` scrapes every ``0x...`` on a DApp page — including
     widely-held tokens (WETH, stETH) and shared infrastructure
     (OptimismPortal, EigenLayer cores) that the protocol *integrates
     with* but does not *own*. Pre-fix, those landed in the protocol's
     ``Contract`` rows tagged with its ``protocol_id``, polluting the
     surface page.

  2. ``upgrade_history`` materializes every historical implementation
     of every proxy a protocol's job analyzes. When the analyzed proxy
     is itself foreign (snuck in via path 1), the backfill multiplied
     the leak — one EigenPodManager proxy → 7 EigenPodManager impls all
     tagged etherfi.

Under the membership gate (DISCOVERY_MEMBERSHIP_GATE_SPEC.md) no source
tag stamps ``protocol_id`` at all: every discovery write is a nomination,
and promotion requires a recorded witness. These tests:

  * verify the writer path nominates without stamping,
  * verify the historical-impl backfill promotes only on a verified
    member-proxy edge (W2) plus a persisted code fact (W1),
  * pin the EigenLayer leak shape end-to-end,
  * pin the applied legacy adoption migrations (``3a8f4d1c9b07``,
    ``4d72e9b1f035``), whose inlined source lists are frozen deploy-time
    snapshots of the retired source-confidence tiers.
"""

from __future__ import annotations

import uuid
from pathlib import Path

import pytest

from tests.conftest import requires_postgres

# ---------------------------------------------------------------------------
# 2. Writer-side gate — db/queue.py
# ---------------------------------------------------------------------------


pytestmark_db = [requires_postgres]


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


@requires_postgres
class TestBulkUpsertOwnershipGate:
    """Membership-gate model (DISCOVERY_MEMBERSHIP_GATE_SPEC.md): NO source
    tag stamps ``protocol_id`` at the persistence boundary — every write is a
    nomination (``nominated_protocol_id``) and promotion is the gate's job.
    The full writer matrix (tag tiers, re-nominations, the single-row helper)
    is pinned in test_discovery_nomination_writers.py; kept here is the named
    path-1 leak shape."""

    def test_dapp_crawl_only_entry_stays_orphan(self, db_session, seed_protocol):
        """Pre-fix: this row landed with ``protocol_id=etherfi`` — that's
        how WETH and Lido ended up "owned by" ether.fi."""
        from db.models import Contract
        from db.queue import bulk_upsert_discovered_contracts

        addr = _addr(0xDA00)
        bulk_upsert_discovered_contracts(
            db_session,
            protocol_id=seed_protocol,
            entries=[
                {
                    "address": addr,
                    "chain": "ethereum",
                    "new_sources": ["dapp_crawl"],
                    "discovery_url": "https://example.com/cash",
                }
            ],
        )
        db_session.commit()
        row = db_session.query(Contract).filter_by(address=addr, chain="ethereum").one()
        assert row.protocol_id is None, (
            "low-confidence-only entry was stamped with protocol_id — "
            "this is the dapp_crawl leak that pulled WETH/Lido into etherfi"
        )
        # Discovery trail is still preserved — the row exists, just not
        # attributed to the protocol; the nominator is recorded.
        assert row.nominated_protocol_id == seed_protocol
        assert "dapp_crawl" in (row.discovery_sources or [])
        assert row.discovery_url == "https://example.com/cash"


# ---------------------------------------------------------------------------
# 3. Backfill-side gate — services/discovery/upgrade_history.py
# ---------------------------------------------------------------------------


@pytest.fixture()
def stub_etherscan(monkeypatch):
    """Stub etherscan name lookup AND the backfill's near-line §3.5 probe so
    the tests stay offline + hermetic (stub-the-wire rule).

    Matches the helpers in ``test_upgrade_history_backfill.py`` —
    duplicated here to keep this file self-contained and runnable in
    isolation.
    """
    import services.clients.etherscan as etherscan_mod

    def fake(address: str):
        return (f"StubImpl-{address[2:6]}", {})

    monkeypatch.setattr(etherscan_mod, "get_contract_info", fake)
    monkeypatch.setattr("services.discovery.membership_gate.probe", lambda session, contract: None)


@requires_postgres
class TestBackfillMembershipGate:
    """Backfilled historical impls route through the membership gate: always
    NOMINATED; MEMBER only via a member-proxy UpgradeEvent edge (W2
    ``historical_implementation``) plus a persisted code fact (W1). The old
    source-tag ownership gate this class used to pin is retired."""

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

    def test_backfill_foreign_owned_row_left_alone(self, db_session, seed_protocol, stub_etherscan):
        """A row already a MEMBER of a different protocol is never touched —
        not renominated, not stamped."""
        from db.models import Contract, Protocol
        from services.discovery.upgrade_history import backfill_historical_impl_contracts

        other = Protocol(name=f"backfill-foreign-{uuid.uuid4().hex[:10]}")
        db_session.add(other)
        db_session.commit()
        addr = _addr(0xE700)
        db_session.add(Contract(address=addr, chain="ethereum", protocol_id=other.id, contract_name="ForeignImpl"))
        db_session.commit()

        backfill_historical_impl_contracts(db_session, protocol_id=seed_protocol, chain="ethereum", impl_addrs={addr})
        db_session.commit()

        row = db_session.query(Contract).filter_by(address=addr).one()
        assert row.protocol_id == other.id
        assert row.nominated_protocol_id is None


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

        # Step 1: dapp_crawl pulls in an EigenLayer-shaped proxy address.
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

        # The whole point: a company-page query keyed on ``protocol_id``
        # returns ZERO of these rows.
        owned = db_session.query(Contract).filter_by(protocol_id=seed_protocol).all()
        leaked = [c for c in owned if c.address == proxy_addr or c.address in impl_addrs]
        assert leaked == [], (
            f"{len(leaked)} foreign row(s) stamped with protocol_id — "
            "this is the EigenLayer leak: foreign proxy via dapp_crawl + "
            "its historical impls all attributed to the protocol"
        )

        # Discovery records still exist — the data is preserved, just
        # not attributed. (Future corroboration can promote them.)
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
    neither admits a D2 controller (invariant 6, ``W3_D2_SOURCES``). The third
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

    def test_call_target_controller_value_never_admits(self, db_session, seed_protocol):
        from db.models import ContractMembershipWitness, ControllerValue

        member, weth9 = self._seed(db_session, seed_protocol, 0)
        db_session.add(
            ControllerValue(
                contract_id=member.id,
                controller_id="nativeWrapper",
                value=weth9.address,
                authority_provenance="call_target",
            )
        )
        self._evaluate(db_session, weth9)

        assert weth9.protocol_id is None
        assert (
            db_session.query(ContractMembershipWitness).filter_by(contract_id=weth9.id, rule="w3_control").count() == 0
        )

    def test_null_provenance_controller_value_never_admits(self, db_session, seed_protocol):
        from db.models import ContractMembershipWitness, ControllerValue

        member, foreign = self._seed(db_session, seed_protocol, 1)
        db_session.add(ControllerValue(contract_id=member.id, controller_id="endpoint", value=foreign.address))
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
    """Membership-gate event 2a at ``static_worker._resolve_proxy``: the
    freshly stored proxy pointers are a fact delta; the gate promotes the
    proxy only on a verified W2 proxy edge (its resolved impl IS a member of
    its NOMINATED protocol) plus W1. This replaces the ad-hoc
    proxy-of-HIGH-impl runtime adoption."""

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
        """No nomination → no membership, whatever the impl points at.
        The stranger-fork / ERC-6551 TBA shape stays out."""
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


@requires_postgres
class TestStructuralOrphanMigration:
    """The migration walks every orphan, checks for structural edges from
    HIGH-owned contracts, and adopts when there's exactly one matching
    protocol. Cross-protocol collisions skip + log."""

    def _seed_high_owner_with_edge(
        self,
        db_session,
        *,
        parent_addr,
        child_addr,
        protocol_id,
        relationship,
        chain="ethereum",
        structurally_linked=True,
    ):
        """Helper: create a HIGH-owned Contract row and a dep edge from it
        to ``child_addr`` with the given structural relationship type.

        When ``structurally_linked`` is True (the default) the parent's
        proxy/beacon fields are set so the corrected migration SELECT
        recognises the structural link. Setting it False seeds the
        Lido-stETH-style false-positive shape: the edge exists with a
        structural ``relationship_type`` but neither side's recorded
        proxy/beacon fields link the two contracts."""
        from db.models import Contract, ContractDependency

        parent_kwargs: dict = {
            "address": parent_addr,
            "chain": chain,
            "protocol_id": protocol_id,
            "contract_name": "ParentImpl",
            "discovery_sources": ["deployer_expansion"],
        }
        if structurally_linked:
            if relationship == "implementation":
                parent_kwargs["is_proxy"] = True
                parent_kwargs["implementation"] = child_addr
            elif relationship == "beacon":
                parent_kwargs["is_proxy"] = True
                parent_kwargs["beacon"] = child_addr

        parent = Contract(**parent_kwargs)
        db_session.add(parent)
        db_session.flush()

        if structurally_linked and relationship == "proxy":
            # ``proxy`` edge: the dep itself is the proxy whose impl is
            # the parent. Mirror that on the (pre-existing) child row.
            child_row = db_session.query(Contract).filter_by(address=child_addr).one_or_none()
            if child_row is not None:
                child_row.is_proxy = True
                child_row.implementation = parent_addr

        db_session.add(
            ContractDependency(
                contract_id=parent.id,
                dependency_address=child_addr,
                relationship_type=relationship,
                source=["dynamic"],
            )
        )
        db_session.commit()
        return parent

    @pytest.fixture(scope="class")
    def migration_module(self):
        """Load the migration file directly. Migration filenames start
        with the revision id (digits) which isn't a valid Python module
        name, so importlib.util by path is the way in.
        """
        import importlib.util

        path = Path(__file__).resolve().parents[2] / "alembic" / "versions" / "3a8f4d1c9b07_adopt_structural_orphans.py"
        spec = importlib.util.spec_from_file_location("_adopt_structural_orphans_mig", path)
        assert spec is not None and spec.loader is not None
        module = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(module)
        return module

    def test_migration_adopts_structural_orphan(self, db_session, seed_protocol, migration_module):
        """Seed (orphan child, HIGH parent with implementation edge) →
        migration adopts the orphan and tags ``structural_adoption``."""
        from db.models import Contract

        parent_addr = _addr(0xAA01)
        child_addr = _addr(0xBB01)
        db_session.add(Contract(address=child_addr, chain="ethereum", protocol_id=None, discovery_sources=None))
        db_session.commit()
        self._seed_high_owner_with_edge(
            db_session,
            parent_addr=parent_addr,
            child_addr=child_addr,
            protocol_id=seed_protocol,
            relationship="implementation",
        )

        # Run the same SQL the migration uses. Direct bind execution
        # exercises the actual statements without alembic's stamping.
        rows = db_session.execute(migration_module._SELECT_STRUCTURAL_ORPHANS).fetchall()
        adopted = 0
        for orphan_id, parent_protocols in rows:
            unique = [pid for pid in (parent_protocols or []) if pid is not None]
            if len(unique) == 1:
                db_session.execute(migration_module._ADOPT_ORPHAN, {"pid": unique[0], "id": orphan_id})
                adopted += 1
        db_session.commit()

        assert adopted >= 1
        row = db_session.query(Contract).filter_by(address=child_addr).one()
        assert row.protocol_id == seed_protocol
        assert "structural_adoption" in (row.discovery_sources or [])

    def test_migration_skips_non_structural_edges(self, db_session, seed_protocol, migration_module):
        """A regular CALL edge from a HIGH parent must NOT cause
        adoption — that's the WETH leak the original gate closed."""
        from db.models import Contract

        parent_addr = _addr(0xAA02)
        child_addr = _addr(0xBB02)
        db_session.add(
            Contract(address=child_addr, chain="ethereum", protocol_id=None, discovery_sources=["dapp_crawl"])
        )
        db_session.commit()
        self._seed_high_owner_with_edge(
            db_session,
            parent_addr=parent_addr,
            child_addr=child_addr,
            protocol_id=seed_protocol,
            relationship="regular",
        )

        rows = db_session.execute(migration_module._SELECT_STRUCTURAL_ORPHANS).fetchall()
        # The child should not appear in the result set at all — the
        # SQL's WHERE clause filters relationship_type to the
        # structural set.
        child_ids_in_result = {
            r[0]
            for r in rows
            if r[0] is not None
            and db_session.query(Contract).get(r[0]) is not None
            and db_session.query(Contract).get(r[0]).address == child_addr
        }
        assert child_ids_in_result == set(), (
            "non-structural edge surfaced as an adoption candidate — "
            "the WHERE clause's relationship_type filter is wrong"
        )

    def test_migration_skips_falsely_classified_dep(self, db_session, seed_protocol, migration_module):
        """Regression: a HIGH parent calling a third-party proxy (e.g.
        ether.fi → Lido stETH) produces a ``relationship_type='proxy'``
        edge in ``contract_dependencies`` because the dep IS classified
        as a proxy in its own right. The earlier migration version
        adopted these by trusting ``relationship_type`` alone, which
        re-opened the WETH/stETH leak. The corrected SELECT requires
        the parent.implementation / parent.beacon / dep.implementation
        fields to actually link the two contracts."""
        from db.models import Contract

        parent_addr = _addr(0xAA05)
        child_addr = _addr(0xBB05)  # the falsely-claimed "proxy" of parent
        # Child IS a proxy, but its impl points to some THIRD address
        # (not parent_addr) — the shape of Lido stETH in the leak case.
        third_impl = _addr(0xCC05)
        db_session.add(
            Contract(
                address=child_addr,
                chain="ethereum",
                protocol_id=None,
                discovery_sources=["dapp_crawl"],
                is_proxy=True,
                implementation=third_impl,
            )
        )
        db_session.commit()
        self._seed_high_owner_with_edge(
            db_session,
            parent_addr=parent_addr,
            child_addr=child_addr,
            protocol_id=seed_protocol,
            relationship="proxy",
            structurally_linked=False,  # parent.implementation != child_addr; child.implementation != parent_addr
        )

        rows = db_session.execute(migration_module._SELECT_STRUCTURAL_ORPHANS).fetchall()
        # Neither this orphan nor any other seeded in this test should
        # surface for adoption — the structural-link check must fail.
        offending = [
            r[0]
            for r in rows
            if db_session.query(Contract).get(r[0]) is not None
            and db_session.query(Contract).get(r[0]).address == child_addr
        ]
        assert offending == [], (
            "third-party proxy was surfaced as a structural-orphan candidate by relationship_type "
            "alone — this is the Lido stETH leak the corrected SELECT must prevent"
        )

    def test_migration_adopts_proxy_of_high_impl_when_referenced(self, db_session, seed_protocol, migration_module):
        """The fourth SQL branch: an orphan that's a proxy whose
        ``.implementation`` points to a HIGH-owned contract, AND is
        referenced by some HIGH-owned-by-same-protocol contract via
        any dep edge. Closes the case where the impl doesn't carry a
        back-edge to its proxy in ``contract_dependencies`` (impls
        typically don't reference their own proxy)."""
        from db.models import Contract, ContractDependency

        # The HIGH impl (e.g., etherfi's LRTSquaredCore — discovered via
        # deployer_expansion).
        impl_addr = _addr(0xAA10)
        db_session.add(
            Contract(
                address=impl_addr,
                chain="ethereum",
                protocol_id=seed_protocol,
                contract_name="HighImpl",
                discovery_sources=["deployer_expansion"],
            )
        )
        # An orphan proxy whose .implementation is the HIGH impl. Its
        # impl is not in any dep edge from a HIGH parent — impls
        # normally don't record their proxy as a dep.
        proxy_addr = _addr(0xBB10)
        db_session.add(
            Contract(
                address=proxy_addr,
                chain="ethereum",
                protocol_id=None,
                contract_name="ProxyOfHighImpl",
                is_proxy=True,
                implementation=impl_addr,
            )
        )
        # Another HIGH-owned contract in the same protocol that
        # references the proxy — this is the "protocol actually
        # integrates with the proxy" signal that distinguishes a real
        # protocol-internal proxy from a per-user clone / fork.
        referencing_addr = _addr(0xCC10)
        ref_contract = Contract(
            address=referencing_addr,
            chain="ethereum",
            protocol_id=seed_protocol,
            contract_name="RefContract",
            discovery_sources=["ai_inventory"],
        )
        db_session.add(ref_contract)
        db_session.flush()
        db_session.add(
            ContractDependency(
                contract_id=ref_contract.id,
                dependency_address=proxy_addr,
                relationship_type="proxy",
                source=["dynamic"],
            )
        )
        db_session.commit()

        rows = db_session.execute(migration_module._SELECT_STRUCTURAL_ORPHANS).fetchall()
        adopted = 0
        for orphan_id, parent_protocols in rows:
            unique = [pid for pid in (parent_protocols or []) if pid is not None]
            if len(unique) == 1:
                db_session.execute(migration_module._ADOPT_ORPHAN, {"pid": unique[0], "id": orphan_id})
                adopted += 1
        db_session.commit()

        assert adopted >= 1
        row = db_session.query(Contract).filter_by(address=proxy_addr).one()
        assert row.protocol_id == seed_protocol
        assert "structural_adoption" in (row.discovery_sources or [])

    def test_migration_skips_proxy_of_high_impl_without_protocol_reference(
        self, db_session, seed_protocol, migration_module
    ):
        """Safety filter for the fourth branch: a proxy whose ``.implementation``
        is HIGH-owned BUT which no HIGH-owned-by-same-protocol contract
        references must NOT be adopted. This is the ERC-6551 token-bound-
        account / fork-of-protocol shape: someone else's proxy that
        happens to share code with a protocol's impl, but isn't actually
        part of the protocol's contract surface."""
        from db.models import Contract

        impl_addr = _addr(0xAA11)
        db_session.add(
            Contract(
                address=impl_addr,
                chain="ethereum",
                protocol_id=seed_protocol,
                contract_name="HighImpl2",
                discovery_sources=["deployer_expansion"],
            )
        )
        # Orphan proxy points to HIGH impl, but NO contract in the same
        # protocol references this proxy → must stay orphan.
        stranger_proxy = _addr(0xBB11)
        db_session.add(
            Contract(
                address=stranger_proxy,
                chain="ethereum",
                protocol_id=None,
                contract_name="ForeignFork",
                is_proxy=True,
                implementation=impl_addr,
            )
        )
        db_session.commit()

        rows = db_session.execute(migration_module._SELECT_STRUCTURAL_ORPHANS).fetchall()
        surfaced_ids = {r[0] for r in rows}
        stranger_row = db_session.query(Contract).filter_by(address=stranger_proxy).one()
        assert stranger_row.id not in surfaced_ids, (
            "fork / TBA-style proxy was surfaced for adoption — the "
            "'must be referenced by HIGH protocol contract' filter is missing"
        )

    def test_migration_skips_low_source_parents(self, db_session, seed_protocol, migration_module):
        """Tightening regression: a parent with ``protocol_id`` set but
        only LOW-confidence sources (``upgrade_history``,
        ``structural_adoption``) must NOT contribute adoption evidence.
        Otherwise the migration extends the cascade past the one-hop
        limit the runtime gate enforces. Shape: orphan would be adopted
        by branch 1 IF parent's sources counted, but parent's only
        source is ``upgrade_history``."""
        from db.models import Contract, ContractDependency

        parent_addr = _addr(0xAA20)
        child_addr = _addr(0xBB20)
        db_session.add(
            Contract(
                address=child_addr,
                chain="ethereum",
                protocol_id=None,
                discovery_sources=None,
            )
        )
        # Parent has protocol_id (transitively, via upgrade_history
        # backfill from a HIGH proxy) but its own sources are LOW. The
        # structural field link is real — what the test pins is that the
        # parent's source tier matters even when the link is valid.
        parent = Contract(
            address=parent_addr,
            chain="ethereum",
            protocol_id=seed_protocol,
            contract_name="LowSourceParent",
            discovery_sources=["upgrade_history"],
            is_proxy=True,
            implementation=child_addr,
        )
        db_session.add(parent)
        db_session.flush()
        db_session.add(
            ContractDependency(
                contract_id=parent.id,
                dependency_address=child_addr,
                relationship_type="implementation",
                source=["dynamic"],
            )
        )
        db_session.commit()

        rows = db_session.execute(migration_module._SELECT_STRUCTURAL_ORPHANS).fetchall()
        surfaced_ids = {r[0] for r in rows}
        child_row = db_session.query(Contract).filter_by(address=child_addr).one()
        assert child_row.id not in surfaced_ids, (
            "orphan was surfaced for adoption on the strength of a LOW-only-"
            "source parent — the migration is no longer consistent with the "
            "runtime gate's one-hop-from-HIGH rule"
        )

    def test_migration_skips_cross_protocol_collisions(self, db_session, seed_protocol, migration_module):
        """An orphan referenced by HIGH-owned contracts of two different
        protocols stays orphan + a warning is logged. Avoids silently
        assigning truly-shared infrastructure to one protocol."""
        from db.models import Contract, Protocol

        # Second protocol so we can simulate a cross-protocol structural edge.
        second_proto = Protocol(name=f"gate-reg-second-{uuid.uuid4().hex[:8]}")
        db_session.add(second_proto)
        db_session.commit()

        child_addr = _addr(0xBB03)
        db_session.add(Contract(address=child_addr, chain="ethereum", protocol_id=None, discovery_sources=None))
        db_session.commit()
        # Edges from two different HIGH-owned parents → collision.
        self._seed_high_owner_with_edge(
            db_session,
            parent_addr=_addr(0xAA03),
            child_addr=child_addr,
            protocol_id=seed_protocol,
            relationship="implementation",
        )
        self._seed_high_owner_with_edge(
            db_session,
            parent_addr=_addr(0xAA04),
            child_addr=child_addr,
            protocol_id=second_proto.id,
            relationship="implementation",
        )

        rows = db_session.execute(migration_module._SELECT_STRUCTURAL_ORPHANS).fetchall()
        for orphan_id, parent_protocols in rows:
            unique = [pid for pid in (parent_protocols or []) if pid is not None]
            if len(unique) == 1:
                db_session.execute(migration_module._ADOPT_ORPHAN, {"pid": unique[0], "id": orphan_id})
        db_session.commit()

        row = db_session.query(Contract).filter_by(address=child_addr).one()
        assert row.protocol_id is None, (
            "cross-protocol collision was silently assigned to one protocol — "
            "shared infra needs manual review, not first-writer-wins"
        )


# ---------------------------------------------------------------------------
# 7. Remaining-orphan adoption — the fifth and sixth ownership branches.
#
# Branch A — deployer-cascade. An orphan whose ``deployer`` is also the
# deployer of some HIGH-sourced contract attributed to a protocol
# inherits that protocol regardless of its own ``discovery_sources``.
# Catches the etherfi orphan class surfaced by PR-87 investigation:
# contracts that landed in the DB via the resolution-cascade spawn at
# ``workers/resolution_worker.py:499-513`` (which only propagates
# ``discovery_relationship`` for impl / beacon edges) — non-impl/beacon
# dependencies arrive with NULL ``discovery_sources`` and no structural
# signal, even when their deployer is one of the protocol's qualified
# deployer EOAs. The HIGH-sourced-sibling requirement keeps WETH / USDC
# / OZ libs out: their deployers never wrote a HIGH-source contract
# attributed to the calling protocol.
#
# Branch B — historical-impl behind a HIGH-impl proxy. The proxy's
# CURRENT implementation is the HIGH anchor (mirrors 3a8f4d1c9b07's
# fourth branch, proxy-of-HIGH-impl). Walking the proxy's full upgrade
# history then sweeps the prior impl rows into the same protocol. The
# proxy itself can be LOW-only — ``structural_adoption`` is the typical
# tag, post-3a8f4d1c9b07 — because anchoring on the impl avoids
# extending the cascade through LOW intermediaries. Empirical scope:
# the 5 LRTSquare* historical impls behind the LRTSquaredCore-impl +
# UUPSProxy chain on PR-87.
# ---------------------------------------------------------------------------


@requires_postgres
class TestRemainingOrphanAdoption:
    """Both branches of ``4d72e9b1f035_adopt_remaining_orphan_classes``:

    Branch A (deployer-cascade) — migration-only sweep of the historical
    orphan set. The runtime helper it mirrored
    (``workers.discovery._deployer_cascade_protocol_id``) is replaced by the
    membership gate's deployer trust ladder (spec §3.3).

    Branch B (historical-impl behind HIGH-impl proxy) — migration-only.
    Anchors on the proxy's current implementation's HIGH source, not
    the proxy's own sources. Mirrors ``3a8f4d1c9b07``'s fourth branch.
    """

    @staticmethod
    def _seed_high_sibling(db_session, *, protocol_id, deployer, sibling_addr, sibling_sources):
        """Create a Contract row that will serve as the HIGH-source sibling
        for deployer-cascade adoption tests."""
        from db.models import Contract

        db_session.add(
            Contract(
                address=sibling_addr,
                chain="ethereum",
                deployer=deployer,
                protocol_id=protocol_id,
                discovery_sources=sibling_sources,
            )
        )
        db_session.commit()

    # ----- migration --------------------------------------------------------

    @pytest.fixture(scope="class")
    def remaining_orphans_migration(self):
        """Load the deployer-cascade migration by file path. Migration
        filenames lead with the revision id, which isn't a valid Python
        module name, so importlib.util by path is the way in."""
        import importlib.util

        path = (
            Path(__file__).resolve().parents[2]
            / "alembic"
            / "versions"
            / "4d72e9b1f035_adopt_remaining_orphan_classes.py"
        )
        spec = importlib.util.spec_from_file_location("_adopt_remaining_orphans_mig", path)
        assert spec is not None and spec.loader is not None
        module = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(module)
        return module

    def test_migration_adopts_orphan_when_high_sibling_shares_deployer(
        self, db_session, seed_protocol, remaining_orphans_migration
    ):
        from db.models import Contract

        deployer = _addr(0xCA01)
        orphan_addr = _addr(0xCB01)

        # Seed the orphan first.
        db_session.add(
            Contract(
                address=orphan_addr,
                chain="ethereum",
                deployer=deployer,
                protocol_id=None,
                discovery_sources=None,
            )
        )
        # And a HIGH-sourced sibling sharing the deployer.
        self._seed_high_sibling(
            db_session,
            protocol_id=seed_protocol,
            deployer=deployer,
            sibling_addr=_addr(0xCC01),
            sibling_sources=["deployer_expansion"],
        )

        rows = db_session.execute(remaining_orphans_migration._SELECT_REMAINING_ORPHANS).fetchall()
        adopted = 0
        for orphan_id, protocols, dominant_protocol in rows:
            unique = [pid for pid in (protocols or []) if pid is not None]
            if len(unique) == 1:
                db_session.execute(
                    remaining_orphans_migration._ADOPT_ORPHAN,
                    {"pid": dominant_protocol, "id": orphan_id},
                )
                adopted += 1
        db_session.commit()

        assert adopted >= 1
        row = db_session.query(Contract).filter_by(address=orphan_addr).one()
        assert row.protocol_id == seed_protocol
        assert "structural_adoption" in (row.discovery_sources or [])

    def test_migration_skips_low_only_siblings(self, db_session, seed_protocol, remaining_orphans_migration):
        """A deployer whose siblings are all LOW (dapp_crawl,
        upgrade_history) does NOT count — this keeps Lido / EigenLayer /
        WETH orphans from being adopted just because some etherfi pipeline
        also saw them."""
        from db.models import Contract

        deployer = _addr(0xCA02)
        orphan_addr = _addr(0xCB02)

        db_session.add(
            Contract(
                address=orphan_addr,
                chain="ethereum",
                deployer=deployer,
                protocol_id=None,
                discovery_sources=None,
            )
        )
        self._seed_high_sibling(
            db_session,
            protocol_id=seed_protocol,
            deployer=deployer,
            sibling_addr=_addr(0xCC02),
            sibling_sources=["dapp_crawl"],  # LOW-only
        )

        rows = db_session.execute(remaining_orphans_migration._SELECT_REMAINING_ORPHANS).fetchall()
        orphan_ids = {r[0] for r in rows}
        target = db_session.query(Contract).filter_by(address=orphan_addr).one()
        assert target.id not in orphan_ids, (
            "deployer-cascade SELECT returned an orphan whose sibling is LOW-only — "
            "this is the WETH leak the gate must block"
        )

    def test_migration_skips_cross_protocol_collision(self, db_session, seed_protocol, remaining_orphans_migration):
        """If a single deployer wrote HIGH-source contracts for two
        different protocols and we'd be choosing one over the other,
        skip the orphan and leave it for manual review. Mirrors the
        existing structural-orphan migration convention."""
        from db.models import Contract, Protocol

        other = Protocol(name=f"dep-cascade-collide-{uuid.uuid4().hex[:10]}")
        db_session.add(other)
        db_session.commit()

        deployer = _addr(0xCA03)
        orphan_addr = _addr(0xCB03)
        db_session.add(
            Contract(
                address=orphan_addr,
                chain="ethereum",
                deployer=deployer,
                protocol_id=None,
                discovery_sources=None,
            )
        )
        # One HIGH sibling on each of two protocols → ambiguous.
        self._seed_high_sibling(
            db_session,
            protocol_id=seed_protocol,
            deployer=deployer,
            sibling_addr=_addr(0xCC03),
            sibling_sources=["deployer_expansion"],
        )
        self._seed_high_sibling(
            db_session,
            protocol_id=other.id,
            deployer=deployer,
            sibling_addr=_addr(0xCC04),
            sibling_sources=["ai_inventory"],
        )

        rows = db_session.execute(remaining_orphans_migration._SELECT_REMAINING_ORPHANS).fetchall()
        for orphan_id, protocols, dominant_protocol in rows:
            unique = [pid for pid in (protocols or []) if pid is not None]
            if len(unique) == 1:
                db_session.execute(
                    remaining_orphans_migration._ADOPT_ORPHAN,
                    {"pid": dominant_protocol, "id": orphan_id},
                )
        db_session.commit()

        row = db_session.query(Contract).filter_by(address=orphan_addr).one()
        assert row.protocol_id is None, (
            "cross-protocol collision was silently assigned to one protocol — "
            "shared deployers across protocols need manual review"
        )

    # ----- branch B: historical-impl behind a HIGH-impl proxy ---------------

    @staticmethod
    def _seed_proxy_with_upgrade_history(
        db_session,
        *,
        protocol_id,
        proxy_addr,
        proxy_sources,
        historical_impls,
        current_impl_addr,
        current_impl_protocol_id=None,
        current_impl_sources=None,
    ):
        """Seed the LRTSquare* chain shape: a current impl (the HIGH
        anchor), a proxy whose ``.implementation`` points at it, and
        UpgradeEvent rows for each address in *historical_impls*.

        Branch B's CTE reads ``impl.discovery_sources`` (the proxy's
        CURRENT impl) for the HIGH gate. Override
        ``current_impl_sources`` with LOW tags to exercise the negative
        path, or override ``current_impl_protocol_id`` to exercise the
        proxy/impl protocol mismatch guard. Defaults reproduce the
        positive case: HIGH ``deployer_expansion`` source, impl shares
        the proxy's protocol_id."""
        from db.models import Contract, UpgradeEvent

        impl_pid = protocol_id if current_impl_protocol_id is None else current_impl_protocol_id
        impl_sources = current_impl_sources if current_impl_sources is not None else ["deployer_expansion"]

        db_session.add(
            Contract(
                address=current_impl_addr,
                chain="ethereum",
                protocol_id=impl_pid,
                contract_name="CurrentImpl",
                discovery_sources=impl_sources,
            )
        )
        proxy = Contract(
            address=proxy_addr,
            chain="ethereum",
            protocol_id=protocol_id,
            discovery_sources=proxy_sources,
            is_proxy=True,
            implementation=current_impl_addr,
        )
        db_session.add(proxy)
        db_session.flush()
        for i, impl_addr in enumerate(historical_impls):
            db_session.add(
                UpgradeEvent(
                    contract_id=proxy.id,
                    proxy_address=proxy_addr,
                    old_impl=historical_impls[i - 1] if i > 0 else None,
                    new_impl=impl_addr,
                    block_number=1_000_000 + i,
                )
            )
        db_session.commit()
        return proxy

    def test_historical_impl_adopted_via_high_current_impl(
        self, db_session, seed_protocol, remaining_orphans_migration
    ):
        """LRTSquare-shape: an orphan historical impl whose only source
        is ``upgrade_history`` (or NULL) is adopted into the protocol
        when the proxy's CURRENT implementation is HIGH-sourced — even
        when the proxy itself carries only LOW tags (the typical post-
        3a8f4d1c9b07 shape: a UUPSProxy adopted via ``structural_adoption``
        from its HIGH impl)."""
        from db.models import Contract

        old_impl_addr = _addr(0xD001)
        proxy_addr = _addr(0xE001)
        current_impl_addr = _addr(0xF001)

        # Orphan historical impl with only LOW source — the prod shape.
        db_session.add(
            Contract(
                address=old_impl_addr,
                chain="ethereum",
                protocol_id=None,
                discovery_sources=["upgrade_history"],
            )
        )
        # LOW-adopted proxy whose current impl is HIGH-sourced.
        self._seed_proxy_with_upgrade_history(
            db_session,
            protocol_id=seed_protocol,
            proxy_addr=proxy_addr,
            proxy_sources=["structural_adoption"],  # LOW — the actual prod tag
            historical_impls=[old_impl_addr, _addr(0xD002)],
            current_impl_addr=current_impl_addr,
            current_impl_sources=["deployer_expansion"],  # HIGH anchor
        )

        rows = db_session.execute(remaining_orphans_migration._SELECT_REMAINING_ORPHANS).fetchall()
        for orphan_id, protocols, dominant_protocol in rows:
            unique = [pid for pid in (protocols or []) if pid is not None]
            if len(unique) == 1:
                db_session.execute(
                    remaining_orphans_migration._ADOPT_ORPHAN,
                    {"pid": dominant_protocol, "id": orphan_id},
                )
        db_session.commit()

        row = db_session.query(Contract).filter_by(address=old_impl_addr).one()
        assert row.protocol_id == seed_protocol, (
            "historical impl behind HIGH-impl proxy stayed orphan — branch B failed"
        )
        assert "structural_adoption" in (row.discovery_sources or [])

    def test_historical_impl_lrtsquare_shape_adopts_all_five(
        self, db_session, seed_protocol, remaining_orphans_migration
    ):
        """Regression pin for the exact PR-87 LRTSquare* shape: HIGH
        LRTSquaredCore impl + LOW-adopted UUPSProxy +
        5 orphan historical impls (LRTSquare ×2, LRTSquared ×2,
        LRTSquaredDummy ×1) → all 5 get adopted into the protocol.

        Before this fix, the migration's branch B required the proxy
        itself to be HIGH-sourced. UUPSProxy carried only
        ``structural_adoption`` (granted by 3a8f4d1c9b07's branch 4 via
        its HIGH impl), so the historical impls stayed orphan."""
        from db.models import Contract

        # The HIGH anchor — LRTSquaredCore — carries deployer_expansion.
        # In prod its sources are {deployer_expansion, upgrade_history};
        # the HIGH tag alone is what the gate reads.
        lrt_squared_core_addr = _addr(0xC0E0)
        # UUPSProxy — protocol_id set (via 3a8f4d1c9b07 branch 4) but
        # only LOW source.
        uups_proxy_addr = _addr(0xC0E1)
        # The five orphan historical impls — protocol_id NULL, sources
        # {upgrade_history} only.
        orphan_impls = [_addr(0xC0E2 + i) for i in range(5)]
        for addr in orphan_impls:
            db_session.add(
                Contract(
                    address=addr,
                    chain="ethereum",
                    protocol_id=None,
                    discovery_sources=["upgrade_history"],
                )
            )

        self._seed_proxy_with_upgrade_history(
            db_session,
            protocol_id=seed_protocol,
            proxy_addr=uups_proxy_addr,
            proxy_sources=["structural_adoption"],
            historical_impls=orphan_impls,
            current_impl_addr=lrt_squared_core_addr,
            current_impl_sources=["deployer_expansion", "upgrade_history"],
        )

        rows = db_session.execute(remaining_orphans_migration._SELECT_REMAINING_ORPHANS).fetchall()
        for orphan_id, protocols, dominant_protocol in rows:
            unique = [pid for pid in (protocols or []) if pid is not None]
            if len(unique) == 1:
                db_session.execute(
                    remaining_orphans_migration._ADOPT_ORPHAN,
                    {"pid": dominant_protocol, "id": orphan_id},
                )
        db_session.commit()

        adopted = (
            db_session.query(Contract)
            .filter(Contract.address.in_(orphan_impls), Contract.protocol_id == seed_protocol)
            .count()
        )
        assert adopted == 5, (
            f"expected all 5 LRTSquare* historical impls adopted, got {adopted} — "
            "branch B did not sweep the full upgrade history"
        )

    def test_historical_impl_skipped_when_current_impl_is_low(
        self, db_session, seed_protocol, remaining_orphans_migration
    ):
        """EigenLayer-leak shape: a foreign proxy imported via
        ``dapp_crawl`` whose current impl is ALSO LOW-sourced has no
        HIGH evidence anywhere in the chain. Historical impls must NOT
        be adopted — anchoring on the impl's HIGH tag must keep this
        gate shut just like the old proxy-HIGH gate did.

        ``current_impl_protocol_id=None`` reproduces the realistic prod
        shape: the impl row exists (the EigenLayer leak puts every
        impl in ``contracts``) but is itself orphan."""
        from db.models import Contract

        old_impl_addr = _addr(0xD003)
        proxy_addr = _addr(0xE002)
        current_impl_addr = _addr(0xF002)

        db_session.add(
            Contract(
                address=old_impl_addr,
                chain="ethereum",
                protocol_id=None,
                discovery_sources=["upgrade_history"],
            )
        )
        # LOW-only proxy AND orphan/LOW current impl → no HIGH anchor.
        self._seed_proxy_with_upgrade_history(
            db_session,
            protocol_id=None,
            proxy_addr=proxy_addr,
            proxy_sources=["dapp_crawl"],
            historical_impls=[old_impl_addr],
            current_impl_addr=current_impl_addr,
            current_impl_protocol_id=None,
            current_impl_sources=["dapp_crawl"],
        )

        rows = db_session.execute(remaining_orphans_migration._SELECT_REMAINING_ORPHANS).fetchall()
        orphan_ids = {r[0] for r in rows}
        target = db_session.query(Contract).filter_by(address=old_impl_addr).one()
        assert target.id not in orphan_ids, (
            "historical impl behind LOW-only chain was returned by the SELECT — "
            "this is the EigenLayer leak shape the gate must block"
        )

    def test_historical_impl_skipped_when_proxy_and_impl_protocols_disagree(
        self, db_session, seed_protocol, remaining_orphans_migration
    ):
        """Protocol-mismatch guard: if the proxy carries protocol_id A
        (e.g., inherited via structural_adoption from a different chain
        of evidence) but its current implementation belongs to protocol
        B, the historical impls must NOT be adopted. Otherwise a fork
        whose impl coincidentally points at someone else's HIGH-owned
        contract would leak across protocols."""
        from db.models import Contract, Protocol

        other = Protocol(name=f"hist-impl-mismatch-{uuid.uuid4().hex[:10]}")
        db_session.add(other)
        db_session.commit()

        old_impl_addr = _addr(0xD030)
        proxy_addr = _addr(0xE030)
        current_impl_addr = _addr(0xF030)

        db_session.add(
            Contract(
                address=old_impl_addr,
                chain="ethereum",
                protocol_id=None,
                discovery_sources=["upgrade_history"],
            )
        )
        # Proxy attributed to ``seed_protocol`` but its current impl is
        # HIGH-sourced in ``other`` protocol.
        self._seed_proxy_with_upgrade_history(
            db_session,
            protocol_id=seed_protocol,
            proxy_addr=proxy_addr,
            proxy_sources=["structural_adoption"],
            historical_impls=[old_impl_addr],
            current_impl_addr=current_impl_addr,
            current_impl_protocol_id=other.id,
            current_impl_sources=["deployer_expansion"],
        )

        rows = db_session.execute(remaining_orphans_migration._SELECT_REMAINING_ORPHANS).fetchall()
        orphan_ids = {r[0] for r in rows}
        target = db_session.query(Contract).filter_by(address=old_impl_addr).one()
        assert target.id not in orphan_ids, (
            "orphan was surfaced for adoption even though proxy.protocol_id != impl.protocol_id — "
            "the mismatch guard is missing or broken"
        )

    def test_historical_impl_zero_address_filtered(self, db_session, seed_protocol, remaining_orphans_migration):
        """Some backfill paths emit synthetic UpgradeEvent rows with
        ``new_impl = 0x0…0`` for the pre-init state. The SELECT must
        filter those out — otherwise we'd be "adopting" the zero
        address as a contract, which doesn't exist."""
        from db.models import Contract

        zero_addr = "0x" + "0" * 40
        proxy_addr = _addr(0xE003)
        current_impl_addr = _addr(0xF003)

        # An orphan row keyed at the zero address would never exist in
        # practice (no contract there), but seed it to verify the
        # filter explicitly — if anyone ever does materialize a row
        # there, this test pins that the migration won't grant ownership.
        db_session.add(
            Contract(
                address=zero_addr,
                chain="ethereum",
                protocol_id=None,
                discovery_sources=["upgrade_history"],
            )
        )
        self._seed_proxy_with_upgrade_history(
            db_session,
            protocol_id=seed_protocol,
            proxy_addr=proxy_addr,
            proxy_sources=["structural_adoption"],
            historical_impls=[zero_addr, _addr(0xD004)],
            current_impl_addr=current_impl_addr,
            current_impl_sources=["deployer_expansion"],
        )

        rows = db_session.execute(remaining_orphans_migration._SELECT_REMAINING_ORPHANS).fetchall()
        orphan_ids = {r[0] for r in rows}
        zero_row = db_session.query(Contract).filter_by(address=zero_addr).one()
        assert zero_row.id not in orphan_ids, (
            "zero-address UpgradeEvent.new_impl rows must be filtered before they reach the adoption SELECT"
        )

    def test_historical_impl_cross_protocol_collision_skipped(
        self, db_session, seed_protocol, remaining_orphans_migration
    ):
        """Two proxies from different protocols, each with a HIGH
        current impl in its own protocol, both used the same historical
        impl at some point (rare — shared init impl across deployments).
        The orphan impl is skipped + logged rather than adopted into
        one arbitrary protocol."""
        from db.models import Contract, Protocol

        other = Protocol(name=f"hist-impl-collide-{uuid.uuid4().hex[:10]}")
        db_session.add(other)
        db_session.commit()

        shared_impl_addr = _addr(0xD005)
        db_session.add(
            Contract(
                address=shared_impl_addr,
                chain="ethereum",
                protocol_id=None,
                discovery_sources=["upgrade_history"],
            )
        )
        # Two proxies on two different protocols, each with its own
        # HIGH current impl and the shared impl in upgrade history.
        self._seed_proxy_with_upgrade_history(
            db_session,
            protocol_id=seed_protocol,
            proxy_addr=_addr(0xE004),
            proxy_sources=["structural_adoption"],
            historical_impls=[shared_impl_addr],
            current_impl_addr=_addr(0xF004),
            current_impl_sources=["deployer_expansion"],
        )
        self._seed_proxy_with_upgrade_history(
            db_session,
            protocol_id=other.id,
            proxy_addr=_addr(0xE005),
            proxy_sources=["structural_adoption"],
            historical_impls=[shared_impl_addr],
            current_impl_addr=_addr(0xF005),
            current_impl_protocol_id=other.id,
            current_impl_sources=["ai_inventory"],
        )

        rows = db_session.execute(remaining_orphans_migration._SELECT_REMAINING_ORPHANS).fetchall()
        for orphan_id, protocols, dominant_protocol in rows:
            unique = [pid for pid in (protocols or []) if pid is not None]
            if len(unique) == 1:
                db_session.execute(
                    remaining_orphans_migration._ADOPT_ORPHAN,
                    {"pid": dominant_protocol, "id": orphan_id},
                )
        db_session.commit()

        row = db_session.query(Contract).filter_by(address=shared_impl_addr).one()
        assert row.protocol_id is None, (
            "shared impl across two protocols was silently assigned to one — "
            "the cross-protocol skip must cover the historical-impl branch too"
        )

    def test_orphan_with_both_branches_matching_same_protocol_adopts(
        self, db_session, seed_protocol, remaining_orphans_migration
    ):
        """Belt-and-suspenders: if the orphan matches via BOTH the
        deployer-cascade and historical-impl branches for the SAME
        protocol, that's not a collision — it's stronger evidence.
        Adopt cleanly."""
        from db.models import Contract

        orphan_addr = _addr(0xD006)
        deployer = _addr(0xCA10)

        # Orphan with a deployer set; will match Branch A via deployer.
        db_session.add(
            Contract(
                address=orphan_addr,
                chain="ethereum",
                deployer=deployer,
                protocol_id=None,
                discovery_sources=["upgrade_history"],
            )
        )
        # HIGH sibling sharing the deployer (Branch A evidence).
        self._seed_high_sibling(
            db_session,
            protocol_id=seed_protocol,
            deployer=deployer,
            sibling_addr=_addr(0xCC10),
            sibling_sources=["deployer_expansion"],
        )
        # Proxy with HIGH current impl + this orphan in upgrade history
        # (Branch B evidence) — same protocol, so the two evidence
        # streams reinforce.
        self._seed_proxy_with_upgrade_history(
            db_session,
            protocol_id=seed_protocol,
            proxy_addr=_addr(0xE006),
            proxy_sources=["structural_adoption"],
            historical_impls=[orphan_addr],
            current_impl_addr=_addr(0xF006),
            current_impl_sources=["ai_inventory"],
        )

        rows = db_session.execute(remaining_orphans_migration._SELECT_REMAINING_ORPHANS).fetchall()
        for orphan_id, protocols, dominant_protocol in rows:
            unique = [pid for pid in (protocols or []) if pid is not None]
            if len(unique) == 1:
                db_session.execute(
                    remaining_orphans_migration._ADOPT_ORPHAN,
                    {"pid": dominant_protocol, "id": orphan_id},
                )
        db_session.commit()

        row = db_session.query(Contract).filter_by(address=orphan_addr).one()
        assert row.protocol_id == seed_protocol
