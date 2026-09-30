"""Wiring only: the firing precondition, the failure domain and call-site provenance.

The cold-cursor case must still reach the table as ``holders`` NULL.
"""

from __future__ import annotations

import threading
import uuid
from types import SimpleNamespace
from typing import Any
from unittest.mock import MagicMock

import pytest
from sqlalchemy import select

from db.models import (
    HOLDER_SET_EXHAUSTIVE_NOT_DETERMINED,
    ROLE_COVERAGE_PARTIAL,
    Contract,
    IndexedEventCursor,
    IndexedEventLog,
    Protocol,
    RoleHolderPlane,
    enrollment_basis_permits_exactness,
)
from db.queue import HEARTBEAT_PROTOCOL_RESTAKING
from services.monitoring import restaking_cycle
from services.monitoring.restaking_cycle import refresh_restaking_plane, run_restaking_loop
from services.monitoring.restaking_enrollment import (
    PUBKEY_LINKED_TOPIC0,
    RESTAKING_FOLD_ENROLLMENT_BASIS,
    enroll_restaking_fold,
    node_addresses_from_fold,
)
from services.resolution.role_holder_plane import ROLE_GRANTED_TOPIC0, ROLE_REVOKED_TOPIC0
from tests.support.witness_wire import stub_seed_witness
from workers.resolution_worker import ResolutionWorker

# Its ``contracts`` row is keyed at the implementation, which emits nothing.
EFNM_PROXY = "0x8b71140ad2e5d1e7018d2a7f8a288bd3cd38916f"
EFNM_IMPLEMENTATION = "0xcf5928ea7d7f164ec868ceda7a69e08a102b5e05"
EFNM_CREATION_BLOCK = 17174453
OTHER_EMITTER = "0x1111111111111111111111111111111111111111"

NODE_A = "0x05b1e40339823e1af30a8ed70c3fbf7f1d0ce9ae"
NODE_B = "0x53e1eb2fa5ec3c5097e67265e33ea4e53ab61b79"

REGISTRY = "0x2222222222222222222222222222222222222222"
PROXY_REGISTRY = "0x3333333333333333333333333333333333333333"
ROLE_HASH = "0x" + "ab" * 32
GRANTEE = "0x4444444444444444444444444444444444444444"


BLOCK = 25643300


def _job_stub() -> Any:
    return SimpleNamespace(id=uuid.uuid4())


def _topic_word(address: str) -> str:
    return "0x" + address.lower().removeprefix("0x").rjust(64, "0")


def _cursor(address: str, topic0: str, *, backfill_complete: bool = False) -> IndexedEventCursor:
    return IndexedEventCursor(
        chain_id=1,
        event_address=address.lower(),
        topic0=topic0.lower(),
        last_indexed_block=BLOCK,
        backfill_complete=backfill_complete,
    )


def _role_log(registry: str, *, log_index: int) -> IndexedEventLog:
    return IndexedEventLog(
        chain_id=1,
        event_address=registry.lower(),
        topic0=ROLE_GRANTED_TOPIC0,
        block_number=BLOCK - 100,
        transaction_index=0,
        log_index=log_index,
        tx_hash=bytes([log_index]) * 32,
        block_hash=bytes([log_index + 1]) * 32,
        topics=[ROLE_GRANTED_TOPIC0, ROLE_HASH, _topic_word(GRANTEE), _topic_word(GRANTEE)],
        data_words=[],
    )


def _pubkey_log(node: str, *, emitter: str, log_index: int) -> IndexedEventLog:
    return IndexedEventLog(
        chain_id=1,
        event_address=emitter.lower(),
        topic0=PUBKEY_LINKED_TOPIC0,
        block_number=BLOCK - 50,
        transaction_index=0,
        log_index=log_index,
        tx_hash=bytes([log_index + 40]) * 32,
        block_hash=bytes([log_index + 41]) * 32,
        topics=[PUBKEY_LINKED_TOPIC0, "0x" + "cd" * 32, _topic_word(node), "0x" + "00" * 32],
        data_words=[],
    )


@pytest.fixture
def role_plane_session(db_session):
    yield db_session
    db_session.rollback()
    db_session.query(RoleHolderPlane).delete()
    db_session.commit()


class TestRoleHolderPlaneFiringCondition:
    def _spy(self, monkeypatch) -> list[dict[str, Any]]:
        calls: list[dict[str, Any]] = []

        def fake_resolve(_session, *, chain_id, registry_address, rpc_url):
            calls.append({"chain_id": chain_id, "registry_address": registry_address, "rpc_url": rpc_url})
            return []

        monkeypatch.setattr("workers.resolution_worker.resolve_role_holder_planes", fake_resolve)
        return calls

    def test_both_cursors_fire_the_producer(self, db_session, monkeypatch):
        calls = self._spy(monkeypatch)
        db_session.add_all([_cursor(REGISTRY, ROLE_GRANTED_TOPIC0), _cursor(REGISTRY, ROLE_REVOKED_TOPIC0)])
        db_session.flush()

        ResolutionWorker()._resolve_role_holder_plane(
            db_session,
            _job_stub(),
            chain_id=1,
            rpc_url="https://rpc.example",
            registry_address=REGISTRY,
        )

        assert calls == [{"chain_id": 1, "registry_address": REGISTRY, "rpc_url": "https://rpc.example"}]
        db_session.rollback()

    @pytest.mark.parametrize(
        "topics",
        [
            pytest.param((ROLE_GRANTED_TOPIC0,), id="granted_only"),
            pytest.param((ROLE_REVOKED_TOPIC0,), id="revoked_only"),
            pytest.param((), id="no_cursor"),
        ],
    )
    def test_a_missing_topic_refuses(self, db_session, monkeypatch, topics):
        calls = self._spy(monkeypatch)
        for topic in topics:
            db_session.add(_cursor(REGISTRY, topic))
        db_session.flush()

        written = ResolutionWorker()._resolve_role_holder_plane(
            db_session,
            _job_stub(),
            chain_id=1,
            rpc_url="https://rpc.example",
            registry_address=REGISTRY,
        )

        assert written == 0
        assert calls == []
        db_session.rollback()

    def test_cursors_on_another_registry_do_not_license_this_one(self, db_session, monkeypatch):
        calls = self._spy(monkeypatch)
        db_session.add_all([_cursor(PROXY_REGISTRY, ROLE_GRANTED_TOPIC0), _cursor(PROXY_REGISTRY, ROLE_REVOKED_TOPIC0)])
        db_session.flush()

        assert (
            ResolutionWorker()._resolve_role_holder_plane(
                db_session,
                _job_stub(),
                chain_id=1,
                rpc_url="https://rpc.example",
                registry_address=REGISTRY,
            )
            == 0
        )
        assert calls == []
        db_session.rollback()

    def test_cursors_on_another_chain_do_not_license_this_one(self, db_session, monkeypatch):
        calls = self._spy(monkeypatch)
        for topic in (ROLE_GRANTED_TOPIC0, ROLE_REVOKED_TOPIC0):
            cursor = _cursor(REGISTRY, topic)
            cursor.chain_id = 8453
            db_session.add(cursor)
        db_session.flush()

        assert (
            ResolutionWorker()._resolve_role_holder_plane(
                db_session,
                _job_stub(),
                chain_id=1,
                rpc_url="https://rpc.example",
                registry_address=REGISTRY,
            )
            == 0
        )
        assert calls == []
        db_session.rollback()

    def test_checksummed_registry_matches_the_lowercased_cursor(self, db_session, monkeypatch):
        calls = self._spy(monkeypatch)
        db_session.add_all([_cursor(REGISTRY, ROLE_GRANTED_TOPIC0), _cursor(REGISTRY, ROLE_REVOKED_TOPIC0)])
        db_session.flush()

        ResolutionWorker()._resolve_role_holder_plane(
            db_session,
            _job_stub(),
            chain_id=1,
            rpc_url="https://rpc.example",
            registry_address=REGISTRY.upper().replace("0X", "0x"),
        )

        assert len(calls) == 1
        db_session.rollback()

    def test_no_rows_writes_nothing(self, db_session, monkeypatch):
        """Row absence is not_determined, not a commit."""
        self._spy(monkeypatch)
        persisted: list[Any] = []
        monkeypatch.setattr(
            "workers.resolution_worker.persist_role_holder_planes",
            lambda _s, rows: persisted.append(rows) or 0,
        )
        db_session.add_all([_cursor(REGISTRY, ROLE_GRANTED_TOPIC0), _cursor(REGISTRY, ROLE_REVOKED_TOPIC0)])
        db_session.flush()

        assert (
            ResolutionWorker()._resolve_role_holder_plane(
                db_session,
                _job_stub(),
                chain_id=1,
                rpc_url="https://rpc.example",
                registry_address=REGISTRY,
            )
            == 0
        )
        assert persisted == []
        db_session.rollback()


class TestRoleHolderPlaneColdCursor:
    def test_cold_cursor_publishes_null_holders_not_an_empty_set(self, role_plane_session, monkeypatch):
        session = role_plane_session
        session.add_all(
            [
                _cursor(REGISTRY, ROLE_GRANTED_TOPIC0, backfill_complete=False),
                _cursor(REGISTRY, ROLE_REVOKED_TOPIC0, backfill_complete=False),
                _role_log(REGISTRY, log_index=1),
            ]
        )
        session.commit()

        def no_probe(*_a, **_kw):
            raise AssertionError("a cold pair must never reach the chain")

        monkeypatch.setattr("services.resolution.role_holder_plane.pin_probe_block", no_probe)

        written = ResolutionWorker()._resolve_role_holder_plane(
            session,
            _job_stub(),
            chain_id=1,
            rpc_url="https://rpc.example",
            registry_address=REGISTRY,
        )

        assert written == 1
        row = session.execute(select(RoleHolderPlane).where(RoleHolderPlane.registry_address == REGISTRY)).scalar_one()
        # ``[]`` would assert the floor was computed and came back empty.
        assert row.holders is None
        assert row.coverage == ROLE_COVERAGE_PARTIAL
        assert row.holder_set_exhaustive == HOLDER_SET_EXHAUSTIVE_NOT_DETERMINED
        assert row.as_of_block is None
        assert row.candidate_count is None
        assert row.fold_chain_disagreements is None


def _stub_stage(monkeypatch, **overrides: Any) -> None:
    tracking_plan = {"contract_address": REGISTRY, "controllers": []}
    contract_analysis = {"subject": {"address": REGISTRY}, "contract_name": "Registry", "functions": []}
    snapshot = {"contract_address": REGISTRY, "controller_values": {}, "block_number": BLOCK}

    monkeypatch.setattr(
        "workers.resolution_worker.get_artifact",
        lambda _s, _j, name: {
            "control_tracking_plan": tracking_plan,
            "contract_analysis": contract_analysis,
        }.get(name),
    )
    monkeypatch.setattr("workers.resolution_worker.store_artifact", lambda *a, **kw: None)
    monkeypatch.setattr("workers.resolution_worker.build_control_snapshot", lambda *a, **kw: snapshot)
    monkeypatch.setattr(
        "workers.resolution_worker.resolve_control_graph",
        lambda **_kw: ({"root_contract_address": REGISTRY, "nodes": [], "edges": []}, {}),
    )
    monkeypatch.setattr("workers.base.update_job_detail", lambda *a, **kw: None)
    monkeypatch.setattr(ResolutionWorker, "_fetch_balances", lambda *a, **kw: None)
    monkeypatch.setattr(ResolutionWorker, "_emit_dependency_edges_from_predicate_trees", lambda *a, **kw: None)
    for name, value in overrides.items():
        monkeypatch.setattr(ResolutionWorker, name, value)


def _job(**overrides: Any) -> SimpleNamespace:
    payload: dict[str, Any] = {
        "id": uuid.uuid4(),
        "address": REGISTRY,
        "name": "Registry",
        "company": None,
        "protocol_id": None,
        "request": {"rpc_url": "https://rpc.example", "chain": "ethereum"},
    }
    payload.update(overrides)
    return SimpleNamespace(**payload)


class TestResolutionStageComposition:
    def test_stage_invokes_the_plane_with_the_job_address(self, monkeypatch):
        seen: list[dict[str, Any]] = []
        _stub_stage(
            monkeypatch,
            _resolve_role_holder_plane=lambda _self, _s, _j, **kw: seen.append(kw) or 0,
        )
        session = MagicMock()
        session.execute.return_value.scalar_one_or_none.return_value = None

        ResolutionWorker().process(session, _job())  # pyright: ignore[reportArgumentType]

        assert len(seen) == 1
        assert seen[0]["registry_address"] == REGISTRY
        assert seen[0]["chain_id"] == 1

    def test_impl_job_registers_the_proxy_not_the_implementation(self, monkeypatch):
        seen: list[dict[str, Any]] = []
        _stub_stage(
            monkeypatch,
            _resolve_role_holder_plane=lambda _self, _s, _j, **kw: seen.append(kw) or 0,
        )
        session = MagicMock()
        session.execute.return_value.scalar_one_or_none.return_value = None
        job = _job(request={"rpc_url": "https://rpc.example", "chain": "ethereum", "proxy_address": PROXY_REGISTRY})

        ResolutionWorker().process(session, job)  # pyright: ignore[reportArgumentType]

        assert seen[0]["registry_address"] == PROXY_REGISTRY

    def test_a_plane_failure_does_not_fail_the_stage(self, monkeypatch):
        def boom(_self, _s, _j, **_kw):
            raise RuntimeError("probe exploded")

        _stub_stage(monkeypatch, _resolve_role_holder_plane=boom)
        degraded: list[str] = []
        monkeypatch.setattr(
            "workers.resolution_worker.record_degraded",
            lambda *, phase, exc, context: degraded.append(phase),
        )
        session = MagicMock()
        session.execute.return_value.scalar_one_or_none.return_value = None
        details: list[str] = []
        monkeypatch.setattr(ResolutionWorker, "update_detail", lambda _self, _s, _j, text: details.append(text))

        ResolutionWorker().process(session, _job())  # pyright: ignore[reportArgumentType]

        assert degraded == ["resolution_role_holder_plane"]
        assert any(d.startswith("Resolution complete") for d in details)
        session.rollback.assert_called()


class _RestakingSpies:
    def __init__(self, monkeypatch, *, records=None, read_raises=None):
        self.order: list[str] = []
        self.persisted: list[dict[str, Any]] = []
        self.enrolled: list[tuple[int, list[str]]] = []
        self.node_scopes: list[str | None] = []
        self.read_kwargs: dict[str, Any] = {}
        self.read_nodes: list[str] = []
        records = records if records is not None else [{"chain_id": 1, "node_address": NODE_A}]

        self.cycles: list[dict[str, Any]] = []
        monkeypatch.setattr(
            restaking_cycle,
            "emit_monitor_cycle",
            lambda process, **kw: self.cycles.append({"process": process, **kw}),
        )
        monkeypatch.setattr(restaking_cycle, "pinned_head", lambda *_a, **_kw: (BLOCK, "0x" + "ee" * 32))
        monkeypatch.setattr(restaking_cycle, "_log_fetcher", lambda *_a, **_kw: lambda *a, **kw: [])
        monkeypatch.setattr(restaking_cycle, "discover_emitters", lambda *_a, **_kw: self._emitters(*_a, **_kw))
        monkeypatch.setattr(restaking_cycle, "protocol_contract_addresses", lambda *_a, **_kw: [EFNM_PROXY])

        def fake_enroll(_session, *, chain_id, emitters):
            self.order.append("enroll")
            self.enrolled.append((chain_id, list(emitters)))
            return len(emitters)

        def fake_nodes(_session, *, chain_id, event_address=None):
            self.node_scopes.append(event_address)
            return [NODE_A]

        def fake_read(nodes, **kw):
            self.order.append("read")
            if read_raises is not None:
                raise read_raises
            self.read_kwargs = kw
            self.read_nodes = list(nodes)
            return list(records)

        def fake_persist(_session, recs, *, manager_contract_id, protocol_id):
            self.order.append("persist")
            self.persisted.append(
                {"records": list(recs), "manager_contract_id": manager_contract_id, "protocol_id": protocol_id}
            )
            return len(recs)

        monkeypatch.setattr(restaking_cycle, "enroll_restaking_fold", fake_enroll)
        monkeypatch.setattr(restaking_cycle, "node_addresses_from_fold", fake_nodes)
        monkeypatch.setattr(restaking_cycle, "read_positions", fake_read)
        monkeypatch.setattr(restaking_cycle, "persist_positions", fake_persist)
        monkeypatch.setattr(restaking_cycle, "manager_contract_id_for", lambda *_a, **_kw: 591)
        self.emitters: list[str] = [EFNM_PROXY]

    def _emitters(self, *_a, **_kw) -> set[str]:
        return set(self.emitters)


@pytest.fixture
def one_protocol(db_session):
    protocol = Protocol(name="etherfi")
    db_session.add(protocol)
    db_session.flush()
    db_session.add(Contract(protocol_id=protocol.id, address=EFNM_PROXY, contract_name="EFNM", chain="ethereum"))
    db_session.flush()
    return protocol


class TestRestakingStepOrder:
    def test_enroll_then_read_then_persist(self, db_session, one_protocol, monkeypatch):
        spies = _RestakingSpies(monkeypatch)

        written = refresh_restaking_plane(db_session, chain_id=1, rpc_url="https://rpc.example")

        assert spies.order == ["enroll", "read", "persist"]
        assert written == 1
        assert spies.enrolled == [(1, [EFNM_PROXY])]
        db_session.rollback()

    def test_nodes_are_scoped_to_the_emitter_that_enumerated_them(self, db_session, one_protocol, monkeypatch):
        spies = _RestakingSpies(monkeypatch)
        spies.emitters = [EFNM_PROXY, OTHER_EMITTER]

        refresh_restaking_plane(db_session, chain_id=1, rpc_url="https://rpc.example")

        assert spies.node_scopes == sorted([EFNM_PROXY, OTHER_EMITTER])
        assert [p["protocol_id"] for p in spies.persisted] == [one_protocol.id, one_protocol.id]
        db_session.rollback()


class TestRestakingStepFailClosed:
    def test_a_chain_without_a_verified_manager_pair_reads_nothing(self, db_session, monkeypatch):
        spies = _RestakingSpies(monkeypatch)

        assert refresh_restaking_plane(db_session, chain_id=8453, rpc_url="https://rpc.example") == 0
        assert spies.order == []
        # A silent return looks like a wedged loop; an unconfigured chain is an absence, not a failure.
        assert spies.cycles[-1]["note"] == "no_manager_pair"
        assert spies.cycles[-1]["partial"] is False
        db_session.rollback()

    def test_no_rpc_url_reads_nothing(self, db_session, monkeypatch):
        spies = _RestakingSpies(monkeypatch)
        monkeypatch.setattr(restaking_cycle, "rpc_url_for_chain_id", lambda *_a, **_kw: None)

        assert refresh_restaking_plane(db_session, chain_id=1) == 0
        assert spies.order == []
        assert spies.cycles[-1]["note"] == "no_rpc_route"
        assert spies.cycles[-1]["partial"] is False
        db_session.rollback()

    def test_no_pinned_head_beats_degraded_not_healthy(self, db_session, one_protocol, monkeypatch):
        """Reporting it healthy would make a dead route look like a protocol with no nodes."""
        spies = _RestakingSpies(monkeypatch)
        monkeypatch.setattr(restaking_cycle, "pinned_head", lambda *_a, **_kw: None)

        assert refresh_restaking_plane(db_session, chain_id=1, rpc_url="https://rpc.example") == 0
        assert spies.order == []
        assert spies.cycles[-1]["note"] == "no_pinned_head"
        assert spies.cycles[-1]["partial"] is True
        db_session.rollback()

    def test_no_proven_emitter_enrolls_nothing(self, db_session, one_protocol, monkeypatch):
        spies = _RestakingSpies(monkeypatch)
        spies.emitters = []

        assert refresh_restaking_plane(db_session, chain_id=1, rpc_url="https://rpc.example") == 0
        assert spies.order == []
        db_session.rollback()

    def test_a_protocol_with_no_contracts_is_skipped(self, db_session, monkeypatch):
        spies = _RestakingSpies(monkeypatch)
        monkeypatch.setattr(restaking_cycle, "protocol_contract_addresses", lambda *_a, **_kw: [])
        db_session.add(Protocol(name="empty"))
        db_session.flush()

        assert refresh_restaking_plane(db_session, chain_id=1, rpc_url="https://rpc.example") == 0
        assert spies.order == []
        db_session.rollback()

    def test_one_protocol_raising_does_not_withhold_another(self, db_session, monkeypatch):
        first = Protocol(name="alpha")
        second = Protocol(name="beta")
        db_session.add_all([first, second])
        db_session.flush()
        spies = _RestakingSpies(monkeypatch)
        failed: list[int] = []

        def selective(_session, *, protocol_id):
            if protocol_id == first.id:
                failed.append(protocol_id)
                raise RuntimeError("etherscan down")
            return [EFNM_PROXY]

        monkeypatch.setattr(restaking_cycle, "protocol_contract_addresses", selective)

        written = refresh_restaking_plane(db_session, chain_id=1, rpc_url="https://rpc.example")

        assert failed == [first.id]
        assert written == 1
        assert [p["protocol_id"] for p in spies.persisted] == [second.id]
        # Otherwise the skipped protocol's absent rows would read as an answer.
        assert spies.cycles[-1]["partial"] is True
        assert spies.cycles[-1]["note"] == "1_failed"
        db_session.rollback()

    def test_a_clean_pass_is_not_marked_partial(self, db_session, one_protocol, monkeypatch):
        spies = _RestakingSpies(monkeypatch)

        refresh_restaking_plane(db_session, chain_id=1, rpc_url="https://rpc.example")

        assert spies.cycles[-1]["partial"] is False
        assert spies.cycles[-1]["note"] is None
        assert spies.cycles[-1]["events_found"] == 1
        assert spies.cycles[-1]["contracts_scanned"] == 1
        db_session.rollback()


class TestRestakingFailureDomain:
    def test_a_cycle_exception_never_leaves_the_loop(self, monkeypatch):
        beats: list[tuple[str, str]] = []
        monkeypatch.setattr(
            restaking_cycle,
            "refresh_restaking_plane",
            lambda *_a, **_kw: (_ for _ in ()).throw(RuntimeError("rpc gone")),
        )
        monkeypatch.setattr(
            restaking_cycle,
            "record_heartbeat",
            lambda process, *, status="running", detail=None: beats.append((process, status)),
        )
        stop = threading.Event()

        original_wait = stop.wait

        def wait_then_stop(_timeout=None):
            stop.set()
            return original_wait(0)

        monkeypatch.setattr(stop, "wait", wait_then_stop)

        run_restaking_loop(0.0, stop)  # must return, not raise

        assert beats == [(HEARTBEAT_PROTOCOL_RESTAKING, "degraded")]


class TestEnrollmentBasis:
    def test_new_cursors_carry_the_asserted_basis(self, db_session, monkeypatch):
        stub_seed_witness(monkeypatch, creation_block=EFNM_CREATION_BLOCK)

        assert enroll_restaking_fold(db_session, chain_id=1, emitters=[EFNM_PROXY]) == 1

        cursor = db_session.execute(
            select(IndexedEventCursor).where(
                IndexedEventCursor.event_address == EFNM_PROXY,
                IndexedEventCursor.topic0 == PUBKEY_LINKED_TOPIC0,
            )
        ).scalar_one()
        assert cursor.enrollment_basis == RESTAKING_FOLD_ENROLLMENT_BASIS
        assert cursor.enrollment_basis == "tracked_topics_asserted"
        # A witnessed floor records provenance; the asserted basis still licenses no exact empty.
        assert cursor.first_indexed_block_basis == "creation_block_minus_one"
        assert not enrollment_basis_permits_exactness(cursor.enrollment_basis)
        db_session.rollback()


class TestFoldScoping:
    def test_the_fold_can_be_narrowed_to_one_emitter(self, db_session):
        db_session.add_all(
            [
                _pubkey_log(NODE_A, emitter=EFNM_PROXY, log_index=1),
                _pubkey_log(NODE_B, emitter=OTHER_EMITTER, log_index=2),
            ]
        )
        db_session.flush()

        assert node_addresses_from_fold(db_session, chain_id=1, event_address=EFNM_PROXY) == [NODE_A]
        assert node_addresses_from_fold(db_session, chain_id=1, event_address=OTHER_EMITTER) == [NODE_B]
        assert node_addresses_from_fold(db_session, chain_id=1) == sorted([NODE_A, NODE_B])
        db_session.rollback()

    def test_an_emitter_that_folded_nothing_is_an_empty_lower_bound(self, db_session):
        db_session.add(_pubkey_log(NODE_A, emitter=EFNM_PROXY, log_index=1))
        db_session.flush()

        assert node_addresses_from_fold(db_session, chain_id=1, event_address=EFNM_IMPLEMENTATION) == []
        db_session.rollback()
