"""W1 — the two Tier-1 producers acquire a caller, and the caller stays honest.

Both modules were already tested as producers. What was untested is everything
between them and a run: the precondition that decides whether they fire at all,
the failure domain that decides what a failure of theirs can take down, and the
provenance the call site is responsible for supplying.

Every arm below is a wiring arm. The producers' own semantics are asserted only
where the wiring could pre-empt them — the cold-cursor case, which must reach the
table as ``holders`` NULL / ``coverage`` partial rather than being filtered out
before the module ever sees it.
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
)
from db.queue import HEARTBEAT_PROTOCOL_RESTAKING
from services.monitoring import restaking_cycle, restaking_enrollment
from services.monitoring.restaking_cycle import refresh_restaking_plane, run_restaking_loop
from services.monitoring.restaking_enrollment import (
    PUBKEY_LINKED_TOPIC0,
    RESTAKING_FOLD_ENROLLMENT_BASIS,
    enroll_restaking_fold,
    node_addresses_from_fold,
)
from services.resolution.role_holder_plane import ROLE_GRANTED_TOPIC0, ROLE_REVOKED_TOPIC0
from workers.resolution_worker import ResolutionWorker

# The measured EtherFiNodesManager PROXY. Its ``contracts`` row is keyed at the
# implementation, which emits nothing — the enrollment target is this address.
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

# Verified at block 25643300: this pod manager answers
# ``beaconChainETHStrategy()`` = 0xbeac0eee…beac0 and ``numPods()`` = 34704, and
# its ``ownerToPod`` agrees with the node's own ``getEigenPod()``.
EIGEN_POD_MANAGER = "0x91e677b07f7af907ec9a428aafa9fc14a0d3a338"
DELEGATION_MANAGER = "0x39053d51b77dc0d36036fc1fcc8cb819df8ef37a"

BLOCK = 25643300


def _job_stub() -> Any:
    """A bare job identity — the plane call site reads only ``id`` (for the log)."""
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
    """``db_session`` sweeps neither plane's table; both are swept here."""
    yield db_session
    db_session.rollback()
    db_session.query(RoleHolderPlane).delete()
    db_session.commit()


# ---------------------------------------------------------------------------
# 1.1 — the both-cursors precondition
# ---------------------------------------------------------------------------


class TestRoleHolderPlaneFiringCondition:
    """Both AccessControl cursors, or the producer is never reached."""

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

    def test_no_registry_address_reads_nothing(self, monkeypatch):
        calls = self._spy(monkeypatch)
        session = MagicMock()

        assert (
            ResolutionWorker()._resolve_role_holder_plane(
                session,
                _job_stub(),
                chain_id=1,
                rpc_url="https://rpc.example",
                registry_address=None,
            )
            == 0
        )
        assert calls == []
        session.execute.assert_not_called()

    def test_no_rows_writes_nothing(self, db_session, monkeypatch):
        """An empty resolve is row-absence, which is not_determined — not a commit."""
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
    """The wiring must not pre-empt or post-process the module's withholding."""

    def test_cold_cursor_publishes_null_holders_not_an_empty_set(self, role_plane_session, monkeypatch):
        session = role_plane_session
        # Both cursors enrolled, neither warm — and a real RoleGranted log, so
        # the module has a role to mint a row for.
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
        # NULL, never ``[]``: the empty list would assert that the floor was
        # computed and came back empty.
        assert row.holders is None
        assert row.coverage == ROLE_COVERAGE_PARTIAL
        assert row.holder_set_exhaustive == HOLDER_SET_EXHAUSTIVE_NOT_DETERMINED
        assert row.as_of_block is None
        assert row.candidate_count is None
        assert row.fold_chain_disagreements is None


# ---------------------------------------------------------------------------
# 1.1 — the composition point inside the resolution stage
# ---------------------------------------------------------------------------


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
        """Logs land at the runtime address; the ``contracts`` row does not."""
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
        # The stage still reached its terminal detail.
        assert any(d.startswith("Resolution complete") for d in details)
        session.rollback.assert_called()

    def test_an_ungated_registry_reaches_the_real_gate_without_a_chain_read(self, monkeypatch):
        """No stub on the producer: the default corpus has no cursors, so the
        gate must close before anything touches the wire."""
        _stub_stage(monkeypatch)
        monkeypatch.setattr(
            "workers.resolution_worker.resolve_role_holder_planes",
            lambda *a, **kw: (_ for _ in ()).throw(AssertionError("gate should have closed")),
        )
        session = MagicMock()
        session.execute.return_value.scalar_one_or_none.return_value = None

        ResolutionWorker().process(session, _job())  # pyright: ignore[reportArgumentType]


# ---------------------------------------------------------------------------
# 1.2 — the restaking periodic step
# ---------------------------------------------------------------------------


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

    def test_the_read_targets_the_verified_managers(self, db_session, one_protocol, monkeypatch):
        spies = _RestakingSpies(monkeypatch)

        refresh_restaking_plane(db_session, chain_id=1, rpc_url="https://rpc.example")

        assert spies.read_kwargs["eigen_pod_manager"] == EIGEN_POD_MANAGER
        assert spies.read_kwargs["delegation_manager"] == DELEGATION_MANAGER
        assert spies.read_kwargs["chain_id"] == 1
        db_session.rollback()

    def test_nodes_are_scoped_to_the_emitter_that_enumerated_them(self, db_session, one_protocol, monkeypatch):
        """``manager_contract_id`` names an enumerating contract, so the node set
        it is attached to must be that contract's."""
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
        # Every refusal still beats, and says which arm refused — a silent
        # return is indistinguishable from a wedged loop. A chain with no
        # configured pair is an absence, not a failed observation.
        assert spies.cycles[-1]["note"] == "no_manager_pair"
        assert spies.cycles[-1]["partial"] is False
        db_session.rollback()

    def test_no_rpc_url_reads_nothing(self, db_session, monkeypatch):
        spies = _RestakingSpies(monkeypatch)
        monkeypatch.setattr(restaking_cycle, "rpc_url_for_chain_id", lambda *_a, **_kw: None)

        assert refresh_restaking_plane(db_session, chain_id=1) == 0
        assert spies.order == []
        assert spies.cycles[-1]["note"] == "no_rpc_route"
        # An unrouted chain is configuration, like the pair above.
        assert spies.cycles[-1]["partial"] is False
        db_session.rollback()

    def test_no_pinned_head_beats_degraded_not_healthy(self, db_session, one_protocol, monkeypatch):
        """``pinned_head`` returns None only when a read failed or answered
        inconsistently. Reporting that cycle healthy would let a permanently
        dead route look like a protocol that simply has no nodes, forever."""
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
        # The survivor's rows are published, and the cycle still declares itself
        # partial — a full-looking heartbeat over a skipped protocol would make
        # that protocol's absent rows read as an answer.
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
    """A restaking failure is confined to the restaking loop."""

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

    def test_the_step_is_a_supervised_sibling_of_the_balance_loop(self):
        """Own thread, own name — the Supervisor's isolation is the failure
        domain, so a restaking crash cannot reach the TVL loop."""
        from db.queue import HEARTBEAT_PROTOCOL_TVL
        from workers.protocol_monitor import _build_default_supervisor

        names = [name for name, _ in _build_default_supervisor("https://rpc.example", None)._loops]

        assert HEARTBEAT_PROTOCOL_RESTAKING in names
        assert HEARTBEAT_PROTOCOL_TVL in names
        assert names.index(HEARTBEAT_PROTOCOL_RESTAKING) != names.index(HEARTBEAT_PROTOCOL_TVL)
        assert len(names) == len(set(names))

    def test_the_step_is_registered_for_the_fleet_view(self):
        from services.monitoring.process_meta import PROCESS_META

        assert HEARTBEAT_PROTOCOL_RESTAKING in PROCESS_META


# ---------------------------------------------------------------------------
# 1.3 — the enrollment basis reaches the cursor
# ---------------------------------------------------------------------------


class TestEnrollmentBasis:
    def test_new_cursors_carry_the_asserted_basis(self, db_session, monkeypatch):
        monkeypatch.setattr(
            restaking_enrollment,
            "get_contract_creation_block",
            lambda addr, *, chain_id: EFNM_CREATION_BLOCK,
        )

        assert enroll_restaking_fold(db_session, chain_id=1, emitters=[EFNM_PROXY]) == 1

        cursor = db_session.execute(
            select(IndexedEventCursor).where(
                IndexedEventCursor.event_address == EFNM_PROXY,
                IndexedEventCursor.topic0 == PUBKEY_LINKED_TOPIC0,
            )
        ).scalar_one()
        assert cursor.enrollment_basis == RESTAKING_FOLD_ENROLLMENT_BASIS
        assert cursor.enrollment_basis == "tracked_topics_asserted"
        # The basis records provenance; it still licenses no exact empty.
        assert cursor.first_indexed_block_basis == "not_determined"
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
        # The unscoped default is unchanged: chain-wide, both emitters.
        assert node_addresses_from_fold(db_session, chain_id=1) == sorted([NODE_A, NODE_B])
        db_session.rollback()

    def test_an_emitter_that_folded_nothing_is_an_empty_lower_bound(self, db_session):
        db_session.add(_pubkey_log(NODE_A, emitter=EFNM_PROXY, log_index=1))
        db_session.flush()

        assert node_addresses_from_fold(db_session, chain_id=1, event_address=EFNM_IMPLEMENTATION) == []
        db_session.rollback()
