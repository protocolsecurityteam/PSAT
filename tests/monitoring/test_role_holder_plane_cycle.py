"""The role-holder plane's periodic refresher — selection, bounds, failure domain.

The producer's own semantics are asserted elsewhere. What is asserted here is
everything the refresher owns: WHICH registries a pass runs against, what it
durably records about a pass that already ran, and what a failure of one
registry (or of the whole cycle) is allowed to take down.

The load-bearing arm is the three-state one. A per-role table cannot say whether
a REGISTRY was ever folded — a registry whose fold proposed nothing is absent
from it exactly as a registry no pass reached is. Every test in
``TestRefreshTrigger`` pins one half of that: "ran and found nothing" must stop
re-selecting, and "never ran" must never stop.
"""

from __future__ import annotations

import threading
import uuid
from datetime import datetime, timedelta, timezone
from types import SimpleNamespace
from typing import Any
from unittest.mock import MagicMock

import pytest
from sqlalchemy import select

from db.models import (
    ROLE_COVERAGE_LOWER_BOUND,
    ROLE_REFRESH_OUTCOME_NO_ROWS,
    ROLE_REFRESH_OUTCOME_ROWS_WRITTEN,
    IndexedEventCursor,
    IndexedEventLog,
    RoleHolderPlane,
    RoleHolderPlaneRefresh,
)
from db.queue import HEARTBEAT_ROLE_HOLDER_PLANE
from services.clients.rpc import EthCallResult
from services.monitoring import role_holder_cycle
from services.monitoring.role_holder_cycle import (
    DUE_CURSORS_WARMED,
    DUE_MAX_AGE,
    DUE_NEVER_REFRESHED,
    DUE_NEW_ROLE_LOGS,
    OUTCOME_GATE_CLOSED,
    OUTCOME_NO_REGISTRY,
    OUTCOME_NO_ROWS,
    OUTCOME_ROWS_WRITTEN,
    collect_candidates,
    refresh_chain_role_holder_planes,
    refresh_role_holder_planes,
    run_role_holder_plane_loop,
)
from services.resolution import role_holder_plane as rhp
from services.resolution.role_holder_plane import ROLE_GRANTED_TOPIC0, ROLE_REVOKED_TOPIC0
from workers.resolution_worker import ResolutionWorker

REGISTRY = "0x1111111111111111111111111111111111111111"
OTHER_REGISTRY = "0x2222222222222222222222222222222222222222"
UNENROLLED = "0x3333333333333333333333333333333333333333"
HALF_ENROLLED = "0x4444444444444444444444444444444444444444"
GRANTEE = "0x5555555555555555555555555555555555555555"
ROLE_HASH = "0x" + "ab" * 32

BLOCK = 25643300
PROBE = rhp.ProbeBlock(number=BLOCK, block_hash=b"\xab" * 32)

TRUE_WORD = EthCallResult(True, "0x" + "0" * 63 + "1", None, None)


def _word(value: str) -> str:
    return "0x" + value.lower().removeprefix("0x").rjust(64, "0")


def _cursor(address: str, topic0: str, *, warm: bool = True) -> IndexedEventCursor:
    return IndexedEventCursor(
        chain_id=1,
        event_address=address.lower(),
        topic0=topic0,
        last_indexed_block=BLOCK - 10,
        backfill_complete=warm,
    )


def _log(address: str, *, block: int = BLOCK - 100, log_index: int = 1, role: str = ROLE_HASH) -> IndexedEventLog:
    return IndexedEventLog(
        chain_id=1,
        event_address=address.lower(),
        topic0=ROLE_GRANTED_TOPIC0,
        tx_hash=(block * 1000 + log_index).to_bytes(8, "big").rjust(32, b"\x00"),
        log_index=log_index,
        block_number=block,
        block_hash=block.to_bytes(8, "big").rjust(32, b"\x77"),
        transaction_index=0,
        topics=[ROLE_GRANTED_TOPIC0, _word(role), _word(GRANTEE), _word(GRANTEE)],
        data_words=[],
    )


def _enrolled(address: str, *, warm: bool = True) -> list[IndexedEventCursor]:
    return [_cursor(address, ROLE_GRANTED_TOPIC0, warm=warm), _cursor(address, ROLE_REVOKED_TOPIC0, warm=warm)]


@pytest.fixture
def plane_session(db_session):
    """``db_session`` sweeps neither the plane nor its watermark; both are swept here."""
    yield db_session
    db_session.rollback()
    db_session.query(RoleHolderPlane).delete()
    db_session.query(RoleHolderPlaneRefresh).delete()
    db_session.commit()


@pytest.fixture
def confirming_reads(monkeypatch):
    """Every ``hasRole`` probe answers true — the wire, stubbed."""

    def fake_batch(_rpc_url, calls, block_tag, *, headers=None, chain_id=None):
        assert block_tag == hex(PROBE.number), "every probe must be pinned at one block"
        return [TRUE_WORD] * len(calls)

    monkeypatch.setattr(rhp, "eth_call_batch", fake_batch)


def _pass(session, **kwargs):
    return refresh_chain_role_holder_planes(
        session,
        chain_id=1,
        rpc_url="http://stub",
        probe_block=PROBE,
        **kwargs,
    )


def _marks(session) -> dict[str, RoleHolderPlaneRefresh]:
    return {row.registry_address: row for row in session.execute(select(RoleHolderPlaneRefresh)).scalars()}


def _planes(session) -> list[RoleHolderPlane]:
    return list(session.execute(select(RoleHolderPlane)).scalars())


# ---------------------------------------------------------------------------
# Selection universe
# ---------------------------------------------------------------------------


class TestSelectionUniverse:
    def test_a_cursor_bearing_registry_with_logs_is_folded_and_persisted(self, plane_session, confirming_reads):
        session = plane_session
        session.add_all([*_enrolled(REGISTRY), _log(REGISTRY)])
        session.commit()

        counters = _pass(session)

        assert counters.refreshed == 1
        assert counters.rows == 1
        rows = _planes(session)
        assert [row.registry_address for row in rows] == [REGISTRY]
        assert rows[0].holders == [GRANTEE]
        assert rows[0].coverage == ROLE_COVERAGE_LOWER_BOUND
        assert rows[0].as_of_block == PROBE.number
        mark = _marks(session)[REGISTRY]
        assert (mark.outcome, mark.rows_written) == (ROLE_REFRESH_OUTCOME_ROWS_WRITTEN, 1)
        assert mark.trigger_log_block == BLOCK - 100

    def test_a_registry_with_no_cursor_is_never_selected(self, plane_session, confirming_reads):
        """Logs alone do not license a read: the cursor table is the universe."""
        session = plane_session
        session.add(_log(UNENROLLED))
        session.commit()

        counters = _pass(session)

        assert [c.registry_address for c in collect_candidates(session, chain_id=1)] == []
        assert (counters.registries_considered, counters.due, counters.refreshed) == (0, 0, 0)
        assert _marks(session) == {}
        assert _planes(session) == []

    def test_a_half_enrolled_registry_is_gate_closed_not_refreshed(self, plane_session, confirming_reads):
        """One topic of the pair proves nothing, and leaves no watermark to expire."""
        session = plane_session
        session.add_all([_cursor(HALF_ENROLLED, ROLE_GRANTED_TOPIC0), _log(HALF_ENROLLED)])
        session.commit()

        counters = _pass(session)

        assert counters.gate_closed == 1
        assert (counters.due, counters.refreshed) == (0, 0)
        assert _marks(session) == {}

    def test_a_gate_that_later_opens_selects_without_clearing_anything(self, plane_session, confirming_reads):
        session = plane_session
        session.add_all([_cursor(REGISTRY, ROLE_GRANTED_TOPIC0), _log(REGISTRY)])
        session.commit()
        assert _pass(session).refreshed == 0

        session.add(_cursor(REGISTRY, ROLE_REVOKED_TOPIC0))
        session.commit()

        counters = _pass(session)
        assert counters.refreshed == 1
        assert _marks(session)[REGISTRY].outcome == ROLE_REFRESH_OUTCOME_ROWS_WRITTEN

    def test_cursors_on_another_chain_do_not_license_this_one(self, plane_session, confirming_reads):
        session = plane_session
        for cursor in _enrolled(REGISTRY):
            cursor.chain_id = 8453
            session.add(cursor)
        session.add(_log(REGISTRY))
        session.commit()

        assert _pass(session).registries_considered == 0


# ---------------------------------------------------------------------------
# The three durable states
# ---------------------------------------------------------------------------


class TestRefreshTrigger:
    def test_confirmed_nothing_is_recorded_and_not_reselected(self, plane_session, confirming_reads):
        """A registry whose fold proposed nothing is durably distinct from one
        no pass ever reached — and does not re-select forever on the strength of
        having produced no row."""
        session = plane_session
        session.add_all(_enrolled(REGISTRY))
        session.commit()

        first = _pass(session)
        assert (first.refreshed, first.no_rows, first.rows) == (1, 1, 0)
        mark = _marks(session)[REGISTRY]
        assert (mark.outcome, mark.rows_written, mark.trigger_log_block) == (ROLE_REFRESH_OUTCOME_NO_ROWS, 0, None)

        second = _pass(session)
        assert (second.due, second.refreshed) == (0, 0)

    def test_never_refreshed_is_not_silently_skipped(self, plane_session):
        session = plane_session
        session.add_all(_enrolled(REGISTRY))
        session.commit()

        candidates = collect_candidates(session, chain_id=1)

        assert [c.due_reason for c in candidates] == [DUE_NEVER_REFRESHED]

    def test_a_wrote_n_registry_is_not_reselected_without_new_activity(self, plane_session, confirming_reads):
        session = plane_session
        session.add_all([*_enrolled(REGISTRY), _log(REGISTRY)])
        session.commit()

        assert _pass(session).rows == 1
        assert _pass(session).due == 0

    def test_a_new_role_log_reopens_a_refreshed_registry(self, plane_session, confirming_reads):
        session = plane_session
        session.add_all([*_enrolled(REGISTRY), _log(REGISTRY)])
        session.commit()
        _pass(session)

        session.add(_log(REGISTRY, block=BLOCK - 50, log_index=2))
        session.commit()

        candidates = collect_candidates(session, chain_id=1)
        assert [c.due_reason for c in candidates] == [DUE_NEW_ROLE_LOGS]
        assert _pass(session).refreshed == 1
        assert _marks(session)[REGISTRY].trigger_log_block == BLOCK - 50

    def test_a_first_log_reopens_a_confirmed_nothing_registry(self, plane_session, confirming_reads):
        """``trigger_log_block`` NULL is an observation of the index, not a
        claim that the registry emits nothing."""
        session = plane_session
        session.add_all(_enrolled(REGISTRY))
        session.commit()
        _pass(session)

        session.add(_log(REGISTRY))
        session.commit()

        assert [c.due_reason for c in collect_candidates(session, chain_id=1)] == [DUE_NEW_ROLE_LOGS]
        assert _pass(session).rows == 1

    def test_cursors_going_warm_reopens_a_registry_folded_cold(self, plane_session, confirming_reads):
        """A floor withheld against a cold surface must not be frozen there when
        the surface warms without a further log landing."""
        session = plane_session
        session.add_all([*_enrolled(REGISTRY, warm=False), _log(REGISTRY)])
        session.commit()
        _pass(session)
        assert _planes(session)[0].holders is None
        assert _marks(session)[REGISTRY].cursors_warm is False

        for cursor in session.execute(select(IndexedEventCursor)).scalars():
            cursor.backfill_complete = True
        session.commit()

        assert [c.due_reason for c in collect_candidates(session, chain_id=1)] == [DUE_CURSORS_WARMED]
        _pass(session)
        assert _planes(session)[0].holders == [GRANTEE]

    def test_an_aged_floor_is_reread(self, plane_session, confirming_reads):
        """``holders`` cites a block; the citation ages even where no log lands."""
        session = plane_session
        session.add_all([*_enrolled(REGISTRY), _log(REGISTRY)])
        session.commit()
        _pass(session)

        mark = _marks(session)[REGISTRY]
        mark.refreshed_at = datetime.now(timezone.utc) - timedelta(days=3)
        session.commit()

        assert [c.due_reason for c in collect_candidates(session, chain_id=1, max_age_s=60)] == [DUE_MAX_AGE]
        assert [c.due_reason for c in collect_candidates(session, chain_id=1, max_age_s=10**7)] == [None]


# ---------------------------------------------------------------------------
# Per-pass bounds
# ---------------------------------------------------------------------------


class TestPassBounds:
    def test_registries_per_pass_is_bounded(self, plane_session, confirming_reads):
        session = plane_session
        addresses = [f"0x{index:040x}" for index in range(1, 6)]
        for address in addresses:
            session.add_all([*_enrolled(address), _log(address)])
        session.commit()

        counters = _pass(session, limit=2)

        assert (counters.due, counters.refreshed, counters.budget_exhausted) == (5, 2, True)
        assert len(_marks(session)) == 2
        # The rest stayed due rather than being recorded as observed.
        assert _pass(session, limit=2).refreshed == 2

    def test_the_read_budget_stops_the_pass_and_leaves_the_rest_due(self, plane_session, confirming_reads):
        session = plane_session
        addresses = [f"0x{index:040x}" for index in range(1, 4)]
        for address in addresses:
            session.add_all([*_enrolled(address), _log(address), _log(address, log_index=2)])
        session.commit()

        counters = _pass(session, read_budget=3)

        assert counters.budget_exhausted is True
        assert counters.refreshed == 1
        assert len(_marks(session)) == 1

    def test_a_registry_larger_than_the_whole_budget_still_runs(self, plane_session, confirming_reads):
        """Stopping at the over-budget registry, rather than stepping over it,
        is what keeps it from starving behind cheaper ones forever."""
        session = plane_session
        session.add_all(_enrolled(REGISTRY))
        for index in range(6):
            session.add(_log(REGISTRY, log_index=index + 1, role="0x" + f"{index:02x}" * 32))
        session.commit()

        counters = _pass(session, read_budget=2)

        assert counters.refreshed == 1
        assert counters.rows == 6


# ---------------------------------------------------------------------------
# Failure domain
# ---------------------------------------------------------------------------


class TestFailureDomain:
    def test_one_registry_failing_does_not_withhold_another(self, plane_session, monkeypatch):
        session = plane_session
        session.add_all([*_enrolled(REGISTRY), _log(REGISTRY)])
        session.add_all([*_enrolled(OTHER_REGISTRY), _log(OTHER_REGISTRY)])
        session.commit()

        real_resolve = rhp.resolve_role_holder_planes

        def flaky(inner_session, *, registry_address, **kwargs):
            if registry_address == REGISTRY:
                raise RuntimeError("probe exploded")
            return real_resolve(inner_session, registry_address=registry_address, **kwargs)

        monkeypatch.setattr(role_holder_cycle, "resolve_role_holder_planes", flaky)
        monkeypatch.setattr(rhp, "eth_call_batch", lambda *a, **kw: [TRUE_WORD] * len(a[1]))

        counters = _pass(session)

        assert counters.failures == 1
        assert counters.refreshed == 1
        marks = _marks(session)
        # No watermark for the failure: it stays due next pass.
        assert set(marks) == {OTHER_REGISTRY}
        assert [row.registry_address for row in _planes(session)] == [OTHER_REGISTRY]

    def test_an_unpinnable_probe_block_watermarks_nothing_and_degrades(self, plane_session, monkeypatch):
        session = plane_session
        session.add_all([*_enrolled(REGISTRY), _log(REGISTRY)])
        session.commit()
        monkeypatch.setattr(role_holder_cycle, "pin_probe_block", lambda *_a, **_kw: None)

        counters = refresh_chain_role_holder_planes(session, chain_id=1, rpc_url="http://stub")

        assert counters.failures == 1
        assert counters.notes == ["no_pinned_head"]
        assert _marks(session) == {}
        assert _planes(session) == []

    def test_no_rpc_route_is_degraded_not_quiet(self, plane_session, monkeypatch):
        session = plane_session
        session.add_all([*_enrolled(REGISTRY), _log(REGISTRY)])
        session.commit()
        monkeypatch.setattr(role_holder_cycle, "rpc_url_for_chain_id", lambda *_a, **_kw: None)

        counters = refresh_chain_role_holder_planes(session, chain_id=1)

        assert (counters.failures, counters.notes) == (1, ["no_rpc_route"])
        assert _marks(session) == {}

    def test_a_cycle_exception_never_leaves_the_loop(self, monkeypatch):
        beats: list[tuple[str, str]] = []
        monkeypatch.setattr(
            role_holder_cycle,
            "refresh_role_holder_planes",
            lambda *_a, **_kw: (_ for _ in ()).throw(RuntimeError("rpc gone")),
        )
        monkeypatch.setattr(
            role_holder_cycle,
            "record_heartbeat",
            lambda process, *, status="running", detail=None: beats.append((process, status)),
        )
        stop = threading.Event()
        original_wait = stop.wait

        def wait_then_stop(_timeout=None):
            stop.set()
            return original_wait(0)

        monkeypatch.setattr(stop, "wait", wait_then_stop)

        run_role_holder_plane_loop(0.0, stop)  # must return, not raise

        assert beats == [(HEARTBEAT_ROLE_HOLDER_PLANE, "degraded")]

    def test_the_loop_is_a_supervised_sibling_of_the_restaking_loop(self):
        from db.queue import HEARTBEAT_PROTOCOL_RESTAKING
        from workers.protocol_monitor import _build_default_supervisor

        names = [name for name, _ in _build_default_supervisor("https://rpc.example", None)._loops]

        assert HEARTBEAT_ROLE_HOLDER_PLANE in names
        assert names.index(HEARTBEAT_ROLE_HOLDER_PLANE) != names.index(HEARTBEAT_PROTOCOL_RESTAKING)
        assert len(names) == len(set(names))

    def test_the_loop_is_registered_for_the_fleet_view(self):
        from services.monitoring.process_meta import PROCESS_META

        assert HEARTBEAT_ROLE_HOLDER_PLANE in PROCESS_META


# ---------------------------------------------------------------------------
# Observability — both call sites, every outcome
# ---------------------------------------------------------------------------


class TestCycleObservability:
    def _beats(self, monkeypatch) -> list[dict[str, Any]]:
        seen: list[dict[str, Any]] = []

        def fake_emit(process, **kwargs):
            seen.append({"process": process, **kwargs})

        monkeypatch.setattr(role_holder_cycle, "emit_monitor_cycle", fake_emit)
        return seen

    def test_every_outcome_shape_reaches_the_heartbeat(self, plane_session, confirming_reads, monkeypatch):
        session = plane_session
        session.add_all([*_enrolled(REGISTRY), _log(REGISTRY)])  # wrote-N
        session.add_all(_enrolled(OTHER_REGISTRY))  # gate open, nothing folded
        session.add(_cursor(HALF_ENROLLED, ROLE_GRANTED_TOPIC0))  # gate closed
        session.commit()
        seen = self._beats(monkeypatch)

        refresh_role_holder_planes(session, chain_id=1, rpc_url="http://stub", probe_block=PROBE)

        assert len(seen) == 1
        detail = seen[0]["extra_detail"]
        assert detail["registries_gate_closed"] == 1
        assert detail["registries_no_rows"] == 1
        assert detail["registries_rows_written"] == 1
        assert seen[0]["events_found"] == 1
        assert seen[0]["partial"] is False

    def test_an_idle_pass_still_beats(self, plane_session, monkeypatch):
        seen = self._beats(monkeypatch)

        refresh_role_holder_planes(plane_session, chain_id=1, rpc_url="http://stub", probe_block=PROBE)

        assert len(seen) == 1
        assert seen[0]["extra_detail"]["registries_due"] == 0

    def test_a_failed_registry_beats_degraded(self, plane_session, monkeypatch):
        session = plane_session
        session.add_all([*_enrolled(REGISTRY), _log(REGISTRY)])
        session.commit()
        monkeypatch.setattr(
            role_holder_cycle,
            "resolve_role_holder_planes",
            lambda *_a, **_kw: (_ for _ in ()).throw(RuntimeError("probe exploded")),
        )
        seen = self._beats(monkeypatch)

        refresh_role_holder_planes(session, chain_id=1, rpc_url="http://stub", probe_block=PROBE)

        assert seen[0]["partial"] is True
        assert seen[0]["extra_detail"]["registries_failed"] == 1


class TestResolutionStageObservability:
    """Follow-up #6 — the stage call site records all three shapes, not just the
    one that wrote rows."""

    def _metrics(self, monkeypatch) -> dict[str, Any]:
        recorded: dict[str, Any] = {}
        monkeypatch.setattr(
            "workers.resolution_worker.record_stage_metric",
            lambda key, value: recorded.__setitem__(key, value),
        )
        return recorded

    def _job(self) -> Any:
        return SimpleNamespace(id=uuid.uuid4())

    def test_a_closed_gate_is_recorded(self, plane_session, monkeypatch):
        recorded = self._metrics(monkeypatch)
        session = plane_session
        session.add(_cursor(HALF_ENROLLED, ROLE_GRANTED_TOPIC0))
        session.flush()

        written = ResolutionWorker()._resolve_role_holder_plane(
            session,
            self._job(),
            chain_id=1,
            rpc_url="http://stub",
            registry_address=HALF_ENROLLED,
        )

        assert written == 0
        assert recorded == {"role_holder_planes": 0, "role_holder_plane_outcome": OUTCOME_GATE_CLOSED}
        session.rollback()

    def test_an_open_gate_with_no_rows_is_recorded(self, plane_session, monkeypatch):
        recorded = self._metrics(monkeypatch)
        session = plane_session
        session.add_all(_enrolled(REGISTRY))
        session.flush()

        written = ResolutionWorker()._resolve_role_holder_plane(
            session,
            self._job(),
            chain_id=1,
            rpc_url="http://stub",
            registry_address=REGISTRY,
        )

        assert written == 0
        assert recorded == {"role_holder_planes": 0, "role_holder_plane_outcome": OUTCOME_NO_ROWS}
        session.rollback()

    def test_written_rows_are_recorded(self, plane_session, monkeypatch, confirming_reads):
        recorded = self._metrics(monkeypatch)
        session = plane_session
        monkeypatch.setattr(rhp, "pin_probe_block", lambda *_a, **_kw: PROBE)
        session.add_all([*_enrolled(REGISTRY), _log(REGISTRY)])
        session.commit()

        written = ResolutionWorker()._resolve_role_holder_plane(
            session,
            self._job(),
            chain_id=1,
            rpc_url="http://stub",
            registry_address=REGISTRY,
        )

        assert written == 1
        assert recorded == {"role_holder_planes": 1, "role_holder_plane_outcome": OUTCOME_ROWS_WRITTEN}

    def test_a_missing_registry_address_is_recorded_without_a_query(self, monkeypatch):
        recorded = self._metrics(monkeypatch)
        session = MagicMock()

        written = ResolutionWorker()._resolve_role_holder_plane(
            session,
            self._job(),
            chain_id=1,
            rpc_url="http://stub",
            registry_address=None,
        )

        assert written == 0
        assert recorded == {"role_holder_planes": 0, "role_holder_plane_outcome": OUTCOME_NO_REGISTRY}
        session.execute.assert_not_called()
