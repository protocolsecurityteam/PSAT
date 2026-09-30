"""Bounded cohort-scanner tests for ``scan_for_events``.

Real test DB and decode pipeline; only the RPC wire is stubbed (head read and the shared
getLogs fetcher). Covers cohort split/rotation, window budgets, per-window commits, the
behind-is-not-skipped invariant, confirmation depth, cursor monotonicity, the lag metric,
the empty-address guard and per-window notify. The last two classes cover the row side.
"""

from __future__ import annotations

import uuid
from unittest.mock import patch

from sqlalchemy import func, select
from sqlalchemy.orm import Session as SASession

from db.models import MonitoredContract, MonitoredEvent
from services.monitoring.event_topics import OWNERSHIP_TRANSFERRED_TOPIC0
from tests.conftest import requires_postgres

MAX_BLOCK_RANGE = 2000


def ADDR(n: int) -> str:
    return "0x" + hex(n)[2:].zfill(40)


def _addr_topic(addr: str) -> str:
    return "0x" + "0" * 24 + addr[2:].lower()


def _ownership_log(address: str, new_owner: str, block: int, log_index: int = 0) -> dict:
    """``_decode_log`` silently drops logs missing block/tx fields."""
    tx = "0x" + f"{block:064x}"
    return {
        "address": address,
        "topics": [
            OWNERSHIP_TRANSFERRED_TOPIC0,
            _addr_topic(ADDR(0xDEAD)),
            _addr_topic(new_owner),
        ],
        "data": "0x",
        "blockNumber": hex(block),
        "blockHash": "0x" + f"{block:064x}",
        "transactionHash": tx,
        "transactionIndex": "0x0",
        "logIndex": hex(log_index),
    }


class Wire:
    """An empty getLogs address list matches any address."""

    def __init__(self, head: int, *, fail_from: int | None = None, logs: list[dict] | None = None):
        self.head = head
        self.fail_from = fail_from
        self.logs = logs or []
        self.getlogs_calls: list[dict] = []
        self.empty_address_seen = False

    def head_rpc(self, url, method, params, *, chain_id=None):
        if method == "eth_blockNumber":
            return hex(self.head)
        raise AssertionError(f"unexpected head-path method {method}")

    def getlogs_rpc(self, url, method, params, *, chain_id=None):
        assert method == "eth_getLogs", method
        p = params[0]
        self.getlogs_calls.append(p)
        if not p["address"]:
            self.empty_address_seen = True
            raise AssertionError("getLogs issued with an empty address list")
        frm = int(p["fromBlock"], 16)
        to = int(p["toBlock"], 16)
        if self.fail_from is not None and frm >= self.fail_from:
            raise RuntimeError("Limit exceeded: too many logs")
        addrs = {a.lower() for a in p["address"]}
        return [lg for lg in self.logs if lg["address"].lower() in addrs and frm <= int(lg["blockNumber"], 16) <= to]

    def install(self, monkeypatch):
        import services.monitoring.unified_watcher as uw
        import services.resolution.repos.event_logs_rpc as elr

        monkeypatch.setattr(uw, "rpc_request", self.head_rpc)
        monkeypatch.setattr(elr, "rpc_request", self.getlogs_rpc)
        return self


def _mk(
    session,
    address: str,
    cursor: int,
    *,
    chain: str = "ethereum",
    config: dict | None = None,
    enrollment_block: int | None = None,
) -> uuid.UUID:
    mc = MonitoredContract(
        id=uuid.uuid4(),
        address=address,
        chain=chain,
        contract_type="regular",
        monitoring_config=config if config is not None else {},
        last_known_state={},
        last_scanned_block=cursor,
        enrollment_block=enrollment_block,
        needs_polling=False,
        is_active=True,
    )
    session.add(mc)
    session.commit()
    return mc.id


def _cursor(session, mc_id: uuid.UUID) -> int:
    session.expire_all()
    return session.execute(
        select(MonitoredContract.last_scanned_block).where(MonitoredContract.id == mc_id)
    ).scalar_one()


def test_cohort_split_at_address_batch(db_session, monkeypatch):
    from services.monitoring.unified_watcher import scan_for_events

    monkeypatch.setenv("PSAT_SCAN_CONFIRMATION_DEPTH", "0")
    for i in range(250):
        _mk(db_session, ADDR(1000 + i), 100)

    wire = Wire(head=200).install(monkeypatch)
    result = scan_for_events(db_session, "http://stub")

    assert result.cohorts == 2
    assert len(wire.getlogs_calls) == 2
    sizes = sorted(len(c["address"]) for c in wire.getlogs_calls)
    assert sizes == [50, 200]
    scanned = {a.lower() for c in wire.getlogs_calls for a in c["address"]}
    assert len(scanned) == 250


def test_most_behind_cohort_scanned_first(db_session, monkeypatch):
    from services.monitoring.unified_watcher import scan_for_events

    monkeypatch.setenv("PSAT_SCAN_CONFIRMATION_DEPTH", "0")
    behind = ADDR(1)
    ahead = ADDR(2)
    _mk(db_session, behind, 100)  # bucket 0, big lag
    _mk(db_session, ahead, 50000)  # bucket 25, smaller lag

    wire = Wire(head=60000).install(monkeypatch)
    scan_for_events(db_session, "http://stub")

    assert wire.getlogs_calls, "expected at least one getLogs"
    first_addrs = {a.lower() for a in wire.getlogs_calls[0]["address"]}
    assert first_addrs == {behind.lower()}


def test_per_cohort_turn_cap_hands_off_within_pass(db_session, monkeypatch):
    """Two equally-behind cohorts split the 50-window budget 25/25."""
    from services.monitoring.unified_watcher import scan_for_events

    monkeypatch.setenv("PSAT_SCAN_CONFIRMATION_DEPTH", "0")
    ids = [_mk(db_session, ADDR(2000 + i), 0) for i in range(201)]
    Wire(head=500_000).install(monkeypatch)

    result = scan_for_events(db_session, "http://stub")

    assert result.windows_scanned == 50
    assert result.budget_exhausted is True
    cursors = {_cursor(db_session, i) for i in ids}
    assert cursors == {25 * MAX_BLOCK_RANGE}


# ---------------------------------------------------------------------------
# Runaway-cursor backstop
# ---------------------------------------------------------------------------


def test_runaway_cohort_yields_to_the_fleet_and_is_capped(db_session, monkeypatch):
    """The audited floor-0 legacy row would otherwise win most-behind-first forever; it's served last, one window per
    pass.
    """
    from services.monitoring.unified_watcher import scan_for_events

    monkeypatch.setenv("PSAT_SCAN_CONFIRMATION_DEPTH", "0")
    head = 2_000_000
    runaway_id = _mk(db_session, ADDR(1), cursor=0)  # 2M behind — past the 1M default
    healthy_id = _mk(db_session, ADDR(2), cursor=head - 1000)  # at head
    wire = Wire(head=head).install(monkeypatch)

    result = scan_for_events(db_session, "http://stub")

    assert {a.lower() for a in wire.getlogs_calls[0]["address"]} == {ADDR(2).lower()}
    assert _cursor(db_session, healthy_id) == head
    assert _cursor(db_session, runaway_id) == MAX_BLOCK_RANGE
    assert result.windows_scanned == 2
    assert result.runaway_cohorts == 1


def test_runaway_cap_is_per_pass_not_per_turn(db_session, monkeypatch):
    """Otherwise the backstop would re-serve it in a loop."""
    from services.monitoring.unified_watcher import scan_for_events

    monkeypatch.setenv("PSAT_SCAN_CONFIRMATION_DEPTH", "0")
    monkeypatch.setenv("PSAT_SCAN_RUNAWAY_WINDOWS_PER_PASS", "3")
    mc_id = _mk(db_session, ADDR(1), cursor=0)
    Wire(head=2_000_000).install(monkeypatch)

    result = scan_for_events(db_session, "http://stub")

    assert result.windows_scanned == 3
    assert _cursor(db_session, mc_id) == 3 * MAX_BLOCK_RANGE
    assert result.runaway_cohorts == 1


def test_runaway_threshold_is_chain_time_not_block_count(db_session, monkeypatch):
    """The budget is wall clock on the cohort's own chain; 1M blocks is ~139 days of mainnet but ~23 of Base."""
    from services.monitoring.unified_watcher import _runaway_lag_blocks_for, scan_for_events

    monkeypatch.setenv("PSAT_SCAN_CONFIRMATION_DEPTH", "0")
    assert _runaway_lag_blocks_for("ethereum") == 1_000_000  # 12s blocks
    assert _runaway_lag_blocks_for("base") == 6_000_000  # 2s blocks
    assert _runaway_lag_blocks_for("not-a-chain") == 0  # no block time ⇒ no demotion

    mc_id = _mk(db_session, ADDR(1), cursor=0, chain="base")
    Wire(head=2_000_000).install(monkeypatch)

    result = scan_for_events(db_session, "http://stub")

    assert result.runaway_cohorts == 0  # 2M Base blocks ≈ 46 days
    assert result.windows_scanned == 50  # full pass budget, not the 1-window cap
    assert _cursor(db_session, mc_id) == 50 * MAX_BLOCK_RANGE


def test_backstop_disabled_restores_the_starvation_it_prevents(db_session, monkeypatch):
    """With the backstop off the runaway eats the whole budget and the head contract is never scanned."""
    from services.monitoring.unified_watcher import scan_for_events

    monkeypatch.setenv("PSAT_SCAN_CONFIRMATION_DEPTH", "0")
    monkeypatch.setenv("PSAT_SCAN_RUNAWAY_LAG_SECONDS", "0")
    runaway_id = _mk(db_session, ADDR(1), cursor=0)
    healthy_id = _mk(db_session, ADDR(2), cursor=1_999_000)
    wire = Wire(head=2_000_000).install(monkeypatch)

    result = scan_for_events(db_session, "http://stub")

    assert {a.lower() for a in wire.getlogs_calls[0]["address"]} == {ADDR(1).lower()}
    assert result.windows_scanned == 50  # the entire pass budget
    assert _cursor(db_session, runaway_id) == 50 * MAX_BLOCK_RANGE
    assert _cursor(db_session, healthy_id) == 1_999_000  # starved
    assert result.runaway_cohorts == 0


def test_confirmation_depth_clamps_window_end(db_session, monkeypatch):
    from services.monitoring.unified_watcher import scan_for_events

    monkeypatch.setenv("PSAT_SCAN_CONFIRMATION_DEPTH", "12")
    mc_id = _mk(db_session, ADDR(1), 100)
    wire = Wire(head=1000).install(monkeypatch)

    result = scan_for_events(db_session, "http://stub")

    assert len(wire.getlogs_calls) == 1
    assert int(wire.getlogs_calls[0]["toBlock"], 16) == 988  # 1000 − 12
    assert _cursor(db_session, mc_id) == 988
    assert result.max_lag_blocks == 12  # raw head − cursor


def test_failed_window_does_not_advance_cursor_and_persists_prior_windows(db_session, monkeypatch):
    from services.monitoring.unified_watcher import scan_for_events

    monkeypatch.setenv("PSAT_SCAN_CONFIRMATION_DEPTH", "0")
    addr = ADDR(1)
    mc_id = _mk(db_session, addr, 0)

    new_owner = ADDR(0xBEEF)
    logs = [_ownership_log(addr, new_owner, block=1500)]  # lands in window 1
    Wire(head=10_000, fail_from=4001, logs=logs).install(monkeypatch)

    result = scan_for_events(db_session, "http://stub")

    assert result.degraded is True
    assert _cursor(db_session, mc_id) == 2 * MAX_BLOCK_RANGE
    events = (
        db_session.execute(select(MonitoredEvent).where(MonitoredEvent.monitored_contract_id == mc_id)).scalars().all()
    )
    assert len(events) == 1
    assert events[0].event_type == "ownership_transferred"
    assert events[0].data.get("new_owner", "").lower() == new_owner.lower()


def test_failure_isolates_to_its_cohort(db_session, monkeypatch):
    from services.monitoring.unified_watcher import scan_for_events

    monkeypatch.setenv("PSAT_SCAN_CONFIRMATION_DEPTH", "0")
    bad = ADDR(1)  # bucket 0
    good = ADDR(2)  # bucket 0 as well but scanned in its own cohort? force split
    bad_id = _mk(db_session, bad, 0)
    good_id = _mk(db_session, good, 0)

    class TwoCohortWire(Wire):
        def getlogs_rpc(self, url, method, params, *, chain_id=None):
            p = params[0]
            self.getlogs_calls.append(p)
            assert p["address"]
            addrs = {a.lower() for a in p["address"]}
            if addrs == {bad.lower()}:
                raise RuntimeError("provider cap")
            frm = int(p["fromBlock"], 16)
            to = int(p["toBlock"], 16)
            return [
                lg for lg in self.logs if lg["address"].lower() in addrs and frm <= int(lg["blockNumber"], 16) <= to
            ]

    monkeypatch.setenv("PSAT_SCAN_ADDRESS_BATCH", "1")
    TwoCohortWire(head=1500).install(monkeypatch)

    result = scan_for_events(db_session, "http://stub")

    assert result.degraded is True
    assert _cursor(db_session, bad_id) == 0  # never advanced
    assert _cursor(db_session, good_id) == 1500  # scanned cleanly


def test_lower_head_second_pass_does_not_rewind(db_session, monkeypatch):
    from services.monitoring.unified_watcher import scan_for_events

    monkeypatch.setenv("PSAT_SCAN_CONFIRMATION_DEPTH", "0")
    mc_id = _mk(db_session, ADDR(1), 0)

    Wire(head=6000).install(monkeypatch)
    scan_for_events(db_session, "http://stub")
    assert _cursor(db_session, mc_id) == 6000

    Wire(head=3000).install(monkeypatch)  # head went backwards
    result = scan_for_events(db_session, "http://stub")
    assert result.windows_scanned == 0
    assert _cursor(db_session, mc_id) == 6000  # unchanged


def test_cohort_greatest_does_not_rewind_ahead_member(db_session, monkeypatch):
    """B was scanned further in a prior pass, then head went lower; dropping GREATEST would rewind it."""
    from services.monitoring.unified_watcher import scan_for_events

    monkeypatch.setenv("PSAT_SCAN_CONFIRMATION_DEPTH", "0")
    a_id = _mk(db_session, ADDR(1), 100)  # bucket 0, defines the cohort window
    b_id = _mk(db_session, ADDR(2), 1500)  # bucket 0, already ahead of window_end

    Wire(head=1000).install(monkeypatch)  # confirmed_head lands between A and B
    result = scan_for_events(db_session, "http://stub")

    assert result.cohorts == 1
    assert _cursor(db_session, a_id) == 1000  # advanced to the window end
    assert _cursor(db_session, b_id) == 1500  # NOT rewound to 1000


def test_36_day_gap_converges_in_three_passes(db_session, monkeypatch):
    from services.monitoring.unified_watcher import scan_for_events

    monkeypatch.setenv("PSAT_SCAN_CONFIRMATION_DEPTH", "0")
    head = 250_000
    mc_id = _mk(db_session, ADDR(1), 0)

    wire1 = Wire(head=head).install(monkeypatch)
    r1 = scan_for_events(db_session, "http://stub")
    assert r1.windows_scanned == 50 and r1.budget_exhausted is True
    assert r1.cohorts == 1
    assert all(c["address"] == [ADDR(1).lower()] for c in wire1.getlogs_calls)
    assert _cursor(db_session, mc_id) == 100_000

    Wire(head=head).install(monkeypatch)
    r2 = scan_for_events(db_session, "http://stub")
    assert r2.windows_scanned == 50 and r2.budget_exhausted is True
    assert _cursor(db_session, mc_id) == 200_000

    Wire(head=head).install(monkeypatch)
    r3 = scan_for_events(db_session, "http://stub")
    assert r3.windows_scanned == 25 and r3.budget_exhausted is False
    assert _cursor(db_session, mc_id) == 250_000
    assert r3.max_lag_blocks == 0


def test_max_lag_blocks_is_head_minus_min_cursor(db_session, monkeypatch):
    from services.monitoring.unified_watcher import scan_for_events

    monkeypatch.setenv("PSAT_SCAN_CONFIRMATION_DEPTH", "0")
    _mk(db_session, ADDR(1), 0)  # bucket 0 — will drain to head
    _mk(db_session, ADDR(2), 240_000)  # bucket 120 — near head
    head = 250_000
    Wire(head=head).install(monkeypatch)

    result = scan_for_events(db_session, "http://stub")

    # The deeply-behind cohort needs 125 windows, so it can't finish in one pass.
    assert result.max_lag_blocks == head - 100_000  # advanced 50 windows


def test_no_getlogs_with_empty_address_list(db_session, monkeypatch):
    from services.monitoring.unified_watcher import scan_for_events

    monkeypatch.setenv("PSAT_SCAN_CONFIRMATION_DEPTH", "0")
    for i in range(5):
        _mk(db_session, ADDR(10 + i), 0)
    wire = Wire(head=5000).install(monkeypatch)

    scan_for_events(db_session, "http://stub")

    assert wire.getlogs_calls
    assert wire.empty_address_seen is False
    assert all(call["address"] for call in wire.getlogs_calls)


def test_notify_fires_once_per_window(db_session, monkeypatch):
    """A long catch-up must not buffer notifications."""
    import services.monitoring.notifier as notifier
    from services.monitoring.unified_watcher import scan_for_events

    monkeypatch.setenv("PSAT_SCAN_CONFIRMATION_DEPTH", "0")
    addr = ADDR(1)
    mc_id = _mk(db_session, addr, 0)

    logs = [
        _ownership_log(addr, ADDR(0xA), block=1000),
        _ownership_log(addr, ADDR(0xB), block=3000),
    ]
    Wire(head=4000, logs=logs).install(monkeypatch)

    calls: list[list[str]] = []

    def _recording_notify(session, events):
        calls.append([e.event_type for e in events])

    monkeypatch.setattr(notifier, "notify_protocol_events", _recording_notify)

    result = scan_for_events(db_session, "http://stub")

    assert len(result) == 2  # both events detected across the pass
    assert calls == [["ownership_transferred"], ["ownership_transferred"]]
    stored = db_session.execute(
        select(func.count()).select_from(MonitoredEvent).where(MonitoredEvent.monitored_contract_id == mc_id)
    ).scalar_one()
    assert stored == 2


def _install_notify_capture(monkeypatch) -> list:
    import services.monitoring.notifier as notifier

    seen: list = []
    monkeypatch.setattr(notifier, "notify_protocol_events", lambda session, events: seen.extend(events))
    return seen


def _jobs_for(session, address: str) -> int:
    from db.models import Job

    return session.execute(
        select(func.count()).select_from(Job).where(func.lower(Job.address) == address.lower())
    ).scalar_one()


def test_pre_enrollment_event_recorded_but_not_notified_or_reanalyzed(db_session, monkeypatch):
    """Pre-enrollment history is persisted as ``historical`` but never notified or reanalyzed (the 2018-USDC
    failure).
    """
    from services.monitoring.unified_watcher import scan_for_events

    monkeypatch.setenv("PSAT_SCAN_CONFIRMATION_DEPTH", "0")
    mc_id = _mk(db_session, ADDR(1), cursor=100, enrollment_block=1000)
    Wire(head=2000, logs=[_ownership_log(ADDR(1), ADDR(0xBEEF), block=500)]).install(monkeypatch)
    notified = _install_notify_capture(monkeypatch)

    result = scan_for_events(db_session, "http://stub")

    assert len(result) == 0  # not among the pass's notifiable events
    assert notified == []  # never notified
    assert _jobs_for(db_session, ADDR(1)) == 0  # no reanalysis queued

    rows = (
        db_session.execute(select(MonitoredEvent).where(MonitoredEvent.monitored_contract_id == mc_id)).scalars().all()
    )
    assert len(rows) == 1  # still recorded for the timeline
    assert rows[0].data and rows[0].data.get("historical") is True


def test_post_enrollment_event_notified_and_reanalyzed(db_session, monkeypatch):
    from services.monitoring.unified_watcher import scan_for_events

    monkeypatch.setenv("PSAT_SCAN_CONFIRMATION_DEPTH", "0")
    mc_id = _mk(db_session, ADDR(1), cursor=100, enrollment_block=100)
    Wire(head=2000, logs=[_ownership_log(ADDR(1), ADDR(0xBEEF), block=1500)]).install(monkeypatch)
    notified = _install_notify_capture(monkeypatch)

    result = scan_for_events(db_session, "http://stub")

    assert len(result) == 1
    assert len(notified) == 1  # notified exactly once
    assert _jobs_for(db_session, ADDR(1)) == 1  # reanalysis queued

    rows = (
        db_session.execute(select(MonitoredEvent).where(MonitoredEvent.monitored_contract_id == mc_id)).scalars().all()
    )
    assert len(rows) == 1
    assert not (rows[0].data or {}).get("historical")


def test_catch_up_event_after_enrollment_is_notified(db_session, monkeypatch):
    """A post-enrollment event monitoring hadn't reached is a real change the operator hasn't seen."""
    from services.monitoring.unified_watcher import scan_for_events

    monkeypatch.setenv("PSAT_SCAN_CONFIRMATION_DEPTH", "0")
    monkeypatch.setenv("PSAT_SCAN_MAX_WINDOWS_PER_COHORT", "50")
    monkeypatch.setenv("PSAT_SCAN_MAX_WINDOWS_PER_PASS", "50")
    mc_id = _mk(db_session, ADDR(1), cursor=100, enrollment_block=100)
    Wire(head=50000, logs=[_ownership_log(ADDR(1), ADDR(0xBEEF), block=10000)]).install(monkeypatch)
    notified = _install_notify_capture(monkeypatch)

    scan_for_events(db_session, "http://stub")

    assert len(notified) == 1  # catch-up change is notified, not suppressed
    rows = (
        db_session.execute(select(MonitoredEvent).where(MonitoredEvent.monitored_contract_id == mc_id)).scalars().all()
    )
    assert len(rows) == 1
    assert not (rows[0].data or {}).get("historical")


@requires_postgres
class TestCohortScanBlock:
    @staticmethod
    def _install(monkeypatch, head, calls):
        def mock_rpc(url, method, params, *, chain_id=None):
            calls.append((method, params))
            if method == "eth_blockNumber":
                return hex(head)
            if method == "eth_getLogs":
                return []
            return None

        monkeypatch.setenv("PSAT_SCAN_CONFIRMATION_DEPTH", "0")
        monkeypatch.setattr("services.monitoring.unified_watcher.rpc_request", mock_rpc)
        monkeypatch.setattr("services.resolution.repos.event_logs_rpc.rpc_request", mock_rpc)

    def test_contracts_at_different_heights_scan_in_separate_cohorts(self, db_session: SASession, monkeypatch):
        from services.monitoring.unified_watcher import scan_for_events

        behind = ADDR(1)
        ahead = ADDR(2)
        db_session.add_all(
            [
                MonitoredContract(
                    id=uuid.uuid4(),
                    address=behind,
                    chain="ethereum",
                    contract_type="regular",
                    monitoring_config={},
                    last_known_state={},
                    last_scanned_block=100,
                    needs_polling=False,
                    is_active=True,
                ),
                MonitoredContract(
                    id=uuid.uuid4(),
                    address=ahead,
                    chain="ethereum",
                    contract_type="regular",
                    monitoring_config={},
                    last_known_state={},
                    last_scanned_block=5000,
                    needs_polling=False,
                    is_active=True,
                ),
            ]
        )
        db_session.commit()

        calls: list = []
        self._install(monkeypatch, 6000, calls)
        scan_for_events(db_session, "http://fake-rpc")

        log_calls = [c for c in calls if c[0] == "eth_getLogs"]
        for _, params in log_calls:
            addrs = {a.lower() for a in params[0]["address"]}
            assert addrs in ({behind.lower()}, {ahead.lower()})

        behind_calls = [c for c in log_calls if behind.lower() in {a.lower() for a in c[1][0]["address"]}]
        ahead_calls = [c for c in log_calls if ahead.lower() in {a.lower() for a in c[1][0]["address"]}]
        assert min(int(c[1][0]["fromBlock"], 16) for c in ahead_calls) == 5001
        assert min(int(c[1][0]["fromBlock"], 16) for c in behind_calls) == 101

    def test_same_block_contracts_share_one_cohort(self, db_session: SASession, monkeypatch):
        from services.monitoring.unified_watcher import scan_for_events

        db_session.add_all(
            [
                MonitoredContract(
                    id=uuid.uuid4(),
                    address=ADDR(1),
                    chain="ethereum",
                    contract_type="regular",
                    monitoring_config={},
                    last_known_state={},
                    last_scanned_block=1000,
                    needs_polling=False,
                    is_active=True,
                ),
                MonitoredContract(
                    id=uuid.uuid4(),
                    address=ADDR(2),
                    chain="ethereum",
                    contract_type="regular",
                    monitoring_config={},
                    last_known_state={},
                    last_scanned_block=1000,
                    needs_polling=False,
                    is_active=True,
                ),
            ]
        )
        db_session.commit()

        calls: list = []
        self._install(monkeypatch, 1500, calls)
        scan_for_events(db_session, "http://fake-rpc")

        log_calls = [c for c in calls if c[0] == "eth_getLogs"]
        assert len(log_calls) == 1
        assert {a.lower() for a in log_calls[0][1][0]["address"]} == {ADDR(1).lower(), ADDR(2).lower()}
        assert int(log_calls[0][1][0]["fromBlock"], 16) == 1001
        assert int(log_calls[0][1][0]["toBlock"], 16) == 1500


@requires_postgres
class TestBatchTimelockDedupe:
    """Batch timelock ops emit one log per call with the same tx, block and type; a 4-tuple dedupe hid the rest of
    the batch.
    """

    def test_batch_call_scheduled_logs_persist_separately(self, db_session: SASession):
        from services.monitoring.event_topics import CALL_SCHEDULED_TOPIC0
        from services.monitoring.unified_watcher import scan_for_events

        timelock_addr = ADDR(7)
        mc = MonitoredContract(
            id=uuid.uuid4(),
            address=timelock_addr,
            chain="ethereum",
            contract_type="timelock",
            monitoring_config={"watch_timelock": True},
            last_known_state={},
            last_scanned_block=100,
            needs_polling=False,
            is_active=True,
        )
        db_session.add(mc)
        db_session.commit()

        # Data: 5 head words, bytes_len, selector.
        head = (
            "0" * 24
            + "00" * 19
            + "01"  # target = 0x...01
            + "0" * 64  # value = 0
            + format(160, "x").zfill(64)  # bytes_offset
            + "0" * 64  # predecessor
            + format(3600, "x").zfill(64)  # delay
        )
        cd_section = format(4, "x").zfill(64) + "deadbeef" + "0" * 56
        log_data = "0x" + head + cd_section

        def mock_rpc(_url, method, _params, *, chain_id=None):
            if method == "eth_blockNumber":
                return hex(200)
            if method == "eth_getLogs":
                return [
                    {
                        "address": timelock_addr,
                        "topics": [
                            CALL_SCHEDULED_TOPIC0,
                            "0x" + "ab" * 32,
                            "0x" + format(0, "x").zfill(64),
                        ],
                        "data": log_data,
                        "blockNumber": "0x96",  # 150
                        "transactionHash": "0x" + "fe" * 32,
                        "blockHash": "0x" + "11" * 32,
                        "transactionIndex": "0x0",
                        "logIndex": "0x0",
                    },
                    {
                        "address": timelock_addr,
                        "topics": [
                            CALL_SCHEDULED_TOPIC0,
                            "0x" + "ab" * 32,
                            "0x" + format(1, "x").zfill(64),  # index=1 (second call in batch)
                        ],
                        "data": log_data,
                        "blockNumber": "0x96",
                        "transactionHash": "0x" + "fe" * 32,
                        "blockHash": "0x" + "11" * 32,
                        "transactionIndex": "0x0",
                        "logIndex": "0x1",
                    },
                ]
            return None

        with (
            patch("services.monitoring.unified_watcher.rpc_request", side_effect=mock_rpc),
            patch("services.resolution.repos.event_logs_rpc.rpc_request", side_effect=mock_rpc),
        ):
            new_events = scan_for_events(db_session, "http://fake-rpc")

        assert len(new_events) == 2, f"expected 2 batch-event rows, got {len(new_events)}"
        ids = {e.id for e in new_events}
        assert len(ids) == 2
        for e in new_events:
            assert e.event_type == "timelock_scheduled"
            assert e.tx_hash == "0x" + "fe" * 32
            assert e.block_number == 150

    def test_batch_call_executed_logs_persist_separately(self, db_session: SASession):
        """CallExecuted is what the UI renders in recent activity."""
        from services.monitoring.event_topics import CALL_EXECUTED_TOPIC0
        from services.monitoring.unified_watcher import scan_for_events

        timelock_addr = ADDR(8)
        mc = MonitoredContract(
            id=uuid.uuid4(),
            address=timelock_addr,
            chain="ethereum",
            contract_type="timelock",
            monitoring_config={"watch_timelock": True},
            last_known_state={},
            last_scanned_block=200,
            needs_polling=False,
            is_active=True,
        )
        db_session.add(mc)
        db_session.commit()

        head = (
            "0" * 24
            + "00" * 19
            + "02"  # target
            + "0" * 64  # value
            + format(96, "x").zfill(64)  # bytes_offset = 3*32
        )
        cd_section = format(4, "x").zfill(64) + "cafef00d" + "0" * 56
        log_data = "0x" + head + cd_section

        def mock_rpc(_url, method, _params, *, chain_id=None):
            if method == "eth_blockNumber":
                return hex(300)
            if method == "eth_getLogs":
                return [
                    {
                        "address": timelock_addr,
                        "topics": [
                            CALL_EXECUTED_TOPIC0,
                            "0x" + "cd" * 32,
                            "0x" + format(0, "x").zfill(64),
                        ],
                        "data": log_data,
                        "blockNumber": "0xfa",  # 250
                        "transactionHash": "0x" + "ba" * 32,
                        "blockHash": "0x" + "22" * 32,
                        "transactionIndex": "0x0",
                        "logIndex": "0x0",
                    },
                    {
                        "address": timelock_addr,
                        "topics": [
                            CALL_EXECUTED_TOPIC0,
                            "0x" + "cd" * 32,
                            "0x" + format(1, "x").zfill(64),
                        ],
                        "data": log_data,
                        "blockNumber": "0xfa",
                        "transactionHash": "0x" + "ba" * 32,
                        "blockHash": "0x" + "22" * 32,
                        "transactionIndex": "0x0",
                        "logIndex": "0x1",
                    },
                ]
            return None

        with (
            patch("services.monitoring.unified_watcher.rpc_request", side_effect=mock_rpc),
            patch("services.resolution.repos.event_logs_rpc.rpc_request", side_effect=mock_rpc),
        ):
            new_events = scan_for_events(db_session, "http://fake-rpc")

        assert len(new_events) == 2
        for e in new_events:
            assert e.event_type == "timelock_executed"
            assert e.tx_hash == "0x" + "ba" * 32
            assert e.block_number == 250
