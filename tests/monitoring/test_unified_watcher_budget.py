"""Bounded cohort-scanner tests for ``scan_for_events``.

Real test DB and decode pipeline; only the RPC wire is stubbed (head read and the shared
getLogs fetcher). Covers cohort split/rotation, window budgets, per-window commits, the
behind-is-not-skipped invariant, confirmation depth, cursor monotonicity, the lag metric,
the empty-address guard and per-window notify. The last two classes cover the row side.
"""

from __future__ import annotations

import uuid

from sqlalchemy import func, select

from db.models import MonitoredContract, MonitoredEvent
from services.monitoring.event_topics import OWNERSHIP_TRANSFERRED_TOPIC0

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
