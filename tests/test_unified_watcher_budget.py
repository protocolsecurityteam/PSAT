"""Bounded cohort-scanner tests for ``scan_for_events`` (Stage 1 / W1a).

Real test DB, real decode/side-effect pipeline; only the RPC wire is stubbed
(``rpc_request`` for the head-block read and for the shared getLogs fetcher).
Covers cohort split, most-behind rotation, per-cohort + per-pass window budgets,
per-window durable commits, the behind-≠-skipped failure invariant, the
confirmation-depth clamp, GREATEST cursor monotonicity, 36-day-gap convergence,
the max_lag_blocks metric, the empty-address guard, and per-window notify.
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
    """A fully-formed OwnershipTransferred RPC log the fetcher will decode.

    ``RpcEventLogFetcher._decode_log`` requires blockHash + transactionHash +
    transactionIndex/logIndex/blockNumber, so a stub that omits them would be
    silently dropped — build the whole shape.
    """
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
    """Stubs both RPC entry points scan_for_events reaches.

    ``eth_blockNumber`` (head) goes through ``unified_watcher.rpc_request``;
    ``eth_getLogs`` goes through the shared fetcher's
    ``event_logs_rpc.rpc_request``. Every getLogs call is captured and its
    address list asserted non-empty (an empty list matches ANY address on the
    wire).
    """

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
            # Provider range/response-cap shape → the fetcher bisects, then
            # (at the span floor) re-raises this.
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


# ---------------------------------------------------------------------------
# Cohort formation
# ---------------------------------------------------------------------------


def test_cohort_split_at_address_batch(db_session, monkeypatch):
    """250 contracts in one block-bucket split into two cohorts of ≤200."""
    from services.monitoring.unified_watcher import scan_for_events

    monkeypatch.setenv("PSAT_SCAN_CONFIRMATION_DEPTH", "0")
    for i in range(250):
        _mk(db_session, ADDR(1000 + i), 100)

    wire = Wire(head=200).install(monkeypatch)
    result = scan_for_events(db_session, "http://stub")

    assert result.cohorts == 2
    # One window per cohort (100→200 fits in a single 2000-block window).
    assert len(wire.getlogs_calls) == 2
    sizes = sorted(len(c["address"]) for c in wire.getlogs_calls)
    assert sizes == [50, 200]
    # Union covers every enrolled address exactly once.
    scanned = {a.lower() for c in wire.getlogs_calls for a in c["address"]}
    assert len(scanned) == 250


def test_most_behind_cohort_scanned_first(db_session, monkeypatch):
    """The cohort with the largest head−cursor lag gets the first window."""
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


# ---------------------------------------------------------------------------
# Budgets
# ---------------------------------------------------------------------------


# The single-cohort 50-window pass cap (windows_scanned==50, budget_exhausted,
# cursor at 50×MAX_BLOCK_RANGE) is asserted by pass 1 of
# ``test_36_day_gap_converges_in_three_passes`` below, which additionally pins
# cohorts==1 and flat single-address hydration.


def test_per_cohort_turn_cap_hands_off_within_pass(db_session, monkeypatch):
    """Per-cohort turn cap (25) yields to the next-most-behind cohort so the
    50-window pass budget splits 25/25 across two equally-behind cohorts."""
    from services.monitoring.unified_watcher import scan_for_events

    monkeypatch.setenv("PSAT_SCAN_CONFIRMATION_DEPTH", "0")
    # 201 contracts at the same cursor → cohort A (200) + cohort B (1), equal lag.
    ids = [_mk(db_session, ADDR(2000 + i), 0) for i in range(201)]
    Wire(head=500_000).install(monkeypatch)

    result = scan_for_events(db_session, "http://stub")

    assert result.windows_scanned == 50
    assert result.budget_exhausted is True
    # Both cohorts advanced by exactly one 25-window turn — neither monopolised.
    cursors = {_cursor(db_session, i) for i in ids}
    assert cursors == {25 * MAX_BLOCK_RANGE}


def test_budget_not_exhausted_when_caught_up(db_session, monkeypatch):
    """Draining all reachable blocks under budget reports not-exhausted."""
    from services.monitoring.unified_watcher import scan_for_events

    monkeypatch.setenv("PSAT_SCAN_CONFIRMATION_DEPTH", "0")
    mc_id = _mk(db_session, ADDR(1), 0)
    Wire(head=3000).install(monkeypatch)  # 2 windows total

    result = scan_for_events(db_session, "http://stub")

    assert result.windows_scanned == 2
    assert result.budget_exhausted is False
    assert _cursor(db_session, mc_id) == 3000


# ---------------------------------------------------------------------------
# Confirmation depth
# ---------------------------------------------------------------------------


def test_confirmation_depth_clamps_window_end(db_session, monkeypatch):
    """Windows never reach past head − CONFIRMATION_DEPTH."""
    from services.monitoring.unified_watcher import scan_for_events

    monkeypatch.setenv("PSAT_SCAN_CONFIRMATION_DEPTH", "12")
    mc_id = _mk(db_session, ADDR(1), 100)
    wire = Wire(head=1000).install(monkeypatch)

    result = scan_for_events(db_session, "http://stub")

    assert len(wire.getlogs_calls) == 1
    assert int(wire.getlogs_calls[0]["toBlock"], 16) == 988  # 1000 − 12
    assert _cursor(db_session, mc_id) == 988
    assert result.max_lag_blocks == 12  # raw head − cursor


# ---------------------------------------------------------------------------
# Failure invariant: behind ≠ skipped
# ---------------------------------------------------------------------------


def test_failed_window_does_not_advance_cursor_and_persists_prior_windows(db_session, monkeypatch):
    """Windows 1–2 commit durably; window 3 fails → cursor stays at window 2's
    end and the pass reports degraded, but window-1's event is persisted."""
    from services.monitoring.unified_watcher import scan_for_events

    monkeypatch.setenv("PSAT_SCAN_CONFIRMATION_DEPTH", "0")
    addr = ADDR(1)
    mc_id = _mk(db_session, addr, 0)

    # Window 1 = [1,2000], window 2 = [2001,4000], window 3 = [4001,6000].
    new_owner = ADDR(0xBEEF)
    logs = [_ownership_log(addr, new_owner, block=1500)]  # lands in window 1
    Wire(head=10_000, fail_from=4001, logs=logs).install(monkeypatch)

    result = scan_for_events(db_session, "http://stub")

    assert result.degraded is True
    # Cursor advanced through the two committed windows only.
    assert _cursor(db_session, mc_id) == 2 * MAX_BLOCK_RANGE
    # Window-1's event survived the later-window failure (per-window commit).
    events = (
        db_session.execute(select(MonitoredEvent).where(MonitoredEvent.monitored_contract_id == mc_id)).scalars().all()
    )
    assert len(events) == 1
    assert events[0].event_type == "ownership_transferred"
    assert events[0].data.get("new_owner", "").lower() == new_owner.lower()


def test_failure_isolates_to_its_cohort(db_session, monkeypatch):
    """A failing cohort ends its turn; a healthy cohort still advances."""
    from services.monitoring.unified_watcher import scan_for_events

    monkeypatch.setenv("PSAT_SCAN_CONFIRMATION_DEPTH", "0")
    bad = ADDR(1)  # bucket 0
    good = ADDR(2)  # bucket 0 as well but scanned in its own cohort? force split
    bad_id = _mk(db_session, bad, 0)
    good_id = _mk(db_session, good, 0)

    # Fail only bad's address by failing all getLogs whose address set is {bad}.
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

    # Put them in separate cohorts via the address batch size = 1.
    monkeypatch.setenv("PSAT_SCAN_ADDRESS_BATCH", "1")
    TwoCohortWire(head=1500).install(monkeypatch)

    result = scan_for_events(db_session, "http://stub")

    assert result.degraded is True
    assert _cursor(db_session, bad_id) == 0  # never advanced
    assert _cursor(db_session, good_id) == 1500  # scanned cleanly


# ---------------------------------------------------------------------------
# Cursor monotonicity
# ---------------------------------------------------------------------------


def test_lower_head_second_pass_does_not_rewind(db_session, monkeypatch):
    """A pass observing a lower head (stale/reorged node) never rewinds."""
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


# The GREATEST cursor monotonicity (a stale/zombie writer replaying an old
# window end can never rewind) is asserted through the real ``scan_for_events``
# in ``test_lower_head_second_pass_does_not_rewind`` above; a raw-UPDATE
# re-assertion here would only re-test Postgres ``GREATEST``.


def test_cohort_greatest_does_not_rewind_ahead_member(db_session, monkeypatch):
    """Within one cohort, the shared per-window UPDATE commits ``window_end`` to
    every member, but GREATEST clamps it so a member already AHEAD of that end
    is never rewound.

    A (cursor 100) and B (cursor 1500) share block-bucket 0 (both ``//2000``),
    so they form a single cohort whose cursor is ``min == 100``. With head 1000
    the cohort's only window ends at ``window_end = min(100+2000, 1000) = 1000``
    — below B's 1500. A advances 100→1000; B, already past the window end
    (a reorged/lower head after B was scanned further in a prior pass), stays at
    1500. Drop GREATEST from the production UPDATE and B rewinds to 1000.
    """
    from services.monitoring.unified_watcher import scan_for_events

    monkeypatch.setenv("PSAT_SCAN_CONFIRMATION_DEPTH", "0")
    a_id = _mk(db_session, ADDR(1), 100)  # bucket 0, defines the cohort window
    b_id = _mk(db_session, ADDR(2), 1500)  # bucket 0, already ahead of window_end

    Wire(head=1000).install(monkeypatch)  # confirmed_head lands between A and B
    result = scan_for_events(db_session, "http://stub")

    # A and B were bucketed together into one cohort committed in one UPDATE.
    assert result.cohorts == 1
    assert _cursor(db_session, a_id) == 1000  # advanced to the window end
    assert _cursor(db_session, b_id) == 1500  # NOT rewound to 1000


# ---------------------------------------------------------------------------
# Convergence + metrics
# ---------------------------------------------------------------------------


def test_36_day_gap_converges_in_three_passes(db_session, monkeypatch):
    """250k-block backlog = 125 windows ⇒ 50 + 50 + 25 across three passes,
    with one cohort and a single-address getLogs each window (flat hydration)."""
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
    """The lag metric is head − the most-behind contract's cursor."""
    from services.monitoring.unified_watcher import scan_for_events

    monkeypatch.setenv("PSAT_SCAN_CONFIRMATION_DEPTH", "0")
    # Two cohorts; only enough budget-free work that one stays far behind.
    _mk(db_session, ADDR(1), 0)  # bucket 0 — will drain to head
    _mk(db_session, ADDR(2), 240_000)  # bucket 120 — near head
    head = 250_000
    Wire(head=head).install(monkeypatch)

    result = scan_for_events(db_session, "http://stub")

    # The deeply-behind cohort can't finish in one 50-window pass (needs 125),
    # so max_lag reflects its remaining distance from head.
    assert result.max_lag_blocks == head - 100_000  # advanced 50 windows


# ---------------------------------------------------------------------------
# Empty-address guard
# ---------------------------------------------------------------------------


def test_no_getlogs_with_empty_address_list(db_session, monkeypatch):
    """Every getLogs carries a non-empty address list (empty = match-any)."""
    from services.monitoring.unified_watcher import scan_for_events

    monkeypatch.setenv("PSAT_SCAN_CONFIRMATION_DEPTH", "0")
    for i in range(5):
        _mk(db_session, ADDR(10 + i), 0)
    wire = Wire(head=5000).install(monkeypatch)

    scan_for_events(db_session, "http://stub")

    assert wire.getlogs_calls
    assert wire.empty_address_seen is False
    assert all(call["address"] for call in wire.getlogs_calls)


# ---------------------------------------------------------------------------
# Per-window notify
# ---------------------------------------------------------------------------


def test_notify_fires_once_per_window(db_session, monkeypatch):
    """notify_protocol_events is called per window with that window's events,
    not once at pass end — so a long catch-up doesn't buffer notifications."""
    import services.monitoring.notifier as notifier
    from services.monitoring.unified_watcher import scan_for_events

    monkeypatch.setenv("PSAT_SCAN_CONFIRMATION_DEPTH", "0")
    addr = ADDR(1)
    mc_id = _mk(db_session, addr, 0)

    # Event in window 1 ([1,2000]) and window 2 ([2001,4000]).
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
    # Two windows, each with exactly one event → two separate notify calls.
    assert calls == [["ownership_transferred"], ["ownership_transferred"]]
    stored = db_session.execute(
        select(func.count()).select_from(MonitoredEvent).where(MonitoredEvent.monitored_contract_id == mc_id)
    ).scalar_one()
    assert stored == 2


# ---------------------------------------------------------------------------
# Pre-enrollment notification floor (enrollment_block)
# ---------------------------------------------------------------------------


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
    """An event below enrollment_block is pre-enrollment history: persisted with
    a ``historical`` marker, but never notified and never queues reanalysis
    (the observed 2018-USDC failure mode). The cohort scans from the low cursor,
    so the ancient event is fetched even though the floor is higher."""
    from services.monitoring.unified_watcher import scan_for_events

    monkeypatch.setenv("PSAT_SCAN_CONFIRMATION_DEPTH", "0")
    # cursor below the event, floor above it → the event is scanned but historical.
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
    """A fresh event at/above enrollment_block notifies exactly once and queues
    reanalysis, exactly as before the floor existed."""
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
    """Chosen catch-up semantics: an event that occurred while monitoring was
    behind but AFTER enrollment (block >= enrollment_block) is a real change the
    operator hasn't seen — notify it, even though it's far from head."""
    from services.monitoring.unified_watcher import scan_for_events

    monkeypatch.setenv("PSAT_SCAN_CONFIRMATION_DEPTH", "0")
    monkeypatch.setenv("PSAT_SCAN_MAX_WINDOWS_PER_COHORT", "50")
    monkeypatch.setenv("PSAT_SCAN_MAX_WINDOWS_PER_PASS", "50")
    # Enrolled at 100, badly behind (cursor 100, head 50000); a post-enrollment
    # governance change at block 10000 that the backlog hadn't reached yet.
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
