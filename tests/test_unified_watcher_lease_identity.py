"""Stage-4 lease gating + event-identity tests for the unified watcher (W2a).

Real test DB, real decode/sync/reanalysis/notify pipeline; only the RPC wire
(``rpc_request`` for head + getLogs, ``rpc_batch_request_with_status`` for
poll) and the
Discord HTTP call (``notifier._send_discord``) are stubbed. Covers design §2.4
(two-layer singleton), HR2 (duplicate-pass produces zero extra rows / jobs /
posts), the batch-timelock identity, the partial-index poll exclusion, the
per-chain daemon-lease gate (skip / renew-loss abort / TTL steal / re-acquire),
the documented poll-path duplicate non-guarantee (Risk #7), and the
governance-rotation dirty-mark (design §2.3 call-site 5).
"""

from __future__ import annotations

import os
import uuid

import pytest
from sqlalchemy import create_engine, func, select, text, update
from sqlalchemy.orm import Session as SASession

from db.models import (
    Contract,
    ControllerValue,
    Job,
    MonitoredContract,
    MonitoredEvent,
    MonitoringEnrollmentQueue,
    Protocol,
    ProtocolSubscription,
)
from db.queue import try_acquire_daemon_lease
from services.monitoring.event_topics import OWNERSHIP_TRANSFERRED_TOPIC0
from services.monitoring.unified_watcher import (
    _LEASE_HOLDER,
    _poller_lease_name,
    _scanner_lease_name,
    poll_for_state_changes,
    scan_for_events,
)

DATABASE_URL = os.environ.get("TEST_DATABASE_URL", "")

MAX_BLOCK_RANGE = 2000


def ADDR(n: int) -> str:
    return "0x" + hex(n)[2:].zfill(40)


def _addr_topic(addr: str) -> str:
    return "0x" + "0" * 24 + addr[2:].lower()


def _ownership_log(address: str, new_owner: str, block: int, log_index: int = 0) -> dict:
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
    """Stubs the head + getLogs RPC entry points scan_for_events reaches.

    ``on_first_getlogs`` fires exactly once, before the first window's logs are
    returned — the hook a renew-loss test uses to steal the lease mid-pass.
    """

    def __init__(self, head: int, *, logs: list[dict] | None = None, on_first_getlogs=None):
        self.head = head
        self.logs = logs or []
        self.getlogs_calls: list[dict] = []
        self.on_first_getlogs = on_first_getlogs

    def head_rpc(self, url, method, params, *, chain_id=None):
        if method == "eth_blockNumber":
            return hex(self.head)
        raise AssertionError(f"unexpected head-path method {method}")

    def getlogs_rpc(self, url, method, params, *, chain_id=None):
        assert method == "eth_getLogs", method
        p = params[0]
        if not self.getlogs_calls and self.on_first_getlogs is not None:
            self.on_first_getlogs()
        self.getlogs_calls.append(p)
        assert p["address"], "getLogs issued with an empty address list"
        frm = int(p["fromBlock"], 16)
        to = int(p["toBlock"], 16)
        addrs = {a.lower() for a in p["address"]}
        return [lg for lg in self.logs if lg["address"].lower() in addrs and frm <= int(lg["blockNumber"], 16) <= to]

    def install(self, monkeypatch):
        import services.monitoring.unified_watcher as uw
        import services.resolution.repos.event_logs_rpc as elr

        monkeypatch.setattr(uw, "rpc_request", self.head_rpc)
        monkeypatch.setattr(elr, "rpc_request", self.getlogs_rpc)
        return self


@pytest.fixture(autouse=True)
def _clean_lease_and_jobs(db_session):
    """Drop scan/poll daemon leases and test Job rows around each test.

    The scanner/poller lease names are fixed, so a leftover *foreign*-holder row
    from one test would make the next test's real pass skip. The shared
    ``db_session`` teardown now clears ``daemon_leases`` but not ``jobs``, and
    we still wipe per-test (not just at teardown) so mid-file ordering is clean.
    """

    def _wipe():
        db_session.execute(
            text("DELETE FROM daemon_leases WHERE name LIKE 'protocol_scanner:%' OR name LIKE 'protocol_poller:%'")
        )
        db_session.execute(text("DELETE FROM jobs"))
        db_session.commit()

    _wipe()
    yield
    _wipe()


def _capture_cycle_notes(monkeypatch):
    """Spy on ``emit_monitor_cycle`` to capture each pass's ``note`` kwarg while
    still delegating to the real heartbeat emit."""
    import services.monitoring.unified_watcher as uw

    real = uw.emit_monitor_cycle
    notes: list = []

    def spy(process, **kwargs):
        notes.append(kwargs.get("note"))
        return real(process, **kwargs)

    monkeypatch.setattr(uw, "emit_monitor_cycle", spy)
    return notes


def _steal_lease(name: str) -> None:
    """Force *name* to a foreign holder with a live TTL, from a separate
    connection so it is committed and visible to the scanner's next renew —
    simulates a window that outran its TTL and lost the lease to a competitor.
    """
    engine = create_engine(DATABASE_URL)
    s = SASession(engine)
    try:
        s.execute(
            text("UPDATE daemon_leases SET holder = :h, expires_at = NOW() + INTERVAL '60 second' WHERE name = :n"),
            {"h": uuid.uuid4(), "n": name},
        )
        s.commit()
    finally:
        s.close()
        engine.dispose()


def _mk(session, address, cursor, *, config=None, contract_id=None, protocol_id=None, state=None, needs_polling=False):
    mc = MonitoredContract(
        id=uuid.uuid4(),
        address=address,
        chain="ethereum",
        contract_type="regular",
        contract_id=contract_id,
        protocol_id=protocol_id,
        monitoring_config=config if config is not None else {},
        last_known_state=state if state is not None else {},
        last_scanned_block=cursor,
        needs_polling=needs_polling,
        is_active=True,
    )
    session.add(mc)
    session.commit()
    return mc


def _cursor(session, mc_id):
    session.expire_all()
    return session.execute(
        select(MonitoredContract.last_scanned_block).where(MonitoredContract.id == mc_id)
    ).scalar_one()


def _count_events(session, mc_id, event_type=None):
    q = select(func.count()).select_from(MonitoredEvent).where(MonitoredEvent.monitored_contract_id == mc_id)
    if event_type is not None:
        q = q.where(MonitoredEvent.event_type == event_type)
    return session.execute(q).scalar_one()


def _count_jobs(session, address):
    return session.execute(
        select(func.count()).select_from(Job).where(func.lower(Job.address) == address.lower())
    ).scalar_one()


# ---------------------------------------------------------------------------
# THE duplicate-pass property test (design §4 Stage 4 / HR2)
# ---------------------------------------------------------------------------


def test_duplicate_scan_pass_adds_zero_rows_jobs_and_posts(db_session, monkeypatch):
    """Two scan passes over IDENTICAL logs — the second re-scanning the same
    range (cursor reset back to 0, i.e. a lease-bug concurrent scanner that
    never saw the first pass advance) — produce ZERO additional MonitoredEvent
    rows, reanalysis jobs, and Discord posts. Layer 2 (the partial unique index
    + RETURNING-gated side effects) carries this WITHOUT the lease: the second
    pass is the same process holder and so wins the lease on re-entry."""
    import services.monitoring.notifier as notifier

    monkeypatch.setenv("PSAT_SCAN_CONFIRMATION_DEPTH", "0")
    proto = Protocol(name=f"dup-proto-{uuid.uuid4().hex[:8]}")
    db_session.add(proto)
    db_session.commit()
    addr = ADDR(0x51A1)
    mc = _mk(db_session, addr, 0, config={"watch_ownership": True}, protocol_id=proto.id)
    db_session.add(
        ProtocolSubscription(id=uuid.uuid4(), protocol_id=proto.id, discord_webhook_url="https://discord/wh")
    )
    db_session.commit()

    posts: list[dict] = []
    monkeypatch.setattr(notifier, "_send_discord", lambda url, embed: posts.append(embed))

    logs = [_ownership_log(addr, ADDR(0xBEEF), block=1500)]
    Wire(head=2000, logs=logs).install(monkeypatch)

    r1 = scan_for_events(db_session, "http://stub")
    assert len(r1) == 1
    rows_1 = _count_events(db_session, mc.id)
    jobs_1 = _count_jobs(db_session, addr)
    posts_1 = len(posts)
    assert rows_1 == 1 and jobs_1 == 1 and posts_1 == 1

    # Rewind the cursor: the duplicate/concurrent pass re-scans the same window.
    db_session.execute(update(MonitoredContract).where(MonitoredContract.id == mc.id).values(last_scanned_block=0))
    db_session.commit()

    Wire(head=2000, logs=logs).install(monkeypatch)
    r2 = scan_for_events(db_session, "http://stub")

    # The re-scanned log lost the ON CONFLICT, so it never reached notify or
    # reanalysis — zero additional anything.
    assert len(r2) == 0
    assert _count_events(db_session, mc.id) == rows_1
    assert _count_jobs(db_session, addr) == jobs_1
    assert len(posts) == posts_1


# ---------------------------------------------------------------------------
# Batch identity + poll partial-index exclusion
# ---------------------------------------------------------------------------


def test_batch_ops_same_tx_distinct_log_index_all_land(db_session, monkeypatch):
    """Same tx_hash + block + event_type but distinct log_index ⇒ distinct
    identities ⇒ every batch row lands (the index does not collapse them)."""
    monkeypatch.setenv("PSAT_SCAN_CONFIRMATION_DEPTH", "0")
    addr = ADDR(0xBA7C)
    mc = _mk(db_session, addr, 0, config={"watch_ownership": True})

    # Three OwnershipTransferred logs sharing tx+block, log_index 0/1/2.
    tx_block = 1500
    logs = []
    for i in range(3):
        lg = _ownership_log(addr, ADDR(0x1000 + i), block=tx_block, log_index=i)
        lg["transactionHash"] = "0x" + "cd" * 32  # force a shared tx hash
        logs.append(lg)
    Wire(head=2000, logs=logs).install(monkeypatch)

    scan_for_events(db_session, "http://stub")

    assert _count_events(db_session, mc.id, "ownership_transferred") == 3
    stored = (
        db_session.execute(select(MonitoredEvent.log_index).where(MonitoredEvent.monitored_contract_id == mc.id))
        .scalars()
        .all()
    )
    assert sorted(stored) == [0, 1, 2]


def test_within_window_duplicate_log_collapses_to_one_row(db_session, monkeypatch):
    """A provider echoing the SAME log twice inside one window inserts one row —
    ON CONFLICT DO NOTHING subsumes the removed in-scan 5-tuple dedupe."""
    monkeypatch.setenv("PSAT_SCAN_CONFIRMATION_DEPTH", "0")
    addr = ADDR(0xEC40)
    mc = _mk(db_session, addr, 0, config={"watch_ownership": True})

    log = _ownership_log(addr, ADDR(0xBEEF), block=1500, log_index=7)
    # Same tx_hash + log_index + event_type twice → one identity.
    Wire(head=2000, logs=[log, dict(log)]).install(monkeypatch)

    scan_for_events(db_session, "http://stub")

    assert _count_events(db_session, mc.id, "ownership_transferred") == 1


def test_two_poll_detections_same_field_both_insert_with_null_log_index(db_session, monkeypatch):
    """Two successive state_changed_poll detections on one contract+field both
    land (they are log_index NULL, outside the partial identity index)."""
    plan = [{"field": "owner", "kind": "getter_call", "selector": "0x8da5cb5b", "type_kind": "address"}]
    mc = _mk(
        db_session,
        ADDR(0x9011),
        0,
        config={"polling_plan": plan, "watch_ownership": True},
        state={"owner": ADDR(0x1).lower()},
        needs_polling=True,
    )

    def _wire(value):
        def stub(url, calls):
            return [(value, False) for _ in calls]

        return stub

    import services.monitoring.unified_watcher as uw

    monkeypatch.setattr(uw, "rpc_batch_request_with_status", _wire("0x" + "0" * 24 + ADDR(0x2)[2:]))
    poll_for_state_changes(db_session, "http://stub")
    monkeypatch.setattr(uw, "rpc_batch_request_with_status", _wire("0x" + "0" * 24 + ADDR(0x3)[2:]))
    poll_for_state_changes(db_session, "http://stub")

    assert _count_events(db_session, mc.id, "state_changed_poll") == 2
    log_indexes = (
        db_session.execute(
            select(MonitoredEvent.log_index).where(
                MonitoredEvent.monitored_contract_id == mc.id,
                MonitoredEvent.event_type == "state_changed_poll",
            )
        )
        .scalars()
        .all()
    )
    assert log_indexes == [None, None]


# ---------------------------------------------------------------------------
# Lease gating (design §2.4 Layer 1)
# ---------------------------------------------------------------------------


def test_scan_skips_when_another_holder_owns_the_lease(db_session, monkeypatch):
    """A live foreign-holder lease ⇒ the pass acquires nothing, issues no
    getLogs, and beats with note='lease_lost'."""
    monkeypatch.setenv("PSAT_SCAN_CONFIRMATION_DEPTH", "0")
    addr = ADDR(0xAA01)
    _mk(db_session, addr, 0, config={"watch_ownership": True})

    # Competitor holds the ethereum scanner lease.
    assert try_acquire_daemon_lease(db_session, _scanner_lease_name("ethereum"), uuid.uuid4(), 60) is True

    notes = _capture_cycle_notes(monkeypatch)
    wire = Wire(head=2000, logs=[_ownership_log(addr, ADDR(0xB), 1500)]).install(monkeypatch)
    result = scan_for_events(db_session, "http://stub")

    assert list(result) == []
    assert wire.getlogs_calls == []
    assert notes == ["lease_lost"]


def test_scan_steals_expired_lease_and_runs(db_session, monkeypatch):
    """An expired competitor lease is stolen; the pass runs normally."""
    monkeypatch.setenv("PSAT_SCAN_CONFIRMATION_DEPTH", "0")
    addr = ADDR(0xAA02)
    mc = _mk(db_session, addr, 0, config={"watch_ownership": True})

    # Seed an already-expired competitor lease (negative TTL).
    assert try_acquire_daemon_lease(db_session, _scanner_lease_name("ethereum"), uuid.uuid4(), -5) is True

    wire = Wire(head=2000, logs=[_ownership_log(addr, ADDR(0xB), 1500)]).install(monkeypatch)
    result = scan_for_events(db_session, "http://stub")

    assert len(wire.getlogs_calls) == 1
    assert len(result) == 1
    assert _cursor(db_session, mc.id) == 2000
    # The scanner now holds the row.
    holder = db_session.execute(
        text("SELECT holder FROM daemon_leases WHERE name = :n"), {"n": _scanner_lease_name("ethereum")}
    ).scalar_one()
    assert holder == _LEASE_HOLDER


def test_scan_renew_loss_mid_pass_aborts_after_committed_window(db_session, monkeypatch):
    """Losing the lease mid-pass aborts AFTER the already-committed window: the
    first window is durable, and no further getLogs is issued."""
    monkeypatch.setenv("PSAT_SCAN_CONFIRMATION_DEPTH", "0")
    addr = ADDR(0xAA03)
    mc = _mk(db_session, addr, 0, config={"watch_ownership": True})

    # head=6000 ⇒ three 2000-block windows are available.
    def steal():
        _steal_lease(_scanner_lease_name("ethereum"))

    wire = Wire(head=6000, logs=[_ownership_log(addr, ADDR(0xB), 1500)], on_first_getlogs=steal).install(monkeypatch)
    scan_for_events(db_session, "http://stub")

    # Only window 1 was fetched; windows 2-3 were never requested.
    assert len(wire.getlogs_calls) == 1
    # Window 1 committed durably before the abort.
    assert _cursor(db_session, mc.id) == 2000
    assert _count_events(db_session, mc.id) == 1


def test_scan_holder_reacquires_across_windows(db_session, monkeypatch):
    """The same process holder renews across every window of a multi-window
    pass — two windows both scan and commit under one continuous lease."""
    monkeypatch.setenv("PSAT_SCAN_CONFIRMATION_DEPTH", "0")
    addr = ADDR(0xAA04)
    mc = _mk(db_session, addr, 0, config={"watch_ownership": True})

    logs = [_ownership_log(addr, ADDR(0xA), 1000), _ownership_log(addr, ADDR(0xB), 3000)]
    wire = Wire(head=4000, logs=logs).install(monkeypatch)
    result = scan_for_events(db_session, "http://stub")

    assert len(wire.getlogs_calls) == 2  # two windows both ran
    assert _cursor(db_session, mc.id) == 4000
    assert len(result) == 2
    holder = db_session.execute(
        text("SELECT holder FROM daemon_leases WHERE name = :n"), {"n": _scanner_lease_name("ethereum")}
    ).scalar_one()
    assert holder == _LEASE_HOLDER


def test_poll_skips_when_another_holder_owns_the_lease(db_session, monkeypatch):
    """Poll passes are lease-gated too: a foreign holder ⇒ skip, note='lease_lost',
    no batch RPC issued."""
    plan = [{"field": "owner", "kind": "getter_call", "selector": "0x8da5cb5b", "type_kind": "address"}]
    _mk(db_session, ADDR(0xAA05), 0, config={"polling_plan": plan}, state={"owner": ADDR(0x1)}, needs_polling=True)
    assert try_acquire_daemon_lease(db_session, _poller_lease_name("ethereum"), uuid.uuid4(), 60) is True

    called = {"n": 0}

    def stub(url, calls):
        called["n"] += 1
        return [(None, False) for _ in calls]

    import services.monitoring.unified_watcher as uw

    notes = _capture_cycle_notes(monkeypatch)
    monkeypatch.setattr(uw, "rpc_batch_request_with_status", stub)
    result = poll_for_state_changes(db_session, "http://stub")

    assert result == []
    assert called["n"] == 0
    assert notes == ["lease_lost"]


def test_poll_path_may_duplicate_without_lease_protection(db_session, monkeypatch):
    """Design Risk #7 (documented non-guarantee): the poll path has NO Layer-2
    identity, so two concurrent detections of the same change (simulated by
    replaying the pre-change state before the second pass — a lease-bug
    concurrent poller) DO produce duplicate state_changed_poll rows. This
    asserts the current behavior so a future per-(mc, field, day) identity is a
    deliberate, test-driven change."""
    plan = [{"field": "owner", "kind": "getter_call", "selector": "0x8da5cb5b", "type_kind": "address"}]
    mc = _mk(
        db_session,
        ADDR(0xAA06),
        0,
        config={"polling_plan": plan},
        state={"owner": ADDR(0x1).lower()},
        needs_polling=True,
    )

    import services.monitoring.unified_watcher as uw

    new_val = "0x" + "0" * 24 + ADDR(0x2)[2:]
    monkeypatch.setattr(uw, "rpc_batch_request_with_status", lambda url, calls: [(new_val, False) for _ in calls])
    poll_for_state_changes(db_session, "http://stub")
    assert _count_events(db_session, mc.id, "state_changed_poll") == 1

    # Replay the pre-change state (the concurrent poller read it before the
    # first committed) and poll again with the same on-chain value.
    db_session.execute(
        update(MonitoredContract)
        .where(MonitoredContract.id == mc.id)
        .values(last_known_state={"owner": ADDR(0x1).lower()})
    )
    db_session.commit()
    poll_for_state_changes(db_session, "http://stub")

    assert _count_events(db_session, mc.id, "state_changed_poll") == 2


# ---------------------------------------------------------------------------
# Governance-rotation dirty-mark (design §2.3 call-site 5)
# ---------------------------------------------------------------------------


def _seed_owned_contract(session, addr, owner_value):
    proto = Protocol(name=f"gov-proto-{uuid.uuid4().hex[:8]}")
    session.add(proto)
    session.commit()
    contract = Contract(address=addr, chain="ethereum", protocol_id=proto.id, contract_name="Vault")
    session.add(contract)
    session.commit()
    session.add(ControllerValue(contract_id=contract.id, controller_id="state_variable:owner", value=owner_value))
    session.commit()
    return proto, contract


def _queue_reason(session, protocol_id):
    return session.execute(
        select(MonitoringEnrollmentQueue.reason).where(MonitoringEnrollmentQueue.protocol_id == protocol_id)
    ).scalar_one_or_none()


def test_scan_owner_change_marks_governance_rotation(db_session, monkeypatch):
    """An OwnershipTransferred flowing through the real scan pipeline that moves
    the owner ControllerValue enqueues a 'governance_rotation' dirty row."""
    monkeypatch.setenv("PSAT_SCAN_CONFIRMATION_DEPTH", "0")
    addr = ADDR(0xC0FF)
    old_owner = ADDR(0x1).lower()
    proto, contract = _seed_owned_contract(db_session, addr, old_owner)
    _mk(db_session, addr, 0, config={"watch_ownership": True}, contract_id=contract.id, protocol_id=proto.id)

    new_owner = ADDR(0xF00D)
    Wire(head=2000, logs=[_ownership_log(addr, new_owner, 1500)]).install(monkeypatch)
    scan_for_events(db_session, "http://stub")

    assert _queue_reason(db_session, proto.id) == "governance_rotation"
    # The controller value actually moved.
    cv = db_session.execute(
        select(ControllerValue.value).where(ControllerValue.contract_id == contract.id)
    ).scalar_one()
    assert cv.lower() == new_owner.lower()


def test_poll_owner_change_marks_governance_rotation(db_session, monkeypatch):
    """A poll-detected owner change also marks 'governance_rotation'."""
    addr = ADDR(0xC0DE)
    old_owner = ADDR(0x1).lower()
    proto, contract = _seed_owned_contract(db_session, addr, old_owner)
    plan = [{"field": "owner", "kind": "getter_call", "selector": "0x8da5cb5b", "type_kind": "address"}]
    _mk(
        db_session,
        addr,
        0,
        config={"polling_plan": plan},
        state={"owner": old_owner},
        contract_id=contract.id,
        protocol_id=proto.id,
        needs_polling=True,
    )

    import services.monitoring.unified_watcher as uw

    new_owner = ADDR(0x2)
    monkeypatch.setattr(
        uw, "rpc_batch_request_with_status", lambda url, calls: [("0x" + "0" * 24 + new_owner[2:], False) for _ in calls]
    )
    poll_for_state_changes(db_session, "http://stub")

    assert _queue_reason(db_session, proto.id) == "governance_rotation"


def test_no_op_change_does_not_mark(db_session, monkeypatch):
    """An event whose synced value equals what is already stored changes
    nothing, so it does NOT enqueue a governance-rotation row."""
    monkeypatch.setenv("PSAT_SCAN_CONFIRMATION_DEPTH", "0")
    addr = ADDR(0xC0A1)
    same_owner = ADDR(0xF00D)
    proto, contract = _seed_owned_contract(db_session, addr, same_owner.lower())
    _mk(db_session, addr, 0, config={"watch_ownership": True}, contract_id=contract.id, protocol_id=proto.id)

    # OwnershipTransferred to the SAME owner already recorded → no CV move.
    Wire(head=2000, logs=[_ownership_log(addr, same_owner, 1500)]).install(monkeypatch)
    scan_for_events(db_session, "http://stub")

    assert _queue_reason(db_session, proto.id) is None
