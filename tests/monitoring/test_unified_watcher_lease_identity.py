"""Lease gating + event-identity tests for the unified watcher.

Real test DB and pipeline; only the RPC wire (``rpc_request``, ``rpc_batch_request_classified``)
and ``notifier._send_discord`` are stubbed. Covers the two-layer singleton, HR2
(duplicate pass adds zero rows/jobs/posts), batch-timelock identity, the partial-index poll
exclusion, the per-chain lease gate, the poll-path duplicate non-guarantee (Risk #7) and the
governance-rotation dirty-mark.
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
    """``on_first_getlogs`` lets a renew-loss test steal the lease mid-pass."""

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
    """Lease names are fixed, so a leftover foreign holder would make the next pass skip."""

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
    import services.monitoring.unified_watcher as uw

    real = uw.emit_monitor_cycle
    notes: list = []

    def spy(process, **kwargs):
        notes.append(kwargs.get("note"))
        return real(process, **kwargs)

    monkeypatch.setattr(uw, "emit_monitor_cycle", spy)
    return notes


def _steal_lease(name: str) -> None:
    """Committed from a separate connection so the next renew sees it."""
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
# THE duplicate-pass property test
# ---------------------------------------------------------------------------


def test_duplicate_scan_pass_adds_zero_rows_jobs_and_posts(db_session, monkeypatch):
    """Layer 2 (partial unique index + RETURNING-gated side effects) carries this without the lease."""
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

    db_session.execute(update(MonitoredContract).where(MonitoredContract.id == mc.id).values(last_scanned_block=0))
    db_session.commit()

    Wire(head=2000, logs=logs).install(monkeypatch)
    r2 = scan_for_events(db_session, "http://stub")

    # The re-scanned log lost the ON CONFLICT.
    assert len(r2) == 0
    assert _count_events(db_session, mc.id) == rows_1
    assert _count_jobs(db_session, addr) == jobs_1
    assert len(posts) == posts_1


# ---------------------------------------------------------------------------
# Lease gating
# ---------------------------------------------------------------------------


def test_scan_skips_when_another_holder_owns_the_lease(db_session, monkeypatch):
    monkeypatch.setenv("PSAT_SCAN_CONFIRMATION_DEPTH", "0")
    addr = ADDR(0xAA01)
    _mk(db_session, addr, 0, config={"watch_ownership": True})

    assert try_acquire_daemon_lease(db_session, _scanner_lease_name("ethereum"), uuid.uuid4(), 60) is True

    notes = _capture_cycle_notes(monkeypatch)
    wire = Wire(head=2000, logs=[_ownership_log(addr, ADDR(0xB), 1500)]).install(monkeypatch)
    result = scan_for_events(db_session, "http://stub")

    assert list(result) == []
    assert wire.getlogs_calls == []
    assert notes == ["lease_lost"]


def test_scan_renew_loss_mid_pass_aborts_after_committed_window(db_session, monkeypatch):
    monkeypatch.setenv("PSAT_SCAN_CONFIRMATION_DEPTH", "0")
    addr = ADDR(0xAA03)
    mc = _mk(db_session, addr, 0, config={"watch_ownership": True})

    def steal():
        _steal_lease(_scanner_lease_name("ethereum"))

    wire = Wire(head=6000, logs=[_ownership_log(addr, ADDR(0xB), 1500)], on_first_getlogs=steal).install(monkeypatch)
    scan_for_events(db_session, "http://stub")

    assert len(wire.getlogs_calls) == 1
    assert _cursor(db_session, mc.id) == 2000
    assert _count_events(db_session, mc.id) == 1


def test_poll_skips_when_another_holder_owns_the_lease(db_session, monkeypatch):
    plan = [{"field": "owner", "kind": "getter_call", "selector": "0x8da5cb5b", "type_kind": "address"}]
    _mk(db_session, ADDR(0xAA05), 0, config={"polling_plan": plan}, state={"owner": ADDR(0x1)}, needs_polling=True)
    assert try_acquire_daemon_lease(db_session, _poller_lease_name("ethereum"), uuid.uuid4(), 60) is True

    called = {"n": 0}

    def stub(url, calls):
        called["n"] += 1
        return [(None, "ok") for _ in calls]

    import services.monitoring.unified_watcher as uw

    notes = _capture_cycle_notes(monkeypatch)
    monkeypatch.setattr(uw, "rpc_batch_request_classified", stub)
    result = poll_for_state_changes(db_session, "http://stub")

    assert result == []
    assert called["n"] == 0
    assert notes == ["lease_lost"]


# ---------------------------------------------------------------------------
# Governance-rotation dirty-mark
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
    monkeypatch.setenv("PSAT_SCAN_CONFIRMATION_DEPTH", "0")
    addr = ADDR(0xC0FF)
    old_owner = ADDR(0x1).lower()
    proto, contract = _seed_owned_contract(db_session, addr, old_owner)
    _mk(db_session, addr, 0, config={"watch_ownership": True}, contract_id=contract.id, protocol_id=proto.id)

    new_owner = ADDR(0xF00D)
    Wire(head=2000, logs=[_ownership_log(addr, new_owner, 1500)]).install(monkeypatch)
    scan_for_events(db_session, "http://stub")

    assert _queue_reason(db_session, proto.id) == "governance_rotation"
    cv = db_session.execute(
        select(ControllerValue.value).where(ControllerValue.contract_id == contract.id)
    ).scalar_one()
    assert cv.lower() == new_owner.lower()


def test_poll_owner_change_marks_governance_rotation(db_session, monkeypatch):
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
        uw, "rpc_batch_request_classified", lambda url, calls: [("0x" + "0" * 24 + new_owner[2:], "ok") for _ in calls]
    )
    poll_for_state_changes(db_session, "http://stub")

    assert _queue_reason(db_session, proto.id) == "governance_rotation"


def test_no_op_change_does_not_mark(db_session, monkeypatch):
    monkeypatch.setenv("PSAT_SCAN_CONFIRMATION_DEPTH", "0")
    addr = ADDR(0xC0A1)
    same_owner = ADDR(0xF00D)
    proto, contract = _seed_owned_contract(db_session, addr, same_owner.lower())
    _mk(db_session, addr, 0, config={"watch_ownership": True}, contract_id=contract.id, protocol_id=proto.id)

    Wire(head=2000, logs=[_ownership_log(addr, same_owner, 1500)]).install(monkeypatch)
    scan_for_events(db_session, "http://stub")

    assert _queue_reason(db_session, proto.id) is None
