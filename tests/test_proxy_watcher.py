"""Unit and integration tests for the proxy upgrade monitoring scanner.

Tests cover:
  - scan_for_upgrades with empty DB, no new blocks, event detection
  - Single eth_getLogs call for multiple proxies
  - Block range chunking for large ranges
  - Filtering of unrelated events
  - Idempotent scans (last_scanned_block advances)
  - resolve_current_implementation with real and empty slots

All tests run without live services (no RPC, no database).
Uses PostgreSQL for WatchedProxy / ProxyUpgradeEvent rows.
"""

from __future__ import annotations

from unittest.mock import call, patch

from conftest import ADDR, _add_proxy, _admin_data, _make_log, _topic_for, requires_postgres

from db.models import ProxyUpgradeEvent
from services.discovery.upgrade_history import (
    ADMIN_CHANGED_TOPIC0,
    BEACON_UPGRADED_TOPIC0,
    UPGRADED_TOPIC0,
)
from services.monitoring.proxy_watcher import (
    MAX_BLOCK_RANGE,
    poll_for_upgrades,
    resolve_current_implementation,
    scan_for_upgrades,
)

pytestmark = requires_postgres

EIP1967_IMPL_SLOT = "0x360894a13ba1a3210667c828492db98dca3e2076cc3735a920a3ca505d382bbc"


# ---------------------------------------------------------------------------
# 1. test_scan_no_proxies
# ---------------------------------------------------------------------------


@patch("services.monitoring.proxy_watcher.rpc_request")
def test_scan_no_proxies(mock_rpc, db_session):
    """scan_for_upgrades with empty DB returns empty list, no RPC calls."""
    result = scan_for_upgrades(db_session, "http://localhost:8545")
    assert result == []
    mock_rpc.assert_not_called()


# ---------------------------------------------------------------------------
# 2. test_scan_no_new_blocks
# ---------------------------------------------------------------------------


@patch("services.monitoring.proxy_watcher.rpc_request")
def test_scan_no_new_blocks(mock_rpc, db_session):
    """When last_scanned_block >= latest block, returns empty (no getLogs calls)."""
    _add_proxy(db_session, ADDR(1), last_scanned_block=100)

    # get_latest_block returns 100 (same as last_scanned_block)
    mock_rpc.return_value = hex(100)

    result = scan_for_upgrades(db_session, "http://localhost:8545")
    assert result == []
    # Only one RPC call: eth_blockNumber
    assert mock_rpc.call_count == 1
    mock_rpc.assert_called_once_with("http://localhost:8545", "eth_blockNumber", [])


# ---------------------------------------------------------------------------
# 3. test_scan_detects_upgrade
# ---------------------------------------------------------------------------


@patch("services.monitoring.proxy_watcher.rpc_request")
def test_scan_detects_upgrade(mock_rpc, db_session):
    """Mock eth_getLogs returning an Upgraded event; verify ProxyUpgradeEvent
    is created, WatchedProxy.last_known_implementation is updated, and
    last_scanned_block advances."""
    proxy_addr = ADDR(1)
    old_impl = ADDR(10)
    new_impl = ADDR(11)
    proxy = _add_proxy(db_session, proxy_addr, last_known_impl=old_impl, last_scanned_block=90)

    latest_block = 100
    log = _make_log(
        proxy_addr,
        UPGRADED_TOPIC0,
        _topic_for(new_impl),
        block=hex(95),
        tx="0x" + "de" * 32,
    )

    def rpc_side_effect(url, method, params, *, chain_id=None):
        if method == "eth_blockNumber":
            return hex(latest_block)
        if method == "eth_getLogs":
            return [log]
        return None

    mock_rpc.side_effect = rpc_side_effect

    events = scan_for_upgrades(db_session, "http://localhost:8545")

    assert len(events) == 1
    evt = events[0]
    assert evt.block_number == 95
    assert evt.old_implementation == old_impl
    assert evt.new_implementation == new_impl
    assert evt.event_type == "upgraded"
    assert evt.watched_proxy_id == proxy.id

    # WatchedProxy should be updated
    db_session.refresh(proxy)
    assert proxy.last_known_implementation == new_impl
    assert proxy.last_scanned_block == latest_block


# ---------------------------------------------------------------------------
# 4. test_scan_detects_admin_changed
# ---------------------------------------------------------------------------


@patch("services.monitoring.proxy_watcher.rpc_request")
def test_scan_detects_admin_changed(mock_rpc, db_session):
    """AdminChanged event is detected and recorded. old_implementation should
    come from the proxy's DB state, not the event data."""
    proxy_addr = ADDR(2)
    prior_impl = ADDR(10)  # distinct from admin addresses to verify source
    old_admin = ADDR(50)
    new_admin = ADDR(51)
    proxy = _add_proxy(db_session, proxy_addr, last_known_impl=prior_impl, last_scanned_block=90)

    log = _make_log(
        proxy_addr,
        ADMIN_CHANGED_TOPIC0,
        data=_admin_data(old_admin, new_admin),
        block=hex(95),
        tx="0x" + "a" * 64,
    )

    def rpc_side_effect(url, method, params, *, chain_id=None):
        if method == "eth_blockNumber":
            return hex(100)
        if method == "eth_getLogs":
            return [log]
        return None

    mock_rpc.side_effect = rpc_side_effect

    events = scan_for_upgrades(db_session, "http://localhost:8545")

    assert len(events) == 1
    evt = events[0]
    assert evt.event_type == "admin_changed"
    assert evt.new_implementation == new_admin
    # old_implementation comes from proxy DB row, not the event data
    assert evt.old_implementation == prior_impl
    assert evt.watched_proxy_id == proxy.id


# ---------------------------------------------------------------------------
# 5. test_scan_detects_beacon_upgraded
# ---------------------------------------------------------------------------


@patch("services.monitoring.proxy_watcher.rpc_request")
def test_scan_detects_beacon_upgraded(mock_rpc, db_session):
    """BeaconUpgraded event is detected and recorded."""
    proxy_addr = ADDR(3)
    old_beacon = ADDR(90)
    new_beacon = ADDR(99)
    proxy = _add_proxy(db_session, proxy_addr, last_known_impl=old_beacon, last_scanned_block=90)

    log = _make_log(
        proxy_addr,
        BEACON_UPGRADED_TOPIC0,
        _topic_for(new_beacon),
        block=hex(95),
        tx="0x" + "bc" * 32,
    )

    def rpc_side_effect(url, method, params, *, chain_id=None):
        if method == "eth_blockNumber":
            return hex(100)
        if method == "eth_getLogs":
            return [log]
        return None

    mock_rpc.side_effect = rpc_side_effect

    events = scan_for_upgrades(db_session, "http://localhost:8545")

    assert len(events) == 1
    evt = events[0]
    assert evt.event_type == "beacon_upgraded"
    assert evt.new_implementation == new_beacon
    assert evt.old_implementation == old_beacon
    assert evt.watched_proxy_id == proxy.id


# ---------------------------------------------------------------------------
# 6. test_scan_multiple_proxies_single_call
# ---------------------------------------------------------------------------


@patch("services.monitoring.proxy_watcher.rpc_request")
def test_scan_multiple_proxies_single_call(mock_rpc, db_session):
    """Two proxies, verify a single eth_getLogs call covers both
    (check mock was called once for eth_getLogs, not once per proxy)."""
    proxy_a = _add_proxy(db_session, ADDR(1), last_scanned_block=90)
    proxy_b = _add_proxy(db_session, ADDR(2), last_scanned_block=90)
    latest_block = 100

    log_a = _make_log(ADDR(1), UPGRADED_TOPIC0, _topic_for(ADDR(11)), block=hex(95), tx="0xa" + "0" * 63)
    log_b = _make_log(ADDR(2), UPGRADED_TOPIC0, _topic_for(ADDR(22)), block=hex(97), tx="0xb" + "0" * 63)

    get_logs_call_count = 0

    def rpc_side_effect(url, method, params, *, chain_id=None):
        nonlocal get_logs_call_count
        if method == "eth_blockNumber":
            return hex(latest_block)
        if method == "eth_getLogs":
            get_logs_call_count += 1
            return [log_a, log_b]
        return None

    mock_rpc.side_effect = rpc_side_effect

    events = scan_for_upgrades(db_session, "http://localhost:8545")

    assert len(events) == 2
    # Only one eth_getLogs call for the whole block range (range is < MAX_BLOCK_RANGE)
    assert get_logs_call_count == 1

    # Both proxies updated
    db_session.refresh(proxy_a)
    db_session.refresh(proxy_b)
    assert proxy_a.last_known_implementation == ADDR(11)
    assert proxy_b.last_known_implementation == ADDR(22)


# ---------------------------------------------------------------------------
# 7. test_scan_chunks_large_ranges
# ---------------------------------------------------------------------------


@patch("services.monitoring.proxy_watcher.rpc_request")
def test_scan_chunks_large_ranges(mock_rpc, db_session):
    """Set last_scanned_block far behind latest, verify multiple eth_getLogs
    calls in MAX_BLOCK_RANGE chunks."""
    _add_proxy(db_session, ADDR(1), last_scanned_block=0)
    latest_block = MAX_BLOCK_RANGE * 3 + 500  # spans 4 chunks

    get_logs_calls = []

    def rpc_side_effect(url, method, params, *, chain_id=None):
        if method == "eth_blockNumber":
            return hex(latest_block)
        if method == "eth_getLogs":
            get_logs_calls.append(params)
            return []
        return None

    mock_rpc.side_effect = rpc_side_effect

    events = scan_for_upgrades(db_session, "http://localhost:8545")

    assert events == []
    # Should be ceil((latest_block) / MAX_BLOCK_RANGE) = 4 calls
    assert len(get_logs_calls) == 4

    # Verify the chunk boundaries are correct
    from_blocks = [int(c[0]["fromBlock"], 16) for c in get_logs_calls]
    to_blocks = [int(c[0]["toBlock"], 16) for c in get_logs_calls]

    # First chunk starts at 1 (last_scanned_block=0, cursor = 0+1)
    assert from_blocks[0] == 1
    # Last chunk ends at latest_block
    assert to_blocks[-1] == latest_block
    # Chunks are contiguous
    for i in range(1, len(from_blocks)):
        assert from_blocks[i] == to_blocks[i - 1] + 1


# ---------------------------------------------------------------------------
# 8. test_scan_ignores_unrelated_events
# ---------------------------------------------------------------------------


@patch("services.monitoring.proxy_watcher.rpc_request")
def test_scan_ignores_unrelated_events(mock_rpc, db_session):
    """Logs from addresses not in the watched list are ignored."""
    _add_proxy(db_session, ADDR(1), last_scanned_block=90)

    # Log from ADDR(99) which is NOT watched
    unrelated_log = _make_log(
        ADDR(99),
        UPGRADED_TOPIC0,
        _topic_for(ADDR(42)),
        block=hex(95),
        tx="0x" + "99" * 32,
    )

    def rpc_side_effect(url, method, params, *, chain_id=None):
        if method == "eth_blockNumber":
            return hex(100)
        if method == "eth_getLogs":
            return [unrelated_log]
        return None

    mock_rpc.side_effect = rpc_side_effect

    events = scan_for_upgrades(db_session, "http://localhost:8545")

    # No events created since the emitter is not watched
    assert events == []


# ---------------------------------------------------------------------------
# 9. test_scan_idempotent_on_restart
# ---------------------------------------------------------------------------


@patch("services.monitoring.proxy_watcher.rpc_request")
def test_scan_idempotent_on_restart(mock_rpc, db_session):
    """After a scan, last_scanned_block is updated; a second scan with
    no new blocks returns empty."""
    proxy = _add_proxy(db_session, ADDR(1), last_scanned_block=90)
    latest_block = 100

    log = _make_log(ADDR(1), UPGRADED_TOPIC0, _topic_for(ADDR(11)), block=hex(95), tx="0x" + "f1" * 32)

    call_count = {"block_number": 0, "get_logs": 0}

    def rpc_side_effect(url, method, params, *, chain_id=None):
        if method == "eth_blockNumber":
            call_count["block_number"] += 1
            return hex(latest_block)
        if method == "eth_getLogs":
            call_count["get_logs"] += 1
            # Only return the log on the first call
            if call_count["get_logs"] == 1:
                return [log]
            return []
        return None

    mock_rpc.side_effect = rpc_side_effect

    # First scan: should find the event
    events_1 = scan_for_upgrades(db_session, "http://localhost:8545")
    assert len(events_1) == 1

    db_session.refresh(proxy)
    assert proxy.last_scanned_block == latest_block

    # Second scan: same latest_block, no new blocks -> empty
    events_2 = scan_for_upgrades(db_session, "http://localhost:8545")
    assert events_2 == []

    # eth_getLogs should NOT have been called a second time
    # (from_block >= latest_block, so the scanner short-circuits)
    assert call_count["get_logs"] == 1


# ---------------------------------------------------------------------------
# 10. test_resolve_current_implementation
# ---------------------------------------------------------------------------


@patch("services.monitoring.proxy_watcher.rpc_request")
def test_resolve_current_implementation(mock_rpc):
    """EIP-1967 slot hit on first try returns immediately."""
    impl_addr = ADDR(42)
    storage_value = "0x" + "0" * 24 + impl_addr[2:]

    mock_rpc.return_value = storage_value

    result = resolve_current_implementation(ADDR(1), "http://localhost:8545")

    assert result is not None
    assert result == impl_addr.lower()

    # First call should be EIP-1967 impl slot; function returns early on match
    first_call = mock_rpc.call_args_list[0]
    assert first_call == call(
        "http://localhost:8545",
        "eth_getStorageAt",
        [ADDR(1), EIP1967_IMPL_SLOT, "latest"],
        chain_id=None,
    )


# ---------------------------------------------------------------------------
# 11. test_resolve_implementation_empty_slot
# ---------------------------------------------------------------------------


@patch("services.monitoring.proxy_watcher.rpc_request")
def test_resolve_implementation_empty_slot(mock_rpc):
    """Returns None for zero-filled slot (no implementation set)."""
    mock_rpc.return_value = "0x" + "0" * 64

    result = resolve_current_implementation(ADDR(1), "http://localhost:8545")
    assert result is None


# ---------------------------------------------------------------------------
# 12. test_duplicate_event_with_mixed_last_scanned_block
# ---------------------------------------------------------------------------


@patch("services.monitoring.proxy_watcher.rpc_request")
def test_no_duplicate_events_with_mixed_last_scanned_block(mock_rpc, db_session):
    """Proxy A (last_scanned_block=1000) and proxy B (last_scanned_block=5000).
    An Upgraded event at block 1500 for proxy A was already detected in a prior
    scan and exists in the DB.

    The scanner must not create a duplicate ProxyUpgradeEvent when it re-encounters
    the same log. It should skip events whose (watched_proxy_id, tx_hash, log_index)
    already exist.
    """
    proxy_a_addr = ADDR(1)
    proxy_b_addr = ADDR(2)
    new_impl_a = ADDR(11)

    # Proxy A was last scanned at block 1000, proxy B at block 5000
    proxy_a = _add_proxy(db_session, proxy_a_addr, last_known_impl=ADDR(10), last_scanned_block=1000)
    proxy_b = _add_proxy(db_session, proxy_b_addr, last_known_impl=ADDR(20), last_scanned_block=5000)

    latest_block = 6000

    # Simulate: proxy A already has an event at block 1500 from a prior scan
    prior_event = ProxyUpgradeEvent(
        watched_proxy_id=proxy_a.id,
        block_number=1500,
        tx_hash="0x" + "a" * 64,
        old_implementation=ADDR(10),
        new_implementation=new_impl_a,
        event_type="upgraded",
    )
    db_session.add(prior_event)
    db_session.commit()

    # eth_getLogs returns the duplicate event AND a genuinely new event for proxy B
    log_a_dup = _make_log(
        proxy_a_addr,
        UPGRADED_TOPIC0,
        _topic_for(new_impl_a),
        block=hex(1500),
        tx="0x" + "a" * 64,
        log_index="0x0",
    )
    new_impl_b = ADDR(22)
    log_b_new = _make_log(
        proxy_b_addr,
        UPGRADED_TOPIC0,
        _topic_for(new_impl_b),
        block=hex(5500),
        tx="0x" + "b" * 64,
        log_index="0x0",
    )

    def rpc_side_effect(url, method, params, *, chain_id=None):
        if method == "eth_blockNumber":
            return hex(latest_block)
        if method == "eth_getLogs":
            filter_obj = params[0]
            from_blk = int(filter_obj["fromBlock"], 16)
            to_blk = int(filter_obj["toBlock"], 16)
            logs = []
            if from_blk <= 1500 <= to_blk:
                logs.append(log_a_dup)
            if from_blk <= 5500 <= to_blk:
                logs.append(log_b_new)
            return logs
        return None

    mock_rpc.side_effect = rpc_side_effect

    events = scan_for_upgrades(db_session, "http://localhost:8545")

    # Dedup must be selective: skip the duplicate for proxy A but create the new event for proxy B
    assert len(events) == 1, "Expected 1 new event (proxy B), duplicate for proxy A should be skipped."
    assert events[0].watched_proxy_id == proxy_b.id
    assert events[0].new_implementation == new_impl_b

    # Verify proxy A still has only the original event (no duplicate)
    from sqlalchemy import select

    all_a_events = (
        db_session.execute(select(ProxyUpgradeEvent).where(ProxyUpgradeEvent.watched_proxy_id == proxy_a.id))
        .scalars()
        .all()
    )
    assert len(all_a_events) == 1, "Only the original ProxyUpgradeEvent for proxy A should exist."


# ---------------------------------------------------------------------------
# 13. test_error_recovery_silent_event_loss
# ---------------------------------------------------------------------------


@patch("services.monitoring.proxy_watcher.rpc_request")
def test_error_recovery_resumes_from_last_successful_block(mock_rpc, db_session):
    """eth_getLogs succeeds for chunk 1 but raises an exception for chunk 2.

    The scanner must only advance last_scanned_block to the end of the last
    successfully scanned chunk, not to latest_block. This ensures the failed
    chunk is retried on the next scan cycle and no events are silently lost.
    """
    proxy = _add_proxy(db_session, ADDR(1), last_scanned_block=0)

    # Make the range span 2 chunks
    latest_block = MAX_BLOCK_RANGE + 500

    chunk_calls = []

    def rpc_side_effect(url, method, params, *, chain_id=None):
        if method == "eth_blockNumber":
            return hex(latest_block)
        if method == "eth_getLogs":
            chunk_calls.append(params)
            if len(chunk_calls) == 1:
                # First chunk succeeds with no events
                return []
            else:
                # Second chunk fails
                raise ConnectionError("RPC node timeout")
        return None

    mock_rpc.side_effect = rpc_side_effect

    events = scan_for_upgrades(db_session, "http://localhost:8545")

    assert events == []
    assert len(chunk_calls) == 2, "Should have attempted two chunks"

    # last_scanned_block must stop at the end of chunk 1 (MAX_BLOCK_RANGE),
    # NOT at latest_block. The failed chunk 2 must be retried next cycle.
    db_session.refresh(proxy)
    assert proxy.last_scanned_block == MAX_BLOCK_RANGE, (
        f"Expected last_scanned_block={MAX_BLOCK_RANGE} (end of last successful chunk), "
        f"got {proxy.last_scanned_block}. The scanner must not skip past failed chunks."
    )


# ---------------------------------------------------------------------------
# 14. test_multiple_upgrades_same_block
# ---------------------------------------------------------------------------


@patch("services.monitoring.proxy_watcher.rpc_request")
def test_multiple_upgrades_same_block(mock_rpc, db_session):
    """Two Upgraded events with different log_index values in the same block
    for the same proxy. Verifies both are detected and the old_implementation
    chains correctly (first event uses the DB value, second uses the first
    event's new_implementation)."""
    proxy_addr = ADDR(1)
    old_impl = ADDR(10)
    impl_v2 = ADDR(11)
    impl_v3 = ADDR(12)
    proxy = _add_proxy(db_session, proxy_addr, last_known_impl=old_impl, last_scanned_block=90)

    block = hex(95)
    tx = "0x" + "b" * 64
    log1 = _make_log(proxy_addr, UPGRADED_TOPIC0, _topic_for(impl_v2), block=block, tx=tx, log_index="0x0")
    log2 = _make_log(proxy_addr, UPGRADED_TOPIC0, _topic_for(impl_v3), block=block, tx=tx, log_index="0x1")

    def rpc_side_effect(url, method, params, *, chain_id=None):
        if method == "eth_blockNumber":
            return hex(100)
        if method == "eth_getLogs":
            return [log1, log2]
        return None

    mock_rpc.side_effect = rpc_side_effect

    events = scan_for_upgrades(db_session, "http://localhost:8545")

    assert len(events) == 2

    # First event: old_impl -> impl_v2
    assert events[0].old_implementation == old_impl
    assert events[0].new_implementation == impl_v2
    assert events[0].block_number == 95

    # Second event: impl_v2 -> impl_v3 (chains from first event's new_impl)
    assert events[1].old_implementation == impl_v2
    assert events[1].new_implementation == impl_v3
    assert events[1].block_number == 95

    # Final state
    db_session.refresh(proxy)
    assert proxy.last_known_implementation == impl_v3


# ---------------------------------------------------------------------------
# 15. test_multiple_events_same_transaction
# ---------------------------------------------------------------------------


@patch("services.monitoring.proxy_watcher.rpc_request")
def test_multiple_events_same_transaction(mock_rpc, db_session):
    """Two events (Upgraded + AdminChanged) in the same transaction for
    the same proxy. Both should be detected."""
    proxy_addr = ADDR(1)
    old_impl = ADDR(10)
    new_impl = ADDR(11)
    old_admin = ADDR(50)
    new_admin = ADDR(51)
    _add_proxy(db_session, proxy_addr, last_known_impl=old_impl, last_scanned_block=90)

    block = hex(95)
    tx = "0x" + "c" * 64

    upgrade_log = _make_log(
        proxy_addr,
        UPGRADED_TOPIC0,
        _topic_for(new_impl),
        block=block,
        tx=tx,
        log_index="0x0",
    )
    admin_log = _make_log(
        proxy_addr,
        ADMIN_CHANGED_TOPIC0,
        data=_admin_data(old_admin, new_admin),
        block=block,
        tx=tx,
        log_index="0x1",
    )

    def rpc_side_effect(url, method, params, *, chain_id=None):
        if method == "eth_blockNumber":
            return hex(100)
        if method == "eth_getLogs":
            return [upgrade_log, admin_log]
        return None

    mock_rpc.side_effect = rpc_side_effect

    events = scan_for_upgrades(db_session, "http://localhost:8545")

    assert len(events) == 2

    upgraded_evt = next(e for e in events if e.event_type == "upgraded")
    admin_evt = next(e for e in events if e.event_type == "admin_changed")

    assert upgraded_evt.new_implementation == new_impl
    assert upgraded_evt.old_implementation == old_impl
    assert upgraded_evt.tx_hash == tx

    assert admin_evt.new_implementation == new_admin
    assert admin_evt.old_implementation == new_impl  # after Upgraded changed last_known_impl
    assert admin_evt.tx_hash == tx


# ---------------------------------------------------------------------------
# 16. test_rapid_successive_upgrades
# ---------------------------------------------------------------------------


@patch("services.monitoring.proxy_watcher.rpc_request")
def test_rapid_successive_upgrades(mock_rpc, db_session):
    """Proxy upgraded at block N, then again at block N+1. Both events
    should be detected and the implementation chain should be correct."""
    proxy_addr = ADDR(1)
    old_impl = ADDR(10)
    impl_v2 = ADDR(11)
    impl_v3 = ADDR(12)
    proxy = _add_proxy(db_session, proxy_addr, last_known_impl=old_impl, last_scanned_block=90)

    log1 = _make_log(
        proxy_addr,
        UPGRADED_TOPIC0,
        _topic_for(impl_v2),
        block=hex(100),
        tx="0x" + "d" * 64,
        log_index="0x0",
    )
    log2 = _make_log(
        proxy_addr,
        UPGRADED_TOPIC0,
        _topic_for(impl_v3),
        block=hex(101),
        tx="0x" + "e" * 64,
        log_index="0x0",
    )

    def rpc_side_effect(url, method, params, *, chain_id=None):
        if method == "eth_blockNumber":
            return hex(105)
        if method == "eth_getLogs":
            return [log1, log2]
        return None

    mock_rpc.side_effect = rpc_side_effect

    events = scan_for_upgrades(db_session, "http://localhost:8545")

    assert len(events) == 2

    assert events[0].block_number == 100
    assert events[0].old_implementation == old_impl
    assert events[0].new_implementation == impl_v2

    assert events[1].block_number == 101
    assert events[1].old_implementation == impl_v2
    assert events[1].new_implementation == impl_v3

    db_session.refresh(proxy)
    assert proxy.last_known_implementation == impl_v3
    assert proxy.last_scanned_block == 105


# ===========================================================================
# Storage slot polling tests
# ===========================================================================


# ---------------------------------------------------------------------------
# 17. test_poll_no_polling_proxies
# ---------------------------------------------------------------------------


@patch("services.monitoring.proxy_watcher.rpc_batch_request")
def test_poll_no_polling_proxies(mock_batch, db_session):
    """poll_for_upgrades with no needs_polling=True proxies returns empty list
    and makes no RPC calls."""
    # Add a proxy that does NOT need polling
    _add_proxy(db_session, ADDR(1), last_known_impl=ADDR(10), needs_polling=False)

    result = poll_for_upgrades(db_session, "http://localhost:8545")

    assert result == []
    mock_batch.assert_not_called()


# ---------------------------------------------------------------------------
# 18. test_poll_detects_implementation_change
# ---------------------------------------------------------------------------


@patch("services.monitoring.proxy_watcher.rpc_batch_request")
def test_poll_detects_implementation_change(mock_batch, db_session):
    """Storage slot polling detects when the implementation address changes.

    Mocks the batch RPC to return a new implementation via the EIP-1967 slot
    (first discovery method). Verifies a ProxyUpgradeEvent with event_type
    'storage_poll' is created, the proxy row is updated, and the proxy type
    is learned for future fast-path resolution.
    """
    old_impl = ADDR(10)
    new_impl = ADDR(11)
    proxy = _add_proxy(db_session, ADDR(1), last_known_impl=old_impl, needs_polling=True)

    storage_value = "0x" + "0" * 24 + new_impl[2:]
    zero = "0x" + "0" * 64
    # Unknown type → 8 discovery calls; EIP-1967 slot (index 0) hits
    mock_batch.return_value = [storage_value] + [zero] * 7

    events = poll_for_upgrades(db_session, "http://localhost:8545")

    assert len(events) == 1
    evt = events[0]
    assert evt.event_type == "storage_poll"
    assert evt.old_implementation == old_impl
    assert evt.new_implementation == new_impl.lower()
    assert evt.watched_proxy_id == proxy.id

    # Proxy row should be updated with new implementation and learned type
    db_session.refresh(proxy)
    assert proxy.last_known_implementation == new_impl.lower()
    assert proxy.proxy_type == "eip1967"


# ---------------------------------------------------------------------------
# 19. test_poll_no_change_no_event
# ---------------------------------------------------------------------------


@patch("services.monitoring.proxy_watcher.rpc_batch_request")
def test_poll_no_change_no_event(mock_batch, db_session):
    """When the storage slot returns the same implementation, no event is created."""
    same_impl = ADDR(10)
    _add_proxy(db_session, ADDR(1), last_known_impl=same_impl, needs_polling=True)

    storage_value = "0x" + "0" * 24 + same_impl[2:]
    zero = "0x" + "0" * 64
    mock_batch.return_value = [storage_value] + [zero] * 7

    events = poll_for_upgrades(db_session, "http://localhost:8545")

    assert events == []


# ---------------------------------------------------------------------------
# 20. test_poll_ignores_non_polling_proxies
# ---------------------------------------------------------------------------


@patch("services.monitoring.proxy_watcher.rpc_batch_request")
def test_poll_ignores_non_polling_proxies(mock_batch, db_session):
    """Only proxies with needs_polling=True are polled. A non-polling proxy
    with a changed implementation should NOT produce an event."""
    old_impl = ADDR(10)
    new_impl = ADDR(11)

    polling_proxy = _add_proxy(db_session, ADDR(1), last_known_impl=old_impl, needs_polling=True)
    _add_proxy(db_session, ADDR(2), last_known_impl=old_impl, needs_polling=False)

    storage_value = "0x" + "0" * 24 + new_impl[2:]
    zero = "0x" + "0" * 64
    # Only the polling proxy is in the batch (8 discovery calls)
    mock_batch.return_value = [storage_value] + [zero] * 7

    events = poll_for_upgrades(db_session, "http://localhost:8545")

    # Only the polling proxy should produce an event
    assert len(events) == 1
    assert events[0].watched_proxy_id == polling_proxy.id


# ---------------------------------------------------------------------------
# 21. test_poll_handles_rpc_failure_gracefully
# ---------------------------------------------------------------------------


@patch("services.monitoring.proxy_watcher.rpc_batch_request")
def test_poll_handles_rpc_failure_gracefully(mock_batch, db_session):
    """If the batch RPC request raises an exception, poll_for_upgrades returns
    an empty list without crashing."""
    _add_proxy(db_session, ADDR(1), last_known_impl=ADDR(10), needs_polling=True)

    mock_batch.side_effect = ConnectionError("RPC node timeout")

    events = poll_for_upgrades(db_session, "http://localhost:8545")

    assert events == []


# ---------------------------------------------------------------------------
# 22. test_poll_skips_none_implementation
# ---------------------------------------------------------------------------


@patch("services.monitoring.proxy_watcher.rpc_batch_request")
def test_poll_skips_none_implementation(mock_batch, db_session):
    """When all discovery methods return zero, no event is created and
    polling is disabled for the proxy."""
    proxy = _add_proxy(db_session, ADDR(1), last_known_impl=ADDR(10), needs_polling=True)

    zero = "0x" + "0" * 64
    mock_batch.return_value = [zero] * 8

    events = poll_for_upgrades(db_session, "http://localhost:8545")

    assert events == []
    # Proxy should have polling disabled since no method resolved
    db_session.refresh(proxy)
    assert proxy.needs_polling is False


# ---------------------------------------------------------------------------
# 23. test_poll_resolves_non_eip1967_proxies
# ---------------------------------------------------------------------------


@patch("services.monitoring.proxy_watcher.rpc_batch_request")
def test_poll_resolves_non_eip1967_proxies(mock_batch, db_session):
    """Polling resolves implementation via getter calls when standard storage
    slots are empty — critical for GnosisSafe, Compound, and Synthetix proxies
    whose implementations live outside EIP-1967 slots.

    Discovery order: EIP-1967, EIP-1822, OZ, implementation(), masterCopy(),
                     comptrollerImplementation(), target(), Gnosis slot.
    Only comptrollerImplementation() (index 5) returns a valid address.
    """
    old_impl = ADDR(10)
    new_impl = ADDR(11)
    proxy = _add_proxy(db_session, ADDR(1), last_known_impl=old_impl, needs_polling=True)

    new_impl_padded = "0x" + "0" * 24 + new_impl[2:]
    zero = "0x" + "0" * 64

    # Slots return zero, implementation()/masterCopy() revert (None),
    # comptrollerImplementation() returns the address.
    mock_batch.return_value = [zero, zero, zero, None, None, new_impl_padded, None, zero]

    events = poll_for_upgrades(db_session, "http://localhost:8545")

    assert len(events) == 1
    assert events[0].event_type == "storage_poll"
    assert events[0].new_implementation == new_impl.lower()
    assert events[0].old_implementation == old_impl

    # Should have learned the compound type
    db_session.refresh(proxy)
    assert proxy.proxy_type == "compound"


# ---------------------------------------------------------------------------
# 24. test_resolve_falls_back_to_slot_zero
# ---------------------------------------------------------------------------


@patch("services.monitoring.proxy_watcher.rpc_request")
def test_resolve_falls_back_to_slot_zero(mock_rpc):
    """When all standard slots and getters fail, resolve_current_implementation
    falls back to slot 0 (GnosisSafe pattern)."""
    gnosis_impl = ADDR(99)
    gnosis_padded = "0x" + "0" * 24 + gnosis_impl[2:]
    zero = "0x" + "0" * 64

    def rpc_side_effect(rpc_url, method, params, *, chain_id=None):
        if method == "eth_getStorageAt":
            slot = params[1]
            # Only slot 0 has a value
            if slot == "0x0":
                return gnosis_padded
            return zero
        if method == "eth_call":
            raise RuntimeError("revert")
        return zero

    mock_rpc.side_effect = rpc_side_effect

    result = resolve_current_implementation(ADDR(1), "http://localhost:8545")
    assert result == gnosis_impl.lower()


# ---------------------------------------------------------------------------
# 25. test_resolve_historical_block_uses_eip1967_only
# ---------------------------------------------------------------------------


@patch("services.monitoring.proxy_watcher.rpc_request")
def test_resolve_historical_block_uses_eip1967_only(mock_rpc):
    """When block != 'latest', only the EIP-1967 slot is read (fast path
    for Aave V2 Upgraded(uint256) in the event scan loop)."""
    impl_addr = ADDR(42)
    mock_rpc.return_value = "0x" + "0" * 24 + impl_addr[2:]

    result = resolve_current_implementation(ADDR(1), "http://localhost:8545", block="0x100")

    assert result == impl_addr.lower()
    # Should be exactly one call — only EIP-1967 slot at the specific block
    mock_rpc.assert_called_once_with(
        "http://localhost:8545",
        "eth_getStorageAt",
        [ADDR(1), EIP1967_IMPL_SLOT, "0x100"],
        chain_id=None,
    )


# ---------------------------------------------------------------------------
# 26. test_resolve_with_proxy_type_dispatches_directly
# ---------------------------------------------------------------------------


@patch("services.monitoring.proxy_watcher.rpc_request")
def test_resolve_with_proxy_type_dispatches_directly(mock_rpc):
    """When proxy_type is provided, resolve_current_implementation makes
    exactly 1 RPC call — no fallback chain."""
    impl_addr = ADDR(55)
    padded = "0x" + "0" * 24 + impl_addr[2:]
    mock_rpc.return_value = padded

    # Each type should result in exactly 1 call to the right method
    cases = [
        ("eip1967", "eth_getStorageAt"),
        ("eip1822", "eth_getStorageAt"),
        ("oz_legacy", "eth_getStorageAt"),
        ("gnosis_safe", "eth_getStorageAt"),
        ("custom", "eth_call"),
        ("compound", "eth_call"),
        ("synthetix", "eth_call"),
    ]

    for proxy_type, expected_method in cases:
        mock_rpc.reset_mock()
        result = resolve_current_implementation(
            ADDR(1),
            "http://localhost:8545",
            proxy_type=proxy_type,
        )
        assert result == impl_addr.lower(), f"{proxy_type}: expected {impl_addr}"
        assert mock_rpc.call_count == 1, f"{proxy_type}: expected 1 RPC call, got {mock_rpc.call_count}"
        actual_method = mock_rpc.call_args[0][1]
        assert actual_method == expected_method, f"{proxy_type}: expected {expected_method}, got {actual_method}"


# ---------------------------------------------------------------------------
# 27. test_poll_uses_proxy_type_for_resolution
# ---------------------------------------------------------------------------


@patch("services.monitoring.proxy_watcher.rpc_batch_request")
def test_poll_uses_proxy_type_for_resolution(mock_batch, db_session):
    """poll_for_upgrades dispatches directly for known proxy_type — single
    targeted call in the batch, not the full discovery chain."""
    old_impl = ADDR(10)
    new_impl = ADDR(11)
    proxy = _add_proxy(db_session, ADDR(1), last_known_impl=old_impl, needs_polling=True)
    proxy.proxy_type = "compound"
    db_session.commit()

    new_impl_padded = "0x" + "0" * 24 + new_impl[2:]
    # Known type → single call in batch
    mock_batch.return_value = [new_impl_padded]

    events = poll_for_upgrades(db_session, "http://localhost:8545")

    assert len(events) == 1
    assert events[0].new_implementation == new_impl.lower()

    # Batch should contain exactly 1 call (direct dispatch for compound type)
    batch_calls = mock_batch.call_args[0][1]
    assert len(batch_calls) == 1
    assert batch_calls[0][0] == "eth_call", "Expected direct eth_call dispatch for compound type"
