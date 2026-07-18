"""Test proxy upgrade detection across all known proxy patterns.

Each test simulates a realistic eth_getLogs response from a specific proxy
type and runs it through the full scan_for_upgrades pipeline to verify
detection. Tests that require storage slot polling (rather than event-based
detection) are grouped in TestPollingRequired.

Proxy types tested:
  SUPPORTED (event-based detection):
    1. EIP-1967 TransparentProxy — Upgraded(address indexed impl)
    2. EIP-1967 UUPS — same Upgraded event
    3. EIP-1967 BeaconProxy — BeaconUpgraded(address indexed beacon)
    4. OZ Legacy (USDC-style) — Upgraded(address) with impl in data, not topics
    5. AdminChanged — addresses in data (standard)
    6. AdminChanged — addresses in indexed topics (variant)
    7. EIP-1167 minimal proxy — immutable clone, no upgrade possible

  POLLING REQUIRED (no events emitted — requires storage slot polling):
    8. Custom proxy — proprietary ImplementationUpdated event
    9. Silent upgrade — SSTORE to impl slot with no event emission
"""

from __future__ import annotations

import os
import sys
import uuid
from pathlib import Path
from unittest.mock import patch

import pytest
from sqlalchemy import create_engine, text
from sqlalchemy.orm import Session as SASession

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from db.models import Base, ProxyUpgradeEvent, WatchedProxy
from services.discovery.upgrade_history import (
    ADMIN_CHANGED_TOPIC0,
    BEACON_UPGRADED_TOPIC0,
    UPGRADED_TOPIC0,
)
from services.monitoring.proxy_watcher import poll_for_upgrades, scan_for_upgrades

DATABASE_URL = os.environ.get("TEST_DATABASE_URL", "")


def _can_connect() -> bool:
    if not DATABASE_URL:
        return False
    try:
        engine = create_engine(DATABASE_URL)
        with engine.connect() as conn:
            conn.execute(text("SELECT 1"))
        engine.dispose()
        return True
    except Exception:
        return False


pytestmark = pytest.mark.skipif(not _can_connect(), reason="PostgreSQL not available")

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

PROXY_ADDR = "0x1111111111111111111111111111111111111111"
IMPL_OLD = "0xaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
IMPL_NEW = "0xbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"
BEACON_ADDR = "0xcccccccccccccccccccccccccccccccccccccccc"
ADMIN_OLD = "0x" + "d" * 40
ADMIN_NEW = "0xeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeee"
BLOCK_HEX = "0x100"
BLOCK_INT = 256
TX_HASH = "0xabcdef1234567890abcdef1234567890abcdef1234567890abcdef1234567890"


def _addr_to_topic(addr: str) -> str:
    """Pad a 20-byte address to a 32-byte topic."""
    return "0x" + "0" * 24 + addr[2:]


def _addr_to_data(addr: str) -> str:
    """ABI-encode a single address into log data."""
    return "0x" + "0" * 24 + addr[2:]


def _two_addrs_to_data(addr1: str, addr2: str) -> str:
    """ABI-encode two addresses into log data."""
    return "0x" + "0" * 24 + addr1[2:] + "0" * 24 + addr2[2:]


def _make_log(address: str, topics: list[str], data: str = "0x") -> dict:
    return {
        "address": address,
        "topics": topics,
        "data": data,
        "blockNumber": BLOCK_HEX,
        "transactionHash": TX_HASH,
        "logIndex": "0x0",
    }


@pytest.fixture
def db_session():
    """PostgreSQL database session with a pre-registered watched proxy."""
    engine = create_engine(DATABASE_URL)
    Base.metadata.create_all(engine)

    session = SASession(engine, expire_on_commit=False)
    proxy = WatchedProxy(
        id=uuid.uuid4(),
        proxy_address=PROXY_ADDR,
        chain="ethereum",
        label="test",
        last_known_implementation=IMPL_OLD,
        last_scanned_block=BLOCK_INT - 10,
    )
    session.add(proxy)
    session.commit()

    yield session, proxy

    session.rollback()
    session.query(ProxyUpgradeEvent).delete()
    session.query(WatchedProxy).delete()
    session.commit()
    session.close()
    engine.dispose()


def _run_scan_with_logs(session, logs: list[dict]) -> list[ProxyUpgradeEvent]:
    """Run scan_for_upgrades with mocked RPC returning the given logs."""

    def mock_rpc(rpc_url, method, params, *, chain_id=None):
        if method == "eth_blockNumber":
            return hex(BLOCK_INT + 5)
        if method == "eth_getLogs":
            return logs
        return None

    with patch("services.monitoring.proxy_watcher.rpc_request", side_effect=mock_rpc):
        return scan_for_upgrades(session, "http://fake-rpc")


# ===========================================================================
# SUPPORTED PROXY TYPES — these should all be detected
# ===========================================================================


class TestSupportedProxyTypes:
    """Proxy types the scanner correctly detects."""

    def test_eip1967_transparent_proxy(self, db_session):
        """EIP-1967 TransparentUpgradeableProxy: Upgraded(address indexed implementation).

        The most common modern proxy pattern. Implementation address is in topics[1].
        """
        session, proxy = db_session
        logs = [_make_log(PROXY_ADDR, [UPGRADED_TOPIC0, _addr_to_topic(IMPL_NEW)])]

        events = _run_scan_with_logs(session, logs)

        assert len(events) == 1
        assert events[0].event_type == "upgraded"
        assert events[0].new_implementation.lower() == IMPL_NEW
        assert events[0].old_implementation is not None
        assert events[0].old_implementation.lower() == IMPL_OLD
        assert events[0].block_number == BLOCK_INT

    def test_eip1967_uups_proxy(self, db_session):
        """EIP-1967 UUPS proxy: emits the same Upgraded(address indexed implementation).

        Identical event format to TransparentProxy — the upgrade logic lives
        in the implementation contract rather than the proxy, but the event
        is the same.
        """
        session, proxy = db_session
        logs = [_make_log(PROXY_ADDR, [UPGRADED_TOPIC0, _addr_to_topic(IMPL_NEW)])]

        events = _run_scan_with_logs(session, logs)

        assert len(events) == 1
        assert events[0].event_type == "upgraded"
        assert events[0].new_implementation.lower() == IMPL_NEW

    def test_eip1967_beacon_proxy(self, db_session):
        """EIP-1967 BeaconProxy: BeaconUpgraded(address indexed beacon).

        The beacon address is in topics[1]. The scanner records the beacon
        address as the new_implementation.
        """
        session, proxy = db_session
        logs = [_make_log(PROXY_ADDR, [BEACON_UPGRADED_TOPIC0, _addr_to_topic(BEACON_ADDR)])]

        events = _run_scan_with_logs(session, logs)

        assert len(events) == 1
        assert events[0].event_type == "beacon_upgraded"
        assert events[0].new_implementation.lower() == BEACON_ADDR

    def test_oz_legacy_upgraded_impl_in_data(self, db_session):
        """OZ legacy proxy (e.g. USDC FiatTokenProxy): Upgraded(address) with
        the implementation as a non-indexed parameter in log data.

        Same topic0 as EIP-1967 Upgraded, but only 1 topic (no indexed param).
        The implementation address is ABI-encoded in the data field.
        """
        session, proxy = db_session
        logs = [_make_log(PROXY_ADDR, [UPGRADED_TOPIC0], data=_addr_to_data(IMPL_NEW))]

        events = _run_scan_with_logs(session, logs)

        assert len(events) == 1
        assert events[0].event_type == "upgraded"
        assert events[0].new_implementation.lower() == IMPL_NEW

    def test_admin_changed_data(self, db_session):
        """AdminChanged(address previousAdmin, address newAdmin) — standard format.

        Both addresses are non-indexed, stored in log data.
        """
        session, proxy = db_session
        logs = [
            _make_log(
                PROXY_ADDR,
                [ADMIN_CHANGED_TOPIC0],
                data=_two_addrs_to_data(ADMIN_OLD, ADMIN_NEW),
            )
        ]

        events = _run_scan_with_logs(session, logs)

        assert len(events) == 1
        assert events[0].event_type == "admin_changed"
        assert events[0].new_implementation.lower() == ADMIN_NEW

    def test_admin_changed_indexed_topics(self, db_session):
        """AdminChanged with addresses as indexed topics (variant encoding).

        Some proxy implementations index the admin addresses instead of
        putting them in data.
        """
        session, proxy = db_session
        logs = [
            _make_log(
                PROXY_ADDR,
                [ADMIN_CHANGED_TOPIC0, _addr_to_topic(ADMIN_OLD), _addr_to_topic(ADMIN_NEW)],
            )
        ]

        events = _run_scan_with_logs(session, logs)

        assert len(events) == 1
        assert events[0].event_type == "admin_changed"
        assert events[0].new_implementation.lower() == ADMIN_NEW

    def test_beacon_upgraded_in_data(self, db_session):
        """BeaconUpgraded with beacon address in data instead of topics.

        Fallback encoding where the beacon is a non-indexed parameter.
        """
        session, proxy = db_session
        logs = [
            _make_log(
                PROXY_ADDR,
                [BEACON_UPGRADED_TOPIC0],
                data=_addr_to_data(BEACON_ADDR),
            )
        ]

        events = _run_scan_with_logs(session, logs)

        assert len(events) == 1
        assert events[0].event_type == "beacon_upgraded"
        assert events[0].new_implementation.lower() == BEACON_ADDR

    def test_multiple_upgrades_in_sequence(self, db_session):
        """Two Upgraded events in one scan — verify both are detected and
        old_implementation chains correctly (second event's old_impl equals
        the first event's new_impl)."""
        session, proxy = db_session
        impl_v2 = "0x" + "b" * 40
        impl_v3 = "0x" + "c" * 40

        log1 = _make_log(
            PROXY_ADDR,
            [UPGRADED_TOPIC0, _addr_to_topic(impl_v2)],
        )
        # Second event at a later block
        log2 = {
            **_make_log(PROXY_ADDR, [UPGRADED_TOPIC0, _addr_to_topic(impl_v3)]),
            "blockNumber": hex(BLOCK_INT + 1),
            "transactionHash": "0x" + "f" * 64,
            "logIndex": "0x0",
        }

        events = _run_scan_with_logs(session, [log1, log2])

        assert len(events) == 2
        assert events[0].event_type == "upgraded"
        assert events[0].old_implementation is not None
        assert events[0].old_implementation.lower() == IMPL_OLD
        assert events[0].new_implementation.lower() == impl_v2

        assert events[1].event_type == "upgraded"
        assert events[1].old_implementation is not None
        assert events[1].old_implementation.lower() == impl_v2
        assert events[1].new_implementation.lower() == impl_v3

    def test_upgraded_event_with_extra_topics(self, db_session):
        """Some contracts emit Upgraded with additional indexed parameters beyond
        the standard single `address indexed implementation`. For example, a
        contract might emit Upgraded(address indexed implementation, uint256 indexed version).

        The scanner should still correctly parse topics[1] as the implementation
        address regardless of extra topics."""
        session, proxy = db_session
        extra_topic = "0x" + "0" * 63 + "2"  # e.g., version=2

        log = {
            "address": PROXY_ADDR,
            "topics": [UPGRADED_TOPIC0, _addr_to_topic(IMPL_NEW), extra_topic],
            "data": "0x",
            "blockNumber": BLOCK_HEX,
            "transactionHash": TX_HASH,
            "logIndex": "0x0",
        }

        events = _run_scan_with_logs(session, [log])

        assert len(events) == 1
        assert events[0].event_type == "upgraded"
        assert events[0].new_implementation.lower() == IMPL_NEW

    def test_mixed_event_types_in_one_scan(self, db_session):
        """Upgraded + AdminChanged + BeaconUpgraded all in one scan for the
        same proxy. All three events should be detected."""
        session, proxy = db_session

        upgraded_log = _make_log(
            PROXY_ADDR,
            [UPGRADED_TOPIC0, _addr_to_topic(IMPL_NEW)],
        )
        admin_log = {
            **_make_log(
                PROXY_ADDR,
                [ADMIN_CHANGED_TOPIC0],
                data=_two_addrs_to_data(ADMIN_OLD, ADMIN_NEW),
            ),
            "logIndex": "0x1",
        }
        beacon_log = {
            **_make_log(
                PROXY_ADDR,
                [BEACON_UPGRADED_TOPIC0, _addr_to_topic(BEACON_ADDR)],
            ),
            "logIndex": "0x2",
        }

        events = _run_scan_with_logs(session, [upgraded_log, admin_log, beacon_log])

        assert len(events) == 3
        types = {e.event_type for e in events}
        assert types == {"upgraded", "admin_changed", "beacon_upgraded"}

    def test_gnosis_safe_master_copy(self, db_session):
        """GnosisSafe ChangedMasterCopy(address) — non-indexed address in data."""
        session, proxy = db_session
        # keccak256("ChangedMasterCopy(address)")
        GNOSIS_TOPIC0 = "0x75e41bc35ff1bf14d81d1d2f649c0084a0f974f9289c803ec9898eeec4c8d0b8"
        logs = [_make_log(PROXY_ADDR, [GNOSIS_TOPIC0], data=_addr_to_data(IMPL_NEW))]

        events = _run_scan_with_logs(session, logs)

        assert len(events) == 1
        assert events[0].event_type == "changed_master_copy"
        assert events[0].new_implementation.lower() == IMPL_NEW

    def test_compound_new_implementation(self, db_session):
        """Compound NewImplementation(address,address) — two addresses in data."""
        session, proxy = db_session
        # keccak256("NewImplementation(address,address)")
        COMPOUND_TOPIC0 = "0xd604de94d45953f9138079ec1b82d533cb2160c906d1076d1f7ed54befbca97a"
        log = _make_log(PROXY_ADDR, [COMPOUND_TOPIC0], data=_two_addrs_to_data(IMPL_OLD, IMPL_NEW))

        events = _run_scan_with_logs(session, [log])

        assert len(events) == 1
        assert events[0].event_type == "new_implementation"
        assert events[0].new_implementation.lower() == IMPL_NEW

    def test_compound_new_pending_implementation(self, db_session):
        """Compound NewPendingImplementation(address,address) — two-step upgrade."""
        session, proxy = db_session
        # keccak256("NewPendingImplementation(address,address)")
        COMPOUND_PENDING_TOPIC0 = "0xe945ccee5d701fc83f9b8aa8ca94ea4219ec1fcbd4f4cab4f0ea57c5c3e1d815"
        log = _make_log(PROXY_ADDR, [COMPOUND_PENDING_TOPIC0], data=_two_addrs_to_data(IMPL_OLD, IMPL_NEW))

        events = _run_scan_with_logs(session, [log])

        assert len(events) == 1
        assert events[0].event_type == "new_pending_implementation"
        assert events[0].new_implementation.lower() == IMPL_NEW

    def test_synthetix_target_updated(self, db_session):
        """Synthetix TargetUpdated(address) — non-indexed address in data."""
        session, proxy = db_session
        # keccak256("TargetUpdated(address)")
        SYNTHETIX_TOPIC0 = "0x814250a3b8c79fcbe2ead2c131c952a278491c8f4322a79fe84b5040a810373e"
        log = _make_log(PROXY_ADDR, [SYNTHETIX_TOPIC0], data=_addr_to_data(IMPL_NEW))

        events = _run_scan_with_logs(session, [log])

        assert len(events) == 1
        assert events[0].event_type == "target_updated"
        assert events[0].new_implementation.lower() == IMPL_NEW

    def test_diamond_proxy_eip2535(self, db_session):
        """EIP-2535 Diamond proxy DiamondCut event with realistic ABI-encoded data.

        The data encodes: FacetCut[] (one Add facet), _init=0x0, _calldata=empty.
        """
        session, proxy = db_session
        DIAMOND_TOPIC0 = "0x8faa70878671ccd212d20771b795c50af8fd3ff6cf27f4bde57e5d4de0aeb673"

        facet = IMPL_NEW[2:]
        # Each ABI word is exactly 64 hex chars (32 bytes)
        data = "0x"
        data += "0" * 62 + "60"  # word 0: offset to FacetCut[] = 0x60 = 96 bytes
        data += "0" * 64  # word 1: _init = address(0)
        data += "0" * 60 + "0140"  # word 2: offset to _calldata
        # -- FacetCut[] at byte offset 96 (word 3) --
        data += "0" * 62 + "01"  # word 3: array length = 1
        data += "0" * 62 + "40"  # word 4: offset to entry[0] = 0x40 = 64 bytes from array start
        # -- FacetCut entry[0] at byte offset 96 + 32 = 128 --
        data += "0" * 24 + facet  # word 5: facetAddress
        data += "0" * 64  # word 6: action = 0 (Add)
        data += "0" * 62 + "60"  # word 7: offset to selectors
        data += "0" * 62 + "01"  # word 8: selectors length = 1
        data += "12345678" + "0" * 56  # word 9: one selector
        # -- _calldata --
        data += "0" * 64  # word 10: calldata length = 0

        log = _make_log(PROXY_ADDR, [DIAMOND_TOPIC0], data=data)
        events = _run_scan_with_logs(session, [log])

        assert len(events) == 1
        assert events[0].event_type == "diamond_cut"
        assert events[0].new_implementation.lower() == IMPL_NEW

    def test_aave_v2_upgraded_uint256(self, db_session):
        """Aave V2 Upgraded(uint256) — scanner reads impl from storage slot."""
        session, proxy = db_session

        AAVE_V2_TOPIC0 = "0x65a5e70879738a94a00f00947edae8111ae0aed9175ce342db680bf1e0fb87fc"
        log = _make_log(PROXY_ADDR, [AAVE_V2_TOPIC0], data="0x" + "0" * 63 + "3")

        def mock_rpc(rpc_url, method, params, *, chain_id=None):
            if method == "eth_blockNumber":
                return hex(BLOCK_INT + 5)
            if method == "eth_getLogs":
                return [log]
            if method == "eth_getStorageAt":
                return "0x" + "0" * 24 + IMPL_NEW[2:]
            return None

        with patch("services.monitoring.proxy_watcher.rpc_request", side_effect=mock_rpc):
            events = scan_for_upgrades(session, "http://fake-rpc")

        assert len(events) == 1
        assert events[0].event_type == "upgraded_revision"
        assert events[0].new_implementation.lower() == IMPL_NEW

    def test_eip1167_minimal_proxy(self, db_session):
        """EIP-1167 minimal proxy (clone): immutable, never upgrades.

        These are bytecode-level clones that delegate to a fixed address.
        No upgrade mechanism exists, so there's nothing to detect.
        Not a gap — working as intended.
        """
        session, proxy = db_session
        events = _run_scan_with_logs(session, [])
        assert len(events) == 0, "EIP-1167 clones don't upgrade (expected)"


# ===========================================================================
# POLLING REQUIRED — proxy types detected via storage slot polling
# ===========================================================================


class TestPollingRequired:
    """Proxy types that require the storage slot polling pipeline.

    These proxy types do not emit standard upgrade events that the
    event-based scanner can detect. They are flagged with needs_polling=True
    and detected by poll_for_upgrades which reads the EIP-1967 implementation
    storage slot directly via eth_getStorageAt.
    """

    def test_custom_proprietary_event_detected_by_polling(self, db_session):
        """Custom proxy with a proprietary upgrade event (unrecognized topic0).

        First verifies the event-based scanner ignores the unknown topic0,
        then verifies the storage slot poller catches the implementation change.
        """
        session, proxy = db_session

        # Step 1: event-based scanner ignores the custom event
        custom_topic = "0x1234567890abcdef1234567890abcdef1234567890abcdef1234567890abcdef"
        logs = [_make_log(PROXY_ADDR, [custom_topic, _addr_to_topic(IMPL_NEW)])]
        scan_events = _run_scan_with_logs(session, logs)
        assert len(scan_events) == 0, "Event scanner should ignore unknown topic0"

        # Step 2: polling pipeline catches the change
        proxy.needs_polling = True
        session.commit()

        storage_value = "0x" + "0" * 24 + IMPL_NEW[2:]
        zero = "0x" + "0" * 64
        with patch("services.monitoring.proxy_watcher.rpc_batch_request", return_value=[storage_value] + [zero] * 7):
            poll_events = poll_for_upgrades(session, "http://fake-rpc")

        assert len(poll_events) == 1
        assert poll_events[0].event_type == "storage_poll"
        assert poll_events[0].new_implementation.lower() == IMPL_NEW
        assert poll_events[0].old_implementation == IMPL_OLD

    def test_silent_upgrade_detected_by_polling(self, db_session):
        """Proxy that upgrades via raw SSTORE with no event emission.

        The event-based scanner has nothing to find (no logs). The storage
        slot poller reads the EIP-1967 slot directly and detects the change.
        """
        session, proxy = db_session

        # Re-create the proxy with needs_polling=True
        proxy.needs_polling = True
        session.commit()

        # Mock batch to return new impl via EIP-1967 slot (first discovery method)
        storage_value = "0x" + "0" * 24 + IMPL_NEW[2:]
        zero = "0x" + "0" * 64

        with patch("services.monitoring.proxy_watcher.rpc_batch_request", return_value=[storage_value] + [zero] * 7):
            events = poll_for_upgrades(session, "http://fake-rpc")

        assert len(events) == 1
        assert events[0].event_type == "storage_poll"
        assert events[0].new_implementation.lower() == IMPL_NEW
