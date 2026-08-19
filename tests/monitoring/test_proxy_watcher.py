"""Unit tests for proxy implementation resolution.

Covers ``resolve_current_implementation`` with real and empty slots, the
priority fallback chain, the historical-block fast path, and known-type
direct dispatch. All tests run without live services (no RPC, no database).
"""

from __future__ import annotations

from unittest.mock import call, patch

from services.monitoring.proxy_watcher import resolve_current_implementation
from tests.conftest import ADDR

EIP1967_IMPL_SLOT = "0x360894a13ba1a3210667c828492db98dca3e2076cc3735a920a3ca505d382bbc"


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


@patch("services.monitoring.proxy_watcher.rpc_request")
def test_resolve_implementation_empty_slot(mock_rpc):
    """Returns None for zero-filled slot (no implementation set)."""
    mock_rpc.return_value = "0x" + "0" * 64

    result = resolve_current_implementation(ADDR(1), "http://localhost:8545")
    assert result is None


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


@patch("services.monitoring.proxy_watcher.rpc_request")
def test_resolve_historical_block_uses_eip1967_only(mock_rpc):
    """When block != 'latest', only the EIP-1967 slot is read (fast path
    for Aave V2 Upgraded(uint256))."""
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
