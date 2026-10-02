"""W6-3: an ``UPGRADE_INTERFACE_VERSION()`` answer alone no longer selects 'proxy_admin'.

Every OZ-v5 UUPS proxy answers it through the implementation, so proxies were typed as terminal proxy admins and
the walk stopped before the real upgrade authority. UIV + nonzero slot or + proxiableUUID is 'contract'; UIV +
zero slot + owner() is 'proxy_admin'; an unreadable discriminator is 'contract' + had_error.
"""

from __future__ import annotations

import pytest

from services.resolution import tracking
from services.resolution.tracking import _classify_uncached, _classify_uncached_batched
from tests.support.isolation import _isolated_classify_cache  # noqa: F401  (fixture, registered by import)

PROXY = "0x" + "8f" * 20  # stands in for the KING proxy 0x8f08b704...
IMPL = "0x" + "1c" * 20  # its implementation
OWNER = "0x" + "a0" * 20  # stands in for 0xa000244b... (the real authority)

_ZERO_WORD = "0x" + "0" * 64


def _uint(n: int) -> str:
    return "0x" + format(n, "x").rjust(64, "0")


def _addr_word(a: str) -> str:
    return "0x" + a[2:].lower().rjust(64, "0")


def _string_word(s: str) -> str:
    raw = s.encode()
    pad = (32 - (len(raw) % 32)) % 32
    return "0x" + format(32, "064x") + format(len(raw), "064x") + raw.hex() + "00" * pad


def _wire(monkeypatch, probe_map, *, storage=_ZERO_WORD, storage_raises=False, batched: bool = True):
    """Missing signatures return "0x" so absent probes don't set had_error."""

    def _outcome(signature: str) -> str:
        return probe_map.get(signature, "0x")

    def _fake_eth_call_raw(_rpc_url, _addr, signature, _block, chain_id=None):
        raw = _outcome(signature)
        if raw == "revert":
            raise RuntimeError("execution reverted")
        if raw == "transport":
            raise RuntimeError("connection reset by peer")
        return raw

    def _fake_batch_with_status(_rpc_url, calls, chain_id=None):
        out = []
        for sig, _abi in tracking._CLASSIFY_PROBE_SIGS:
            raw = _outcome(sig)
            out.append((None, True) if raw in ("revert", "transport") else (raw, False))
        return out

    def _fake_storage(*_a, **_k):
        if storage_raises:
            raise RuntimeError("read timed out")
        return storage

    monkeypatch.setattr(tracking, "_get_code", lambda *_a, **_k: "0x6000")
    monkeypatch.setattr(tracking, "type_authority_contract", lambda *_a, **_k: {})
    monkeypatch.setattr(tracking, "_eth_call_raw", _fake_eth_call_raw)
    monkeypatch.setattr(tracking, "_get_storage_at", _fake_storage)
    monkeypatch.setattr(tracking, "_rpc_batch_request_with_status", _fake_batch_with_status)
    del batched


# The KING-proxy shape at block 25619159.
_UUPS_PROXY = {"UPGRADE_INTERFACE_VERSION()": _string_word("5.0.0")}


@pytest.mark.parametrize("batched", [False, True])
def test_uups_proxy_is_a_contract_not_a_proxy_admin(monkeypatch, batched):
    """Non-terminal, so the walk continues."""
    _wire(monkeypatch, _UUPS_PROXY, storage=_addr_word(IMPL))
    fn = _classify_uncached_batched if batched else _classify_uncached
    kind, details, had_error = fn("https://rpc", PROXY, "latest")
    assert kind == "contract"
    assert details["erc1967_implementation"] == IMPL
    assert details["upgrade_interface_version"] == "5.0.0"
    assert had_error is False


@pytest.mark.parametrize("batched", [False, True])
def test_bare_uups_implementation_is_a_contract(monkeypatch, batched):
    probe_map = dict(_UUPS_PROXY)
    probe_map["proxiableUUID()"] = "0x360894a13ba1a3210667c828492db98dca3e2076cc3735a920a3ca505d382bbc"
    _wire(monkeypatch, probe_map, storage=_ZERO_WORD)
    fn = _classify_uncached_batched if batched else _classify_uncached
    kind, details, had_error = fn("https://rpc", PROXY, "latest")
    assert kind == "contract"
    assert details["uups_implementation"] is True
    assert had_error is False


@pytest.mark.parametrize("batched", [False, True])
def test_slot_read_failure_withholds_the_verdict_uncached(monkeypatch, batched):
    probe_map = dict(_UUPS_PROXY)
    probe_map["owner()"] = _addr_word(OWNER)
    _wire(monkeypatch, probe_map, storage_raises=True)
    fn = _classify_uncached_batched if batched else _classify_uncached
    kind, details, had_error = fn("https://rpc", PROXY, "latest")
    assert kind == "contract"
    assert had_error is True
    assert "erc1967_implementation" not in details


def test_walk_continues_through_a_uups_proxy_to_the_real_authority(monkeypatch):
    """A UUPS proxy typed 'contract' lets the walk reach the real owner through the implementation."""
    from services.clients.rpc import EthCallResult, selector
    from workers import policy_worker as pw

    owner_selector = selector("owner()")

    def _fake_batch(rpc_url, calls, block_tag="latest", *, chain_id=None, headers=None):
        out = []
        for call in calls:
            if call["to"].lower() == PROXY and call["data"] == owner_selector:
                out.append(EthCallResult(True, _addr_word(OWNER), None, None))
            else:
                out.append(EthCallResult(False, "0x", None, "execution reverted"))
        return out

    monkeypatch.setattr(tracking, "_eth_call_batch", _fake_batch)
    monkeypatch.setattr(
        pw, "classify_resolved_address_with_status", lambda *_a, **_k: ("eoa", {"address": OWNER}, True)
    )

    from services.governance.principals import resolve_terminal_principal

    resolver = pw._make_terminal_controller_resolver("https://rpc", chain_id=1)
    assert resolver is not None
    record = resolve_terminal_principal(PROXY, "contract", resolve_controllers=resolver)
    assert record["terminal"] is True
    assert record["resolved_type"] == "eoa"
    assert record["address"] == OWNER
    assert record["chain"] == [PROXY, OWNER]
