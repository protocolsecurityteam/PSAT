"""Negative-control discipline for the duck-typed classifier (W6-2).

A catch-all fallback answers every selector: 0x008702e6 answered ``getMinDelay()`` and ``0xdeadbeef`` alike and
was published as a timelock with ``delay=1``. A nonsense selector must revert before any duck-typed kind is
published; an answer means plain ``contract``, a transport error withholds the kind uncached.
"""

from __future__ import annotations

import pytest

from services.clients.rpc import EthCallResult, selector
from services.resolution import tracking
from services.resolution.tracking import (
    _classify_uncached,
    _classify_uncached_batched,
    read_contract_controllers,
)

ADDR = "0x" + "ab" * 20
OWNER = "0x" + "44" * 20


@pytest.fixture(autouse=True)
def _isolated_classify_cache():
    tracking.clear_classify_cache()
    yield
    tracking.clear_classify_cache()


def _uint(n: int) -> str:
    return "0x" + format(n, "x").rjust(64, "0")


def _addr_word(a: str) -> str:
    return "0x" + a[2:].lower().rjust(64, "0")


def _wire(monkeypatch, probe_map, *, batched: bool):
    """Missing signatures revert, like an unimplemented selector."""

    def _outcome(signature: str) -> str:
        return probe_map.get(signature, "revert")

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

    monkeypatch.setattr(tracking, "_get_code", lambda *_a, **_k: "0x6000")
    monkeypatch.setattr(tracking, "type_authority_contract", lambda *_a, **_k: {})
    monkeypatch.setattr(tracking, "_eth_call_raw", _fake_eth_call_raw)
    # classify_resolved_address_with_status always dispatches through the batched path.
    del batched
    monkeypatch.setattr(tracking, "_rpc_batch_request_with_status", _fake_batch_with_status)


_CATCH_ALL = {
    "getOwners()": _uint(1),  # not a decodable address[] (offset 1) → safe arm skips
    "getThreshold()": _uint(1),
    "getMinDelay()": _uint(1),
    "delay()": _uint(1),
    "UPGRADE_INTERFACE_VERSION()": _uint(1),
    "owner()": _addr_word(ADDR),  # echoes an address, like the observed contract
    tracking._NEGATIVE_CONTROL_SIG: _uint(1),
}

_REAL_TIMELOCK = {
    "getMinDelay()": _uint(86400),
    "owner()": _addr_word(OWNER),
}


@pytest.mark.parametrize("batched", [False, True])
def test_catch_all_fallback_is_not_a_timelock(monkeypatch, batched):
    _wire(monkeypatch, _CATCH_ALL, batched=batched)
    fn = _classify_uncached_batched if batched else _classify_uncached
    kind, details, had_error = fn("https://rpc", ADDR, "latest")
    assert kind == "contract"
    assert details.get("duck_type_negative_control") == "failed"
    assert "delay" not in details
    assert had_error is False  # a definitive observation — cacheable


@pytest.mark.parametrize("batched", [False, True])
def test_real_timelock_with_reverting_control_stays_timelock(monkeypatch, batched):
    _wire(monkeypatch, _REAL_TIMELOCK, batched=batched)
    fn = _classify_uncached_batched if batched else _classify_uncached
    kind, details, _had_error = fn("https://rpc", ADDR, "latest")
    assert kind == "timelock"
    assert details["delay"] == 86400
    assert details["owner"] == OWNER


@pytest.mark.parametrize("batched", [False, True])
def test_catch_all_fallback_is_not_a_safe(monkeypatch, batched):
    owners_blob = "0x" + format(32, "064x") + format(1, "064x") + OWNER[2:].rjust(64, "0")
    probe_map = dict(_CATCH_ALL)
    probe_map["getOwners()"] = owners_blob
    _wire(monkeypatch, probe_map, batched=batched)
    fn = _classify_uncached_batched if batched else _classify_uncached
    kind, details, _had_error = fn("https://rpc", ADDR, "latest")
    assert kind == "contract"
    assert details.get("duck_type_negative_control") == "failed"
    assert "owners" not in details


@pytest.mark.parametrize("batched", [False, True])
def test_control_transport_error_withholds_concrete_type_uncached(monkeypatch, batched):
    """A control that couldn't be established is not a pass."""
    probe_map = dict(_REAL_TIMELOCK)
    probe_map[tracking._NEGATIVE_CONTROL_SIG] = "transport"
    _wire(monkeypatch, probe_map, batched=batched)
    fn = _classify_uncached_batched if batched else _classify_uncached
    kind, details, had_error = fn("https://rpc", ADDR, "latest")
    assert kind == "contract"
    assert had_error is True
    assert "duck_type_negative_control" not in details
    _kind, _details, cacheable = tracking.classify_resolved_address_with_status("https://rpc", ADDR)
    assert cacheable is False


@pytest.mark.parametrize("batched", [False, True])
def test_oversized_uint_return_is_not_a_delay(monkeypatch, batched):
    """A 64-byte blob is not a uint256 answer."""
    probe_map = {"getMinDelay()": _uint(1) + "ff" * 32}
    _wire(monkeypatch, probe_map, batched=batched)
    fn = _classify_uncached_batched if batched else _classify_uncached
    kind, details, _had_error = fn("https://rpc", ADDR, "latest")
    assert kind == "contract"
    assert "delay" not in details


def test_negative_control_probe_tristate(monkeypatch):
    outcomes = {}

    def _raw(_rpc_url, _addr, _sig, _block, chain_id=None):
        value = outcomes["value"]
        if isinstance(value, Exception):
            raise value
        return value

    monkeypatch.setattr(tracking, "_eth_call_raw", _raw)
    outcomes["value"] = _uint(1)
    assert tracking._negative_control_probe("https://rpc", ADDR, "latest") == "failed"
    outcomes["value"] = "0x"
    assert tracking._negative_control_probe("https://rpc", ADDR, "latest") == "passed"
    outcomes["value"] = RuntimeError("execution reverted: whatever")
    assert tracking._negative_control_probe("https://rpc", ADDR, "latest") == "passed"
    outcomes["value"] = RuntimeError("read timed out")
    assert tracking._negative_control_probe("https://rpc", ADDR, "latest") == "error"


# read_contract_controllers's control is a fourth call in the same batch.


def _controllers_stub(monkeypatch, answers):
    def _fake(rpc_url, calls, block_tag="latest", *, chain_id=None, headers=None):
        by_selector = {selector(sig): value for sig, value in answers.items()}
        out = []
        for call in calls:
            value = by_selector.get(call["data"], "revert")
            if value == "transport":
                out.append(EthCallResult(False, "0x", None, "connection reset"))
            elif value == "revert":
                out.append(EthCallResult(False, "0x", None, "execution reverted"))
            else:
                out.append(EthCallResult(True, value, None, None))
        return out

    monkeypatch.setattr(tracking, "_eth_call_batch", _fake)


def test_catch_all_fallback_yields_no_controller_set(monkeypatch):
    """Its owner() answer is not a witnessed control plane."""
    _controllers_stub(
        monkeypatch,
        {
            "owner()": _addr_word(OWNER),
            tracking._NEGATIVE_CONTROL_SIG: _uint(1),
        },
    )
    assert read_contract_controllers("https://rpc", ADDR) is None


def test_owner_with_reverting_control_is_witnessed(monkeypatch):
    _controllers_stub(monkeypatch, {"owner()": _addr_word(OWNER)})
    assert read_contract_controllers("https://rpc", ADDR) == [OWNER]


def test_control_transport_error_makes_set_indeterminate(monkeypatch):
    _controllers_stub(
        monkeypatch,
        {
            "owner()": _addr_word(OWNER),
            tracking._NEGATIVE_CONTROL_SIG: "transport",
        },
    )
    assert read_contract_controllers("https://rpc", ADDR) is None
