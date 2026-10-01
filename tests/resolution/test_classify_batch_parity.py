"""The batched classify path must preserve ``_PROBE_ERROR`` under partial failure and match the sequential path
byte-for-byte on every branch.
"""

from __future__ import annotations

import pytest

from services.resolution import tracking
from services.resolution.tracking import (
    _classify_uncached,
    _classify_uncached_batched,
)
from tests.support.isolation import _isolated_classify_cache  # noqa: F401  (fixture, registered by import)

ADDR_OWNER = "0x" + "11" * 20  # an "owner" address used in several mocks


def _abi_encode_address(addr: str) -> str:
    return "0x" + addr.lower().replace("0x", "").rjust(64, "0")


def _abi_encode_uint256(n: int) -> str:
    return "0x" + format(n, "x").rjust(64, "0")


def _abi_encode_address_array(addrs: list[str]) -> str:
    body = format(32, "064x")  # offset to data
    body += format(len(addrs), "064x")  # length
    for a in addrs:
        body += a.lower().replace("0x", "").rjust(64, "0")
    return "0x" + body


def _abi_encode_string(s: str) -> str:
    raw = s.encode("utf-8")
    pad = (32 - (len(raw) % 32)) % 32
    body = format(32, "064x") + format(len(raw), "064x")
    body += raw.hex() + ("00" * pad)
    return "0x" + body


def _probe_responses_for(scenario: str) -> dict[str, str]:
    """Missing selectors imply "0x"."""
    if scenario == "safe":
        return {
            "getOwners()": _abi_encode_address_array([ADDR_OWNER]),
            "getThreshold()": _abi_encode_uint256(1),
        }
    if scenario == "timelock_min_delay":
        return {
            "getMinDelay()": _abi_encode_uint256(60 * 60 * 24),  # 1 day
            "owner()": _abi_encode_address(ADDR_OWNER),
        }
    if scenario == "timelock_fallback_delay":
        return {
            "delay()": _abi_encode_uint256(60 * 60),
            "owner()": _abi_encode_address(ADDR_OWNER),
        }
    if scenario == "proxy_admin":
        # UIV with a nonzero slot is a UUPS proxy instead (test_classify_uiv_shape.py).
        return {
            "UPGRADE_INTERFACE_VERSION()": _abi_encode_string("5.0.0"),
            "owner()": _abi_encode_address(ADDR_OWNER),
        }
    if scenario == "contract_no_probes":
        return {}
    raise AssertionError(f"unknown scenario {scenario!r}")


def _mock_sequential(monkeypatch, probe_map, *, code="0x60", get_code_raises=False, type_authority_raises=False):

    def _fake_get_code(_rpc_url, _addr, _block, chain_id=None):
        if get_code_raises:
            raise RuntimeError("getCode failed")
        return code

    def _fake_eth_call_raw(_rpc_url, _addr, signature, _block, chain_id=None):
        raw = probe_map.get(signature, "0x")
        if raw == "revert":
            raise RuntimeError("execution reverted")
        return raw

    def _fake_type_authority(*_a, **_kw):
        if type_authority_raises:
            raise RuntimeError("type_authority blew up")
        return {}

    monkeypatch.setattr(tracking, "_get_code", _fake_get_code)
    monkeypatch.setattr(tracking, "_eth_call_raw", _fake_eth_call_raw)
    monkeypatch.setattr(tracking, "_get_storage_at", lambda *_a, **_k: probe_map.get("storage", "0x" + "0" * 64))
    monkeypatch.setattr(tracking, "type_authority_contract", _fake_type_authority)


def _mock_batched(
    monkeypatch,
    probe_map,
    *,
    code="0x60",
    get_code_raises=False,
    type_authority_raises=False,
    batch_errors=False,
):

    def _fake_get_code(_rpc_url, _addr, _block, chain_id=None):
        if get_code_raises:
            raise RuntimeError("getCode failed")
        return code

    def _fake_batch_with_status(_rpc_url, calls, chain_id=None):
        if batch_errors:
            return [(None, True)] * len(calls)
        out = []
        for sig, _abi in tracking._CLASSIFY_PROBE_SIGS:
            raw = probe_map.get(sig, "0x")
            out.append((raw, False))
        return out

    def _fake_type_authority(*_a, **_kw):
        if type_authority_raises:
            raise RuntimeError("type_authority blew up")
        return {}

    def _fake_eth_call_raw(_rpc_url, _addr, signature, _block, chain_id=None):
        raw = probe_map.get(signature, "0x")
        if raw == "revert":
            raise RuntimeError("execution reverted")
        return raw

    monkeypatch.setattr(tracking, "_get_code", _fake_get_code)
    monkeypatch.setattr(tracking, "_rpc_batch_request_with_status", _fake_batch_with_status)
    monkeypatch.setattr(tracking, "_eth_call_raw", _fake_eth_call_raw)
    monkeypatch.setattr(tracking, "_get_storage_at", lambda *_a, **_k: probe_map.get("storage", "0x" + "0" * 64))
    monkeypatch.setattr(tracking, "type_authority_contract", _fake_type_authority)


def _both_paths(monkeypatch, probe_map, **kwargs):
    addr = "0x" + "ab" * 20
    block = "latest"

    _mock_sequential(monkeypatch, probe_map, **{k: v for k, v in kwargs.items() if k != "batch_errors"})
    seq_result = _classify_uncached("https://rpc.example", addr, block)

    _mock_batched(monkeypatch, probe_map, **kwargs)
    batch_result = _classify_uncached_batched("https://rpc.example", addr, block)

    return seq_result, batch_result


def test_zero_address_parity(monkeypatch):
    addr = "0x" + "00" * 20
    seq = _classify_uncached("https://rpc", addr, "latest")
    batch = _classify_uncached_batched("https://rpc", addr, "latest")
    assert seq == batch == ("zero", {"address": addr}, False)


@pytest.mark.parametrize(
    ("scenario", "kwargs", "kind", "details", "had_error"),
    [
        pytest.param(None, {"code": "0x"}, "eoa", {}, False, id="eoa"),
        pytest.param(None, {"get_code_raises": True}, "contract", {}, True, id="get_code_failure"),
        pytest.param("safe", {}, "safe", {"owners": [ADDR_OWNER.lower()], "threshold": 1}, False, id="safe"),
        pytest.param(
            "timelock_min_delay",
            {},
            "timelock",
            {"delay": 60 * 60 * 24, "owner": ADDR_OWNER.lower()},
            False,
            id="timelock_min_delay",
        ),
        pytest.param(
            "timelock_fallback_delay", {}, "timelock", {"delay": 60 * 60}, False, id="timelock_fallback_delay"
        ),
        pytest.param(
            "proxy_admin",
            {},
            "proxy_admin",
            {"upgrade_interface_version": "5.0.0", "owner": ADDR_OWNER.lower()},
            False,
            id="proxy_admin",
        ),
        pytest.param("contract_no_probes", {}, "contract", {}, False, id="generic_contract"),
        pytest.param(
            "contract_no_probes",
            {"type_authority_raises": True},
            "contract",
            {},
            True,
            id="generic_contract_type_authority_failure",
        ),
    ],
)
def test_classify_branch_parity(monkeypatch, scenario, kwargs, kind, details, had_error):
    probe_map = _probe_responses_for(scenario) if scenario else {}
    seq, batch = _both_paths(monkeypatch, probe_map, **kwargs)
    assert seq == batch
    assert seq[0] == kind
    for key, value in details.items():
        assert seq[1][key] == value
    assert seq[2] is had_error


def test_whole_batch_failure_marks_had_error(monkeypatch):
    """Compared structurally, since the sequential path also lands there via the type_authority fallback."""

    def _seq_all_raise(_rpc_url, _addr, _signature, _block, chain_id=None):
        raise RuntimeError("RPC down")

    def _fake_get_code(_rpc_url, _addr, _block, chain_id=None):
        return "0x60"  # contract present

    def _fake_type_authority(*_a, **_kw):
        return {}

    monkeypatch.setattr(tracking, "_get_code", _fake_get_code)
    monkeypatch.setattr(tracking, "_eth_call_raw", _seq_all_raise)
    monkeypatch.setattr(tracking, "type_authority_contract", _fake_type_authority)
    seq = _classify_uncached("https://rpc", "0xab", "latest")

    monkeypatch.setattr(
        tracking,
        "_rpc_batch_request_with_status",
        lambda *_a, **_kw: [(None, True)] * len(tracking._CLASSIFY_PROBE_SIGS),
    )
    batch = _classify_uncached_batched("https://rpc", "0xab", "latest")

    assert seq[0] == batch[0] == "contract"
    assert seq[2] is True
    assert batch[2] is True


def test_partial_per_call_error_preserves_had_error(monkeypatch):
    """had_error keeps the result out of the cache."""

    def _fake_get_code(_rpc_url, _addr, _block, chain_id=None):
        return "0x60"

    def _fake_type_authority(*_a, **_kw):
        return {}

    def _fake_batch(_rpc_url, calls, chain_id=None):
        out = [
            (_abi_encode_address_array([ADDR_OWNER]), False),
            (_abi_encode_uint256(1), False),
            (None, True),  # errored
            ("0x", False),
            ("0x", False),
            ("0x", False),
        ]
        return out

    monkeypatch.setattr(tracking, "_get_code", _fake_get_code)
    monkeypatch.setattr(tracking, "_rpc_batch_request_with_status", _fake_batch)
    monkeypatch.setattr(tracking, "_eth_call_raw", lambda *_a, **_k: "0x")
    monkeypatch.setattr(tracking, "type_authority_contract", _fake_type_authority)
    kind, details, had_error = _classify_uncached_batched("https://rpc", "0xab", "latest")
    assert kind == "safe"
    assert had_error is True, "an errored probe in the batch must still set had_error"


@pytest.mark.parametrize(
    ("batch_enabled", "expected_calls"),
    [
        pytest.param(True, {"batched": 1, "sequential": 0}, id="batched_when_env_enabled"),
        pytest.param(False, {"batched": 0, "sequential": 1}, id="sequential_when_env_disabled"),
    ],
)
def test_classify_dispatch_follows_env_flag(monkeypatch, batch_enabled, expected_calls):
    addr = "0x" + "aa" * 20
    monkeypatch.setattr(tracking, "_CLASSIFY_BATCH_ENABLED", batch_enabled)
    called = {"batched": 0, "sequential": 0}
    monkeypatch.setattr(
        tracking,
        "_classify_uncached_batched",
        lambda *_a, **_kw: (called.update({"batched": called["batched"] + 1}), ("zero", {"address": addr}, False))[1],
    )
    monkeypatch.setattr(
        tracking,
        "_classify_uncached",
        lambda *_a, **_kw: (
            called.update({"sequential": called["sequential"] + 1}),
            ("zero", {"address": addr}, False),
        )[1],
    )
    tracking.classify_resolved_address_with_status("https://rpc", addr)
    assert called == expected_calls


def test_whole_batch_failure_falls_back_to_sequential_path(monkeypatch):
    """Some private RPCs reject JSON-RPC batches; whole-batch failure falls back to the sequential classifier."""
    sequential_called = {"count": 0}

    def _fake_get_code(_rpc_url, _addr, _block, chain_id=None):
        return "0x60"

    def _fake_type_authority(*_a, **_kw):
        return {}

    def _failing_batch(*_a, **_kw):
        return [(None, True)] * len(tracking._CLASSIFY_PROBE_SIGS)

    def _safe_seq_eth_call(_rpc_url, _addr, signature, _block, chain_id=None):
        sequential_called["count"] += 1
        if signature == "getOwners()":
            return _abi_encode_address_array([ADDR_OWNER])
        if signature == "getThreshold()":
            return _abi_encode_uint256(1)
        return "0x"

    monkeypatch.setattr(tracking, "_get_code", _fake_get_code)
    monkeypatch.setattr(tracking, "_rpc_batch_request_with_status", _failing_batch)
    monkeypatch.setattr(tracking, "_eth_call_raw", _safe_seq_eth_call)
    monkeypatch.setattr(tracking, "type_authority_contract", _fake_type_authority)

    kind, details, had_error = _classify_uncached_batched("https://rpc", "0xab", "latest")

    assert kind == "safe", (
        "whole-batch failure must fall back to sequential probes, which would have classified correctly"
    )
    assert details["owners"] == [ADDR_OWNER.lower()]
    assert details["threshold"] == 1
    assert had_error is False, "fallback to sequential succeeded — must be cacheable"
    assert sequential_called["count"] >= 1, "fallback must have actually invoked sequential probes"


def test_partial_batch_failure_does_not_trigger_fallback(monkeypatch):
    """Partial failure is normal ("0x" for getOwners on a non-Safe)."""
    sequential_called = {"count": 0}

    def _fake_get_code(_rpc_url, _addr, _block, chain_id=None):
        return "0x60"

    def _fake_type_authority(*_a, **_kw):
        return {}

    def _partial_batch(*_a, **_kw):
        return [
            ("0x", False),
            ("0x", False),
            (None, True),
            ("0x", False),
            ("0x", False),
            ("0x", False),
        ]

    def _seq_should_not_run(*_a, **_kw):
        sequential_called["count"] += 1
        raise AssertionError("sequential path should not be invoked on partial failure")

    monkeypatch.setattr(tracking, "_get_code", _fake_get_code)
    monkeypatch.setattr(tracking, "_rpc_batch_request_with_status", _partial_batch)
    monkeypatch.setattr(tracking, "_eth_call_raw", _seq_should_not_run)
    monkeypatch.setattr(tracking, "type_authority_contract", _fake_type_authority)

    kind, _details, had_error = _classify_uncached_batched("https://rpc", "0xab", "latest")
    assert kind == "contract"
    assert had_error is True, "the one errored probe still propagates"
    assert sequential_called["count"] == 0, "no fallback should fire on partial failure"


# Probes are caller-independent views, so Multicall3 as msg.sender can't change a value; the wire is stubbed so the real
# encode/decode runs.


def _run_multicall(
    monkeypatch,
    probe_map,
    *,
    code="0x60",
    get_code_raises=False,
    type_authority_raises=False,
    revert_sigs: frozenset[str] | set[str] = frozenset(),
):
    """``revert_sigs`` forces selectors to success=False."""
    import services.clients.rpc as rpc_mod

    revert_selectors = {tracking._selector(sig) for sig in revert_sigs}
    sel_to_sig = {tracking._selector(sig): sig for sig, _abi in tracking._CLASSIFY_PROBE_SIGS}

    def _fake_get_code(_rpc_url, _addr, _block, chain_id=None):
        if get_code_raises:
            raise RuntimeError("getCode failed")
        return code

    def _fake_type_authority(*_a, **_kw):
        if type_authority_raises:
            raise RuntimeError("type_authority blew up")
        return {}

    def _fake_rpc_request(_rpc_url, method, params, **_kw):
        assert method == "eth_call"
        call = params[0]
        assert call["to"].lower() == rpc_mod.MULTICALL3_ADDRESS.lower()
        from eth_abi.abi import decode, encode

        sub_calls = decode(["(address,bool,bytes)[]"], bytes.fromhex(call["data"][10:]))[0]
        out = []
        for _target, _allow, calldata in sub_calls:
            sel = "0x" + calldata.hex()[:8]
            if sel in revert_selectors:
                out.append((False, b""))
                continue
            sig = sel_to_sig.get(sel)
            raw = probe_map.get(sig, "0x") if sig else "0x"
            ok = isinstance(raw, str) and raw.startswith("0x") and len(raw) > 2
            raw_bytes = bytes.fromhex(raw[2:]) if ok else b""
            out.append((True, raw_bytes))
        return "0x" + encode(["(bool,bytes)[]"], [out]).hex()

    # ``_eth_call_raw`` binds ``_rpc_request`` at module level, not the patched attribute.
    def _fake_eth_call_raw(_rpc_url, _addr, signature, _block, chain_id=None):
        raw = probe_map.get(signature, "0x")
        if raw == "revert":
            raise RuntimeError("execution reverted")
        return raw

    monkeypatch.setattr(tracking, "_get_code", _fake_get_code)
    monkeypatch.setattr(tracking, "type_authority_contract", _fake_type_authority)
    monkeypatch.setattr(tracking, "_eth_call_raw", _fake_eth_call_raw)
    monkeypatch.setattr(tracking, "_get_storage_at", lambda *_a, **_k: probe_map.get("storage", "0x" + "0" * 64))
    monkeypatch.setattr(tracking, "_CLASSIFY_MULTICALL_ENABLED", True)
    monkeypatch.setattr(rpc_mod, "rpc_request", _fake_rpc_request)
    return _classify_uncached_batched("https://rpc.example", "0x" + "ab" * 20, "latest")


@pytest.mark.parametrize(
    "scenario",
    ["safe", "timelock_min_delay", "timelock_fallback_delay", "proxy_admin", "contract_no_probes"],
)
def test_multicall_matches_sequential(monkeypatch, scenario):
    probe_map = _probe_responses_for(scenario)
    _mock_sequential(monkeypatch, probe_map)
    seq = _classify_uncached("https://rpc.example", "0x" + "ab" * 20, "latest")
    mc = _run_multicall(monkeypatch, probe_map)
    assert seq == mc


def test_multicall_eoa_short_circuits_without_aggregate3(monkeypatch):
    import services.clients.rpc as rpc_mod

    monkeypatch.setattr(tracking, "_CLASSIFY_MULTICALL_ENABLED", True)
    monkeypatch.setattr(tracking, "_get_code", lambda *_a, **_k: "0x")
    monkeypatch.setattr(
        rpc_mod, "rpc_request", lambda *a, **k: (_ for _ in ()).throw(AssertionError("aggregate3 should not run"))
    )
    kind, _details, had_error = _classify_uncached_batched("https://rpc", "0x" + "ab" * 20, "latest")
    assert kind == "eoa"
    assert had_error is False


def test_multicall_revert_maps_to_probe_error(monkeypatch):
    mc = _run_multicall(monkeypatch, _probe_responses_for("safe"), revert_sigs={"getMinDelay()"})
    assert mc[0] == "safe"
    assert mc[1]["owners"] == [ADDR_OWNER.lower()]
    assert mc[2] is True


def test_multicall_failure_falls_back_to_batch(monkeypatch):
    import services.clients.rpc as rpc_mod

    monkeypatch.setattr(tracking, "_CLASSIFY_MULTICALL_ENABLED", True)
    monkeypatch.setattr(tracking, "_get_code", lambda *_a, **_k: "0x60")
    monkeypatch.setattr(tracking, "type_authority_contract", lambda *_a, **_k: {})
    monkeypatch.setattr(tracking, "_eth_call_raw", lambda *_a, **_k: "0x")
    monkeypatch.setattr(rpc_mod, "rpc_request", lambda *a, **k: (_ for _ in ()).throw(RuntimeError("no multicall")))

    def _safe_batch(_rpc_url, _calls, chain_id=None):
        return [
            (_abi_encode_address_array([ADDR_OWNER]), False),
            (_abi_encode_uint256(1), False),
            ("0x", False),
            ("0x", False),
            ("0x", False),
            ("0x", False),
        ]

    monkeypatch.setattr(tracking, "_rpc_batch_request_with_status", _safe_batch)
    kind, details, had_error = _classify_uncached_batched("https://rpc", "0x" + "ab" * 20, "latest")
    assert kind == "safe"
    assert details["owners"] == [ADDR_OWNER.lower()]
    assert had_error is False, "fallback to the batch path succeeded → cacheable"
