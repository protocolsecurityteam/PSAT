"""Parity tests for the batched classify path in ``services.resolution.tracking``.

The batched path (``PSAT_CLASSIFY_BATCH``, default ON; ``=0`` disables) must preserve
the ``_PROBE_ERROR`` sentinel under partial failures and return identical (kind,
details, cacheable) on every branch. Both paths run against the same mocked RPC
responses and must be byte-identical; env-dispatch tests patch the constant directly.

Branches (each in batched and sequential mode): zero address; EOA (no probes); Safe;
Timelock via getMinDelay / fallback delay(); OZ-v5 ProxyAdmin (UIV + zero 1967 slot +
no proxiableUUID + owner); generic contract; generic contract WITH per-probe RPC error
(had_error=True, cacheable=False); whole-batch RPC failure (had_error=True).
"""

from __future__ import annotations

import pytest

from services.resolution import tracking
from services.resolution.tracking import (
    _classify_uncached,
    _classify_uncached_batched,
)


@pytest.fixture(autouse=True)
def _isolated_classify_cache():
    tracking.clear_classify_cache()
    yield
    tracking.clear_classify_cache()


# Encoded constants used to build mock responses.
ZERO_RESULT = "0x" + "0" * 64
ADDR_OWNER = "0x" + "11" * 20  # an "owner" address used in several mocks


def _abi_encode_address(addr: str) -> str:
    return "0x" + addr.lower().replace("0x", "").rjust(64, "0")


def _abi_encode_uint256(n: int) -> str:
    return "0x" + format(n, "x").rjust(64, "0")


def _abi_encode_address_array(addrs: list[str]) -> str:
    """Tail-encoded address[]: offset, length, then each address right-padded to 32 bytes."""
    body = format(32, "064x")  # offset to data
    body += format(len(addrs), "064x")  # length
    for a in addrs:
        body += a.lower().replace("0x", "").rjust(64, "0")
    return "0x" + body


def _abi_encode_string(s: str) -> str:
    """Minimal ABI-encoded string: offset, length, padded bytes."""
    raw = s.encode("utf-8")
    pad = (32 - (len(raw) % 32)) % 32
    body = format(32, "064x") + format(len(raw), "064x")
    body += raw.hex() + ("00" * pad)
    return "0x" + body


# Probe responses keyed by selector; the same set drives both the sequential and batched mocks.
def _probe_responses_for(scenario: str) -> dict[str, str]:
    """Selector → raw eth_call response (selectors from tracking._CLASSIFY_PROBE_SIGS);
    missing selectors imply "0x" (no data)."""
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
        # No getMinDelay, only delay()
        return {
            "delay()": _abi_encode_uint256(60 * 60),
            "owner()": _abi_encode_address(ADDR_OWNER),
        }
    if scenario == "proxy_admin":
        # OZ-v5 ProxyAdmin: UIV answers, the ERC-1967 slot is zero, proxiableUUID() absent,
        # owner() answers. UIV with a NONZERO slot is a UUPS proxy (test_classify_uiv_shape.py).
        return {
            "UPGRADE_INTERFACE_VERSION()": _abi_encode_string("5.0.0"),
            "owner()": _abi_encode_address(ADDR_OWNER),
        }
    if scenario == "contract_no_probes":
        # Every probe returns empty
        return {}
    raise AssertionError(f"unknown scenario {scenario!r}")


def _mock_sequential(monkeypatch, probe_map, *, code="0x60", get_code_raises=False, type_authority_raises=False):
    """Wire the sequential path: _get_code returns `code`, _try_eth_call_decoded routes to `probe_map`."""

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
    # ERC-1967 slot read (the UIV-arm discriminator): zero word unless the scenario gives "storage".
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
    """Wire the batched path; ``probe_map`` is keyed by selector and aligned with _CLASSIFY_PROBE_SIGS."""

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

    # The lazy negative-control probe rides _eth_call_raw on every path.
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
    """Run a scenario through both paths and return both results."""
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


def test_eoa_parity(monkeypatch):
    """eth_getCode == '0x' → EOA, no probes issued either way."""
    seq, batch = _both_paths(monkeypatch, {}, code="0x")
    assert seq == batch
    assert seq[0] == "eoa"
    assert seq[2] is False  # no error


def test_get_code_failure_parity(monkeypatch):
    """getCode raised → both paths return (contract, ..., had_error=True)."""
    seq, batch = _both_paths(monkeypatch, {}, get_code_raises=True)
    assert seq == batch
    assert seq[0] == "contract"
    assert seq[2] is True  # had_error


def test_safe_branch_parity(monkeypatch):
    seq, batch = _both_paths(monkeypatch, _probe_responses_for("safe"))
    assert seq == batch
    assert seq[0] == "safe"
    assert seq[1]["owners"] == [ADDR_OWNER.lower()]
    assert seq[1]["threshold"] == 1


def test_timelock_min_delay_branch_parity(monkeypatch):
    seq, batch = _both_paths(monkeypatch, _probe_responses_for("timelock_min_delay"))
    assert seq == batch
    assert seq[0] == "timelock"
    assert seq[1]["delay"] == 60 * 60 * 24
    assert seq[1]["owner"] == ADDR_OWNER.lower()


def test_timelock_fallback_delay_branch_parity(monkeypatch):
    seq, batch = _both_paths(monkeypatch, _probe_responses_for("timelock_fallback_delay"))
    assert seq == batch
    assert seq[0] == "timelock"
    assert seq[1]["delay"] == 60 * 60


def test_proxy_admin_branch_parity(monkeypatch):
    seq, batch = _both_paths(monkeypatch, _probe_responses_for("proxy_admin"))
    assert seq == batch
    assert seq[0] == "proxy_admin"
    assert seq[1]["upgrade_interface_version"] == "5.0.0"
    assert seq[1]["owner"] == ADDR_OWNER.lower()


def test_generic_contract_branch_parity(monkeypatch):
    """No probes succeed → 'contract' branch with type_authority info merged in."""
    seq, batch = _both_paths(monkeypatch, _probe_responses_for("contract_no_probes"))
    assert seq == batch
    assert seq[0] == "contract"
    assert seq[2] is False  # no errors in this scenario


def test_generic_contract_with_type_authority_failure_parity(monkeypatch):
    """type_authority_contract raised → both paths set had_error=True though no probe returned _PROBE_ERROR."""
    seq, batch = _both_paths(monkeypatch, _probe_responses_for("contract_no_probes"), type_authority_raises=True)
    assert seq == batch
    assert seq[0] == "contract"
    assert seq[2] is True


def test_whole_batch_failure_marks_had_error(monkeypatch):
    """A (None, True) batch result for every slot (network or provider rejection) must
    classify as 'contract' with had_error=True, as if every sequential probe had raised.
    Compared structurally (the sequential path also lands there via the type_authority fallback)."""

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

    # Both land at "contract" with had_error=True; details has only the address.
    assert seq[0] == batch[0] == "contract"
    assert seq[2] is True
    assert batch[2] is True


def test_partial_per_call_error_preserves_had_error(monkeypatch):
    """One probe errored but the rest classify as Safe: had_error must still be True so
    the result isn't cached, though the kind was correct."""

    def _fake_get_code(_rpc_url, _addr, _block, chain_id=None):
        return "0x60"

    def _fake_type_authority(*_a, **_kw):
        return {}

    def _fake_batch(_rpc_url, calls, chain_id=None):
        # Slots 0 (getOwners), 1 (getThreshold) succeed → Safe; slot 2 (getMinDelay) errors, irrelevant.
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
    # Negative control (lazy _eth_call_raw): empty return → control passes.
    monkeypatch.setattr(tracking, "_eth_call_raw", lambda *_a, **_k: "0x")
    monkeypatch.setattr(tracking, "type_authority_contract", _fake_type_authority)
    kind, details, had_error = _classify_uncached_batched("https://rpc", "0xab", "latest")
    assert kind == "safe"
    assert had_error is True, "an errored probe in the batch must still set had_error"


def test_classify_dispatch_uses_batched_path_when_env_enabled(monkeypatch):
    """classify_resolved_address_with_status must route to the batched path when PSAT_CLASSIFY_BATCH is on."""
    addr = "0x" + "00" * 20
    monkeypatch.setattr(tracking, "_CLASSIFY_BATCH_ENABLED", True)
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
    tracking.classify_resolved_address_with_status("https://rpc", "0x" + "aa" * 20)
    assert called == {"batched": 1, "sequential": 0}


def test_classify_dispatch_uses_sequential_path_when_env_disabled(monkeypatch):
    monkeypatch.setattr(tracking, "_CLASSIFY_BATCH_ENABLED", False)
    called = {"batched": 0, "sequential": 0}
    addr = "0x" + "aa" * 20
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
    assert called == {"batched": 0, "sequential": 1}


# Codex-iter-1 finding: whole-batch failure must fall back to sequential


def test_whole_batch_failure_falls_back_to_sequential_path(monkeypatch):
    """Codex review finding: some private RPCs reject JSON-RPC batches, so the batch
    helper returns (None, True) for every slot. Without a fallback the batched classifier
    yields ('contract', ..., had_error=True) though the SEQUENTIAL path would classify
    correctly; enabling the flag must not degrade accuracy on such providers. Whole-batch
    failure falls back to ``_classify_uncached`` and recovers the Safe."""
    sequential_called = {"count": 0}

    def _fake_get_code(_rpc_url, _addr, _block, chain_id=None):
        return "0x60"

    def _fake_type_authority(*_a, **_kw):
        return {}

    # Batch helper: a provider that rejects every JSON-RPC batch.
    def _failing_batch(*_a, **_kw):
        return [(None, True)] * len(tracking._CLASSIFY_PROBE_SIGS)

    # Sequential helper: a Safe responding correctly to individual eth_calls.
    def _safe_seq_eth_call(_rpc_url, _addr, signature, _block, chain_id=None):
        sequential_called["count"] += 1
        if signature == "getOwners()":
            return _abi_encode_address_array([ADDR_OWNER])
        if signature == "getThreshold()":
            return _abi_encode_uint256(1)
        # Other probes "succeed" but return empty (function absent).
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
    """The fallback fires ONLY on whole-batch failure; if one probe succeeded we trust
    the batch (partial failure is normal, e.g. "0x" for getOwners on a non-Safe)."""
    sequential_called = {"count": 0}

    def _fake_get_code(_rpc_url, _addr, _block, chain_id=None):
        return "0x60"

    def _fake_type_authority(*_a, **_kw):
        return {}

    def _partial_batch(*_a, **_kw):
        # Only slot 2 (getMinDelay) errored, the rest "succeeded" empty: NOT a whole-batch failure.
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


# Multicall3 classify path (PSAT_CLASSIFY_MULTICALL) — byte-identical to the sequential /
# JSON-RPC-batch paths. Probes are caller-independent view getters, so Multicall3 (which
# becomes msg.sender) can't change a value; a reverting probe → success=False →
# _PROBE_ERROR, like a per-call JSON-RPC error. The wire is stubbed at
# services.clients.rpc.rpc_request so the REAL _multicall_probe + multicall3_aggregate3 run hermetically.


def _run_multicall(
    monkeypatch,
    probe_map,
    *,
    code="0x60",
    get_code_raises=False,
    type_authority_raises=False,
    revert_sigs: frozenset[str] | set[str] = frozenset(),
):
    """Drive _classify_uncached_batched through the real Multicall3 probe path.

    Absent probes are success/empty ("0x"), as in the other mocks, so results are
    comparable; ``revert_sigs`` forces those selectors to success=False (revert).
    """
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

    # The lazy negative-control probe goes through _eth_call_raw (module-bound _rpc_request,
    # not the patched attribute) — stub it at the probe_map layer so it's scenario-driven.
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
    """Every classification branch resolves identically via Multicall3 and the sequential path."""
    probe_map = _probe_responses_for(scenario)
    _mock_sequential(monkeypatch, probe_map)
    seq = _classify_uncached("https://rpc.example", "0x" + "ab" * 20, "latest")
    mc = _run_multicall(monkeypatch, probe_map)
    assert seq == mc


def test_multicall_eoa_short_circuits_without_aggregate3(monkeypatch):
    """No code → 'eoa' before any probe; the aggregate3 wire must never be hit."""
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
    """A reverting probe (success=False) sets had_error=True (not cached), like a (None, True)
    slot on the JSON-RPC-batch path; Safe still classifies."""
    mc = _run_multicall(monkeypatch, _probe_responses_for("safe"), revert_sigs={"getMinDelay()"})
    assert mc[0] == "safe"
    assert mc[1]["owners"] == [ADDR_OWNER.lower()]
    assert mc[2] is True


def test_multicall_failure_falls_back_to_batch(monkeypatch):
    """If the aggregate3 eth_call raises (no Multicall3 / provider rejects), _probe_classify
    falls back to the JSON-RPC batch with no accuracy loss."""
    import services.clients.rpc as rpc_mod

    monkeypatch.setattr(tracking, "_CLASSIFY_MULTICALL_ENABLED", True)
    monkeypatch.setattr(tracking, "_get_code", lambda *_a, **_k: "0x60")
    monkeypatch.setattr(tracking, "type_authority_contract", lambda *_a, **_k: {})
    # Negative control (lazy _eth_call_raw): empty return → control passes.
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


def test_probe_classify_dispatch_on_flag(monkeypatch):
    """_probe_classify routes to Multicall3 when the flag is on, else the JSON-RPC batch."""
    seen = {"mc": 0, "batch": 0}
    monkeypatch.setattr(
        tracking,
        "_multicall_probe",
        lambda *a, **k: (seen.__setitem__("mc", seen["mc"] + 1), [tracking._PROBE_ERROR])[1],
    )
    monkeypatch.setattr(
        tracking,
        "_batch_probe",
        lambda *a, **k: (seen.__setitem__("batch", seen["batch"] + 1), [tracking._PROBE_ERROR])[1],
    )

    monkeypatch.setattr(tracking, "_CLASSIFY_MULTICALL_ENABLED", True)
    tracking._probe_classify("https://rpc", "0xab", "latest")
    assert seen == {"mc": 1, "batch": 0}

    monkeypatch.setattr(tracking, "_CLASSIFY_MULTICALL_ENABLED", False)
    tracking._probe_classify("https://rpc", "0xab", "latest")
    assert seen == {"mc": 1, "batch": 1}
