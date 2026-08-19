"""Negative-control discipline for the duck-typed address classifier (W6-2).

An unverified contract with a catch-all fallback answers EVERY selector —
including ``getMinDelay()``/``delay()``/``getOwners()`` — so a single
successful probe is not evidence of an interface. Observed on mainnet:
0x008702e6…84 answered ``getMinDelay()`` and the nonsense selector
``0xdeadbeef`` with the same payload and was published as
``resolved_type='timelock'`` with ``details.delay=1``, which the scorer reads
as full protective credit. The discriminating control was a real, verified
``TimelockController`` (0x5eb52f8a…), which reverts on nonsense selectors.

Discipline under test (services/resolution/tracking.py):
  * before ANY concrete duck-typed kind (safe / timelock / the
    UPGRADE_INTERFACE_VERSION arm) is published, a probe of a selector no
    real contract implements must revert or return empty ("passed");
  * an address that ANSWERS it is classified plain ``contract`` with the
    definitive ``details.duck_type_negative_control = 'failed'`` marker;
  * a control that cannot be established (transport error) withholds the
    concrete kind AND marks the classification uncacheable (not determined,
    retryable) — never a concrete type;
  * single-word probe returns must be exactly 32 bytes
    (returndata-length discipline).

Wire is stubbed per the repo convention (``_eth_call_raw`` /
``_rpc_batch_request_with_status`` / the aggregate3 ``rpc_request``), never
live-probed.
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
    """Stub both classify paths from ONE signature→outcome map.

    Values: raw hex string (successful return), ``"revert"`` (definitive
    revert), ``"transport"`` (read did not happen). Missing signatures revert —
    the shape a real contract produces for an unimplemented selector.
    """

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
    # Stub the batch layer on both parametrizations: the `batched` flag chooses
    # which classifier the test drives, but classify_resolved_address_with_status
    # (exercised for cacheability) always dispatches through the batched path.
    del batched
    monkeypatch.setattr(tracking, "_rpc_batch_request_with_status", _fake_batch_with_status)


# A catch-all fallback answers everything with the same word — including the
# negative-control selector.
_CATCH_ALL = {
    "getOwners()": _uint(1),  # not a decodable address[] (offset 1) → safe arm skips
    "getThreshold()": _uint(1),
    "getMinDelay()": _uint(1),
    "delay()": _uint(1),
    "UPGRADE_INTERFACE_VERSION()": _uint(1),
    "owner()": _addr_word(ADDR),  # echoes an address, like the observed contract
    tracking._NEGATIVE_CONTROL_SIG: _uint(1),
}

# A real TimelockController: getMinDelay answers, everything else — including
# the negative control — reverts.
_REAL_TIMELOCK = {
    "getMinDelay()": _uint(86400),
    "owner()": _addr_word(OWNER),
}


@pytest.mark.parametrize("batched", [False, True])
def test_catch_all_fallback_is_not_a_timelock(monkeypatch, batched):
    """The observed 0x008702e6 shape: every selector answers → the sentinel
    fires and the address is a plain contract with the definitive marker, never
    a 'timelock' with a fabricated delay."""
    _wire(monkeypatch, _CATCH_ALL, batched=batched)
    fn = _classify_uncached_batched if batched else _classify_uncached
    kind, details, had_error = fn("https://rpc", ADDR, "latest")
    assert kind == "contract"
    assert details.get("duck_type_negative_control") == "failed"
    assert "delay" not in details
    assert had_error is False  # a definitive observation — cacheable


@pytest.mark.parametrize("batched", [False, True])
def test_real_timelock_with_reverting_control_stays_timelock(monkeypatch, batched):
    """Positive control: the verified-TimelockController shape (answers
    getMinDelay, reverts on the nonsense selector) keeps its earned type."""
    _wire(monkeypatch, _REAL_TIMELOCK, batched=batched)
    fn = _classify_uncached_batched if batched else _classify_uncached
    kind, details, _had_error = fn("https://rpc", ADDR, "latest")
    assert kind == "timelock"
    assert details["delay"] == 86400
    assert details["owner"] == OWNER


@pytest.mark.parametrize("batched", [False, True])
def test_catch_all_fallback_is_not_a_safe(monkeypatch, batched):
    """Same discipline on the safe arm: decodable getOwners()+getThreshold()
    from an answer-everything address must not mint a Safe."""
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
    """A control that could not be established is NOT a pass: the concrete type
    is withheld and the classification is uncacheable (retryable), with no
    definitive 'failed' marker minted."""
    probe_map = dict(_REAL_TIMELOCK)
    probe_map[tracking._NEGATIVE_CONTROL_SIG] = "transport"
    _wire(monkeypatch, probe_map, batched=batched)
    fn = _classify_uncached_batched if batched else _classify_uncached
    kind, details, had_error = fn("https://rpc", ADDR, "latest")
    assert kind == "contract"
    assert had_error is True
    assert "duck_type_negative_control" not in details
    # And the public entry point must report it uncacheable.
    _kind, _details, cacheable = tracking.classify_resolved_address_with_status("https://rpc", ADDR)
    assert cacheable is False


@pytest.mark.parametrize("batched", [False, True])
def test_oversized_uint_return_is_not_a_delay(monkeypatch, batched):
    """Returndata-length discipline: a 64-byte blob is not a uint256 answer,
    so the timelock arm never matches (and the control is never consulted)."""
    probe_map = {"getMinDelay()": _uint(1) + "ff" * 32}
    _wire(monkeypatch, probe_map, batched=batched)
    fn = _classify_uncached_batched if batched else _classify_uncached
    kind, details, _had_error = fn("https://rpc", ADDR, "latest")
    assert kind == "contract"
    assert "delay" not in details


def test_negative_control_probe_tristate(monkeypatch):
    """The sentinel itself: answered → failed, revert/empty → passed,
    transport → error."""
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


# ---------------------------------------------------------------------------
# read_contract_controllers rides the same discipline (its control is a 4th
# call in the SAME eth_call batch).
# ---------------------------------------------------------------------------


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
    """An address that answers the nonsense selector answers everything — its
    owner() 'answer' is not a witnessed control plane. Not determined (None),
    never a plane set and never the silent []."""
    _controllers_stub(
        monkeypatch,
        {
            "owner()": _addr_word(OWNER),
            tracking._NEGATIVE_CONTROL_SIG: _uint(1),
        },
    )
    assert read_contract_controllers("https://rpc", ADDR) is None


def test_owner_with_reverting_control_is_witnessed(monkeypatch):
    """Positive control: the ordinary Ownable shape (owner() answers, nonsense
    reverts) still yields its plane set."""
    _controllers_stub(monkeypatch, {"owner()": _addr_word(OWNER)})
    assert read_contract_controllers("https://rpc", ADDR) == [OWNER]


def test_control_transport_error_makes_set_indeterminate(monkeypatch):
    """If the control read itself did not happen, the plane set is not
    dispositively known → None (retryable)."""
    _controllers_stub(
        monkeypatch,
        {
            "owner()": _addr_word(OWNER),
            tracking._NEGATIVE_CONTROL_SIG: "transport",
        },
    )
    assert read_contract_controllers("https://rpc", ADDR) is None
