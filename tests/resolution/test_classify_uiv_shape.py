"""UPGRADE_INTERFACE_VERSION() no longer selects 'proxy_admin' (W6-3).

The '5.0.0' string is the OZ-v5 UUPSUpgradeable constant: it is answered
THROUGH every OZ-v5 UUPS proxy (via delegatecall to the implementation), by
every bare UUPS implementation, and by the v5 ProxyAdmin — while the corpus's
genuine (v4) ProxyAdmin does not implement it at all. Publishing 'proxy_admin'
off a UIV answer alone therefore typed PROXIES as proxy admins at
confidence=high (chain-verified: 5/5 published proxy_admin nodes carried a
nonzero ERC-1967 implementation slot at pinned block 25619159, e.g. the KING
ERC-20 proxy 0x8f08b704...; the genuine ProxyAdmin 0x8b9566ad... reverts on
UIV and got typed 'contract'). Because proxy_admin is terminal
(services/governance/principals.TERMINAL_PRINCIPAL_TYPES), the terminal walk
stopped AT the proxy and the real upgrade authority was never reached.

Discipline under test (services/resolution/tracking._resolve_uiv_shape):
  * UIV + nonzero ERC-1967 implementation slot -> 'contract' (the address IS a
    proxy; non-terminal, so the walk continues through it to the real
    authority), details carry the witnessed erc1967_implementation;
  * UIV + zero slot + proxiableUUID() answers -> 'contract' (bare UUPS
    implementation), details.uups_implementation;
  * UIV + zero slot + no proxiableUUID + owner() -> 'proxy_admin' (the OZ-v5
    ProxyAdmin shape - the only earner of the token in this classifier);
  * a discriminator read that did not happen -> 'contract' + had_error
    (not determined, uncached, retryable).

Wire stubbed per repo convention; probe shapes mirror the pinned on-chain
observations from the re-verification (no live probes).
"""

from __future__ import annotations

import pytest

from services.resolution import tracking
from services.resolution.tracking import _classify_uncached, _classify_uncached_batched

PROXY = "0x" + "8f" * 20  # stands in for the KING proxy 0x8f08b704...
IMPL = "0x" + "1c" * 20  # its implementation
OWNER = "0x" + "a0" * 20  # stands in for 0xa000244b... (the real authority)

_ZERO_WORD = "0x" + "0" * 64


@pytest.fixture(autouse=True)
def _isolated_classify_cache():
    tracking.clear_classify_cache()
    yield
    tracking.clear_classify_cache()


def _uint(n: int) -> str:
    return "0x" + format(n, "x").rjust(64, "0")


def _addr_word(a: str) -> str:
    return "0x" + a[2:].lower().rjust(64, "0")


def _string_word(s: str) -> str:
    raw = s.encode()
    pad = (32 - (len(raw) % 32)) % 32
    return "0x" + format(32, "064x") + format(len(raw), "064x") + raw.hex() + "00" * pad


def _wire(monkeypatch, probe_map, *, storage=_ZERO_WORD, storage_raises=False, batched: bool = True):
    """Stub both classify paths from one signature→outcome map (values: raw
    hex, "revert", "transport"; missing → "0x", the empty-success shape the
    sibling harnesses use so absent probes do not set had_error — the
    revert-vs-error conflation of the probe layers is pre-existing and not
    under test here)."""

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


# The observed KING-proxy probe shape at pinned block 25619159: every classify
# probe reverts except UIV; the negative control reverts (honest dispatch);
# the ERC-1967 implementation slot is nonzero.
_UUPS_PROXY = {"UPGRADE_INTERFACE_VERSION()": _string_word("5.0.0")}


@pytest.mark.parametrize("batched", [False, True])
def test_uups_proxy_is_a_contract_not_a_proxy_admin(monkeypatch, batched):
    """The KING-proxy shape: UIV answers, 1967 impl slot nonzero → the address
    is a PROXY. Typed 'contract' (non-terminal — the walk continues), never
    'proxy_admin'."""
    _wire(monkeypatch, _UUPS_PROXY, storage=_addr_word(IMPL))
    fn = _classify_uncached_batched if batched else _classify_uncached
    kind, details, had_error = fn("https://rpc", PROXY, "latest")
    assert kind == "contract"
    assert details["erc1967_implementation"] == IMPL
    assert details["upgrade_interface_version"] == "5.0.0"
    assert had_error is False


@pytest.mark.parametrize("batched", [False, True])
def test_bare_uups_implementation_is_a_contract(monkeypatch, batched):
    """UIV + zero slot + proxiableUUID answers → a bare UUPS implementation,
    not a proxy admin."""
    probe_map = dict(_UUPS_PROXY)
    probe_map["proxiableUUID()"] = "0x360894a13ba1a3210667c828492db98dca3e2076cc3735a920a3ca505d382bbc"
    _wire(monkeypatch, probe_map, storage=_ZERO_WORD)
    fn = _classify_uncached_batched if batched else _classify_uncached
    kind, details, had_error = fn("https://rpc", PROXY, "latest")
    assert kind == "contract"
    assert details["uups_implementation"] is True
    assert had_error is False


@pytest.mark.parametrize("batched", [False, True])
def test_v5_proxy_admin_shape_earns_the_token(monkeypatch, batched):
    """Positive control (R4): UIV + zero slot + no proxiableUUID + owner() is
    the OZ-v5 ProxyAdmin shape — the one earner of 'proxy_admin' here."""
    probe_map = dict(_UUPS_PROXY)
    probe_map["owner()"] = _addr_word(OWNER)
    _wire(monkeypatch, probe_map, storage=_ZERO_WORD)
    fn = _classify_uncached_batched if batched else _classify_uncached
    kind, details, had_error = fn("https://rpc", PROXY, "latest")
    assert kind == "proxy_admin"
    assert details["owner"] == OWNER
    assert had_error is False


@pytest.mark.parametrize("batched", [False, True])
def test_v4_proxy_admin_keeps_contract_type(monkeypatch, batched):
    """The corpus's genuine (v4) ProxyAdmin 0x8b9566ad... reverts on UIV and
    answers owner(): it stays 'contract' (unchanged — a non-terminal way-point
    whose owner the walk can still reach)."""
    _wire(monkeypatch, {"owner()": _addr_word(OWNER)}, storage=_ZERO_WORD)
    fn = _classify_uncached_batched if batched else _classify_uncached
    kind, details, _had_error = fn("https://rpc", PROXY, "latest")
    assert kind == "contract"
    assert "upgrade_interface_version" not in details


@pytest.mark.parametrize("batched", [False, True])
def test_slot_read_failure_withholds_the_verdict_uncached(monkeypatch, batched):
    """If the 1967-slot discriminator read did not happen, neither 'proxy'
    nor 'proxy_admin' is determined: plain 'contract' + had_error (uncached)."""
    probe_map = dict(_UUPS_PROXY)
    probe_map["owner()"] = _addr_word(OWNER)
    _wire(monkeypatch, probe_map, storage_raises=True)
    fn = _classify_uncached_batched if batched else _classify_uncached
    kind, details, had_error = fn("https://rpc", PROXY, "latest")
    assert kind == "contract"
    assert had_error is True
    assert "erc1967_implementation" not in details


@pytest.mark.parametrize("batched", [False, True])
def test_uups_proxy_behind_catch_all_control_stays_gated(monkeypatch, batched):
    """W6-2 gate composes: an address answering the negative control never
    reaches the UIV discriminators at all."""
    probe_map = dict(_UUPS_PROXY)
    probe_map[tracking._NEGATIVE_CONTROL_SIG] = _uint(1)
    _wire(monkeypatch, probe_map, storage=_addr_word(IMPL))
    fn = _classify_uncached_batched if batched else _classify_uncached
    kind, details, _had_error = fn("https://rpc", PROXY, "latest")
    assert kind == "contract"
    assert details.get("duck_type_negative_control") == "failed"
    assert "erc1967_implementation" not in details


def test_walk_continues_through_a_uups_proxy_to_the_real_authority(monkeypatch):
    """The 0x6db24ee6→0xa000244b control: a UUPS proxy typed 'contract' is
    non-terminal, so the terminal-principal walk probes its canonical getters
    (delegatecalled to the implementation) and reaches the real owner —
    instead of stopping at the proxy as terminal 'proxy_admin'."""
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
