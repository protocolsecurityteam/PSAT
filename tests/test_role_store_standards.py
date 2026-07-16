"""Recognized role-store standards table + proxy-hop probe-code resolution."""

from __future__ import annotations

import sys
from pathlib import Path
from typing import Any, cast

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from eth_utils.crypto import keccak  # noqa: E402

import services.resolution.role_store_standards as rss  # noqa: E402
from services.resolution.role_store_standards import (  # noqa: E402
    OZ_ACCESS_CONTROL_ENUMERABLE,
    SOLADY_ENUMERABLE_ROLES,
    STANDARDS,
    all_topic0s,
    detect_standards,
    resolve_probe_code,
)


def _sel(sig: str) -> str:
    return "0x" + keccak(text=sig).hex()[:8]


def _code_with(*selectors: str) -> str:
    # A minimal dispatcher body: each selector prefixed with the PUSH4 opcode.
    return "0x" + "".join("63" + s.removeprefix("0x") for s in selectors)


# --- the table matches on-chain ground truth -------------------------------


def test_solady_roleset_topic0_matches_ground_truth():
    (event,) = SOLADY_ENUMERABLE_ROLES.grant_events
    assert event.topic0 == "0xaddc47d7e02c95c00ec667676636d772a589ffbf0663cfd7cd4dd3d4758201b8"
    assert (event.holder_topic_index, event.role_topic_index) == (1, 2)
    assert event.active_topic_index == 3 and event.active_when is None


def test_solady_hasrole_marker_selector():
    assert _sel("hasRole(address,uint256)") == "0x5c97f4a2"
    assert "0x5c97f4a2" in SOLADY_ENUMERABLE_ROLES.marker_selectors


def test_oz_grant_revoke_polarity_and_eip165():
    grant, revoke = OZ_ACCESS_CONTROL_ENUMERABLE.grant_events
    assert grant.active_when is True and revoke.active_when is False
    assert (grant.holder_topic_index, grant.role_topic_index) == (2, 1)
    assert OZ_ACCESS_CONTROL_ENUMERABLE.eip165_interface_id == "0x5a05180f"


def test_all_topic0s_is_the_sorted_union():
    expected = set()
    for standard in STANDARDS:
        expected.update(standard.topic0s())
    assert all_topic0s() == sorted(expected)
    # Solady RoleSet + OZ RoleGranted/RoleRevoked = 3 distinct topics.
    assert len(all_topic0s()) == 3


# --- detect_standards ------------------------------------------------------


def test_detect_solady_by_all_markers():
    code = _code_with(*SOLADY_ENUMERABLE_ROLES.marker_selectors)
    assert detect_standards(code) == [SOLADY_ENUMERABLE_ROLES]


def test_detect_oz_by_all_markers():
    code = _code_with(*OZ_ACCESS_CONTROL_ENUMERABLE.marker_selectors)
    assert detect_standards(code) == [OZ_ACCESS_CONTROL_ENUMERABLE]


def test_partial_markers_is_inconclusive():
    # Missing one Solady marker → no detection (falls to union-enroll upstream).
    partial = _code_with(*SOLADY_ENUMERABLE_ROLES.marker_selectors[:-1])
    assert detect_standards(partial) == []


def test_detect_empty_or_none_code():
    assert detect_standards(None) == []
    assert detect_standards("0x") == []


# --- resolve_probe_code: proxy hop -----------------------------------------


class _FakeSession:
    """Stand-in for a SQLAlchemy session that answers the contracts.implementation
    lookup from an in-memory ``{address: implementation}`` map."""

    def __init__(self, impl_by_addr: dict[str, str]):
        self._impl = {k.lower(): v for k, v in impl_by_addr.items()}

    def execute(self, _stmt):
        # The statement filters lower(address)==<addr>; recover <addr> from the
        # compiled bind params so the fake honours whatever address was queried.
        addr = None
        for val in _stmt.compile().params.values():
            if isinstance(val, str) and val.startswith("0x") and len(val) == 42:
                addr = val.lower()
                break
        impl = self._impl.get(addr) if addr else None

        class _Res:
            def first(self):
                return (impl,) if impl else None

        return _Res()


def _sess(impl_by_addr: dict[str, str]) -> Any:
    return cast(Any, _FakeSession(impl_by_addr))


_PROXY = "0x" + "62" * 20
_IMPL = "0x" + "3b" * 20


def test_resolve_probe_code_db_hop(monkeypatch):
    impl_code = _code_with(*SOLADY_ENUMERABLE_ROLES.marker_selectors)
    fetched: list[str] = []

    def _fake_get_code(rpc_url, address, *, chain_id=None):
        fetched.append(address.lower())
        return impl_code if address.lower() == _IMPL else "0x00"

    monkeypatch.setattr(rss, "get_code", _fake_get_code)
    # DB links proxy → impl; the slot read must never be consulted on the DB path.
    monkeypatch.setattr(rss, "rpc_request", lambda *a, **k: (_ for _ in ()).throw(AssertionError("slot read")))

    code = resolve_probe_code(_sess({_PROXY: _IMPL}), _PROXY, 1, rpc_url="http://local")
    assert detect_standards(code) == [SOLADY_ENUMERABLE_ROLES]
    assert _IMPL in fetched


def test_resolve_probe_code_eip1967_slot_fallback(monkeypatch):
    impl_code = _code_with(*SOLADY_ENUMERABLE_ROLES.marker_selectors)

    def _fake_get_code(rpc_url, address, *, chain_id=None):
        return impl_code if address.lower() == _IMPL else "0x00"

    def _fake_rpc(rpc_url, method, params, **_kw):
        assert method == "eth_getStorageAt"
        assert params[1] == rss.EIP1967_IMPL_SLOT
        return "0x" + "00" * 12 + _IMPL.removeprefix("0x")

    monkeypatch.setattr(rss, "get_code", _fake_get_code)
    monkeypatch.setattr(rss, "rpc_request", _fake_rpc)

    # DB has no linkage → slot read supplies the impl hop.
    code = resolve_probe_code(_sess({}), _PROXY, 1, rpc_url="http://local")
    assert detect_standards(code) == [SOLADY_ENUMERABLE_ROLES]


def test_resolve_probe_code_raw_when_no_proxy(monkeypatch):
    # A non-proxy authority that itself carries the markers: no impl link, no
    # slot → the raw code is returned.
    raw = _code_with(*OZ_ACCESS_CONTROL_ENUMERABLE.marker_selectors)
    monkeypatch.setattr(rss, "get_code", lambda rpc_url, address, **k: raw)
    monkeypatch.setattr(rss, "rpc_request", lambda *a, **k: None)
    code = resolve_probe_code(_sess({}), _PROXY, 1, rpc_url="http://local")
    assert detect_standards(code) == [OZ_ACCESS_CONTROL_ENUMERABLE]


def test_resolve_probe_code_two_hop_bound(monkeypatch):
    # proxy -> a -> b -> c; with max_hops=2 we reach b, never c.
    a, b, c = ("0x" + "aa" * 20, "0x" + "bb" * 20, "0x" + "cc" * 20)
    chain = {_PROXY: a, a: b, b: c}
    reached: list[str] = []

    def _fake_get_code(rpc_url, address, *, chain_id=None):
        reached.append(address.lower())
        return "0x00"

    monkeypatch.setattr(rss, "get_code", _fake_get_code)
    monkeypatch.setattr(rss, "rpc_request", lambda *a, **k: None)
    resolve_probe_code(_sess(chain), _PROXY, 1, rpc_url="http://local")
    assert c not in reached and b in reached


def test_resolve_probe_code_rejects_zero_and_bad_address():
    assert resolve_probe_code(_sess({}), "0x" + "00" * 20, 1, rpc_url="http://local") is None
    assert resolve_probe_code(_sess({}), "not-an-address", 1, rpc_url="http://local") is None


def test_resolve_probe_code_cycle_terminates(monkeypatch):
    # proxy -> impl -> proxy: the impl link points back. Must not loop forever;
    # the seen-set breaks the second hop and the code reached is still returned.
    impl_code = _code_with(*SOLADY_ENUMERABLE_ROLES.marker_selectors)
    monkeypatch.setattr(rss, "get_code", lambda u, a, **k: impl_code if a.lower() == _IMPL else "0x00")
    monkeypatch.setattr(rss, "rpc_request", lambda *a, **k: None)
    code = resolve_probe_code(_sess({_PROXY: _IMPL, _IMPL: _PROXY}), _PROXY, 1, rpc_url="http://local")
    assert detect_standards(code) == [SOLADY_ENUMERABLE_ROLES]


def test_resolve_probe_code_zero_impl_from_db_and_slot(monkeypatch):
    # DB and the EIP-1967 slot both hand back the zero address: neither is a real
    # impl, so no hop is taken and detection stays inconclusive (→ union upstream).
    monkeypatch.setattr(rss, "get_code", lambda u, a, **k: "0x00")
    monkeypatch.setattr(rss, "rpc_request", lambda *a, **k: "0x" + "00" * 32)
    code = resolve_probe_code(_sess({_PROXY: "0x" + "00" * 20}), _PROXY, 1, rpc_url="http://local")
    assert detect_standards(code) == []


def test_resolve_probe_code_none_rpc_url_degrades(monkeypatch):
    # default_rpc_url yields no URL (no RPC configured): every wire hop is a no-op,
    # so the probe returns None and detection is inconclusive — never a raise.
    monkeypatch.setattr(rss, "default_rpc_url", lambda **k: None)
    monkeypatch.setattr(rss, "get_code", lambda *a, **k: (_ for _ in ()).throw(AssertionError("get_code with no url")))
    code = resolve_probe_code(_sess({_PROXY: _IMPL}), _PROXY, 1)
    assert code is None
    assert detect_standards(code) == []
