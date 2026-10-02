from __future__ import annotations

from typing import Any, cast

import pytest
from eth_utils.crypto import keccak

import services.resolution.role_store_standards as rss
from services.resolution.role_store_standards import (
    OZ_ACCESS_CONTROL_ENUMERABLE,
    SOLADY_ENUMERABLE_ROLES,
    detect_standards,
    resolve_probe_code,
)


def _sel(sig: str) -> str:
    return "0x" + keccak(text=sig).hex()[:8]


def _code_with(*selectors: str) -> str:
    # PUSH4 before each selector.
    return "0x" + "".join("63" + s.removeprefix("0x") for s in selectors)


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


@pytest.mark.parametrize(
    ("code", "expected"),
    [
        pytest.param(
            _code_with(*SOLADY_ENUMERABLE_ROLES.marker_selectors), [SOLADY_ENUMERABLE_ROLES], id="solady_all_markers"
        ),
        pytest.param(
            _code_with(*OZ_ACCESS_CONTROL_ENUMERABLE.marker_selectors),
            [OZ_ACCESS_CONTROL_ENUMERABLE],
            id="oz_all_markers",
        ),
        pytest.param(_code_with(*SOLADY_ENUMERABLE_ROLES.marker_selectors[:-1]), [], id="partial_markers_inconclusive"),
        pytest.param(None, [], id="none_code"),
        pytest.param("0x", [], id="empty_code"),
    ],
)
def test_detect_standards(code, expected):
    assert detect_standards(code) == expected


class _FakeSession:
    def __init__(self, impl_by_addr: dict[str, str]):
        self._impl = {k.lower(): v for k, v in impl_by_addr.items()}

    def execute(self, _stmt):
        # Recover the queried address from the compiled bind params.
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

    code = resolve_probe_code(_sess({}), _PROXY, 1, rpc_url="http://local")
    assert detect_standards(code) == [SOLADY_ENUMERABLE_ROLES]


def test_resolve_probe_code_raw_when_no_proxy(monkeypatch):
    raw = _code_with(*OZ_ACCESS_CONTROL_ENUMERABLE.marker_selectors)
    monkeypatch.setattr(rss, "get_code", lambda rpc_url, address, **k: raw)
    monkeypatch.setattr(rss, "rpc_request", lambda *a, **k: None)
    code = resolve_probe_code(_sess({}), _PROXY, 1, rpc_url="http://local")
    assert detect_standards(code) == [OZ_ACCESS_CONTROL_ENUMERABLE]


def test_resolve_probe_code_two_hop_bound(monkeypatch):
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
    # The seen-set breaks the impl-to-proxy loop.
    impl_code = _code_with(*SOLADY_ENUMERABLE_ROLES.marker_selectors)
    monkeypatch.setattr(rss, "get_code", lambda u, a, **k: impl_code if a.lower() == _IMPL else "0x00")
    monkeypatch.setattr(rss, "rpc_request", lambda *a, **k: None)
    code = resolve_probe_code(_sess({_PROXY: _IMPL, _IMPL: _PROXY}), _PROXY, 1, rpc_url="http://local")
    assert detect_standards(code) == [SOLADY_ENUMERABLE_ROLES]


def test_resolve_probe_code_zero_impl_from_db_and_slot(monkeypatch):
    monkeypatch.setattr(rss, "get_code", lambda u, a, **k: "0x00")
    monkeypatch.setattr(rss, "rpc_request", lambda *a, **k: "0x" + "00" * 32)
    code = resolve_probe_code(_sess({_PROXY: "0x" + "00" * 20}), _PROXY, 1, rpc_url="http://local")
    assert detect_standards(code) == []


def test_resolve_probe_code_none_rpc_url_degrades(monkeypatch):
    # No RPC configured: probe returns None, never raises.
    monkeypatch.setattr(rss, "default_rpc_url", lambda **k: None)
    monkeypatch.setattr(rss, "get_code", lambda *a, **k: (_ for _ in ()).throw(AssertionError("get_code with no url")))
    code = resolve_probe_code(_sess({_PROXY: _IMPL}), _PROXY, 1)
    assert code is None
    assert detect_standards(code) == []
