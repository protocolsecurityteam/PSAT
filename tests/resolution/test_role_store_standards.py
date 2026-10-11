from __future__ import annotations

from typing import Any, cast

from eth_utils.crypto import keccak
from sqlalchemy import create_engine
from sqlalchemy.orm import Session

import services.resolution.role_store_standards as rss
from db.models import Contract
from services.resolution.role_store_standards import (
    SOLADY_ENUMERABLE_ROLES,
    detect_standards,
    resolve_probe_code,
)
from tests.conftest import DATABASE_URL, requires_postgres


def _sel(sig: str) -> str:
    return "0x" + keccak(text=sig).hex()[:8]


def _code_with(*selectors: str) -> str:
    # PUSH4 before each selector.
    return "0x" + "".join("63" + s.removeprefix("0x") for s in selectors)


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


def test_resolve_probe_code_cycle_terminates(monkeypatch):
    # The seen-set breaks the impl-to-proxy loop.
    impl_code = _code_with(*SOLADY_ENUMERABLE_ROLES.marker_selectors)
    monkeypatch.setattr(rss, "get_code", lambda u, a, **k: impl_code if a.lower() == _IMPL else "0x00")
    monkeypatch.setattr(rss, "rpc_request", lambda *a, **k: None)
    code = resolve_probe_code(_sess({_PROXY: _IMPL, _IMPL: _PROXY}), _PROXY, 1, rpc_url="http://local")
    assert detect_standards(code) == [SOLADY_ENUMERABLE_ROLES]


@requires_postgres
def test_probe_code_follows_only_the_authoritys_own_chain_implementation(monkeypatch):
    proxy = "0x" + "a7" * 20
    mainnet_impl = "0x" + "11" * 20
    base_impl = "0x" + "22" * 20
    engine = create_engine(DATABASE_URL)
    session = Session(engine, expire_on_commit=False)
    try:
        session.add(Contract(address=proxy, chain="base", is_proxy=True, implementation=base_impl))
        session.commit()
        codes = {proxy: "0xproxy", mainnet_impl: "0xmainnetimpl", base_impl: "0xbaseimpl"}
        monkeypatch.setattr(rss, "get_code", lambda url, addr, chain_id=None: codes.get(addr.lower()))
        slot_word = "0x" + "0" * 24 + mainnet_impl[2:]
        monkeypatch.setattr(
            rss,
            "rpc_request",
            lambda url, method, params, chain_id=None: slot_word if params[0].lower() == proxy else "0x" + "0" * 64,
        )

        assert resolve_probe_code(session, proxy, 1, rpc_url="http://stub") == "0xmainnetimpl"
        assert resolve_probe_code(session, proxy, 8453, rpc_url="http://stub") == "0xbaseimpl"
    finally:
        session.rollback()
        session.query(Contract).filter(Contract.address == proxy).delete()
        session.commit()
        session.close()
        engine.dispose()
