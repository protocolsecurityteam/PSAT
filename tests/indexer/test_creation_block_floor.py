"""``services.resolution.creation_block_floor.resolve_scan_floor`` — the floor a
log scan may start from.

The floor is what keeps a backfill from asking an upstream for the whole chain,
and its three answers are distinct: a durable cursor (free, and preferred), a
creation block from Etherscan (paid, memoized per address), or DEFER. It never
fails open to block 0 — a scan that started at 0 because the floor was unknown
would read downstream as a scan that covered everything.

Pure unit tests: the module's two collaborators are monkeypatched, so nothing
here touches a cursor table or the Etherscan wire.
"""

from __future__ import annotations


def test_resolve_scan_floor_caches_per_address(monkeypatch):
    # The floor memoizes per (address, chain) so a multi-key fold or sibling
    # functions never issue duplicate Etherscan lookups.
    import services.resolution.creation_block_floor as floor_mod

    floor_mod.clear_scan_floor_cache()
    monkeypatch.setattr(floor_mod, "_floor_from_cursor", lambda *_a, **_k: None)
    calls: list[str] = []

    def fake_lookup(addr, **_k):
        calls.append(addr)
        return 6_000_000

    monkeypatch.setattr(floor_mod, "get_contract_creation_block", fake_lookup)
    addr = "0x" + "ab" * 20
    assert floor_mod.resolve_scan_floor(addr, 1) == 6_000_000 - 1
    assert floor_mod.resolve_scan_floor(addr, 1) == 6_000_000 - 1
    assert calls == [addr]  # second call served from cache


def test_resolve_scan_floor_prefers_durable_cursor(monkeypatch):
    # A durable cursor floor is preferred over an Etherscan call (no rate limit).
    import services.resolution.creation_block_floor as floor_mod

    floor_mod.clear_scan_floor_cache()
    monkeypatch.setattr(floor_mod, "_floor_from_cursor", lambda *_a, **_k: 5_000_000)
    monkeypatch.setattr(
        floor_mod,
        "get_contract_creation_block",
        lambda *_a, **_k: (_ for _ in ()).throw(AssertionError("cursor floor must win, no Etherscan call")),
    )
    assert floor_mod.resolve_scan_floor("0x" + "cd" * 20, 1) == 5_000_000


def test_resolve_scan_floor_defers_on_unknown(monkeypatch):
    # No cursor + no creation block → DEFER (None), never fail-open to 0.
    import services.resolution.creation_block_floor as floor_mod

    floor_mod.clear_scan_floor_cache()
    monkeypatch.setattr(floor_mod, "_floor_from_cursor", lambda *_a, **_k: None)
    monkeypatch.setattr(floor_mod, "get_contract_creation_block", lambda *_a, **_k: None)
    assert floor_mod.resolve_scan_floor("0x" + "ab" * 20, 1) is None


def test_resolve_scan_floor_none_for_zero_or_missing_address(monkeypatch):
    import services.resolution.creation_block_floor as floor_mod

    floor_mod.clear_scan_floor_cache()
    monkeypatch.setattr(
        floor_mod,
        "_floor_from_cursor",
        lambda *_a, **_k: (_ for _ in ()).throw(AssertionError("must not query for zero/invalid")),
    )
    assert floor_mod.resolve_scan_floor("0x" + "0" * 40, 1) is None
    assert floor_mod.resolve_scan_floor(None, 1) is None
    assert floor_mod.resolve_scan_floor("not-an-address", 1) is None
